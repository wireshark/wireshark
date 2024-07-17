/* packet-ntp.c
 * Routines for NTP packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <math.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include <epan/tvbparse.h>
#include <epan/conversation.h>

#include <wsutil/epochs.h>

#include "packet-ntp.h"

void proto_register_ntp(void);
void proto_reg_handoff_ntp(void);

static dissector_handle_t ntp_handle;

/*
 * Dissecting NTP packets version 3 and 4 (RFC5905, RFC2030, RFC1769, RFC1361,
 * RFC1305).
 *
 * Those packets have simple structure:
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Root Delay                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Root Dispersion                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Reference Identifier                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Reference Timestamp (64)                    |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Originate Timestamp (64)                    |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Receive Timestamp (64)                     |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Transmit Timestamp (64)                    |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Key Identifier (optional) (32)                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Message Digest (optional) (128/160)           |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * NTP timestamps are represented as a 64-bit unsigned fixed-point number,
 * in seconds relative to 0h on 1 January 1900. The integer part is in the
 * first 32 bits and the fraction part in the last 32 bits.
 *
 *
 * NTP Control messages as defined in version 2, 3 and 4 (RFC1119, RFC1305) use
 * the following structure:
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |00 | VN  | 110 |R E M| OpCode  |           Sequence            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Status             |        Association ID         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Offset             |             Count             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                     Data (468 octets max)                     |
 * |                                                               |
 * |                               |        Padding (zeros)        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Authenticator (optional) (96)                 |
 * |                                                               |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Not yet implemented: complete dissection of TPCTRL_OP_SETTRAP,
 * NTPCTRL_OP_ASYNCMSG, NTPCTRL_OP_UNSETTRAPSETTRAP Control-Messages
 *
 */

#define UDP_PORT_NTP	123
#define TCP_PORT_NTP	123

/* Leap indicator, 2bit field is used to warn of a inserted/deleted
 * second, or clock unsynchronized indication.
 */
#define NTP_LI_MASK	0xC0

#define NTP_LI_NONE	0
#define NTP_LI_61	1
#define NTP_LI_59	2
#define NTP_LI_UNKNOWN	3

static const value_string li_types[] = {
	{ NTP_LI_NONE,	  "no warning" },
	{ NTP_LI_61,	  "last minute of the day has 61 seconds" },
	{ NTP_LI_59,	  "last minute of the day has 59 seconds" },
	{ NTP_LI_UNKNOWN, "unknown (clock unsynchronized)" },
	{ 0,		  NULL}
};

/* Version info, 3bit field informs about NTP version used in particular
 * packet. According to rfc2030, version info could be only 3 or 4, but I
 * have noticed packets with 1 or even 6 as version numbers. They are
 * produced as a result of ntptrace command. Are those packets malformed
 * on purpose? I don't know yet, probably some browsing through ntp sources
 * would help. My solution is to put them as reserved for now.
 */
#define NTP_VN_MASK	0x38

static const value_string ver_nums[] = {
	{ 0,	"reserved" },
	{ 1,	"NTP Version 1" },
	{ 2,	"NTP Version 2" },
	{ 3,	"NTP Version 3" },
	{ 4,	"NTP Version 4" },
	{ 5,	"reserved" },
	{ 6,	"reserved" },
	{ 7,	"reserved" },
	{ 0,	NULL}
};

/* Mode, 3bit field representing mode of communication.
 */
#define NTP_MODE_MASK   7

#define NTP_MODE_RSV	0
#define NTP_MODE_SYMACT	1
#define NTP_MODE_SYMPAS	2
#define NTP_MODE_CLIENT	3
#define NTP_MODE_SERVER	4
#define NTP_MODE_BCAST	5
#define NTP_MODE_CTRL	6
#define NTP_MODE_PRIV	7

static const value_string mode_types[] = {
	{ NTP_MODE_RSV,		"reserved" },
	{ NTP_MODE_SYMACT,	"symmetric active" },
	{ NTP_MODE_SYMPAS,	"symmetric passive" },
	{ NTP_MODE_CLIENT,	"client" },
	{ NTP_MODE_SERVER,	"server" },
	{ NTP_MODE_BCAST,	"broadcast" },
	{ NTP_MODE_CTRL,	"reserved for NTP control message"},
	{ NTP_MODE_PRIV,	"reserved for private use" },
	{ 0,		NULL}
};

static const value_string info_mode_types[] = {
	{ NTP_MODE_RSV,		"reserved" },
	{ NTP_MODE_SYMACT,	"symmetric active" },
	{ NTP_MODE_SYMPAS,	"symmetric passive" },
	{ NTP_MODE_CLIENT,	"client" },
	{ NTP_MODE_SERVER,	"server" },
	{ NTP_MODE_BCAST,	"broadcast" },
	{ NTP_MODE_CTRL,	"control"},
	{ NTP_MODE_PRIV,	"private" },
	{ 0,		NULL}
};

/* According to rfc, unspecified or invalid (stratum-0) servers should
 * set their Reference ID (4bytes field) according to following table:
 * https://www.iana.org/assignments/ntp-parameters/ntp-parameters.xhtml#ntp-parameters-2
 */
static const struct {
	const char *id;
	const char *data;
} kod_messages[] = {
	/* IANA / RFC 5905 */
	{ "ACST",	"The association belongs to a unicast server" },
	{ "AUTH",	"Server authentication failed" },
	{ "AUTO",	"Autokey sequence failed" },
	{ "BCST",	"The association belongs to a broadcast server" },
	{ "CRYP",	"Cryptographic authentication or identification failed" },
	{ "DENY",	"Access denied by remote server" },
	{ "DROP",	"Lost peer in symmetric mode" },
	{ "RSTR",	"Access denied due to local policy" },
	{ "INIT",	"The association has not yet synchronized for the first time" },
	{ "MCST",	"The association belongs to a dynamically discovered server" },
	{ "NKEY",	"No key found. Either the key was never installed or is not trusted" },
	{ "NTSN",	"Network Time Security (NTS) negative-acknowledgment (NAK)" },
	{ "RATE",	"Rate exceeded. The server has temporarily denied access because the client exceeded the rate threshold" },
	{ "RMOT",	"Alteration of association from a remote host running ntpdc." },
	{ "STEP",	"A step change in system time has occurred, but the association has not yet resynchronized" },
	{ "\0\0\0\0",	"NULL" },
	{ NULL,		NULL}
};

/* According to rfc 4330, primary (stratum-1) servers should set
 * their Reference ID (4bytes field) according to following table:
 */
static const struct {
	const char *id;
	const char *data;
} primary_sources[] = {
	/* Reference Identifier Codes
	 *  https://www.iana.org/assignments/ntp-parameters/ntp-parameters.xhtml#ntp-parameters-1
	 */
	{ "GOES",	"Geostationary Orbit Environment Satellite" },
	{ "GPS\0",	"Global Position System" },
	{ "GAL\0",	"Galileo Positioning System" },
	{ "PPS\0",	"Generic pulse-per-second" },
	{ "IRIG",	"Inter-Range Instrumentation Group" },
	{ "WWVB",	"LF Radio WWVB Ft. Collins, CO 60 kHz" },
	{ "DCF\0",	"LF Radio DCF77 Mainflingen, DE 77.5 kHz" },
	{ "HBG\0",	"LF Radio HBG Prangins, HB 75 kHz" },
	{ "MSF\0",	"LF Radio MSF Anthorn, UK 60 kHz" },
	{ "JJY\0",	"LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz" },
	{ "LORC",	"MF Radio LORAN C station, 100 kHz" },
	{ "TDF\0",	"MF Radio Allouis, FR 162 kHz" },
	{ "CHU\0",	"HF Radio CHU Ottawa, Ontario" },
	{ "WWV\0",	"HF Radio WWV Ft. Collins, CO" },
	{ "WWVH",	"HF Radio WWVH Kauai, HI" },
	{ "NIST",	"NIST telephone modem" },
	{ "ACTS",	"NIST telephone modem" },
	{ "USNO",	"USNO telephone modem" },
	{ "PTB\0",	"European telephone modem" },
	{ "DFM\0",	"UTC(DFM)"},

	/* Unofficial codes */
	{ "LCL\0",	"uncalibrated local clock" },
	{ "LOCL",	"uncalibrated local clock" },
	{ "CESM",	"calibrated Cesium clock" },
	{ "RBDM",	"calibrated Rubidium clock" },
	{ "OMEG",	"OMEGA radionavigation system" },
	{ "DCN\0",	"DCN routing protocol" },
	{ "TSP\0",	"TSP time protocol" },
	{ "DTS\0",	"Digital Time Service" },
	{ "ATOM",	"Atomic clock (calibrated)" },
	{ "VLF\0",	"VLF radio (OMEGA,, etc.)" },
	{ "DCFa",	"DCF77 with amplitude modulation" },
	{ "DCFp",	"DCF77 with phase modulation/pseudo random phase modulation" },
	{ "PZF\0",	"DCF77 correlation receiver for middle Europe" },
	{ "PZFs",	"DCF77 correlation receiver (with shared memory access)" },
	{ "PZFi",	"DCF77 correlation receiver (with interrupt based access)" },
	{ "GPSD",	"GPSD client driver" },
	{ "GPSs",	"GPS (with shared memory access)" },
	{ "GPSi",	"GPS (with interrupt based access)" },
	{ "GLNs",	"GPS/GLONASS (with shared memory access)" },
	{ "GLNi",	"GPS/GLONASS (with interrupt based access)" },
	{ "GNSS",	"Global Navigation Satellite System" },
	{ "MRS\0",	"Multi Reference System" },
	{ "Nut1",	"UT1(NIST)" },
	{ "1PPS",	"External 1 PPS input" },
	{ "FREE",	"(Internal clock)" },
	// { "INIT",	"(Initialization)" },
	{ "\0\0\0\0",	"NULL" },
	{ NULL,		NULL}
};


#define NTPCTRL_R_MASK 0x80

#define ctrl_r_types ext_r_types

#define NTPCTRL_ERROR_MASK 0x40
#define NTPCTRL_MORE_MASK 0x20
#define NTPCTRL_OP_MASK 0x1f

#define NTPCTRL_OP_UNSPEC 0		/* unspecified */
#define NTPCTRL_OP_READSTAT 1		/* read status */
#define NTPCTRL_OP_READVAR 2		/* read variables */
#define NTPCTRL_OP_WRITEVAR 3		/* write variables */
#define NTPCTRL_OP_READCLOCK 4		/* read clock variables */
#define NTPCTRL_OP_WRITECLOCK 5		/* write clock variables */
#define NTPCTRL_OP_SETTRAP 6		/* set trap address */
#define NTPCTRL_OP_ASYNCMSG 7		/* asynchronous message */
#define NTPCTRL_OP_CONFIGURE 8		/* runtime configuration */
#define NTPCTRL_OP_SAVECONFIG 9		/* save config to file */
#define NTPCTRL_OP_READ_MRU 10		/* retrieve MRU (mrulist) */
#define NTPCTRL_OP_READ_ORDLIST_A 11	/* ordered list req. auth. */
#define NTPCTRL_OP_REQ_NONCE 12		/* request a client nonce */
#define NTPCTRL_OP_UNSETTRAP 31		/* unset trap */

static const value_string ctrl_op_types[] = {
	{ NTPCTRL_OP_UNSPEC,		"reserved" },
	{ NTPCTRL_OP_READSTAT,		"read status" },
	{ NTPCTRL_OP_READVAR,		"read variables" },
	{ NTPCTRL_OP_WRITEVAR,		"write variables" },
	{ NTPCTRL_OP_READCLOCK,		"read clock variables" },
	{ NTPCTRL_OP_WRITECLOCK,	"write clock variables" },
	{ NTPCTRL_OP_SETTRAP,		"set trap address/port" },
	{ NTPCTRL_OP_ASYNCMSG,		"asynchronous message" },
	{ NTPCTRL_OP_CONFIGURE,		"runtime configuration" },
	{ NTPCTRL_OP_SAVECONFIG,	"save config to file" },
	{ NTPCTRL_OP_READ_MRU,		"retrieve MRU (mrulist)" },
	{ NTPCTRL_OP_READ_ORDLIST_A,	"retrieve ordered list" },
	{ NTPCTRL_OP_REQ_NONCE,		"request a client nonce" },
	{ NTPCTRL_OP_UNSETTRAP,		"unset trap address/port" },
	{ 0,		NULL}
};

#define NTPCTRL_SYSSTATUS_LI_MASK		0xC000
#define NTPCTRL_SYSSTATUS_CLK_MASK		0x3F00
#define NTPCTRL_SYSSTATUS_COUNT_MASK	0x00F0
#define NTPCTRL_SYSSTATUS_CODE_MASK		0x000F

static const value_string ctrl_sys_status_clksource_types[] = {
	{ 0,		"unspecified or unknown" },
	{ 1,		"Calibrated atomic clock (e.g. HP 5061)" },
	{ 2,		"VLF (band 4) or LF (band 5) radio (e.g. OMEGA, WWVB)" },
	{ 3,		"HF (band 7) radio (e.g. CHU, MSF, WWV/H)" },
	{ 4,		"UHF (band 9) satellite (e.g. GOES, GPS)" },
	{ 5,		"local net (e.g. DCN, TSP, DTS)" },
	{ 6,		"UDP/NTP" },
	{ 7,		"UDP/TIME" },
	{ 8,		"eyeball-and-wristwatch" },
	{ 9,		"telephone modem (e.g. NIST)" },
	{ 0,		NULL}
};

static const value_string ctrl_sys_status_event_types[] = {
	{ 0,		"unspecified" },
	{ 1,		"frequency correction (drift) file not available" },
	{ 2,		"frequency correction started (frequency stepped)" },
	{ 3,		"spike detected and ignored, starting stepout timer" },
	{ 4,		"frequency training started" },
	{ 5,		"clock synchronized" },
	{ 6,		"system restart" },
	{ 7,		"panic stop (required step greater than panic threshold)" },
	{ 8,		"no system peer" },
	{ 9,		"leap second insertion/deletion armed" },
	{ 10,		"leap second disarmed" },
	{ 11,		"leap second inserted or deleted" },
	{ 12,		"clock stepped (stepout timer expired)" },
	{ 13,		"kernel loop discipline status changed" },
	{ 14,		"leapseconds table loaded from file" },
	{ 15,		"leapseconds table outdated, updated file needed" },
	{ 0,		NULL}
};

#define NTPCTRL_PEERSTATUS_STATUS_MASK		0xF800
#define NTPCTRL_PEERSTATUS_CONFIG_MASK		0x8000
#define NTPCTRL_PEERSTATUS_AUTHENABLE_MASK	0x4000
#define NTPCTRL_PEERSTATUS_AUTHENTIC_MASK	0x2000
#define NTPCTRL_PEERSTATUS_REACH_MASK		0x1000
#define NTPCTRL_PEERSTATUS_BCAST_MASK		0x0800
#define NTPCTRL_PEERSTATUS_SEL_MASK		0x0700
#define NTPCTRL_PEERSTATUS_COUNT_MASK		0x00F0
#define NTPCTRL_PEERSTATUS_CODE_MASK		0x000F

static const true_false_string tfs_ctrl_peer_status_config = {"configured (peer.config)", "not configured (peer.config)" };
static const true_false_string tfs_ctrl_peer_status_authenable = { "authentication enabled (peer.authenable)", "authentication disabled (peer.authenable)" };
static const true_false_string tfs_ctrl_peer_status_authentic = { "authentication okay (peer.authentic)", "authentication not okay (peer.authentic)" };
static const true_false_string tfs_ctrl_peer_status_reach = {"reachability okay (peer.reach != 0)", "reachability not okay (peer.reach != 0)" };

static const value_string ctrl_peer_status_selection_types[] = {
	{ 0,		"rejected" },
	{ 1,		"passed sanity checks (tests 1 through 8 in Section 3.4.3)" },
	{ 2,		"passed correctness checks (intersection algorithm in Section 4.2.1)" },
	{ 3,		"passed candidate checks (if limit check implemented)" },
	{ 4,		"passed outlier checks (clustering algorithm in Section 4.2.2)" },
	{ 5,		"current synchronization source; max distance exceeded (if limit check implemented)" },
	{ 6,		"current synchronization source; max distance okay" },
	{ 7,		"reserved" },
	{ 0,		NULL}
};

static const value_string ctrl_peer_status_event_types[] = {
	{ 0,		"unspecified" },
	{ 1,		"association mobilized" },
	{ 2,		"association demobilized" },
	{ 3,		"peer unreachable (peer.reach was nonzero now zero)" },
	{ 4,		"peer reachable (peer.reach was zero now nonzero)" },
	{ 5,		"association restarted or timed out" },
	{ 6,		"no server found (ntpdate mode)" },
	{ 7,		"rate exceeded (kiss code RATE)" },
	{ 8,		"access denied (kiss code DENY)" },
	{ 9,		"leap armed from server LI code" },
	{ 10,		"become system peer" },
	{ 11,		"reference clock event (see clock status word)" },
	{ 12,		"authentication failure" },
	{ 13,		"popcorn spike suppressor" },
	{ 14,		"entering interleave mode" },
	{ 15,		"interleave error (recovered)" },
	{ 0,		NULL}
};

#define NTPCTRL_CLKSTATUS_STATUS_MASK	0xFF00
#define NTPCTRL_CLKSTATUS_CODE_MASK		0x00FF

static const value_string ctrl_clk_status_types[] = {
	{ 0,		"clock operating within nominals" },
	{ 1,		"reply timeout" },
	{ 2,		"bad reply format" },
	{ 3,		"hardware or software fault" },
	{ 4,		"propagation failure" },
	{ 5,		"bad date format or value" },
	{ 6,		"bad time format or value" },
	{ 0,		NULL}
};

#define NTP_CTRL_ERRSTATUS_CODE_MASK	0xFF00

static const value_string ctrl_err_status_types[] = {
	{ 0,		"unspecified" },
	{ 1,		"authentication failure" },
	{ 2,		"invalid message length or format" },
	{ 3,		"invalid opcode" },
	{ 4,		"unknown association identifier" },
	{ 5,		"unknown variable name" },
	{ 6,		"invalid variable value" },
	{ 7,		"administratively prohibited" },
	{ 0,		NULL}
};

static const value_string err_values_types[] = {
	{ 0,		"No error" },
	{ 1,		"incompatible implementation number"},
	{ 2,		"unimplemented request code" },
	{ 3,		"format error" },
	{ 4,		"no data available" },
	{ 5,		"unknown" },
	{ 6,		"unknown" },
	{ 7,		"authentication failure"},
	{ 0,		NULL}
};

#define NTPPRIV_R_MASK 0x80

#define NTPPRIV_MORE_MASK 0x40

#define NTPPRIV_AUTH_MASK 0x80
#define NTPPRIV_SEQ_MASK 0x7f

#define XNTPD_OLD 0x02
#define XNTPD 0x03

static const value_string priv_impl_types[] = {
	{ 0,		"UNIV" },
	{ XNTPD_OLD,	"XNTPD_OLD (pre-IPv6)" },
	{ XNTPD,	"XNTPD" },
	{ 0,		NULL}
};

static const value_string priv_mode7_int_action[] = {
	{ 1,	"Interface exists" },
	{ 2,	"Interface created" },
	{ 3,	"Interface deleted" },
	{ 0,	NULL}
};

#define PRIV_RC_PEER_LIST       0
#define PRIV_RC_PEER_LIST_SUM   1
#define PRIV_RC_PEER_INFO       2
#define PRIV_RC_PEER_STATS      3
#define PRIV_RC_SYS_INFO        4
#define PRIV_RC_SYS_STATS       5
#define PRIV_RC_IO_STATS        6
#define PRIV_RC_MEM_STATS       7
#define PRIV_RC_LOOP_INFO       8
#define PRIV_RC_TIMER_STATS     9
#define PRIV_RC_CONFIG         10
#define PRIV_RC_UNCONFIG       11
#define PRIV_RC_SET_SYS_FLAG   12
#define PRIV_RC_CLR_SYS_FLAG   13
#define PRIV_RC_GET_RESTRICT   16
#define PRIV_RC_RESADDFLAGS    17
#define PRIV_RC_RESSUBFLAGS    18
#define PRIV_RC_UNRESTRICT     19
#define PRIV_RC_MON_GETLIST    20
#define PRIV_RC_RESET_STATS    21
#define PRIV_RC_RESET_PEER     22
#define PRIV_RC_TRUSTKEY       26
#define PRIV_RC_UNTRUSTKEY     27
#define PRIV_RC_AUTHINFO       28
#define PRIV_RC_TRAPS          29
#define PRIV_RC_ADD_TRAP       30
#define PRIV_RC_CLR_TRAP       31
#define PRIV_RC_REQUEST_KEY    32
#define PRIV_RC_CONTROL_KEY    33
#define PRIV_RC_CTL_STATS      34
#define PRIV_RC_GET_CLOCKINFO  36
#define PRIV_RC_SET_CLKFUDGE   37
#define PRIV_RC_GET_KERNEL     38
#define PRIV_RC_GET_CLKBUGINFO 39
#define PRIV_RC_MON_GETLIST_1  42
#define PRIV_RC_IF_STATS       44
#define PRIV_RC_IF_RELOAD      45

static const value_string priv_rc_types[] = {
	{ PRIV_RC_PEER_LIST,		"PEER_LIST" },
	{ PRIV_RC_PEER_LIST_SUM,	"PEER_LIST_SUM" },
	{ PRIV_RC_PEER_INFO,		"PEER_INFO" },
	{ PRIV_RC_PEER_STATS,		"PEER_STATS" },
	{ PRIV_RC_SYS_INFO,		"SYS_INFO" },
	{ PRIV_RC_SYS_STATS,		"SYS_STATS" },
	{ PRIV_RC_IO_STATS,		"IO_STATS" },
	{ PRIV_RC_MEM_STATS,		"MEM_STATS" },
	{ PRIV_RC_LOOP_INFO,		"LOOP_INFO" },
	{ PRIV_RC_TIMER_STATS,		"TIMER_STATS" },
	{ PRIV_RC_CONFIG,		"CONFIG" },
	{ PRIV_RC_UNCONFIG,		"UNCONFIG" },
	{ PRIV_RC_SET_SYS_FLAG,		"SET_SYS_FLAG" },
	{ PRIV_RC_CLR_SYS_FLAG,		"CLR_SYS_FLAG" },
	{ 14,				"MONITOR" },
	{ 15,				"NOMONITOR" },
	{ PRIV_RC_GET_RESTRICT,		"GET_RESTRICT" },
	{ PRIV_RC_RESADDFLAGS,		"RESADDFLAGS" },
	{ PRIV_RC_RESSUBFLAGS,		"RESSUBFLAGS" },
	{ PRIV_RC_UNRESTRICT,		"UNRESTRICT" },
	{ PRIV_RC_MON_GETLIST,		"MON_GETLIST" },
	{ PRIV_RC_RESET_STATS,		"RESET_STATS" },
	{ PRIV_RC_RESET_PEER,		"RESET_PEER" },
	{ 23,				"REREAD_KEYS" },
	{ 24,				"DO_DIRTY_HACK" },
	{ 25,				"DONT_DIRTY_HACK" },
	{ PRIV_RC_TRUSTKEY,		"TRUSTKEY" },
	{ PRIV_RC_UNTRUSTKEY,		"UNTRUSTKEY" },
	{ PRIV_RC_AUTHINFO,		"AUTHINFO" },
	{ PRIV_RC_TRAPS,		"TRAPS" },
	{ PRIV_RC_ADD_TRAP,		"ADD_TRAP" },
	{ PRIV_RC_CLR_TRAP,		"CLR_TRAP" },
	{ PRIV_RC_REQUEST_KEY,		"REQUEST_KEY" },
	{ PRIV_RC_CONTROL_KEY,		"CONTROL_KEY" },
	{ PRIV_RC_CTL_STATS,		"GET_CTLSTATS" },
	{ 35,				"GET_LEAPINFO" },
	{ PRIV_RC_GET_CLOCKINFO,	"GET_CLOCKINFO" },
	{ PRIV_RC_SET_CLKFUDGE,		"SET_CLKFUDGE" },
	{ PRIV_RC_GET_KERNEL,		"GET_KERNEL" },
	{ PRIV_RC_GET_CLKBUGINFO,	"GET_CLKBUGINFO" },
	{ 40,				"UNASSIGNED" },     /* included to allow direct lookup */
	{ 41,				"SET_PRECISION" },
	{ PRIV_RC_MON_GETLIST_1,	"MON_GETLIST_1" },
	{ 43,				"HOSTNAME_ASSOCID" },
	{ PRIV_RC_IF_STATS,		"IF_STATS" },
	{ PRIV_RC_IF_RELOAD,		"IF_RELOAD" },
	{ 0,				NULL}
};
static value_string_ext priv_rc_types_ext = VALUE_STRING_EXT_INIT(priv_rc_types);

#define PRIV_INFO_FLAG_CONFIG        0x1
#define PRIV_INFO_FLAG_SYSPEER       0x2
#define PRIV_INFO_FLAG_BURST         0x4
#define PRIV_INFO_FLAG_REFCLOCK      0x8
#define PRIV_INFO_FLAG_PREFER        0x10
#define PRIV_INFO_FLAG_AUTHENABLE    0x20
#define PRIV_INFO_FLAG_SEL_CANDIDATE 0x40
#define PRIV_INFO_FLAG_SHORTLIST     0x80
/* XXX PRIV_INFO_FLAG_IBURST is unused, is a field needed? */
#define PRIV_INFO_FLAG_IBURST        0x100

#define PRIV_CONF_FLAG_AUTHENABLE    0x01
#define PRIV_CONF_FLAG_PREFER        0x02
#define PRIV_CONF_FLAG_BURST         0x04
#define PRIV_CONF_FLAG_IBURST        0x08
#define PRIV_CONF_FLAG_NOSELECT      0x10
#define PRIV_CONF_FLAG_SKEY          0x20

#define PRIV_SYS_FLAG_BCLIENT    0x01
#define PRIV_SYS_FLAG_PPS        0x02
#define PRIV_SYS_FLAG_NTP        0x04
#define PRIV_SYS_FLAG_KERNEL     0x08
#define PRIV_SYS_FLAG_MONITOR    0x10
#define PRIV_SYS_FLAG_FILEGEN    0x20
#define PRIV_SYS_FLAG_AUTH       0x40
#define PRIV_SYS_FLAG_CAL        0x80

#define PRIV_RESET_FLAG_ALLPEERS 0x00000001
#define PRIV_RESET_FLAG_IO       0x00000002
#define PRIV_RESET_FLAG_SYS      0x00000004
#define PRIV_RESET_FLAG_MEM      0x00000008
#define PRIV_RESET_FLAG_TIMER    0x00000010
#define PRIV_RESET_FLAG_AUTH     0x00000020
#define PRIV_RESET_FLAG_CTL      0x00000040

static const range_string stratum_rvals[] = {
	{ 0,	0, "unspecified or invalid" },
	{ 1,	1, "primary reference" },
	{ 2,	15, "secondary reference" },
	{ 16,	16, "unsynchronized" },
	{ 17,	255, "reserved" },
	{ 0,	0, NULL }
};

#define NTP_MD5_ALGO 0
#define NTP_SHA_ALGO 1

static const value_string authentication_types[] = {
	{ NTP_MD5_ALGO,		"MD5" },
	{ NTP_SHA_ALGO,		"SHA" },
	{ 0,		NULL}
};

/*
 * NTP Extension Field Types.
 * https://www.iana.org/assignments/ntp-parameters/ntp-parameters.xhtml#ntp-parameters-3
 */
static const value_string ntp_ext_field_types[] = {
	{ 0x0002, "No-Operation Request" },
	{ 0x0102, "Association Message Request" },
	{ 0x0104, "Unique Identifier" },
	{ 0x0202, "Certificate Message Request" },
	{ 0x0204, "NTS Cookie" },
	{ 0x0302, "Cookie Message Request" },
	{ 0x0304, "NTS Cookie Placeholder" },
	{ 0x0402, "Autokey Message Request" },
	{ 0x0404, "NTS Authenticator and Encrypted Extension Fields" },
	{ 0x0502, "Leapseconds Message Request" },
	{ 0x0602, "Sign Message Request" },
	{ 0x0702, "IFF Identity Message Request" },
	{ 0x0802, "GQ Identity Message Request" },
	{ 0x0902, "MV Identity Message Request" },
	{ 0x2005, "Checksum Complement" },
	{ 0x8002, "No-Operation Response" },
	{ 0x8102, "Association Message Response" },
	{ 0x8202, "Certificate Message Response" },
	{ 0x8302, "Cookie Message Response" },
	{ 0x8402, "Autokey Message Response" },
	{ 0x8502, "Leapseconds Message Response" },
	{ 0x8602, "Sign Message Response" },
	{ 0x8702, "IFF Identity Message Response" },
	{ 0x8802, "GQ Identity Message Response" },
	{ 0x8902, "MV Identity Message Response" },
	{ 0xC002, "No-Operation Error Response" },
	{ 0xC102, "Association Message Error Response" },
	{ 0xC202, "Certificate Message Error Response" },
	{ 0xC302, "Cookie Message Error Response" },
	{ 0xC402, "Autokey Message Error Response" },
	{ 0xC502, "Leapseconds Message Error Response" },
	{ 0xC602, "Sign Message Error Response" },
	{ 0xC702, "IFF Identity Message Error Response" },
	{ 0xC802, "GQ Identity Message Error Response" },
	{ 0xC902, "MV Identity Message Error Response" },
	{ 0xF323, "Monotonic Timestamp & Root Delay/Dispersion (exp)" },
	{ 0xF324, "Network PTP Time correction (exp)" },
	{ 0, NULL }
};


typedef struct {
	uint32_t req_frame;
	uint32_t resp_frame;
	nstime_t req_time;
	uint32_t seq;
} ntp_trans_info_t;

typedef struct {
	wmem_tree_t *trans;
} ntp_conv_info_t;


static int proto_ntp;

static int hf_ntp_flags;
static int hf_ntp_flags_li;
static int hf_ntp_flags_vn;
static int hf_ntp_flags_mode;
static int hf_ntp_stratum;
static int hf_ntp_ppoll;
static int hf_ntp_precision;
static int hf_ntp_rootdelay;
static int hf_ntp_rootdispersion;
static int hf_ntp_refid;
static int hf_ntp_reftime;
static int hf_ntp_org;
static int hf_ntp_rec;
static int hf_ntp_xmt;
static int hf_ntp_keyid;
static int hf_ntp_mac;
static int hf_ntp_padding;
static int hf_ntp_key_type;
static int hf_ntp_key_index;
static int hf_ntp_key_signature;
static int hf_ntp_response_in;
static int hf_ntp_request_in;
static int hf_ntp_delta_time;

static int hf_ntp_ext;
static int hf_ntp_ext_type;
static int hf_ntp_ext_length;
static int hf_ntp_ext_value;

static int hf_ntpctrl_flags2;
static int hf_ntpctrl_flags2_r;
static int hf_ntpctrl_flags2_error;
static int hf_ntpctrl_flags2_more;
static int hf_ntpctrl_flags2_opcode;
static int hf_ntpctrl_sequence;
static int hf_ntpctrl_status;
static int hf_ntpctrl_error_status_word;
static int hf_ntpctrl_sys_status_li;
static int hf_ntpctrl_sys_status_clksrc;
static int hf_ntpctrl_sys_status_count;
static int hf_ntpctrl_sys_status_code;
static int hf_ntpctrl_peer_status_b0;
static int hf_ntpctrl_peer_status_b1;
static int hf_ntpctrl_peer_status_b2;
static int hf_ntpctrl_peer_status_b3;
static int hf_ntpctrl_peer_status_b4;
static int hf_ntpctrl_peer_status_selection;
static int hf_ntpctrl_peer_status_count;
static int hf_ntpctrl_peer_status_code;
static int hf_ntpctrl_clk_status;
static int hf_ntpctrl_clk_status_code;
static int hf_ntpctrl_associd;
static int hf_ntpctrl_offset;
static int hf_ntpctrl_count;
static int hf_ntpctrl_data;
static int hf_ntpctrl_item;
static int hf_ntpctrl_trapmsg;
static int hf_ntpctrl_ordlist;
static int hf_ntpctrl_configuration;
static int hf_ntpctrl_mru;
static int hf_ntpctrl_nonce;

static int hf_ntppriv_flags_r;
static int hf_ntppriv_flags_more;
static int hf_ntppriv_auth_seq;
static int hf_ntppriv_auth;
static int hf_ntppriv_seq;
static int hf_ntppriv_impl;
static int hf_ntppriv_reqcode;
static int hf_ntppriv_errcode;
static int hf_ntppriv_numitems;
static int hf_ntppriv_mbz;
static int hf_ntppriv_mode7_item;
static int hf_ntppriv_itemsize;
static int hf_ntppriv_avgint;
static int hf_ntppriv_lsint;
static int hf_ntppriv_count;
static int hf_ntppriv_restr;
static int hf_ntppriv_addr;
static int hf_ntppriv_daddr;
static int hf_ntppriv_flags;
static int hf_ntppriv_port;
static int hf_ntppriv_mode;
static int hf_ntppriv_version;
static int hf_ntppriv_v6_flag;
static int hf_ntppriv_unused;
static int hf_ntppriv_addr6;
static int hf_ntppriv_daddr6;
static int hf_ntppriv_tstamp;
static int hf_ntppriv_mode7_addr;
static int hf_ntppriv_mode7_mask;
static int hf_ntppriv_mode7_bcast;
static int hf_ntppriv_mode7_port;
static int hf_ntppriv_mode7_hmode;
static int hf_ntppriv_mode7_peer_flags;
static int hf_ntppriv_mode7_v6_flag;
static int hf_ntppriv_mode7_unused;
static int hf_ntppriv_mode7_addr6;
static int hf_ntppriv_mode7_mask6;
static int hf_ntppriv_mode7_bcast6;
static int hf_ntppriv_mode7_peer_flags_config;
static int hf_ntppriv_mode7_peer_flags_syspeer;
static int hf_ntppriv_mode7_peer_flags_burst;
static int hf_ntppriv_mode7_peer_flags_refclock;
static int hf_ntppriv_mode7_peer_flags_prefer;
static int hf_ntppriv_mode7_peer_flags_authenable;
static int hf_ntppriv_mode7_peer_flags_sel_candidate;
static int hf_ntppriv_mode7_peer_flags_shortlist;
static int hf_ntppriv_mode7_dstaddr;
static int hf_ntppriv_mode7_srcaddr;
static int hf_ntppriv_mode7_srcport;
static int hf_ntppriv_mode7_count;
static int hf_ntppriv_mode7_hpoll;
static int hf_ntppriv_mode7_reach;
static int hf_ntppriv_mode7_delay;
static int hf_ntppriv_mode7_offset;
static int hf_ntppriv_mode7_dispersion;
static int hf_ntppriv_mode7_dstaddr6;
static int hf_ntppriv_mode7_srcaddr6;
static int hf_ntppriv_mode7_leap;
static int hf_ntppriv_mode7_pmode;
static int hf_ntppriv_mode7_version;
static int hf_ntppriv_mode7_unreach;
static int hf_ntppriv_mode7_flash;
static int hf_ntppriv_mode7_ttl;
static int hf_ntppriv_mode7_flash2;
static int hf_ntppriv_mode7_associd;
static int hf_ntppriv_mode7_pkeyid;
static int hf_ntppriv_mode7_timer;
static int hf_ntppriv_mode7_filtdelay;
static int hf_ntppriv_mode7_filtoffset;
static int hf_ntppriv_mode7_order;
static int hf_ntppriv_mode7_selectdis;
static int hf_ntppriv_mode7_estbdelay;
static int hf_ntppriv_mode7_bdelay;
static int hf_ntppriv_mode7_authdelay;
static int hf_ntppriv_mode7_stability;
static int hf_ntppriv_mode7_timeup;
static int hf_ntppriv_mode7_timereset;
static int hf_ntppriv_mode7_timereceived;
static int hf_ntppriv_mode7_timetosend;
static int hf_ntppriv_mode7_timereachable;
static int hf_ntppriv_mode7_sent;
static int hf_ntppriv_mode7_processed;
static int hf_ntppriv_mode7_badauth;
static int hf_ntppriv_mode7_bogusorg;
static int hf_ntppriv_mode7_oldpkt;
static int hf_ntppriv_mode7_seldisp;
static int hf_ntppriv_mode7_selbroken;
static int hf_ntppriv_mode7_candidate;
static int hf_ntppriv_mode7_minpoll;
static int hf_ntppriv_mode7_maxpoll;
static int hf_ntppriv_mode7_config_flags;
static int hf_ntppriv_mode7_config_flags_auth;
static int hf_ntppriv_mode7_config_flags_prefer;
static int hf_ntppriv_mode7_config_flags_burst;
static int hf_ntppriv_mode7_config_flags_iburst;
static int hf_ntppriv_mode7_config_flags_noselect;
static int hf_ntppriv_mode7_config_flags_skey;
static int hf_ntppriv_mode7_key_file;
static int hf_ntppriv_mode7_sys_flags;
static int hf_ntppriv_mode7_sys_flags8;
static int hf_ntppriv_mode7_sys_flags_bclient;
static int hf_ntppriv_mode7_sys_flags_pps;
static int hf_ntppriv_mode7_sys_flags_ntp;
static int hf_ntppriv_mode7_sys_flags_kernel;
static int hf_ntppriv_mode7_sys_flags_monitor;
static int hf_ntppriv_mode7_sys_flags_filegen;
static int hf_ntppriv_mode7_sys_flags_auth;
static int hf_ntppriv_mode7_sys_flags_cal;
static int hf_ntppriv_mode7_reset_stats_flags;
static int hf_ntppriv_mode7_reset_stats_flags_allpeers;
static int hf_ntppriv_mode7_reset_stats_flags_io;
static int hf_ntppriv_mode7_reset_stats_flags_sys;
static int hf_ntppriv_mode7_reset_stats_flags_mem;
static int hf_ntppriv_mode7_reset_stats_flags_timer;
static int hf_ntppriv_mode7_reset_stats_flags_auth;
static int hf_ntppriv_mode7_reset_stats_flags_ctl;
static int hf_ntppriv_mode7_req;
static int hf_ntppriv_mode7_badpkts;
static int hf_ntppriv_mode7_responses;
static int hf_ntppriv_mode7_frags;
static int hf_ntppriv_mode7_errors;
static int hf_ntppriv_mode7_tooshort;
static int hf_ntppriv_mode7_inputresp;
static int hf_ntppriv_mode7_inputfrag;
static int hf_ntppriv_mode7_inputerr;
static int hf_ntppriv_mode7_badoffset;
static int hf_ntppriv_mode7_badversion;
static int hf_ntppriv_mode7_datatooshort;
static int hf_ntppriv_mode7_badop;
static int hf_ntppriv_mode7_asyncmsgs;
static int hf_ntppriv_mode7_type;
static int hf_ntppriv_mode7_clock_flags;
static int hf_ntppriv_mode7_lastevent;
static int hf_ntppriv_mode7_currentstatus;
static int hf_ntppriv_mode7_polls;
static int hf_ntppriv_mode7_noresponse;
static int hf_ntppriv_mode7_badformat;
static int hf_ntppriv_mode7_baddata;
static int hf_ntppriv_mode7_timestarted;
static int hf_ntppriv_mode7_fudgetime1;
static int hf_ntppriv_mode7_fudgetime2;
static int hf_ntppriv_mode7_fudgeval1;
static int hf_ntppriv_mode7_fudgeval2;
static int hf_ntppriv_mode7_kernel_offset;
static int hf_ntppriv_mode7_freq;
static int hf_ntppriv_mode7_maxerror;
static int hf_ntppriv_mode7_esterror;
static int hf_ntppriv_mode7_status;
static int hf_ntppriv_mode7_shift;
static int hf_ntppriv_mode7_constant;
static int hf_ntppriv_mode7_precision;
static int hf_ntppriv_mode7_tolerance;
static int hf_ntppriv_mode7_ppsfreq;
static int hf_ntppriv_mode7_jitter;
static int hf_ntppriv_mode7_stabil;
static int hf_ntppriv_mode7_jitcnt;
static int hf_ntppriv_mode7_calcnt;
static int hf_ntppriv_mode7_errcnt;
static int hf_ntppriv_mode7_stbcnt;
static int hf_ntppriv_mode7_key;
static int hf_ntppriv_mode7_numkeys;
static int hf_ntppriv_mode7_numfreekeys;
static int hf_ntppriv_mode7_keylookups;
static int hf_ntppriv_mode7_keynotfound;
static int hf_ntppriv_mode7_encryptions;
static int hf_ntppriv_mode7_decryptions;
static int hf_ntppriv_mode7_expired;
static int hf_ntppriv_mode7_keyuncached;
static int hf_ntppriv_mode7_local_addr;
static int hf_ntppriv_mode7_trap_addr;
static int hf_ntppriv_mode7_trap_port;
static int hf_ntppriv_mode7_sequence;
static int hf_ntppriv_mode7_settime;
static int hf_ntppriv_mode7_origtime;
static int hf_ntppriv_mode7_resets;
static int hf_ntppriv_traps_flags;
static int hf_ntppriv_mode7_local_addr6;
static int hf_ntppriv_mode7_trap_addr6;
static int hf_ntppriv_mode7_last_offset;
static int hf_ntppriv_mode7_drift_comp;
static int hf_ntppriv_mode7_compliance;
static int hf_ntppriv_mode7_watchdog_timer;
static int hf_ntppriv_mode7_poll32;
static int hf_ntppriv_mode7_denied;
static int hf_ntppriv_mode7_oldversion;
static int hf_ntppriv_mode7_newversion;
static int hf_ntppriv_mode7_badlength;
static int hf_ntppriv_mode7_limitrejected;
static int hf_ntppriv_mode7_lamport;
static int hf_ntppriv_mode7_tsrounding;
static int hf_ntppriv_mode7_totalmem;
static int hf_ntppriv_mode7_freemem;
static int hf_ntppriv_mode7_findpeer_calls;
static int hf_ntppriv_mode7_allocations;
static int hf_ntppriv_mode7_demobilizations;
static int hf_ntppriv_mode7_hashcount;
static int hf_ntppriv_mode7_totalrecvbufs;
static int hf_ntppriv_mode7_freerecvbufs;
static int hf_ntppriv_mode7_fullrecvbufs;
static int hf_ntppriv_mode7_lowwater;
static int hf_ntppriv_mode7_dropped;
static int hf_ntppriv_mode7_ignored;
static int hf_ntppriv_mode7_received;
static int hf_ntppriv_mode7_notsent;
static int hf_ntppriv_mode7_interrupts;
static int hf_ntppriv_mode7_int_received;
static int hf_ntppriv_mode7_alarms;
static int hf_ntppriv_mode7_overflows;
static int hf_ntppriv_mode7_xmtcalls;
static int hf_ntppriv_mode7_rflags;
static int hf_ntppriv_mode7_mflags;
static int hf_ntppriv_mode7_int_name;
static int hf_ntppriv_mode7_int_flags;
static int hf_ntppriv_mode7_last_ttl;
static int hf_ntppriv_mode7_num_mcast;
static int hf_ntppriv_mode7_uptime;
static int hf_ntppriv_mode7_scopeid;
static int hf_ntppriv_mode7_ifindex;
static int hf_ntppriv_mode7_ifnum;
static int hf_ntppriv_mode7_peercnt;
static int hf_ntppriv_mode7_family;
static int hf_ntppriv_mode7_ignore_pkt;
static int hf_ntppriv_mode7_action;
static int hf_ntppriv_mode7_nvalues;
static int hf_ntppriv_mode7_ntimes;
static int hf_ntppriv_mode7_svalues;
static int hf_ntppriv_mode7_stimes;
static int hf_ntppriv_mode7_values;
static int hf_ntppriv_mode7_times;
static int hf_ntppriv_mode7_which;
static int hf_ntppriv_mode7_fudgetime;
static int hf_ntppriv_mode7_fudgeval_flags;
static int hf_ntppriv_mode7_ippeerlimit;
static int hf_ntppriv_mode7_restrict_flags;

static int ett_ntp;
static int ett_ntp_flags;
static int ett_ntp_ext;
static int ett_ntp_ext_flags;
static int ett_ntpctrl_flags2;
static int ett_ntpctrl_status;
static int ett_ntpctrl_data;
static int ett_ntpctrl_item;
static int ett_ntppriv_auth_seq;
static int ett_mode7_item;
static int ett_ntp_authenticator;
static int ett_ntppriv_peer_list_flags;
static int ett_ntppriv_config_flags;
static int ett_ntppriv_sys_flag_flags;
static int ett_ntppriv_reset_stats_flags;

static expert_field ei_ntp_ext;

static const char *mon_names[12] = {
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec"
};

static int * const ntp_header_fields[] = {
	&hf_ntp_flags_li,
	&hf_ntp_flags_vn,
	&hf_ntp_flags_mode,
	NULL
};

/*
	* dissect peer status word:
	*                      1
	*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	* | Status  | Sel | Count | Code  |
	* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
static int * const peer_status_flags[] = {
	&hf_ntpctrl_peer_status_b0,
	&hf_ntpctrl_peer_status_b1,
	&hf_ntpctrl_peer_status_b2,
	&hf_ntpctrl_peer_status_b3,
	&hf_ntpctrl_peer_status_b4,
	&hf_ntpctrl_peer_status_selection,
	&hf_ntpctrl_peer_status_count,
	&hf_ntpctrl_peer_status_code,
	NULL
};

static int * const ntppriv_peer_list_flags[] = {
	&hf_ntppriv_mode7_peer_flags_config,
	&hf_ntppriv_mode7_peer_flags_syspeer,
	&hf_ntppriv_mode7_peer_flags_burst,
	&hf_ntppriv_mode7_peer_flags_refclock,
	&hf_ntppriv_mode7_peer_flags_prefer,
	&hf_ntppriv_mode7_peer_flags_authenable,
	&hf_ntppriv_mode7_peer_flags_sel_candidate,
	&hf_ntppriv_mode7_peer_flags_shortlist,
	NULL
};

static int * const ntppriv_config_flags[] = {
	&hf_ntppriv_mode7_config_flags_auth,
	&hf_ntppriv_mode7_config_flags_prefer,
	&hf_ntppriv_mode7_config_flags_burst,
	&hf_ntppriv_mode7_config_flags_iburst,
	&hf_ntppriv_mode7_config_flags_noselect,
	&hf_ntppriv_mode7_config_flags_skey,
	NULL
};

static int * const ntppriv_sys_flag_flags[] = {
	&hf_ntppriv_mode7_sys_flags_bclient,
	&hf_ntppriv_mode7_sys_flags_pps,
	&hf_ntppriv_mode7_sys_flags_ntp,
	&hf_ntppriv_mode7_sys_flags_kernel,
	&hf_ntppriv_mode7_sys_flags_monitor,
	&hf_ntppriv_mode7_sys_flags_filegen,
	&hf_ntppriv_mode7_sys_flags_auth,
	&hf_ntppriv_mode7_sys_flags_cal,
	NULL
};

static int * const ntppriv_reset_stats_flags[] = {
	&hf_ntppriv_mode7_reset_stats_flags_allpeers,
	&hf_ntppriv_mode7_reset_stats_flags_io,
	&hf_ntppriv_mode7_reset_stats_flags_sys,
	&hf_ntppriv_mode7_reset_stats_flags_mem,
	&hf_ntppriv_mode7_reset_stats_flags_timer,
	&hf_ntppriv_mode7_reset_stats_flags_auth,
	&hf_ntppriv_mode7_reset_stats_flags_ctl,
	NULL
};

/* parser definitions */
static tvbparse_wanted_t *want;
static tvbparse_wanted_t *want_ignore;

/*
 * NTP_BASETIME is in fact epoch - ntp_start_time; ntp_start_time
 * is January 1, 2036, 00:00:00 UTC.
 */
#define NTP_BASETIME EPOCH_DELTA_1900_01_01_00_00_00_UTC
#define NTP_FLOAT_DENOM 4294967296.0
#define NTP_TS_SIZE 110

/* tvb_ntp_fmt_ts_sec - converts an NTP timestamps second part (32bits) to an human readable string.
* TVB and an offset (IN).
* returns pointer to filled buffer.  This buffer will be freed automatically once
* dissection of the next packet occurs.
*/
const char *
tvb_ntp_fmt_ts_sec(tvbuff_t *tvb, int offset)
{
	uint32_t tempstmp;
	time_t temptime;
	struct tm *bd;
	char *buff;

	tempstmp = tvb_get_ntohl(tvb, offset);
	if (tempstmp == 0){
		return "NULL";
	}

	/* We need a temporary variable here so the unsigned math
	* works correctly (for years > 2036 according to RFC 2030
	* chapter 3).
	*/
	temptime = (time_t)(tempstmp - NTP_BASETIME);
	bd = gmtime(&temptime);
	if (!bd){
		return "Not representable";
	}

	buff = (char *)wmem_alloc(wmem_packet_scope(), NTP_TS_SIZE);
	snprintf(buff, NTP_TS_SIZE,
		"%s %2d, %d %02d:%02d:%02d UTC",
		mon_names[bd->tm_mon],
		bd->tm_mday,
		bd->tm_year + 1900,
		bd->tm_hour,
		bd->tm_min,
		bd->tm_sec);
	return buff;
}

void
ntp_to_nstime(tvbuff_t *tvb, int offset, nstime_t *nstime)
{
	uint32_t tempstmp;

	/* We need a temporary variable here so the unsigned math
	 * works correctly (for years > 2036 according to RFC 2030
	 * chapter 3).
	 */
	tempstmp  = tvb_get_ntohl(tvb, offset);
	if (tempstmp)
		nstime->secs = (time_t)(tempstmp - NTP_BASETIME);
	else
		nstime->secs = (time_t)tempstmp; /* 0 */

	nstime->nsecs = (int)(tvb_get_ntohl(tvb, offset+4)/(NTP_FLOAT_DENOM/1000000000.0));
}


static int
dissect_ntp_ext(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ntp_tree, int offset)
{
	proto_tree *ext_tree;
	proto_item *tf;
	uint16_t extlen;
	int value_length;

	extlen = tvb_get_ntohs(tvb, offset+2);
	tf = proto_tree_add_item(ntp_tree, hf_ntp_ext, tvb, offset, extlen, ENC_NA);
	ext_tree = proto_item_add_subtree(tf, ett_ntp_ext);

	proto_tree_add_item(ext_tree, hf_ntp_ext_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	tf = proto_tree_add_item(ext_tree, hf_ntp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	if (extlen < 8) {
		/* Extension length isn't enough for the extension header.
		 * Report the error, and return an offset that goes to
		 * the end of the tvbuff, so we stop dissecting.
		 */
		expert_add_info_format(pinfo, tf, &ei_ntp_ext, "Extension length %u < 8", extlen);
		return tvb_reported_length(tvb);
	}
	if (extlen % 4) {
		/* Extension length isn't a multiple of 4.
		 * Report the error, and return an offset that goes
		 * to the end of the tvbuff, so we stop dissecting.
		 */
		expert_add_info_format(pinfo, tf, &ei_ntp_ext, "Extension length %u isn't a multiple of 4",
				extlen);
		return tvb_reported_length(tvb);
	}

	value_length = extlen - 4;
	proto_tree_add_item(ext_tree, hf_ntp_ext_value, tvb, offset, value_length, ENC_NA);
	offset += value_length;

	return offset;
}

static void
dissect_ntp_std(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ntp_tree, ntp_conv_info_t *ntp_conv)
{
	uint8_t stratum;
	int8_t ppoll;
	int8_t precision;
	uint32_t rootdelay;
	double rootdelay_double;
	uint32_t rootdispersion;
	double rootdispersion_double;
	uint32_t refid_addr;
	char *buff;
	int i;
	int efs_end;
	uint16_t last_extlen = 0;
	int macofs;
	unsigned maclen;
	ntp_trans_info_t *ntp_trans;
	wmem_tree_key_t key[3];
	uint64_t flags;
	uint32_t seq;

	proto_tree_add_bitmask_ret_uint64(ntp_tree, tvb, 0, hf_ntp_flags, ett_ntp_flags,
	                                  ntp_header_fields, ENC_NA, &flags);

	seq = 0xffffffff;
	key[0].length = 1;
	key[0].key = &seq;
	key[1].length = 1;
	key[1].key = &pinfo->num;
	key[2].length = 0;
	key[2].key = NULL;
	if ((flags & NTP_MODE_MASK) == NTP_MODE_CLIENT) {
		if (!PINFO_FD_VISITED(pinfo)) {
			ntp_trans = wmem_new(wmem_file_scope(), ntp_trans_info_t);
			ntp_trans->req_frame = pinfo->num;
			ntp_trans->resp_frame = 0;
			ntp_trans->req_time = pinfo->abs_ts;
			ntp_trans->seq = seq;
			wmem_tree_insert32_array(ntp_conv->trans, key, (void *)ntp_trans);
		} else {
			ntp_trans = (ntp_trans_info_t *)wmem_tree_lookup32_array_le(ntp_conv->trans, key);
			if (ntp_trans && ntp_trans->resp_frame != 0 && ntp_trans->seq == seq) {
				proto_item *resp_it;

				resp_it = proto_tree_add_uint(ntp_tree, hf_ntp_response_in, tvb, 0, 0, ntp_trans->resp_frame);
				proto_item_set_generated(resp_it);
			}
		}
	} else if ((flags & NTP_MODE_MASK) == NTP_MODE_SERVER) {
		ntp_trans = (ntp_trans_info_t *)wmem_tree_lookup32_array_le(ntp_conv->trans, key);
		if (ntp_trans && ntp_trans->seq == seq) {
			if (!PINFO_FD_VISITED(pinfo)) {
				if (ntp_trans->resp_frame == 0) {
					ntp_trans->resp_frame = pinfo->num;
				}
			} else if (ntp_trans->resp_frame == pinfo->num) {
				proto_item *req_it;
				nstime_t delta;

				req_it = proto_tree_add_uint(ntp_tree, hf_ntp_request_in, tvb, 0, 0, ntp_trans->req_frame);
				proto_item_set_generated(req_it);
				nstime_delta(&delta, &pinfo->abs_ts, &ntp_trans->req_time);
				req_it = proto_tree_add_time(ntp_tree, hf_ntp_delta_time, tvb, 0, 0, &delta);
				proto_item_set_generated(req_it);
			}
		}
	}

	/* Stratum, 1byte field represents distance from primary source
	 */
	proto_tree_add_item(ntp_tree, hf_ntp_stratum, tvb, 1, 1, ENC_NA);
	stratum = tvb_get_uint8(tvb, 1);

	/* Poll interval, 1byte field indicating the maximum interval
	 * between successive messages, in seconds to the nearest
	 * power of two.
	 */
	ppoll = tvb_get_int8(tvb, 2);
	proto_tree_add_int_format_value(ntp_tree, hf_ntp_ppoll, tvb, 2, 1,
		ppoll, ppoll >= 0 ? "%d (%.0f seconds)" : "%d (%5.3f seconds)",
		ppoll, pow(2, ppoll));

	/* Precision, 1 byte field indicating the precision of the
	 * local clock, in seconds to the nearest power of two.
	 */
	precision = tvb_get_int8(tvb, 3);
	proto_tree_add_int_format_value(ntp_tree, hf_ntp_precision, tvb, 3, 1,
		precision, "%d (%11.9f seconds)", precision, pow(2, precision));

	/* Root Delay is a 32-bit signed fixed-point number indicating
	 * the total roundtrip delay to the primary reference source,
	 * in seconds with fraction point between bits 15 and 16.
	 */
	rootdelay = tvb_get_ntohl(tvb, 4);
	rootdelay_double = (rootdelay >> 16) + (rootdelay & 0xffff) / 65536.0;
	proto_tree_add_uint_format_value(ntp_tree, hf_ntp_rootdelay, tvb, 4, 4,
		rootdelay, "%8.6f seconds", rootdelay_double);

	/* Root Dispersion, 32-bit unsigned fixed-point number indicating
	 * the nominal error relative to the primary reference source, in
	 * seconds with fraction point between bits 15 and 16.
	 */
	rootdispersion = tvb_get_ntohl(tvb, 8);
	rootdispersion_double = (rootdispersion >> 16) + (rootdispersion & 0xffff) / 65536.0;
	proto_tree_add_uint_format_value(ntp_tree, hf_ntp_rootdispersion, tvb, 8, 4,
		rootdispersion, "%8.6f seconds", rootdispersion_double);

	/* Now, there is a problem with secondary servers.  Standards
	 * asks from stratum-2 - stratum-15 servers to set this to the
	 * low order 32 bits of the latest transmit timestamp of the
	 * reference source.
	 * But, all V3 and V4 servers set this to IP address of their
	 * higher level server. My decision was to resolve this address.
	 */
	buff = (char *)wmem_alloc(pinfo->pool, NTP_TS_SIZE);
	if (stratum == 0) {
		snprintf (buff, NTP_TS_SIZE, "Unidentified Kiss-o\'-Death message '%s'",
			tvb_get_string_enc(pinfo->pool, tvb, 12, 4, ENC_ASCII));
		for (i = 0; kod_messages[i].id; i++) {
			if (tvb_memeql(tvb, 12, kod_messages[i].id, 4) == 0) {
				snprintf(buff, NTP_TS_SIZE, "%s",
					kod_messages[i].data);
				break;
			}
		}
	} else if (stratum == 1) {
		snprintf (buff, NTP_TS_SIZE, "Unidentified reference source '%s'",
			tvb_get_string_enc(pinfo->pool, tvb, 12, 4, ENC_ASCII));
		for (i = 0; primary_sources[i].id; i++) {
			if (tvb_memeql(tvb, 12, (const uint8_t*)primary_sources[i].id, 4) == 0) {
				snprintf(buff, NTP_TS_SIZE, "%s",
					primary_sources[i].data);
				break;
			}
		}
	} else {
		int buffpos;
		refid_addr = tvb_get_ipv4(tvb, 12);
		buffpos = snprintf(buff, NTP_TS_SIZE, "%s", get_hostname (refid_addr));
		if (buffpos >= NTP_TS_SIZE) {
			buff[NTP_TS_SIZE-4]='.';
			buff[NTP_TS_SIZE-3]='.';
			buff[NTP_TS_SIZE-2]='.';
			buff[NTP_TS_SIZE-1]=0;
		}
	}
	proto_tree_add_bytes_format_value(ntp_tree, hf_ntp_refid, tvb, 12, 4,
					NULL, "%s", buff);

	/* Reference Timestamp: This is the time at which the local clock was
	 * last set or corrected.
	 */
	proto_tree_add_item(ntp_tree, hf_ntp_reftime, tvb, 16, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);

	/* Originate Timestamp: This is the time at which the request departed
	 * the client for the server.
	 */
	proto_tree_add_item(ntp_tree, hf_ntp_org, tvb, 24, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);

	/* Receive Timestamp: This is the time at which the request arrived at
	 * the server.
	 */
	proto_tree_add_item(ntp_tree, hf_ntp_rec, tvb, 32, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);

	/* Transmit Timestamp: This is the time at which the reply departed the
	 * server for the client.
	 */
	proto_tree_add_item(ntp_tree, hf_ntp_xmt, tvb, 40, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);

	/*
	 * Optional fields:
	 *
	 * - Optional Extension fields (EFs), at minimum 16 bytes each.
	 *   Used for Autokey (RFC 5906, requires a MAC) and others.
	 *
	 * - Optional Message Authentication Codes (MACs), consisting of a
	 *   32-bit key ID concatenated with the digest. Per RFC 7822, this MAC
	 *   can be 24 bytes (SHA-1, AES-CMAC from RFC 8573), 20 octets (MD5),
	 *   or 4 bytes (crypto-NAK, MAC contains four zeroes). However,
	 *   implementations such as chrony and NTPsec support additional hash
	 *   algorithms such as SHA-512 which result in a MAC of 68 bytes.
	 *
	 * Since MACs cannot unambiguously be recognized from EFs based on size
	 * alone due to the larger, non-standard MAC algorithms, follow this:
	 *
	 * 1. Find the end of EFs, stopping as soon as it looks invalid (too
	 *    small or large Length field).
	 * 2. If there is any trailing data, assume a MAC is present. If it is
	 *    too small, remove a field that was assumed to be an EF.
	 */
	efs_end = 48;
	while (tvb_reported_length_remaining(tvb, efs_end) >= 16) {
		uint16_t extlen = tvb_get_ntohs(tvb, efs_end + 2);
		if (extlen < 16) {
			break;
		}
		if (tvb_reported_length_remaining(tvb, efs_end) < extlen) {
			break;
		}
		efs_end += extlen;
		last_extlen = extlen;
	}

	maclen = tvb_reported_length_remaining(tvb, efs_end);
	if (maclen == 0) {
		/* MAC is missing. */
	} else if (maclen == 4 && tvb_get_ntohl(tvb, efs_end) == 0) {
		/* crypto-NAK - continue as normal. */
	} else if (maclen < 20) {
		/* last field was most likely not an EF, remove it. */
		efs_end -= last_extlen;
	}

	macofs = 48;
	while (macofs < efs_end) {
		macofs = dissect_ntp_ext(tvb, pinfo, ntp_tree, macofs);
	}

	/* When the NTP authentication scheme is implemented, the
	 * Key Identifier and Message Digest fields contain the
	 * message authentication code (MAC) information defined in
	 * Appendix C of RFC-1305. Will print this as hex code for now.
	 */
	if (tvb_reported_length_remaining(tvb, macofs) >= 4)
		proto_tree_add_item(ntp_tree, hf_ntp_keyid, tvb, macofs, 4, ENC_NA);
	macofs += 4;
	maclen = tvb_reported_length_remaining(tvb, macofs);
	if (maclen > 0)
		proto_tree_add_item(ntp_tree, hf_ntp_mac, tvb, macofs, maclen, ENC_NA);
}

static void
dissect_ntp_ctrl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *ntp_tree, ntp_conv_info_t *ntp_conv)
{
	uint8_t flags2;
	proto_tree *data_tree, *item_tree, *auth_tree;
	proto_item *td, *ti;
	uint16_t associd;
	uint16_t datalen;
	uint16_t data_offset;
	int length_remaining;
	bool auth_diss = false;
	ntp_trans_info_t *ntp_trans;
	uint32_t seq;
	wmem_tree_key_t key[3];

	tvbparse_t *tt;
	tvbparse_elem_t *element;

	static int * const ntpctrl_flags[] = {
		&hf_ntpctrl_flags2_r,
		&hf_ntpctrl_flags2_error,
		&hf_ntpctrl_flags2_more,
		&hf_ntpctrl_flags2_opcode,
		NULL
	};
	proto_tree_add_bitmask(ntp_tree, tvb, 0, hf_ntp_flags, ett_ntp_flags, ntp_header_fields, ENC_NA);
	proto_tree_add_bitmask(ntp_tree, tvb, 1, hf_ntpctrl_flags2, ett_ntpctrl_flags2, ntpctrl_flags, ENC_NA);
	flags2 = tvb_get_uint8(tvb, 1);

	proto_tree_add_item_ret_uint(ntp_tree, hf_ntpctrl_sequence, tvb, 2, 2, ENC_BIG_ENDIAN, &seq);
	key[0].length = 1;
	key[0].key = &seq;
	key[1].length = 1;
	key[1].key = &pinfo->num;
	key[2].length = 0;
	key[2].key = NULL;
	associd = tvb_get_ntohs(tvb, 6);
	/*
	 * further processing of status is only necessary in server responses
	 */
	if (flags2 & NTPCTRL_R_MASK) {
		ntp_trans = (ntp_trans_info_t *)wmem_tree_lookup32_array_le(ntp_conv->trans, key);
		if (ntp_trans && ntp_trans->seq == seq) {
			if (!PINFO_FD_VISITED(pinfo)) {
				if (ntp_trans->resp_frame == 0) {
					ntp_trans->resp_frame = pinfo->num;
				}
			} else {
				proto_item *req_it;
				nstime_t delta;

				req_it = proto_tree_add_uint(ntp_tree, hf_ntp_request_in, tvb, 0, 0, ntp_trans->req_frame);
				proto_item_set_generated(req_it);
				nstime_delta(&delta, &pinfo->abs_ts, &ntp_trans->req_time);
				req_it = proto_tree_add_time(ntp_tree, hf_ntp_delta_time, tvb, 0, 0, &delta);
				proto_item_set_generated(req_it);
			}
		}
		if (flags2 & NTPCTRL_ERROR_MASK) {
			/*
			 * if error bit is set: dissect error status word
			 *                      1
			 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * |  Error Code   |   reserved    |
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 */
			static int * const errorstatus[] = {
				&hf_ntpctrl_error_status_word,
				NULL
			};

			/* Check if this is an error response... */
			proto_tree_add_bitmask(ntp_tree, tvb, 4, hf_ntpctrl_status, ett_ntpctrl_status, errorstatus, ENC_BIG_ENDIAN);
		} else {
			/* ...otherwise status word depends on OpCode */
			switch (flags2 & NTPCTRL_OP_MASK) {
			case NTPCTRL_OP_READSTAT:
			case NTPCTRL_OP_READVAR:
			case NTPCTRL_OP_WRITEVAR:
			case NTPCTRL_OP_ASYNCMSG:
				if (associd)
					proto_tree_add_bitmask(ntp_tree, tvb, 4, hf_ntpctrl_status, ett_ntpctrl_status, peer_status_flags, ENC_BIG_ENDIAN);
				else
				{
					/*
					 * dissect system status word:
					 *                      1
					 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					 * |LI | ClkSource | Count | Code  |
					 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					 */
					static int * const systemstatus[] = {
						&hf_ntpctrl_sys_status_li,
						&hf_ntpctrl_sys_status_clksrc,
						&hf_ntpctrl_sys_status_count,
						&hf_ntpctrl_sys_status_code,
						NULL
					};

					proto_tree_add_bitmask(ntp_tree, tvb, 4, hf_ntpctrl_status, ett_ntpctrl_status, systemstatus, ENC_BIG_ENDIAN);
				}
				break;
			case NTPCTRL_OP_READCLOCK:
			case NTPCTRL_OP_WRITECLOCK:
				{
				/*
				 * dissect clock status word:
				 *                      1
				 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 * | Clock Status  |  Event Code   |
				 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				 */
				static int * const clockstatus[] = {
					&hf_ntpctrl_clk_status,
					&hf_ntpctrl_clk_status_code,
					NULL
				};

				proto_tree_add_bitmask(ntp_tree, tvb, 4, hf_ntpctrl_status, ett_ntpctrl_status, clockstatus, ENC_BIG_ENDIAN);
				}
				break;
			case NTPCTRL_OP_SETTRAP:
			case NTPCTRL_OP_UNSETTRAP:
			default:
				proto_tree_add_item(ntp_tree, hf_ntpctrl_status, tvb, 4, 2, ENC_BIG_ENDIAN);
				break;
			}
		}
	}
	else
	{
		if (!PINFO_FD_VISITED(pinfo)) {
			ntp_trans = wmem_new(wmem_file_scope(), ntp_trans_info_t);
			ntp_trans->req_frame = pinfo->num;
			ntp_trans->resp_frame = 0;
			ntp_trans->req_time = pinfo->abs_ts;
			ntp_trans->seq = seq;
			wmem_tree_insert32_array(ntp_conv->trans, key, (void *)ntp_trans);
		} else {
			ntp_trans = (ntp_trans_info_t *)wmem_tree_lookup32_array_le(ntp_conv->trans, key);
			if (ntp_trans && ntp_trans->resp_frame != 0 && ntp_trans->seq == seq) {
				proto_item *resp_it;

				resp_it = proto_tree_add_uint(ntp_tree, hf_ntp_response_in, tvb, 0, 0, ntp_trans->resp_frame);
				proto_item_set_generated(resp_it);
			}
		}
		proto_tree_add_item(ntp_tree, hf_ntpctrl_status, tvb, 4, 2, ENC_BIG_ENDIAN);
	}
	proto_tree_add_item(ntp_tree, hf_ntpctrl_associd, tvb, 6, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(ntp_tree, hf_ntpctrl_offset, tvb, 8, 2, ENC_BIG_ENDIAN);
	datalen = tvb_get_ntohs(tvb, 10);
	proto_tree_add_uint(ntp_tree, hf_ntpctrl_count, tvb, 10, 2, datalen);

	/*
	 * dissect Data part of the NTP control message
	 */
	if (datalen) {
		data_offset = 12;
		td = proto_tree_add_item(ntp_tree, hf_ntpctrl_data, tvb, data_offset, datalen, ENC_NA);
		data_tree = proto_item_add_subtree(td, ett_ntpctrl_data);
		switch(flags2 & NTPCTRL_OP_MASK) {
		case NTPCTRL_OP_READSTAT:
			if (!associd) {
				/*
				 * if associd == 0 then data part contains a list of the form
				 * <association identifier><status word>,
				 */
				while(datalen) {
					ti = proto_tree_add_item(data_tree, hf_ntpctrl_item, tvb, data_offset, 4, ENC_NA);
					item_tree = proto_item_add_subtree(ti, ett_ntpctrl_item);
					proto_tree_add_item(item_tree, hf_ntpctrl_associd, tvb, data_offset, 2, ENC_BIG_ENDIAN);
					data_offset += 2;
					proto_tree_add_bitmask(ntp_tree, tvb, data_offset, hf_ntpctrl_status, ett_ntpctrl_status, peer_status_flags, ENC_BIG_ENDIAN);
					data_offset += 2;
					datalen -= 4;
				}
				break;
			}
			/*
			 * but if associd != 0,
			 * then data part could be the same as if opcode is NTPCTRL_OP_READVAR
			 * --> so, no "break" here!
			 */
			/* FALL THROUGH */
		case NTPCTRL_OP_READVAR:
		case NTPCTRL_OP_WRITEVAR:
		case NTPCTRL_OP_READCLOCK:
		case NTPCTRL_OP_WRITECLOCK:
			tt = tvbparse_init(pinfo->pool, tvb, data_offset, datalen, NULL, want_ignore);
			while( (element = tvbparse_get(tt, want)) != NULL ) {
				tvbparse_tree_add_elem(data_tree, element);
			}
			break;
		case NTPCTRL_OP_ASYNCMSG:
			proto_tree_add_item(data_tree, hf_ntpctrl_trapmsg, tvb, data_offset, datalen, ENC_ASCII);
			break;
		case NTPCTRL_OP_CONFIGURE:
		case NTPCTRL_OP_SAVECONFIG:
			proto_tree_add_item(data_tree, hf_ntpctrl_configuration, tvb, data_offset, datalen, ENC_ASCII);
			auth_diss = true;
			break;
		case NTPCTRL_OP_READ_MRU:
			proto_tree_add_item(data_tree, hf_ntpctrl_mru, tvb, data_offset, datalen, ENC_ASCII);
			auth_diss = true;
			break;
		case NTPCTRL_OP_READ_ORDLIST_A:
			proto_tree_add_item(data_tree, hf_ntpctrl_ordlist, tvb, data_offset, datalen, ENC_ASCII);
			auth_diss = true;
			break;
		case NTPCTRL_OP_REQ_NONCE:
			proto_tree_add_item(data_tree, hf_ntpctrl_nonce, tvb, data_offset, datalen, ENC_ASCII);
			auth_diss = true;
			break;
		/* these opcodes doesn't carry any data: NTPCTRL_OP_SETTRAP, NTPCTRL_OP_UNSETTRAP, NTPCTRL_OP_UNSPEC */
		}
	}

	data_offset = 12+datalen;

	/* Check if there is authentication */
	if (((flags2 & NTPCTRL_R_MASK) == 0) || auth_diss == true)
	{
		int padding_length;

		length_remaining = tvb_reported_length_remaining(tvb, data_offset);
		/* Check padding presence */
		padding_length = (data_offset & 7) ? 8 - (data_offset & 7) : 0;
		if (length_remaining > padding_length)
		{
			if (padding_length)
			{
				proto_tree_add_item(ntp_tree, hf_ntp_padding, tvb, data_offset, padding_length, ENC_NA);
				data_offset += padding_length;
				length_remaining -= padding_length;
			}
			auth_tree = proto_tree_add_subtree(ntp_tree, tvb, data_offset, -1, ett_ntp_authenticator, NULL, "Authenticator");
			switch (length_remaining)
			{
			case 20:
				ti = proto_tree_add_uint(auth_tree, hf_ntp_key_type, tvb, data_offset, 0, NTP_MD5_ALGO);
				proto_item_set_generated(ti);
				proto_tree_add_item(auth_tree, hf_ntp_key_index, tvb, data_offset, 4, ENC_BIG_ENDIAN);
				proto_tree_add_item(auth_tree, hf_ntp_key_signature, tvb, data_offset+4, 16, ENC_NA);
				break;
			case 24:
				ti = proto_tree_add_uint(auth_tree, hf_ntp_key_type, tvb, data_offset, 0, NTP_SHA_ALGO);
				proto_item_set_generated(ti);
				proto_tree_add_item(auth_tree, hf_ntp_key_index, tvb, data_offset, 4, ENC_BIG_ENDIAN);
				proto_tree_add_item(auth_tree, hf_ntp_key_signature, tvb, data_offset+4, 20, ENC_NA);
				break;
			}
		}
	}
}

/*
 * Initialize tvb-parser, which is used to dissect data part of NTP control
 * messages
 *
 * Here some constants are defined, which describes character groups used for
 * various purposes. These groups are then used to configure the two global
 * variables "want_ignore" and "want" that we use for dissection
 */
static void
init_parser(void)
{
	/* specify what counts as character */
	tvbparse_wanted_t *want_identifier_str = tvbparse_chars(-1, 1, 0,
		"abcdefghijklmnopqrstuvwxyz-_ABCDEFGHIJKLMNOPQRSTUVWXYZ.0123456789", NULL, NULL, NULL);
	/* this is the equal sign used in assignments */
	tvbparse_wanted_t *want_equalsign = tvbparse_char(-1, "=", NULL, NULL, NULL);
	/* possible characters allowed for values */
	tvbparse_wanted_t *want_value = tvbparse_set_oneof(0, NULL, NULL, NULL,
		tvbparse_quoted(-1, NULL, NULL, tvbparse_shrink_token_cb, '\"', '\\'),
		tvbparse_quoted(-1, NULL, NULL, tvbparse_shrink_token_cb, '\'', '\\'),
		tvbparse_chars(-1, 1, 0, "abcdefghijklmnopqrstuvwxyz-_ABCDEFGHIJKLMNOPQRSTUVWXYZ.0123456789 ", NULL, NULL, NULL),
		NULL);
	tvbparse_wanted_t *want_comma = tvbparse_until(-1, NULL, NULL, NULL,
		tvbparse_char(-1, ",", NULL, NULL, NULL), TP_UNTIL_SPEND);
	/* the following specifies an identifier */
	tvbparse_wanted_t *want_identifier = tvbparse_set_seq(-1, NULL, NULL, NULL,
		want_identifier_str,
		tvbparse_some(-1, 0, 1, NULL, NULL, NULL, want_comma),
		NULL);
	/* the following specifies an assignment of the form identifier=value */
	tvbparse_wanted_t *want_assignment = tvbparse_set_seq(-1, NULL, NULL, NULL,
		want_identifier_str,
		want_equalsign,
		tvbparse_some(-1, 0, 1, NULL, NULL, NULL, want_value),
		tvbparse_some(-1, 0, 1, NULL, NULL, NULL, want_comma),
		NULL);

	/* we ignore white space characters */
	want_ignore = tvbparse_chars(-1, 1, 0, " \t\r\n", NULL, NULL, NULL);
	/* data part of control messages consists of either identifiers or assignments */
	want = tvbparse_set_oneof(-1, NULL, NULL, NULL,
		want_assignment,
		want_identifier,
		NULL);
}

static void
dissect_ntp_priv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *ntp_tree, ntp_conv_info_t *ntp_conv)
{
	uint32_t impl, reqcode;
	uint64_t flags, auth_seq;
	ntp_trans_info_t *ntp_trans;
	wmem_tree_key_t key[3];
	uint32_t seq;

	static int * const priv_flags[] = {
		&hf_ntppriv_flags_r,
		&hf_ntppriv_flags_more,
		&hf_ntp_flags_vn,
		&hf_ntp_flags_mode,
		NULL
	};

	static int * const auth_flags[] = {
		&hf_ntppriv_auth,
		&hf_ntppriv_seq,
		NULL
	};

	proto_tree_add_bitmask_ret_uint64(ntp_tree, tvb, 0, hf_ntp_flags, ett_ntp_flags, priv_flags, ENC_NA, &flags);
	proto_tree_add_bitmask_ret_uint64(ntp_tree, tvb, 1, hf_ntppriv_auth_seq, ett_ntppriv_auth_seq, auth_flags, ENC_NA, &auth_seq);
	proto_tree_add_item_ret_uint(ntp_tree, hf_ntppriv_impl, tvb, 2, 1, ENC_NA, &impl);
	proto_tree_add_item_ret_uint(ntp_tree, hf_ntppriv_reqcode, tvb, 3, 1, ENC_NA, &reqcode);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s, %s",
		(flags & NTPPRIV_R_MASK) ? "Response" : "Request",
		val_to_str_ext_const(reqcode, &priv_rc_types_ext, "Unknown"));


	seq = 0xff000000 | impl;
	key[0].length = 1;
	key[0].key = &seq;
	key[1].length = 1;
	key[1].key = &pinfo->num;
	key[2].length = 0;
	key[2].key = NULL;

	if (flags & NTPPRIV_R_MASK) {
		/* response */
		ntp_trans = (ntp_trans_info_t *)wmem_tree_lookup32_array_le(ntp_conv->trans, key);
		if (ntp_trans && ntp_trans->seq == seq) {
			if (!PINFO_FD_VISITED(pinfo)) {
				if (ntp_trans->resp_frame == 0) {
					ntp_trans->resp_frame = pinfo->num;
				}
			} else {
				proto_item *req_it;
				nstime_t delta;

				req_it = proto_tree_add_uint(ntp_tree, hf_ntp_request_in, tvb, 0, 0, ntp_trans->req_frame);
				proto_item_set_generated(req_it);
				nstime_delta(&delta, &pinfo->abs_ts, &ntp_trans->req_time);
				req_it = proto_tree_add_time(ntp_tree, hf_ntp_delta_time, tvb, 0, 0, &delta);
				proto_item_set_generated(req_it);
			}
		}
	} else {
		/* request */
		if (!PINFO_FD_VISITED(pinfo)) {
			ntp_trans = wmem_new(wmem_file_scope(), ntp_trans_info_t);
			ntp_trans->req_frame = pinfo->num;
			ntp_trans->resp_frame = 0;
			ntp_trans->req_time = pinfo->abs_ts;
			ntp_trans->seq = seq;
			wmem_tree_insert32_array(ntp_conv->trans, key, (void *)ntp_trans);
		} else {
			ntp_trans = (ntp_trans_info_t *)wmem_tree_lookup32_array_le(ntp_conv->trans, key);
			if (ntp_trans && ntp_trans->resp_frame != 0 && ntp_trans->seq == seq) {
				proto_item *resp_it;

				resp_it = proto_tree_add_uint(ntp_tree, hf_ntp_response_in, tvb, 0, 0, ntp_trans->resp_frame);
				proto_item_set_generated(resp_it);
			}
		}
	}

	if (impl == XNTPD) {

		uint64_t numitems;
		uint64_t itemsize;
		uint16_t offset;
		unsigned i;

		uint32_t v6_flag = 0;

		proto_item *mode7_item;
		proto_tree *mode7_item_tree = NULL;

		proto_tree_add_bits_item(ntp_tree, hf_ntppriv_errcode, tvb, 32, 4, ENC_BIG_ENDIAN);
		proto_tree_add_bits_ret_val(ntp_tree, hf_ntppriv_numitems, tvb, 36, 12, &numitems, ENC_BIG_ENDIAN);
		proto_tree_add_bits_item(ntp_tree, hf_ntppriv_mbz, tvb, 48, 4, ENC_BIG_ENDIAN);
		proto_tree_add_bits_ret_val(ntp_tree, hf_ntppriv_itemsize, tvb, 52, 12, &itemsize, ENC_BIG_ENDIAN);

		for (i = 0; i < (uint16_t)numitems; i++) {

			offset = 8 + (uint16_t)itemsize * i;

			if ((reqcode != PRIV_RC_MON_GETLIST) && (reqcode != PRIV_RC_MON_GETLIST_1)) {
				mode7_item = proto_tree_add_string_format(ntp_tree, hf_ntppriv_mode7_item, tvb, offset,(int)itemsize,
					"", "%s Item", val_to_str_ext_const(reqcode, &priv_rc_types_ext, "Unknown") );
				mode7_item_tree = proto_item_add_subtree(mode7_item, ett_mode7_item);
			}

			switch (reqcode) {
			case PRIV_RC_MON_GETLIST:
			case PRIV_RC_MON_GETLIST_1:

				mode7_item = proto_tree_add_string_format(ntp_tree, hf_ntppriv_mode7_item, tvb, offset,
					(int)itemsize, "Monlist Item", "Monlist item: address: %s:%u",
					tvb_ip_to_str(pinfo->pool, tvb, offset + 16), tvb_get_ntohs(tvb, offset + ((reqcode == PRIV_RC_MON_GETLIST_1) ? 28 : 20)));
				mode7_item_tree = proto_item_add_subtree(mode7_item, ett_mode7_item);

				proto_tree_add_item(mode7_item_tree, hf_ntppriv_avgint, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_lsint, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_restr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_count, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				if (reqcode == PRIV_RC_MON_GETLIST_1) {
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_daddr, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
				}
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_port, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_version, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item_ret_uint(mode7_item_tree, hf_ntppriv_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN, &v6_flag);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_unused, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				if (v6_flag != 0) {
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_addr6, tvb, offset, 16, ENC_NA);
					offset += 16;
					if (reqcode == PRIV_RC_MON_GETLIST_1)
						proto_tree_add_item(mode7_item_tree, hf_ntppriv_daddr6, tvb, offset, 16, ENC_NA);
				}
				break;

			case PRIV_RC_PEER_LIST:

				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_port, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_hmode, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_bitmask(mode7_item_tree, tvb, offset, hf_ntppriv_mode7_peer_flags, ett_ntppriv_peer_list_flags, ntppriv_peer_list_flags, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr6, tvb, offset, 16, ENC_NA);
				break;

			case PRIV_RC_PEER_LIST_SUM:

				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_dstaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_srcaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_srcport, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntp_stratum, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_hpoll, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntp_ppoll, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_reach, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_bitmask(mode7_item_tree, tvb, offset, hf_ntppriv_mode7_peer_flags, ett_ntppriv_peer_list_flags, ntppriv_peer_list_flags, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_hmode, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
				offset += 8;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_dispersion, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_dstaddr6, tvb, offset, 16, ENC_NA);
				offset += 16;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_srcaddr6, tvb, offset, 16, ENC_NA);
				break;

			case PRIV_RC_PEER_INFO:

				if (flags & NTPPRIV_R_MASK) {
					/* response */
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_dstaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_srcaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_srcport, tvb, offset, 2, ENC_BIG_ENDIAN);
					offset += 2;
					proto_tree_add_bitmask(mode7_item_tree, tvb, offset, hf_ntppriv_mode7_peer_flags, ett_ntppriv_peer_list_flags, ntppriv_peer_list_flags, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_leap, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_hmode, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_pmode, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntp_stratum, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntp_ppoll, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_hpoll, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntp_precision, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_version, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 1, ENC_NA);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_reach, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unreach, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_flash, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_flash2, tvb, offset, 2, ENC_BIG_ENDIAN);
					offset += 2;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_associd, tvb, offset, 2, ENC_BIG_ENDIAN);
					offset += 2;
					proto_tree_add_item(mode7_item_tree, hf_ntp_keyid, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_pkeyid, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntp_refid, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_timer, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntp_rootdelay, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntp_rootdispersion, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntp_reftime, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
					offset += 8;
					proto_tree_add_item(mode7_item_tree, hf_ntp_org, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
					offset += 8;
					proto_tree_add_item(mode7_item_tree, hf_ntp_rec, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
					offset += 8;
					proto_tree_add_item(mode7_item_tree, hf_ntp_xmt, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
					offset += 8;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_filtdelay, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_filtoffset, tvb, offset, 8, ENC_BIG_ENDIAN);
					offset += 8;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_order, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_delay, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_dispersion, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
					offset += 8;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_selectdis, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_estbdelay, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_dstaddr6, tvb, offset, 16, ENC_NA);
					offset += 16;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_srcaddr6, tvb, offset, 16, ENC_NA);
				} else {
					/* request */
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_port, tvb, offset, 2, ENC_BIG_ENDIAN);
					offset += 2;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_hmode, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_bitmask(mode7_item_tree, tvb, offset, hf_ntppriv_mode7_peer_flags, ett_ntppriv_peer_list_flags, ntppriv_peer_list_flags, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr6, tvb, offset, 16, ENC_NA);
				}
				break;

			case PRIV_RC_PEER_STATS:

				if (flags & NTPPRIV_R_MASK) {
					/* response */
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_dstaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_srcaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_srcport, tvb, offset, 2, ENC_BIG_ENDIAN);
					offset += 2;
					proto_tree_add_bitmask(mode7_item_tree, tvb, offset, hf_ntppriv_mode7_peer_flags, ett_ntppriv_peer_list_flags, ntppriv_peer_list_flags, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_timereset, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_timereceived, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_timetosend, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_timereachable, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_sent, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_processed, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_badauth, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_bogusorg, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_oldpkt, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_seldisp, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_selbroken, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_candidate, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 1, ENC_NA);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 1, ENC_NA);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 1, ENC_NA);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_dstaddr6, tvb, offset, 16, ENC_NA);
					offset += 16;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_srcaddr6, tvb, offset, 16, ENC_NA);
				} else {
					/* request */
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_port, tvb, offset, 2, ENC_BIG_ENDIAN);
					offset += 2;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_hmode, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_bitmask(mode7_item_tree, tvb, offset, hf_ntppriv_mode7_peer_flags, ett_ntppriv_peer_list_flags, ntppriv_peer_list_flags, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr6, tvb, offset, 16, ENC_NA);
				}
				break;

			case PRIV_RC_SYS_INFO:
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_pmode, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_leap, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntp_stratum, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntp_precision, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntp_rootdelay, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntp_rootdispersion, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntp_refid, tvb, offset, 4, ENC_NA);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntp_reftime, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
				offset += 8;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_poll32, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_bitmask(mode7_item_tree, tvb, offset, hf_ntppriv_mode7_sys_flags8, ett_ntppriv_sys_flag_flags, ntppriv_sys_flag_flags, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 3, ENC_NA);
				offset += 3;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_bdelay, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_freq, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_authdelay, tvb, offset, 8, ENC_BIG_ENDIAN);
				offset += 8;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_stability, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr6, tvb, offset, 16, ENC_NA);
				break;

			case PRIV_RC_SYS_STATS:
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_timeup, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_timereset, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_denied, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_oldversion, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_newversion, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_badversion, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_badlength, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_processed, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_badauth, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_timereceived, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_limitrejected, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_lamport, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_tsrounding, tvb, offset, 4, ENC_BIG_ENDIAN);
				break;

			case PRIV_RC_IO_STATS:
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_timereset, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_totalrecvbufs, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_freerecvbufs, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_fullrecvbufs, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_lowwater, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_dropped, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_ignored, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_received, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_sent, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_notsent, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_interrupts, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_int_received, tvb, offset, 4, ENC_BIG_ENDIAN);
				break;

			case PRIV_RC_MEM_STATS:
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_timereset, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_totalmem, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_freemem, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_findpeer_calls, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_allocations, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_demobilizations, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_hashcount, tvb, offset, (int)itemsize - 20, ENC_NA);
				break;

			case PRIV_RC_LOOP_INFO:
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_last_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
				offset += 8;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_drift_comp, tvb, offset, 8, ENC_BIG_ENDIAN);
				offset += 8;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_compliance, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_watchdog_timer, tvb, offset, 4, ENC_BIG_ENDIAN);
				break;

			case PRIV_RC_TIMER_STATS:
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_timereset, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_alarms, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_overflows, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_xmtcalls, tvb, offset, 4, ENC_BIG_ENDIAN);
				break;

			case PRIV_RC_CONFIG:

				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_hmode, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_version, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_minpoll, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_maxpoll, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_bitmask(mode7_item_tree, tvb, offset, hf_ntppriv_mode7_config_flags, ett_ntppriv_config_flags, ntppriv_config_flags, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 2, ENC_NA);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntp_keyid, tvb, offset, 4, ENC_NA);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_key_file, tvb, offset, 128, ENC_ASCII);
				offset += 128;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr6, tvb, offset, 16, ENC_NA);
				break;

			case PRIV_RC_UNCONFIG:

				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr6, tvb, offset, 16, ENC_NA);
				break;

			case PRIV_RC_SET_SYS_FLAG:
			case PRIV_RC_CLR_SYS_FLAG:

				proto_tree_add_bitmask(mode7_item_tree, tvb, offset, hf_ntppriv_mode7_sys_flags, ett_ntppriv_sys_flag_flags, ntppriv_sys_flag_flags, ENC_BIG_ENDIAN);
				break;

			case PRIV_RC_GET_RESTRICT:
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_count, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_rflags, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_mflags, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr6, tvb, offset, 16, ENC_NA);
				offset += 16;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_mask6, tvb, offset, 16, ENC_NA);
				break;

			case PRIV_RC_RESADDFLAGS:
			case PRIV_RC_RESSUBFLAGS:
			case PRIV_RC_UNRESTRICT:
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_ippeerlimit, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_restrict_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_mflags, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr6, tvb, offset, 16, ENC_NA);
				offset += 16;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_mask6, tvb, offset, 16, ENC_NA);
				break;

			case PRIV_RC_RESET_STATS:

				proto_tree_add_bitmask(mode7_item_tree, tvb, offset, hf_ntppriv_mode7_reset_stats_flags, ett_ntppriv_reset_stats_flags, ntppriv_reset_stats_flags, ENC_BIG_ENDIAN);
				break;

			case PRIV_RC_RESET_PEER:

				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr6, tvb, offset, 16, ENC_NA);
				break;

			case PRIV_RC_TRUSTKEY:
			case PRIV_RC_UNTRUSTKEY:

				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_key, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				break;

			case PRIV_RC_AUTHINFO:

				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_timereset, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_numkeys, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_numfreekeys, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_keylookups, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_keynotfound, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_encryptions, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_decryptions, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_expired, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_keyuncached, tvb, offset, 4, ENC_BIG_ENDIAN);
				break;

			case PRIV_RC_TRAPS:

				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_local_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_trap_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_trap_port, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_sequence, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_settime, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_origtime, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_resets, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_traps_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_local_addr6, tvb, offset, 16, ENC_NA);
				offset += 16;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_trap_addr6, tvb, offset, 16, ENC_NA);
				break;

			case PRIV_RC_ADD_TRAP:
			case PRIV_RC_CLR_TRAP:

				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_local_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_trap_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_trap_port, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 2, ENC_NA);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_local_addr6, tvb, offset, 16, ENC_NA);
				offset += 16;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_trap_addr6, tvb, offset, 16, ENC_NA);
				break;

			case PRIV_RC_REQUEST_KEY:
			case PRIV_RC_CONTROL_KEY:

				proto_tree_add_item(mode7_item_tree, hf_ntp_keyid, tvb, offset, 4, ENC_NA);
				break;

			case PRIV_RC_CTL_STATS:

				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_timereset, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_req, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_badpkts, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_responses, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_frags, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_errors, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_tooshort, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_inputresp, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_inputfrag, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_inputerr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_badoffset, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_badversion, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_datatooshort, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_badop, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_asyncmsgs, tvb, offset, 4, ENC_BIG_ENDIAN);
				break;

			case PRIV_RC_GET_CLOCKINFO:

				if (flags & NTPPRIV_R_MASK) {
					/* response */
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_type, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_clock_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_lastevent, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_currentstatus, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_polls, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_noresponse, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_badformat, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_baddata, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_timestarted, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_fudgetime1, tvb, offset, 8, ENC_BIG_ENDIAN);
					offset += 8;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_fudgetime2, tvb, offset, 8, ENC_BIG_ENDIAN);
					offset += 8;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_fudgeval1, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_fudgeval2, tvb, offset, 4, ENC_BIG_ENDIAN);
				} else {
					/* request */
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				}
				break;

			case PRIV_RC_SET_CLKFUDGE:
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_which, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_fudgetime, tvb, offset, 8, ENC_BIG_ENDIAN);
				offset += 8;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_fudgeval_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
				break;

			case PRIV_RC_GET_KERNEL:

				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_kernel_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_freq, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_maxerror, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_esterror, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_status, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_shift, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_constant, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_precision, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_tolerance, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_ppsfreq, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_jitter, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_stabil, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_jitcnt, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_calcnt, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_errcnt, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_stbcnt, tvb, offset, 4, ENC_BIG_ENDIAN);
				break;

			case PRIV_RC_GET_CLKBUGINFO:
				if (flags & NTPPRIV_R_MASK) {
					/* response */
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_nvalues, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_ntimes, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset += 1;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_svalues, tvb, offset, 2, ENC_BIG_ENDIAN);
					offset += 2;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_stimes, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_values, tvb, offset, 64, ENC_NA);
					offset += 64;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_times, tvb, offset, 256, ENC_NA);
				} else {
					/* request */
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
				}
				break;

			case PRIV_RC_IF_STATS:
			case PRIV_RC_IF_RELOAD:
				v6_flag = tvb_get_ntohl(tvb, offset + 48);
				if (v6_flag == 0) {
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 16;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_bcast, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 16;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 16;
				} else {
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_addr6, tvb, offset, 16, ENC_NA);
					offset += 16;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_bcast6, tvb, offset, 16, ENC_NA);
					offset += 16;
					proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_mask6, tvb, offset, 16, ENC_NA);
					offset += 16;
				}
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_v6_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_int_name, tvb, offset, 32, ENC_ASCII);
				offset += 32;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_int_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_last_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_num_mcast, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_received, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_sent, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_notsent, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_uptime, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_scopeid, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_ifindex, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_ifnum, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_peercnt, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_family, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_ignore_pkt, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_action, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(mode7_item_tree, hf_ntppriv_mode7_unused, tvb, offset, 4, ENC_NA);
				break;

			}
		}
	}
	if ((flags & NTPPRIV_R_MASK) == 0 && (auth_seq & NTPPRIV_AUTH_MASK)) {
		/* request message with authentication bit */
		int len;
		proto_tree_add_item(ntp_tree, hf_ntppriv_tstamp, tvb, 184, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
		proto_tree_add_item(ntp_tree, hf_ntp_keyid, tvb, 192, 4, ENC_NA);
		len = tvb_reported_length_remaining(tvb, 196);
		if (len)
			proto_tree_add_item(ntp_tree, hf_ntp_mac, tvb, 196, len, ENC_NA);
	}
}

/* dissect_ntp - dissects NTP packet data
 * tvb - tvbuff for packet data (IN)
 * pinfo - packet info
 * proto_tree - resolved protocol tree
 */
static int
dissect_ntp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree *ntp_tree;
	proto_item *ti = NULL;
	uint8_t flags;
	conversation_t *conversation;
	ntp_conv_info_t *ntp_conv;
	void (*dissector)(tvbuff_t *, packet_info *, proto_tree *, ntp_conv_info_t *);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NTP");

	col_clear(pinfo->cinfo, COL_INFO);

	flags = tvb_get_uint8(tvb, 0);
	switch (flags & NTP_MODE_MASK) {
	default:
		dissector = dissect_ntp_std;
		break;
	case NTP_MODE_CTRL:
		dissector = dissect_ntp_ctrl;
		break;
	case NTP_MODE_PRIV:
		dissector = dissect_ntp_priv;
		break;
	}

	/* Adding NTP item and subtree */
	ti = proto_tree_add_item(tree, proto_ntp, tvb, 0, -1, ENC_NA);
	ntp_tree = proto_item_add_subtree(ti, ett_ntp);

	/* Show version and mode in info column and NTP root */
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s, %s",
		val_to_str_const((flags & NTP_VN_MASK) >> 3, ver_nums, "Unknown version"),
		val_to_str_const(flags & NTP_MODE_MASK, info_mode_types, "Unknown"));

	proto_item_append_text(ti, " (%s, %s)",
		val_to_str_const((flags & NTP_VN_MASK) >> 3, ver_nums, "Unknown version"),
		val_to_str_const(flags & NTP_MODE_MASK, info_mode_types, "Unknown"));

	conversation = find_or_create_conversation(pinfo);
	ntp_conv = (ntp_conv_info_t *)conversation_get_proto_data(conversation, proto_ntp);
	if (!ntp_conv) {
		ntp_conv = wmem_new(wmem_file_scope(), ntp_conv_info_t);
		ntp_conv->trans = wmem_tree_new(wmem_file_scope());
		conversation_add_proto_data(conversation, proto_ntp, ntp_conv);
	}

	/* Dissect according to mode */
	(*dissector)(tvb, pinfo, ntp_tree, ntp_conv);
	return tvb_captured_length(tvb);
}

void
proto_register_ntp(void)
{
	static hf_register_info hf[] = {
		{ &hf_ntp_flags, {
			"Flags", "ntp.flags", FT_UINT8, BASE_HEX,
			NULL, 0, "Flags (Leap/Version/Mode)", HFILL }},
		{ &hf_ntp_flags_li, {
			"Leap Indicator", "ntp.flags.li", FT_UINT8, BASE_DEC,
			VALS(li_types), NTP_LI_MASK, "Warning of an impending leap second to be inserted or deleted in the last minute of the current month", HFILL }},
		{ &hf_ntp_flags_vn, {
			"Version number", "ntp.flags.vn", FT_UINT8, BASE_DEC,
			VALS(ver_nums), NTP_VN_MASK, NULL, HFILL }},
		{ &hf_ntp_flags_mode, {
			"Mode", "ntp.flags.mode", FT_UINT8, BASE_DEC,
			VALS(mode_types), NTP_MODE_MASK, NULL, HFILL }},
		{ &hf_ntp_stratum, {
			"Peer Clock Stratum", "ntp.stratum", FT_UINT8, BASE_DEC|BASE_RANGE_STRING,
			RVALS(stratum_rvals), 0, NULL, HFILL }},
		{ &hf_ntp_ppoll, {
			"Peer Polling Interval", "ntp.ppoll", FT_INT8, BASE_DEC,
			NULL, 0, "Maximum interval between successive messages", HFILL }},
		{ &hf_ntp_precision, {
			"Peer Clock Precision", "ntp.precision", FT_INT8, BASE_DEC,
			NULL, 0, "The precision of the system clock", HFILL }},
		{ &hf_ntp_rootdelay, {
			"Root Delay", "ntp.rootdelay", FT_UINT32, BASE_DEC,
			NULL, 0, "Total round-trip delay to the reference clock", HFILL }},
		{ &hf_ntp_rootdispersion, {
			"Root Dispersion", "ntp.rootdispersion", FT_UINT32, BASE_DEC,
			NULL, 0, "Total dispersion to the reference clock", HFILL }},
		{ &hf_ntp_refid, {
			"Reference ID", "ntp.refid", FT_BYTES, BASE_NONE,
			NULL, 0, "Particular server or reference clock being used", HFILL }},
		{ &hf_ntp_reftime, {
			"Reference Timestamp", "ntp.reftime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC,
			NULL, 0, "Time when the system clock was last set or corrected", HFILL }},
		{ &hf_ntp_org, {
			"Origin Timestamp", "ntp.org", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC,
			NULL, 0, "Time at the client when the request departed for the server", HFILL }},
		{ &hf_ntp_rec, {
			"Receive Timestamp", "ntp.rec", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC,
			NULL, 0, "Time at the server when the request arrived from the client", HFILL }},
		{ &hf_ntp_xmt, {
			"Transmit Timestamp", "ntp.xmt", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC,
			NULL, 0, "Time at the server when the response left for the client", HFILL }},
		{ &hf_ntp_keyid, {
			"Key ID", "ntp.keyid", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntp_mac, {
			"Message Authentication Code", "ntp.mac", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntp_padding, {
			"Padding", "ntp.padding", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntp_key_type, {
			"Key type", "ntp.key_type", FT_UINT8, BASE_DEC,
			VALS(authentication_types), 0, "Authentication algorithm used", HFILL }},
		{ &hf_ntp_key_index, {
			"KeyIndex", "ntp.key_index", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntp_key_signature, {
			"Signature", "ntp.key_signature", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntp_response_in, {
			"Response In", "ntp.response_in", FT_FRAMENUM, BASE_NONE,
			FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0, NULL, HFILL }},
		{ &hf_ntp_request_in, {
			"Request In", "ntp.request_in", FT_FRAMENUM, BASE_NONE,
			FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0, NULL, HFILL }},
		{ &hf_ntp_delta_time, {
			"Delta Time", "ntp.delta_time", FT_RELATIVE_TIME, BASE_NONE,
			NULL, 0, "Time between request and response", HFILL }},

		{ &hf_ntp_ext, {
			"Extension", "ntp.ext", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntp_ext_type, {
			"Field Type", "ntp.ext.type", FT_UINT16, BASE_HEX,
			VALS(ntp_ext_field_types), 0, NULL, HFILL }},
		{ &hf_ntp_ext_length, {
			"Length", "ntp.ext.length", FT_UINT16, BASE_DEC,
			NULL, 0, "Entire extension length including padding", HFILL }},
		{ &hf_ntp_ext_value, {
			"Value", "ntp.ext.value", FT_BYTES, BASE_NONE,
			NULL, 0, "Type-specific value", HFILL }},

		{ &hf_ntpctrl_flags2, {
			"Flags 2", "ntp.ctrl.flags2", FT_UINT8, BASE_HEX,
			NULL, 0, "Flags (Response/Error/More/Opcode)", HFILL }},
		{ &hf_ntpctrl_flags2_r, {
			"Response bit", "ntp.ctrl.flags2.r", FT_BOOLEAN, 8,
			TFS(&tfs_response_request), NTPCTRL_R_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_flags2_error, {
			"Error bit", "ntp.ctrl.flags2.error", FT_UINT8, BASE_DEC,
			NULL, NTPCTRL_ERROR_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_flags2_more, {
			"More bit", "ntp.ctrl.flags2.more", FT_UINT8, BASE_DEC,
			NULL, NTPCTRL_MORE_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_flags2_opcode, {
			"Opcode", "ntp.ctrl.flags2.opcode", FT_UINT8, BASE_DEC,
			VALS(ctrl_op_types), NTPCTRL_OP_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_sequence, {
			"Sequence", "ntp.ctrl.sequence", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntpctrl_status, {
			"Status", "ntp.ctrl.status", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntpctrl_error_status_word, {
			"Error Status Word", "ntp.ctrl.err_status", FT_UINT16, BASE_DEC,
			VALS(ctrl_err_status_types), NTP_CTRL_ERRSTATUS_CODE_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_sys_status_li, {
			"Leap Indicator", "ntp.ctrl.sys_status.li", FT_UINT16, BASE_DEC,
			VALS(li_types), NTPCTRL_SYSSTATUS_LI_MASK, "Warning of an impending leap second to be inserted or deleted in the last minute of the current month", HFILL }},
		{ &hf_ntpctrl_sys_status_clksrc, {
			"Clock Source", "ntp.ctrl.sys_status.clksrc", FT_UINT16, BASE_DEC,
			VALS(ctrl_sys_status_clksource_types), NTPCTRL_SYSSTATUS_CLK_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_sys_status_count, {
			"System Event Counter", "ntp.ctrl.sys_status.count", FT_UINT16, BASE_DEC,
			NULL, NTPCTRL_SYSSTATUS_COUNT_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_sys_status_code, {
			"System Event Code", "ntp.ctrl.sys_status.code", FT_UINT16, BASE_DEC,
			VALS(ctrl_sys_status_event_types), NTPCTRL_SYSSTATUS_CODE_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_peer_status_b0, {
			"Peer Status", "ntp.ctrl.peer_status.config", FT_BOOLEAN, 16,
			TFS(&tfs_ctrl_peer_status_config), NTPCTRL_PEERSTATUS_CONFIG_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_peer_status_b1, {
			"Peer Status", "ntp.ctrl.peer_status.authenable", FT_BOOLEAN, 16,
			TFS(&tfs_ctrl_peer_status_authenable), NTPCTRL_PEERSTATUS_AUTHENABLE_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_peer_status_b2, {
			"Peer Status", "ntp.ctrl.peer_status.authentic", FT_BOOLEAN, 16,
			TFS(&tfs_ctrl_peer_status_authentic), NTPCTRL_PEERSTATUS_AUTHENTIC_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_peer_status_b3, {
			"Peer Status", "ntp.ctrl.peer_status.reach", FT_BOOLEAN, 16,
			TFS(&tfs_ctrl_peer_status_reach), NTPCTRL_PEERSTATUS_REACH_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_peer_status_b4, {
			"Peer Status broadcast association", "ntp.ctrl.peer_status.bcast", FT_BOOLEAN, 16,
			TFS(&tfs_set_notset), NTPCTRL_PEERSTATUS_BCAST_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_peer_status_selection, {
			"Peer Selection", "ntp.ctrl.peer_status.selection", FT_UINT16, BASE_DEC,
			VALS(ctrl_peer_status_selection_types), NTPCTRL_PEERSTATUS_SEL_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_peer_status_count, {
			"Peer Event Counter", "ntp.ctrl.peer_status.count", FT_UINT16, BASE_DEC,
			NULL, NTPCTRL_PEERSTATUS_COUNT_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_peer_status_code, {
			"Peer Event Code", "ntp.ctrl.peer_status.code", FT_UINT16, BASE_DEC,
			VALS(ctrl_peer_status_event_types), NTPCTRL_PEERSTATUS_CODE_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_clk_status, {
			"Clock Status", "ntp.ctrl.clock_status.status", FT_UINT16, BASE_DEC,
			VALS(ctrl_clk_status_types), NTPCTRL_CLKSTATUS_STATUS_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_clk_status_code, {
			"Clock Event Code", "ntp.ctrl.clock_status.code", FT_UINT16, BASE_DEC,
			NULL, NTPCTRL_CLKSTATUS_CODE_MASK, NULL, HFILL }},
		{ &hf_ntpctrl_data, {
			"Data", "ntp.ctrl.data", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntpctrl_item, {
			"Item", "ntp.ctrl.item", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntpctrl_associd, {
			"AssociationID", "ntp.ctrl.associd", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntpctrl_offset, {
			"Offset", "ntp.ctrl.offset", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntpctrl_count, {
			"Count", "ntp.ctrl.count", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntpctrl_trapmsg, {
			"Trap message", "ntp.ctrl.trapmsg", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntpctrl_configuration, {
			"Configuration", "ntp.ctrl.configuration", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntpctrl_mru, {
			"MRU", "ntp.ctrl.mru", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntpctrl_ordlist, {
			"Ordered List", "ntp.ctrl.ordlist", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntpctrl_nonce, {
			"Nonce", "ntp.ctrl.nonce", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_ntppriv_flags_r, {
			"Response bit", "ntp.priv.flags.r", FT_BOOLEAN, 8,
			TFS(&tfs_response_request), NTPPRIV_R_MASK, NULL, HFILL }},
		{ &hf_ntppriv_flags_more, {
			"More bit", "ntp.priv.flags.more", FT_UINT8, BASE_DEC,
			NULL, NTPPRIV_MORE_MASK, NULL, HFILL }},
		{ &hf_ntppriv_auth_seq, {
			"Auth, sequence", "ntp.priv.auth_seq", FT_UINT8, BASE_DEC,
			NULL, 0, "Auth bit, sequence number", HFILL }},
		{ &hf_ntppriv_auth, {
			"Auth bit", "ntp.priv.auth", FT_UINT8, BASE_DEC,
			NULL, NTPPRIV_AUTH_MASK, NULL, HFILL }},
		{ &hf_ntppriv_seq, {
			"Sequence number", "ntp.priv.seq", FT_UINT8, BASE_DEC,
			NULL, NTPPRIV_SEQ_MASK, NULL, HFILL }},
		{ &hf_ntppriv_impl, {
			"Implementation", "ntp.priv.impl", FT_UINT8, BASE_DEC,
			VALS(priv_impl_types), 0, NULL, HFILL }},
		{ &hf_ntppriv_reqcode, {
			"Request code", "ntp.priv.reqcode", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
			&priv_rc_types_ext, 0, NULL, HFILL }},
		{ &hf_ntppriv_errcode, {
			"Err", "ntp.priv.err", FT_UINT8, BASE_HEX,
			VALS(err_values_types), 0, NULL, HFILL }},
		{ &hf_ntppriv_numitems, {
			"Number of data items", "ntp.priv.numitems", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mbz, {
			"Reserved", "ntp.priv.reserved", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_item, {
			"Mode7 item", "ntp.priv.mode7.item",
			FT_STRINGZ, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_ntppriv_itemsize, {
			"Size of data item", "ntp.priv.itemsize", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_avgint, {
			"avgint", "ntp.priv.monlist.avgint", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_lsint, {
			"lsint", "ntp.priv.monlist.lsint", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_restr, {
			"restr", "ntp.priv.monlist.restr", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_count, {
			"count", "ntp.priv.monlist.count", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_addr, {
			"remote address", "ntp.priv.monlist.remote_address", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_daddr, {
			"local address", "ntp.priv.monlist.local_address", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_flags, {
			"flags", "ntp.priv.monlist.flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_port, {
			"port", "ntp.priv.monlist.port", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode, {
			"mode", "ntp.priv.monlist.mode", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_version, {
			"version", "ntp.priv.monlist.version", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_v6_flag, {
			"ipv6", "ntp.priv.monlist.ipv6", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_unused, {
			"unused", "ntp.priv.monlist.unused", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_addr6, {
			"ipv6 remote addr", "ntp.priv.monlist.addr6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_daddr6, {
			"ipv6 local addr", "ntp.priv.monlist.daddr6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_tstamp, {
			"Authentication timestamp", "ntp.priv.tstamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_addr, {
			"Address", "ntp.priv.mode7.address", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_mask, {
			"Mask", "ntp.priv.mode7.mask", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_bcast, {
			"Bcast", "ntp.priv.mode7.bcast", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_port, {
			"Port", "ntp.priv.mode7.port", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_hmode, {
			"HMode", "ntp.priv.mode7.hmode", FT_UINT8, BASE_DEC,
			VALS(mode_types), 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_peer_flags, {
			"Flags", "ntp.priv.mode7.peer.flags", FT_UINT8, BASE_HEX,
			NULL, 0xFF, NULL, HFILL }},
		{ &hf_ntppriv_mode7_v6_flag, {
			"IPv6 Flag", "ntp.priv.mode7.ipv6_flag", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_unused, {
			"Unused", "ntp.priv.mode7.unused", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_addr6, {
			"IPv6 addr", "ntp.priv.mode7.address6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_mask6, {
			"IPv6 mask", "ntp.priv.mode7.mask6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_bcast6, {
			"IPv6 bcast", "ntp.priv.mode7.bcast6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_peer_flags_config, {
			"Config", "ntp.priv.mode7.peer.flags.config", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_INFO_FLAG_CONFIG, NULL, HFILL }},
		{ &hf_ntppriv_mode7_peer_flags_syspeer, {
			"Syspeer", "ntp.priv.mode7.peer.flags.syspeer", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_INFO_FLAG_SYSPEER, NULL, HFILL }},
		{ &hf_ntppriv_mode7_peer_flags_burst, {
			"Burst", "ntp.priv.mode7.peer.flags.burst", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_INFO_FLAG_BURST, NULL, HFILL }},
		{ &hf_ntppriv_mode7_peer_flags_refclock, {
			"Refclock", "ntp.priv.mode7.peer.flags.refclock", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_INFO_FLAG_REFCLOCK, NULL, HFILL }},
		{ &hf_ntppriv_mode7_peer_flags_prefer, {
			"Prefer", "ntp.priv.mode7.peer.flags.prefer", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_INFO_FLAG_PREFER, NULL, HFILL }},
		{ &hf_ntppriv_mode7_peer_flags_authenable, {
			"Auth enable", "ntp.priv.mode7.peer.flags.authenable", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_INFO_FLAG_AUTHENABLE, NULL, HFILL }},
		{ &hf_ntppriv_mode7_peer_flags_sel_candidate, {
			"Sel Candidate", "ntp.priv.mode7.peer.flags.sel_candidate", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_INFO_FLAG_SEL_CANDIDATE, NULL, HFILL }},
		{ &hf_ntppriv_mode7_peer_flags_shortlist, {
			"Shortlist", "ntp.priv.mode7.peer.flags.shortlist", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_INFO_FLAG_SHORTLIST, NULL, HFILL }},
		{ &hf_ntppriv_mode7_dstaddr, {
			"Destination address", "ntp.priv.mode7.dstaddress", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_srcaddr, {
			"Source address", "ntp.priv.mode7.srcaddress", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_srcport, {
			"Source port", "ntp.priv.mode7.srcport", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_count, {
			"Count", "ntp.priv.mode7.count", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_hpoll, {
			"Host polling interval", "ntp.priv.mode7.hpoll", FT_INT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_reach, {
			"Reach", "ntp.priv.mode7.reach", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_delay, {
			"Delay", "ntp.priv.mode7.delay", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_offset, {
			"Offset", "ntp.priv.mode7.offset", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_dispersion, {
			"Dispersion", "ntp.priv.mode7.dispersion", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_dstaddr6, {
			"IPv6 destination addr", "ntp.priv.mode7.dstaddress6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_srcaddr6, {
			"IPv6 source addr", "ntp.priv.mode7.srcaddress6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_leap, {
			"Leap", "ntp.priv.mode7.leap", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_pmode, {
			"Peer mode", "ntp.priv.mode7.pmode", FT_UINT8, BASE_DEC,
			VALS(mode_types), 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_version, {
			"Version", "ntp.priv.mode7.version", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_unreach, {
			"Unreach", "ntp.priv.mode7.unreach", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_flash, {
			"Flash", "ntp.priv.mode7.flash", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_ttl, {
			"TTL", "ntp.priv.mode7.ttl", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_flash2, {
			"Flash new", "ntp.priv.mode7.flash2", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_associd, {
			"Association ID", "ntp.priv.mode7.associd", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_pkeyid, {
			"Peer Key ID", "ntp.priv.mode7.pkeyid", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_timer, {
			"Timer", "ntp.priv.mode7.timer", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_filtdelay, {
			"Filt delay", "ntp.priv.mode7.filtdelay", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_filtoffset, {
			"Filt offset", "ntp.priv.mode7.filtoffset", FT_INT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_order, {
			"Order", "ntp.priv.mode7.order", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_selectdis, {
			"Selectdis", "ntp.priv.mode7.selectdis", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_estbdelay, {
			"Estbdelay", "ntp.priv.mode7.estbdelay", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_bdelay, {
			"Bdelay", "ntp.priv.mode7.bdelay", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_authdelay, {
			"Auth delay", "ntp.priv.mode7.authdelay", FT_INT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_minpoll, {
			"Minpoll", "ntp.priv.mode7.minpoll", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_maxpoll, {
			"Maxpoll", "ntp.priv.mode7.maxpoll", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_config_flags, {
			"Flags", "ntp.priv.config.flags", FT_UINT8, BASE_HEX,
			NULL, 0xFF, NULL, HFILL }},
		{ &hf_ntppriv_mode7_config_flags_auth, {
			"Authenable", "ntp.priv.mode7.config.flags.authenable", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_CONF_FLAG_AUTHENABLE, NULL, HFILL }},
		{ &hf_ntppriv_mode7_config_flags_prefer, {
			"Prefer", "ntp.priv.mode7.config.flags.prefer", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_CONF_FLAG_PREFER, NULL, HFILL }},
		{ &hf_ntppriv_mode7_config_flags_burst, {
			"Burst", "ntp.priv.mode7.config.flags.burst", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_CONF_FLAG_BURST, NULL, HFILL }},
		{ &hf_ntppriv_mode7_config_flags_iburst, {
			"IBurst", "ntp.priv.mode7.config.flags.iburst", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_CONF_FLAG_IBURST, NULL, HFILL }},
		{ &hf_ntppriv_mode7_config_flags_noselect, {
			"No Select", "ntp.priv.mode7.config.flags.no_select", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_CONF_FLAG_NOSELECT, NULL, HFILL }},
		{ &hf_ntppriv_mode7_config_flags_skey, {
			"Skey", "ntp.priv.mode7.config.flags.skey", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_CONF_FLAG_SKEY, NULL, HFILL }},
		{ &hf_ntppriv_mode7_key_file, {
			"Key file name", "ntp.priv.mode7.key_file", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_sys_flags, {
			"Flags", "ntp.priv.mode7.sys.flags", FT_UINT32, BASE_HEX,
			NULL, 0xFF, NULL, HFILL }},
		{ &hf_ntppriv_mode7_sys_flags_bclient, {
			"Bclient", "ntp.priv.mode7.sys.flags.bclient", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_SYS_FLAG_BCLIENT, NULL, HFILL }},
		{ &hf_ntppriv_mode7_sys_flags_pps, {
			"PPS", "ntp.priv.mode7.sys.flags.pps", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_SYS_FLAG_PPS, NULL, HFILL }},
		{ &hf_ntppriv_mode7_sys_flags_ntp, {
			"NTP", "ntp.priv.mode7.sys.flags.ntp", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_SYS_FLAG_NTP, NULL, HFILL }},
		{ &hf_ntppriv_mode7_sys_flags_kernel, {
			"Kernel", "ntp.priv.mode7.sys.flags.kernel", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_SYS_FLAG_KERNEL, NULL, HFILL }},
		{ &hf_ntppriv_mode7_sys_flags_monitor, {
			"Monitor", "ntp.priv.mode7.sys.flags.monitor", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_SYS_FLAG_MONITOR, NULL, HFILL }},
		{ &hf_ntppriv_mode7_sys_flags_filegen, {
			"Filegen", "ntp.priv.mode7.sys.flags.filegen", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_SYS_FLAG_FILEGEN, NULL, HFILL }},
		{ &hf_ntppriv_mode7_sys_flags_auth, {
			"Auth", "ntp.priv.mode7.sys.flags.auth", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_SYS_FLAG_AUTH, NULL, HFILL }},
		{ &hf_ntppriv_mode7_sys_flags_cal, {
			"Cal", "ntp.priv.mode7.sys.flags.cal", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), PRIV_SYS_FLAG_CAL, NULL, HFILL }},
		{ &hf_ntppriv_mode7_reset_stats_flags, {
			"Flags", "ntp.priv.mode7.reset_stats.flags", FT_UINT32, BASE_HEX,
			NULL, 0xFF, NULL, HFILL }},
		{ &hf_ntppriv_mode7_reset_stats_flags_allpeers, {
			"All Peers", "ntp.priv.mode7.reset_stats.flags.allpeers", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), PRIV_RESET_FLAG_ALLPEERS, NULL, HFILL }},
		{ &hf_ntppriv_mode7_reset_stats_flags_io, {
			"IO", "ntp.priv.mode7.reset_stats.flags.io", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), PRIV_RESET_FLAG_IO, NULL, HFILL }},
		{ &hf_ntppriv_mode7_reset_stats_flags_sys, {
			"Sys", "ntp.priv.mode7.reset_stats.flags.sys", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), PRIV_RESET_FLAG_SYS, NULL, HFILL }},
		{ &hf_ntppriv_mode7_reset_stats_flags_mem, {
			"Mem", "ntp.priv.mode7.reset_stats.flags.mem", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), PRIV_RESET_FLAG_MEM, NULL, HFILL }},
		{ &hf_ntppriv_mode7_reset_stats_flags_timer, {
			"Timer", "ntp.priv.mode7.reset_stats.flags.timer", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), PRIV_RESET_FLAG_TIMER, NULL, HFILL }},
		{ &hf_ntppriv_mode7_reset_stats_flags_auth, {
			"Auth", "ntp.priv.mode7.reset_stats.flags.auth", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), PRIV_RESET_FLAG_AUTH, NULL, HFILL }},
		{ &hf_ntppriv_mode7_reset_stats_flags_ctl, {
			"Ctl", "ntp.priv.mode7.reset_stats.flags.ctl", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), PRIV_RESET_FLAG_CTL, NULL, HFILL }},
		{ &hf_ntppriv_mode7_key, {
			"Key", "ntp.priv.mode7.key", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_timeup, {
			"Time up", "ntp.priv.mode7.timeup", FT_UINT32, BASE_DEC,
			NULL, 0, "time counters were reset", HFILL }},
		{ &hf_ntppriv_mode7_timereset, {
			"Time reset", "ntp.priv.mode7.timereset", FT_UINT32, BASE_DEC,
			NULL, 0, "time counters were reset", HFILL }},
		{ &hf_ntppriv_mode7_timereceived, {
			"Time received", "ntp.priv.mode7.timereceived", FT_UINT32, BASE_DEC,
			NULL, 0, "time since a packet received", HFILL }},
		{ &hf_ntppriv_mode7_timetosend, {
			"Time to send", "ntp.priv.mode7.timetosend", FT_UINT32, BASE_DEC,
			NULL, 0, "time until a packet sent", HFILL }},
		{ &hf_ntppriv_mode7_timereachable, {
			"Time reachable", "ntp.priv.mode7.timereachable", FT_UINT32, BASE_DEC,
			NULL, 0, "time peer has been reachable", HFILL }},
		{ &hf_ntppriv_mode7_sent, {
			"Sent", "ntp.priv.mode7.sent", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_processed, {
			"Processed", "ntp.priv.mode7.processed", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_badauth, {
			"Bad authentication", "ntp.priv.mode7.badauth", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_bogusorg, {
			"Bogus origin", "ntp.priv.mode7.bogusorg", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_oldpkt, {
			"Old packet", "ntp.priv.mode7.oldpkt", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_seldisp, {
			"Bad dispersion", "ntp.priv.mode7.seldisp", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_selbroken, {
			"Bad reference time", "ntp.priv.mode7.selbroken", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_candidate, {
			"Candidate", "ntp.priv.mode7.candidate", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_numkeys, {
			"Num keys", "ntp.priv.mode7.numkeys", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_numfreekeys, {
			"Num free keys", "ntp.priv.mode7.numfreekeys", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_keylookups, {
			"Keylookups", "ntp.priv.mode7.keylookups", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_keynotfound, {
			"Key not found", "ntp.priv.mode7.keynotfound", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_encryptions, {
			"Encryptions", "ntp.priv.mode7.encryptions", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_decryptions, {
			"Decryptions", "ntp.priv.mode7.decryptions", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_expired, {
			"Expired", "ntp.priv.mode7.expired", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_keyuncached, {
			"Key uncached", "ntp.priv.mode7.keyuncached", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_local_addr, {
			"Local address", "ntp.priv.mode7.local_address", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_trap_addr, {
			"Trap address", "ntp.priv.mode7.trap_address", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_trap_port, {
			"Trap port", "ntp.priv.mode7.trap_port", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_sequence, {
			"Sequence number", "ntp.priv.mode7.sequence", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_settime, {
			"Trap set time", "ntp.priv.mode7.settime", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_origtime, {
			"Trap originally time", "ntp.priv.mode7.origtime", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_resets, {
			"Resets", "ntp.priv.mode7.resets", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_traps_flags, {
			"Flags", "ntp.priv.traps.flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_local_addr6, {
			"IPv6 local addr", "ntp.priv.mode7.local_address6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_trap_addr6, {
			"IPv6 trap addr", "ntp.priv.mode7.trap_address6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_req, {
			"Requests", "ntp.priv.mode7.requests", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_badpkts, {
			"Bad packets", "ntp.priv.mode7.bad_packets", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_responses, {
			"Responses", "ntp.priv.mode7.responses", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_frags, {
			"Fragments", "ntp.priv.mode7.fragments", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_errors, {
			"Errors", "ntp.priv.mode7.errors", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_tooshort, {
			"Too short packets", "ntp.priv.mode7.too_short", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_inputresp, {
			"Responses on input", "ntp.priv.mode7.input_responses", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_inputfrag, {
			"Fragments on input", "ntp.priv.mode7.input_fragments", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_inputerr, {
			"Errors on input", "ntp.priv.mode7.input_errors", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_badoffset, {
			"Non zero offset packets", "ntp.priv.mode7.bad_offset", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_badversion, {
			"Unknown version packets", "ntp.priv.mode7.bad_version", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_datatooshort, {
			"Data too short", "ntp.priv.mode7.data_too_short", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_badop, {
			"Bad op code found", "ntp.priv.mode7.badop", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_asyncmsgs, {
			"Async messages", "ntp.priv.mode7.async_messages", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_type, {
			"Type", "ntp.priv.mode7.type", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_clock_flags, {
			"Clock Flags", "ntp.priv.mode7.clock_flags", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_lastevent, {
			"Last event", "ntp.priv.mode7.lastevent", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_currentstatus, {
			"Current status", "ntp.priv.mode7.currentstatus", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_polls, {
			"Polls", "ntp.priv.mode7.polls", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_noresponse, {
			"Noresponse", "ntp.priv.mode7.noresponse", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_badformat, {
			"Bad format", "ntp.priv.mode7.badformat", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_baddata, {
			"Bad data", "ntp.priv.mode7.baddata", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_timestarted, {
			"Time started", "ntp.priv.mode7.timestarted", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_fudgetime1, {
			"Fudge time 1", "ntp.priv.mode7.fudgetime1", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_fudgetime2, {
			"Fudge time 2", "ntp.priv.mode7.fudgetime2", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_fudgeval1, {
			"Fudge val 1", "ntp.priv.mode7.fudgeval1", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_fudgeval2, {
			"Fudge val 2", "ntp.priv.mode7.fudgeval2", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_kernel_offset, {
			"Offset", "ntp.priv.mode7.kernel_offset", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_freq, {
			"Freq", "ntp.priv.mode7.freq", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_stability, {
			"Stability (ppm)", "ntp.priv.mode7.stability", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_maxerror, {
			"Max error", "ntp.priv.mode7.maxerror", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_esterror, {
			"Est error", "ntp.priv.mode7.esterror", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_status, {
			"Status", "ntp.priv.mode7.status", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_shift, {
			"Shift", "ntp.priv.mode7.shift", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_constant, {
			"Constant", "ntp.priv.mode7.constant", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_precision, {
			"Precision", "ntp.priv.mode7.precision", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_tolerance, {
			"tolerance", "ntp.priv.mode7.tolerance", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_ppsfreq, {
			"ppsfreq", "ntp.priv.mode7.ppsfreq", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_jitter, {
			"jitter", "ntp.priv.mode7.jitter", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_stabil, {
			"stabil", "ntp.priv.mode7.stabil", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_jitcnt, {
			"jitcnt", "ntp.priv.mode7.jitcnt", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_calcnt, {
			"calcnt", "ntp.priv.mode7.calcnt", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_errcnt, {
			"errcnt", "ntp.priv.mode7.errcnt", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_stbcnt, {
			"stbcnt", "ntp.priv.mode7.stbcnt", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_last_offset, {
			"Last offset", "ntp.priv.mode7.last_offset", FT_INT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_drift_comp, {
			"Drift comp", "ntp.priv.mode7.drift_comp", FT_INT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_compliance, {
			"Compliance", "ntp.priv.mode7.compliance", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_watchdog_timer, {
			"Watchdog timer", "ntp.priv.mode7.watchdog_timer", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_poll32, {
			"Poll", "ntp.priv.mode7.poll", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_sys_flags8, {
			"Flags", "ntp.priv.mode7.sys.flags8", FT_UINT8, BASE_HEX,
			NULL, 0xFF, NULL, HFILL }},
		{ &hf_ntppriv_mode7_denied, {
			"Denied", "ntp.priv.mode7.denied", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_oldversion, {
			"Old version", "ntp.priv.mode7.oldversion", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_newversion, {
			"New version", "ntp.priv.mode7.newversion", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_badlength, {
			"Bad length", "ntp.priv.mode7.badlength", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_limitrejected, {
			"Limit rejected", "ntp.priv.mode7.limitrejected", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_lamport, {
			"Lamport violation", "ntp.priv.mode7.lamport", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_tsrounding, {
			"Timestamp rounding error", "ntp.priv.mode7.tsrounding", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_totalmem, {
			"Total memory", "ntp.priv.mode7.totalmem", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_freemem, {
			"Free memory", "ntp.priv.mode7.freemem", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_findpeer_calls, {
			"Find peer calls", "ntp.priv.mode7.findpeer_calls", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_allocations, {
			"Allocations", "ntp.priv.mode7.allocations", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_demobilizations, {
			"Demobilizations", "ntp.priv.mode7.demobilizations", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_hashcount, {
			"Hashcount", "ntp.priv.mode7.hashcount", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_totalrecvbufs, {
			"Toal receive buffer", "ntp.priv.mode7.totalrecvbufs", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_freerecvbufs, {
			"Free receive buffer", "ntp.priv.mode7.freerecvbufs", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_fullrecvbufs, {
			"Full receive buffer", "ntp.priv.mode7.fullrecvbufs", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_lowwater, {
			"Low water", "ntp.priv.mode7.lowwater", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_dropped, {
			"Dropped packets", "ntp.priv.mode7.dropped", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_ignored, {
			"Ignored packets", "ntp.priv.mode7.ignored", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_received, {
			"Received packets", "ntp.priv.mode7.received", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_notsent, {
			"Not sent packets", "ntp.priv.mode7.notsent", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_interrupts, {
			"Interrupts", "ntp.priv.mode7.interrupts", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_int_received, {
			"Received by interrupt handler", "ntp.priv.mode7.int_received", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_alarms, {
			"Alarms", "ntp.priv.mode7.alarms", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_overflows, {
			"Overflows", "ntp.priv.mode7.overflows", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_xmtcalls, {
			"Transmitted calls", "ntp.priv.mode7.xmtcalls", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_rflags, {
			"Rflags", "ntp.priv.mode7.rflags", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_mflags, {
			"Mflags", "ntp.priv.mode7.mflags", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_int_name, {
			"Interface name", "ntp.priv.mode7.int_name", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_int_flags, {
			"Interface flags", "ntp.priv.mode7.int_flags", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_last_ttl, {
			"Last TTL specified", "ntp.priv.mode7.last_ttl", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_num_mcast, {
			"Numer multicast sockets", "ntp.priv.mode7.num_mcast", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_uptime, {
			"Uptime", "ntp.priv.mode7.uptime", FT_INT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_scopeid, {
			"Scopeid", "ntp.priv.mode7.scopeid", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_ifindex, {
			"Ifindex", "ntp.priv.mode7.ifindex", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_ifnum, {
			"Ifnum", "ntp.priv.mode7.ifnum", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_peercnt, {
			"Peer count", "ntp.priv.mode7.peercnt", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_family, {
			"Address family", "ntp.priv.mode7.family", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_ignore_pkt, {
			"Ignore packets", "ntp.priv.mode7.ignore_pkts", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_action, {
			"Action", "ntp.priv.mode7.action", FT_UINT8, BASE_DEC,
			VALS(priv_mode7_int_action), 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_nvalues, {
			"Nvalues", "ntp.priv.mode7.nvalues", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_ntimes, {
			"Ntimes", "ntp.priv.mode7.ntimes", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_svalues, {
			"Svalues", "ntp.priv.mode7.svalues", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_stimes, {
			"Stimes", "ntp.priv.mode7.stimes", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_values, {
			"Values", "ntp.priv.mode7.values", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_times, {
			"Times", "ntp.priv.mode7.times", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_which, {
			"Which", "ntp.priv.mode7.which", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_fudgetime, {
			"Fudgetime", "ntp.priv.mode7.fudgetime", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_fudgeval_flags, {
			"Fudgeval flags", "ntp.priv.mode7.fudgeval_flags", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_ippeerlimit, {
			"IP peer limit", "ntp.priv.mode7.ippeerlimit", FT_INT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_ntppriv_mode7_restrict_flags, {
			"Restrict flags", "ntp.priv.mode7.restrict_flags", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		/* Todo */
	};

	static int *ett[] = {
		&ett_ntp,
		&ett_ntp_flags,
		&ett_ntp_ext,
		&ett_ntp_ext_flags,
		&ett_ntpctrl_flags2,
		&ett_ntpctrl_status,
		&ett_ntpctrl_data,
		&ett_ntpctrl_item,
		&ett_ntppriv_auth_seq,
		&ett_mode7_item,
		&ett_ntppriv_peer_list_flags,
		&ett_ntppriv_config_flags,
		&ett_ntppriv_sys_flag_flags,
		&ett_ntppriv_reset_stats_flags,
		&ett_ntp_authenticator
	};

	static ei_register_info ei[] = {
		{ &ei_ntp_ext, { "ntp.ext.invalid_length", PI_PROTOCOL, PI_WARN, "Extension invalid length", EXPFILL }},
	};

	expert_module_t* expert_ntp;

	proto_ntp = proto_register_protocol("Network Time Protocol", "NTP", "ntp");
	proto_register_field_array(proto_ntp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_ntp = expert_register_protocol(proto_ntp);
	expert_register_field_array(expert_ntp, ei, array_length(ei));

	ntp_handle = register_dissector("ntp", dissect_ntp, proto_ntp);

	init_parser();
}

void
proto_reg_handoff_ntp(void)
{
	dissector_add_uint_with_preference("udp.port", UDP_PORT_NTP, ntp_handle);
	dissector_add_uint_with_preference("tcp.port", TCP_PORT_NTP, ntp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
