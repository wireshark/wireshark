/* packet-syslog.h
 * Routines for syslog message dissection
 *
 * Copyright 2000, Gerald Combs <gerald[AT]wireshark.org>
 *
 * Support for passing SS7 MSUs (from the Cisco ITP Packet Logging
 * facility) to the MTP3 dissector by Abhik Sarkar <sarkar.abhik[AT]gmail.com>
 * with some rework by Jeff Morriss <jeff.morriss.ws [AT] gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SYSLOG_H__
#define __PACKET_SYSLOG_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Level / Priority */
#define LEVEL_EMERG     0
#define LEVEL_ALERT     1
#define LEVEL_CRIT      2
#define LEVEL_ERR       3
#define LEVEL_WARNING   4
#define LEVEL_NOTICE    5
#define LEVEL_INFO      6
#define LEVEL_DEBUG     7

static const value_string syslog_level_vals[] = {
  { LEVEL_EMERG,        "EMERG - system is unusable" },
  { LEVEL_ALERT,        "ALERT - action must be taken immediately" },
  { LEVEL_CRIT,         "CRIT - critical conditions" },
  { LEVEL_ERR,          "ERR - error conditions" },
  { LEVEL_WARNING,      "WARNING - warning conditions" },
  { LEVEL_NOTICE,       "NOTICE - normal but significant condition" },
  { LEVEL_INFO,         "INFO - informational" },
  { LEVEL_DEBUG,        "DEBUG - debug-level messages" },
  { 0, NULL }
};

/* Facility */
#define FAC_KERN        0
#define FAC_USER        1
#define FAC_MAIL        2
#define FAC_DAEMON      3
#define FAC_AUTH        4
#define FAC_SYSLOG      5
#define FAC_LPR         6
#define FAC_NEWS        7
#define FAC_UUCP        8
#define FAC_CRON        9
#define FAC_AUTHPRIV    10
#define FAC_FTP         11
#define FAC_NTP         12
#define FAC_LOGAUDIT    13
#define FAC_LOGALERT    14
#define FAC_CRON_SOL    15
#define FAC_LOCAL0      16
#define FAC_LOCAL1      17
#define FAC_LOCAL2      18
#define FAC_LOCAL3      19
#define FAC_LOCAL4      20
#define FAC_LOCAL5      21
#define FAC_LOCAL6      22
#define FAC_LOCAL7      23

static const value_string syslog_facility_vals[] = {
  { FAC_KERN,           "KERN - kernel messages" },
  { FAC_USER,           "USER - random user-level messages" },
  { FAC_MAIL,           "MAIL - mail system" },
  { FAC_DAEMON,         "DAEMON - system daemons" },
  { FAC_AUTH,           "AUTH - security/authorization messages" },
  { FAC_SYSLOG,         "SYSLOG - messages generated internally by syslogd" },
  { FAC_LPR,            "LPR - line printer subsystem" },
  { FAC_NEWS,           "NEWS - network news subsystem" },
  { FAC_UUCP,           "UUCP - UUCP subsystem" },
  { FAC_CRON,           "CRON - clock daemon (BSD, Linux)" },
  { FAC_AUTHPRIV,       "AUTHPRIV - security/authorization messages (private)" },
  { FAC_FTP,            "FTP - ftp daemon" },
  { FAC_NTP,            "NTP - ntp subsystem" },
  { FAC_LOGAUDIT,       "LOGAUDIT - log audit" },
  { FAC_LOGALERT,       "LOGALERT - log alert" },
  { FAC_CRON_SOL,       "CRON - clock daemon (Solaris)" },
  { FAC_LOCAL0,         "LOCAL0 - reserved for local use" },
  { FAC_LOCAL1,         "LOCAL1 - reserved for local use" },
  { FAC_LOCAL2,         "LOCAL2 - reserved for local use" },
  { FAC_LOCAL3,         "LOCAL3 - reserved for local use" },
  { FAC_LOCAL4,         "LOCAL4 - reserved for local use" },
  { FAC_LOCAL5,         "LOCAL5 - reserved for local use" },
  { FAC_LOCAL6,         "LOCAL6 - reserved for local use" },
  { FAC_LOCAL7,         "LOCAL7 - reserved for local use" },
  { 0, NULL }
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // __PACKET_SYSLOG_H__
