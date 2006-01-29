/* packet-syslog.c
 * Routines for syslog message dissection
 *
 * Copyright 2000, Gerald Combs <gerald@ethereal.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <string.h>
#include <glib.h>
#include <epan/packet.h>

#define UDP_PORT_SYSLOG 514

#define PRIORITY_MASK 0x0007  /* 0000 0111 */
#define FACILITY_MASK 0x03f8  /* 1111 1000 */

/* The maximum number if priority digits to read in. */
#define MAX_DIGITS 3

static const value_string short_lev[] = {
  { 0,      "EMERG" },
  { 1,      "ALERT" },
  { 2,      "CRIT" },
  { 3,      "ERR" },
  { 4,      "WARNING" },
  { 5,      "NOTICE" },
  { 6,      "INFO" },
  { 7,      "DEBUG" },
  { 0, NULL },
};

static const value_string short_fac[] = {
  { 0,     "KERN" },
  { 1,     "USER" },
  { 2,     "MAIL" },
  { 3,     "DAEMON" },
  { 4,     "AUTH" },
  { 5,     "SYSLOG" },
  { 6,     "LPR" },
  { 7,     "NEWS" },
  { 8,     "UUCP" },
  { 9,     "CRON" },		/* The BSDs, Linux, and others */
  { 10,    "AUTHPRIV" },
  { 11,    "FTP" },
  { 15,    "CRON" },		/* Solaris */
  { 16,    "LOCAL0" },
  { 17,    "LOCAL1" },
  { 18,    "LOCAL2" },
  { 19,    "LOCAL3" },
  { 20,    "LOCAL4" },
  { 21,    "LOCAL5" },
  { 22,    "LOCAL6" },
  { 23,    "LOCAL7" },
  { 0, NULL },
};

static const value_string long_lev[] = {
  { 0,      "EMERG - system is unusable" },
  { 1,      "ALERT - action must be taken immediately" },
  { 2,      "CRIT - critical conditions" },
  { 3,      "ERR - error conditions" },
  { 4,      "WARNING - warning conditions" },
  { 5,      "NOTICE - normal but significant condition" },
  { 6,      "INFO - informational" },
  { 7,      "DEBUG - debug-level messages" },
  { 0, NULL },
};

static const value_string long_fac[] = {
  { 0,     "KERN - kernel messages" },
  { 1,     "USER - random user-level messages" },
  { 2,     "MAIL - mail system" },
  { 3,     "DAEMON - system daemons" },
  { 4,     "AUTH - security/authorization messages" },
  { 5,     "SYSLOG - messages generated internally by syslogd" },
  { 6,     "LPR - line printer subsystem" },
  { 7,     "NEWS - network news subsystem" },
  { 8,     "UUCP - UUCP subsystem" },
  { 9,     "CRON - clock daemon (BSD, Linux)" },
  { 10,    "AUTHPRIV - security/authorization messages (private)" },
  { 11,    "FTP - ftp daemon" },
  { 15,    "CRON - clock daemon (Solaris)" },
  { 16,    "LOCAL0 - reserved for local use" },
  { 17,    "LOCAL1 - reserved for local use" },
  { 18,    "LOCAL2 - reserved for local use" },
  { 19,    "LOCAL3 - reserved for local use" },
  { 20,    "LOCAL4 - reserved for local use" },
  { 21,    "LOCAL5 - reserved for local use" },
  { 22,    "LOCAL6 - reserved for local use" },
  { 23,    "LOCAL7 - reserved for local use" },
  { 0, NULL },
};

static gint proto_syslog = -1;
static gint hf_syslog_level = -1;
static gint hf_syslog_facility = -1;
static gint hf_syslog_msg = -1;

static gint ett_syslog = -1;

/* I couldn't find any documentation for the syslog message format.
   According to the BSD sources, the message format is '<', P, '>', and
   T.  P is a decimal value, which should be treated as an 8 bit
   unsigned integer.  The lower three bits comprise the level, and the
   upper five bits are the facility.  T is the message text.
 */

static void dissect_syslog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  gint pri = -1, lev = -1, fac = -1;
  gint msg_off = 0, msg_len;
  proto_item *ti;
  proto_tree *syslog_tree;
  const char *msg_str;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Syslog");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  if (tvb_get_guint8(tvb, msg_off) == '<') {
    /* A facility and level follow. */
    msg_off++;
    pri = 0;
    while (tvb_bytes_exist(tvb, msg_off, 1) &&
           isdigit(tvb_get_guint8(tvb, msg_off)) && msg_off <= MAX_DIGITS) {
      pri = pri * 10 + (tvb_get_guint8(tvb, msg_off) - '0');
      msg_off++;
    }
    if (tvb_get_guint8(tvb, msg_off) == '>')
      msg_off++;
    fac = (pri & FACILITY_MASK) >> 3;
    lev = pri & PRIORITY_MASK;
  }

  msg_len = tvb_ensure_length_remaining(tvb, msg_off);
  msg_str = tvb_format_text(tvb, msg_off, msg_len);
  if (check_col(pinfo->cinfo, COL_INFO)) {
    if (pri >= 0) {
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s.%s: %s",
        val_to_str(fac, short_fac, "UNKNOWN"),
        val_to_str(lev, short_lev, "UNKNOWN"), msg_str);
    } else {
      col_add_str(pinfo->cinfo, COL_INFO, msg_str);
    }
  }

  if (tree) {
    if (pri >= 0) {
      ti = proto_tree_add_protocol_format(tree, proto_syslog, tvb, 0, -1,
        "Syslog message: %s.%s: %s",
        val_to_str(fac, short_fac, "UNKNOWN"),
        val_to_str(lev, short_lev, "UNKNOWN"), msg_str);
    } else {
      ti = proto_tree_add_protocol_format(tree, proto_syslog, tvb, 0, -1,
        "Syslog message: (unknown): %s", msg_str);
    }
    syslog_tree = proto_item_add_subtree(ti, ett_syslog);
    if (pri >= 0) {
      ti = proto_tree_add_uint(syslog_tree, hf_syslog_facility, tvb, 0,
        msg_off, pri);
      ti = proto_tree_add_uint(syslog_tree, hf_syslog_level, tvb, 0,
        msg_off, pri);
    }
    proto_tree_add_item(syslog_tree, hf_syslog_msg, tvb, msg_off,
      msg_len, FALSE);
  }
  return;
}

/* Register the protocol with Ethereal */
void proto_register_syslog(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_syslog_facility,
      { "Facility",           "syslog.facility",
      FT_UINT8, BASE_DEC, VALS(long_fac), FACILITY_MASK,
      "Message facility", HFILL }
    },
    { &hf_syslog_level,
      { "Level",              "syslog.level",
      FT_UINT8, BASE_DEC, VALS(long_lev), PRIORITY_MASK,
      "Message level", HFILL }
    },
    { &hf_syslog_msg,
      { "Message",            "syslog.msg",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "Message Text", HFILL }
    },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_syslog,
  };

  /* Register the protocol name and description */
  proto_syslog = proto_register_protocol("Syslog message", "Syslog", "syslog");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_syslog, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_syslog(void)
{
  dissector_handle_t syslog_handle;

  syslog_handle = create_dissector_handle(dissect_syslog, proto_syslog);
  dissector_add("udp.port", UDP_PORT_SYSLOG, syslog_handle);
}
