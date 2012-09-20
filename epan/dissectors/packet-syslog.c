/* packet-syslog.c
 * Routines for syslog message dissection
 *
 * Copyright 2000, Gerald Combs <gerald[AT]wireshark.org>
 *
 * Support for passing SS7 MSUs (from the Cisco ITP Packet Logging
 * facility) to the MTP3 dissector by Abhik Sarkar <sarkar.abhik[AT]gmail.com>
 * with some rework by Jeff Morriss <jeff.morriss.ws [AT] gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#define UDP_PORT_SYSLOG 514

#define PRIORITY_MASK 0x0007  /* 0000 0111 */
#define FACILITY_MASK 0x03f8  /* 1111 1000 */

/* The maximum number if priority digits to read in. */
#define MAX_DIGITS 3

#define LEVEL_EMERG	0
#define LEVEL_ALERT	1
#define LEVEL_CRIT	2
#define LEVEL_ERR	3
#define LEVEL_WARNING	4
#define LEVEL_NOTICE	5
#define LEVEL_INFO	6
#define LEVEL_DEBUG	7
static const value_string short_lev[] = {
  { LEVEL_EMERG,	"EMERG" },
  { LEVEL_ALERT,	"ALERT" },
  { LEVEL_CRIT,		"CRIT" },
  { LEVEL_ERR,		"ERR" },
  { LEVEL_WARNING,	"WARNING" },
  { LEVEL_NOTICE,	"NOTICE" },
  { LEVEL_INFO,		"INFO" },
  { LEVEL_DEBUG,	"DEBUG" },
  { 0, NULL }
};

#define FAC_KERN	0
#define FAC_USER	1
#define FAC_MAIL	2
#define FAC_DAEMON	3
#define FAC_AUTH	4
#define FAC_SYSLOG	5
#define FAC_LPR		6
#define FAC_NEWS	7
#define FAC_UUCP	8
#define FAC_CRON	9
#define FAC_AUTHPRIV	10
#define FAC_FTP		11
#define FAC_NTP		12
#define FAC_LOGAUDIT	13
#define FAC_LOGALERT	14
#define FAC_CRON_SOL	15
#define FAC_LOCAL0	16
#define FAC_LOCAL1	17
#define FAC_LOCAL2	18
#define FAC_LOCAL3	19
#define FAC_LOCAL4	20
#define FAC_LOCAL5	21
#define FAC_LOCAL6	22
#define FAC_LOCAL7	23
static const value_string short_fac[] = {
  { FAC_KERN,		"KERN" },
  { FAC_USER,		"USER" },
  { FAC_MAIL,		"MAIL" },
  { FAC_DAEMON,		"DAEMON" },
  { FAC_AUTH,		"AUTH" },
  { FAC_SYSLOG,		"SYSLOG" },
  { FAC_LPR,		"LPR" },
  { FAC_NEWS,		"NEWS" },
  { FAC_UUCP,		"UUCP" },
  { FAC_CRON,		"CRON" },	/* The BSDs, Linux, and others */
  { FAC_AUTHPRIV,	"AUTHPRIV" },
  { FAC_FTP,		"FTP" },
  { FAC_NTP,		"NTP" },
  { FAC_LOGAUDIT,	"LOGAUDIT" },
  { FAC_LOGALERT,	"LOGALERT" },
  { FAC_CRON_SOL,	"CRON" },	/* Solaris */
  { FAC_LOCAL0,		"LOCAL0" },
  { FAC_LOCAL1,		"LOCAL1" },
  { FAC_LOCAL2,		"LOCAL2" },
  { FAC_LOCAL3,		"LOCAL3" },
  { FAC_LOCAL4,		"LOCAL4" },
  { FAC_LOCAL5,		"LOCAL5" },
  { FAC_LOCAL6,		"LOCAL6" },
  { FAC_LOCAL7,		"LOCAL7" },
  { 0, NULL }
};

static const value_string long_lev[] = {
  { LEVEL_EMERG,	"EMERG - system is unusable" },
  { LEVEL_ALERT,	"ALERT - action must be taken immediately" },
  { LEVEL_CRIT,		"CRIT - critical conditions" },
  { LEVEL_ERR,		"ERR - error conditions" },
  { LEVEL_WARNING,	"WARNING - warning conditions" },
  { LEVEL_NOTICE,	"NOTICE - normal but significant condition" },
  { LEVEL_INFO,		"INFO - informational" },
  { LEVEL_DEBUG,	"DEBUG - debug-level messages" },
  { 0, NULL }
};

static const value_string long_fac[] = {
  { FAC_KERN,		"KERN - kernel messages" },
  { FAC_USER,		"USER - random user-level messages" },
  { FAC_MAIL,		"MAIL - mail system" },
  { FAC_DAEMON,		"DAEMON - system daemons" },
  { FAC_AUTH,		"AUTH - security/authorization messages" },
  { FAC_SYSLOG,		"SYSLOG - messages generated internally by syslogd" },
  { FAC_LPR,		"LPR - line printer subsystem" },
  { FAC_NEWS,		"NEWS - network news subsystem" },
  { FAC_UUCP,		"UUCP - UUCP subsystem" },
  { FAC_CRON,		"CRON - clock daemon (BSD, Linux)" },
  { FAC_AUTHPRIV,	"AUTHPRIV - security/authorization messages (private)" },
  { FAC_FTP,		"FTP - ftp daemon" },
  { FAC_NTP,		"NTP - ntp subsystem" },
  { FAC_LOGAUDIT,	"LOGAUDIT - log audit" },
  { FAC_LOGALERT,	"LOGALERT - log alert" },
  { FAC_CRON_SOL,	"CRON - clock daemon (Solaris)" },
  { FAC_LOCAL0,		"LOCAL0 - reserved for local use" },
  { FAC_LOCAL1,		"LOCAL1 - reserved for local use" },
  { FAC_LOCAL2,		"LOCAL2 - reserved for local use" },
  { FAC_LOCAL3,		"LOCAL3 - reserved for local use" },
  { FAC_LOCAL4,		"LOCAL4 - reserved for local use" },
  { FAC_LOCAL5,		"LOCAL5 - reserved for local use" },
  { FAC_LOCAL6,		"LOCAL6 - reserved for local use" },
  { FAC_LOCAL7,		"LOCAL7 - reserved for local use" },
  { 0, NULL }
};

static gint proto_syslog = -1;
static gint hf_syslog_level = -1;
static gint hf_syslog_facility = -1;
static gint hf_syslog_msg = -1;
static gint hf_syslog_msu_present = -1;

static gint ett_syslog = -1;

static dissector_handle_t mtp_handle;

/*  The Cisco ITP's packet logging facility allows selected (SS7) MSUs to be
 *  to be encapsulated in syslog UDP datagrams and sent to a monitoring tool.
 *  However, no actual tool to monitor/decode the MSUs is provided. The aim
 *  of this routine is to extract the hex dump of the MSU from the syslog
 *  packet so that it can be passed on to the mtp3 dissector for decoding.
 */
static tvbuff_t *
mtp3_msu_present(tvbuff_t *tvb, packet_info *pinfo, gint fac, gint level, const char *msg_str, gint chars_truncated)
{
  size_t nbytes;
  size_t len;
  gchar **split_string, *msu_hex_dump;
  tvbuff_t *mtp3_tvb = NULL;
  guint8 *byte_array;

  /*  In the sample capture I have, all MSUs are LOCAL0.DEBUG.
   *  Try to optimize this routine for most syslog users by short-cutting
   *  out here.
   */
  if (!(fac == FAC_LOCAL0 && level == LEVEL_DEBUG))
    return NULL;

  if (strstr(msg_str, "msu=") == NULL)
    return NULL;

  split_string = g_strsplit(msg_str, "msu=", 2);
  msu_hex_dump = split_string[1];

  if (msu_hex_dump && (len = strlen(msu_hex_dump))) {

    /*  convert_string_to_hex() will return NULL if it gets an incomplete
     *  byte.  If we have an odd string length then chop off the remaining
     *  nibble so we can get at least a partial MSU (chances are the
     *  subdissector will except out, of course).
     */
    if (len % 2)
	msu_hex_dump[len - 1] = '\0';

    byte_array = convert_string_to_hex(msu_hex_dump, &nbytes);

    if (byte_array) {
	mtp3_tvb = tvb_new_child_real_data(tvb, byte_array, (guint)nbytes,
                                           (guint)nbytes + chars_truncated / 2);
	tvb_set_free_cb(mtp3_tvb, g_free);
        /* ...and add the encapsulated MSU as a new data source so that it gets
         * its own tab in the packet bytes pane.
         */
        add_new_data_source(pinfo, mtp3_tvb, "Encapsulated MSU");
    }
  }

  g_strfreev(split_string);

  return(mtp3_tvb);
}

/* The message format is defined in RFC 3164 */
static void
dissect_syslog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  gint pri = -1, lev = -1, fac = -1;
  gint msg_off = 0, msg_len, reported_msg_len;
  proto_item *ti;
  proto_tree *syslog_tree;
  const char *msg_str;
  tvbuff_t *mtp3_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Syslog");
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
  reported_msg_len = tvb_reported_length_remaining(tvb, msg_off);

  mtp3_tvb = mtp3_msu_present(tvb, pinfo, fac, lev, msg_str,
			      (reported_msg_len - msg_len));

  if (mtp3_tvb == NULL && check_col(pinfo->cinfo, COL_INFO)) {
    if (pri >= 0) {
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s.%s: %s",
        val_to_str_const(fac, short_fac, "UNKNOWN"),
        val_to_str_const(lev, short_lev, "UNKNOWN"), msg_str);
    } else {
      col_add_str(pinfo->cinfo, COL_INFO, msg_str);
    }
  }

  if (tree) {
    if (pri >= 0) {
      ti = proto_tree_add_protocol_format(tree, proto_syslog, tvb, 0, -1,
        "Syslog message: %s.%s: %s",
        val_to_str_const(fac, short_fac, "UNKNOWN"),
        val_to_str_const(lev, short_lev, "UNKNOWN"), msg_str);
    } else {
      ti = proto_tree_add_protocol_format(tree, proto_syslog, tvb, 0, -1,
        "Syslog message: (unknown): %s", msg_str);
    }
    syslog_tree = proto_item_add_subtree(ti, ett_syslog);
    if (pri >= 0) {
      proto_tree_add_uint(syslog_tree, hf_syslog_facility, tvb, 0,
        msg_off, pri);
      proto_tree_add_uint(syslog_tree, hf_syslog_level, tvb, 0,
        msg_off, pri);
    }
    proto_tree_add_item(syslog_tree, hf_syslog_msg, tvb, msg_off,
      msg_len, ENC_ASCII|ENC_NA);

    if (mtp3_tvb) {
      proto_item *mtp3_item;
      mtp3_item = proto_tree_add_boolean(syslog_tree, hf_syslog_msu_present,
					 tvb, msg_off, msg_len, TRUE);
      PROTO_ITEM_SET_GENERATED(mtp3_item);
    }
  }

  /* Call MTP dissector if encapsulated MSU was found... */
  if (mtp3_tvb) {
    call_dissector(mtp_handle, mtp3_tvb, pinfo, tree);
  }

  return;
}

/* Register the protocol with Wireshark */
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
    { &hf_syslog_msu_present,
      { "SS7 MSU present",    "syslog.msu_present",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "True if an SS7 MSU was detected in the syslog message",
      HFILL }
    }
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
  dissector_add_uint("udp.port", UDP_PORT_SYSLOG, syslog_handle);
  dissector_add_handle("tcp.port", syslog_handle);

  /* Find the mtp3 dissector */
  mtp_handle = find_dissector("mtp3");
}
