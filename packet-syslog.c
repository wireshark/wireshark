/* packet-syslog.c
 * Routines for syslog message dissection
 *
 * Copyright 2000, Gerald Combs <gerald@zing.org>
 *
 * $Id: packet-syslog.c,v 1.1 2000/06/11 05:19:20 gerald Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
#include "packet.h"

#define UDP_PORT_SYSLOG 514

#define PRIORITY_MASK 0x0007  /* 0000 0111 */
#define FACILITY_MASK 0x03f8  /* 1111 1000 */

/* On my RH 6.2 box, memcpy overwrites nearby chunks of memory if this is
   a multiple of four.  */
#define COL_INFO_LEN 35
#define ELLIPSIS "..." /* ISO 8859-1 doesn't appear to have a real ellipsis. */
#define ELL_LEN ((COL_INFO_LEN - strlen(ELLIPSIS)) - 1)

static const value_string short_pri[] = {
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
  { 9,     "CRON" },
  { 10,    "AUTHPRIV" },
  { 11,    "FTP" },
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

static const value_string long_pri[] = {
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
  { 9,     "CRON - clock daemon" },
  { 10,    "AUTHPRIV - security/authorization messages (private)" },
  { 11,    "FTP - ftp daemon" },
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
static gint hf_syslog_priority = -1;
static gint hf_syslog_facility = -1;
static gint hf_syslog_msg_len = -1;

static gint ett_syslog = -1;

/* I couldn't find any documentation for the syslog message format.  
   According to the BSD sources, the message format is '<', N, '>', and
   T.  N is a decimal value, which should be treated as an 8 bit
   unsigned integer.  The lower three bits comprise the priority, and the
   upper five bits are the facility.  T is the message text.
 */

#if 0
static void dissect_syslog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  gint num = -1, pri, fac;
  gint msg_off = 0, msg_len;
  proto_item *ti;
  proto_tree *syslog_tree;
  gchar msg_str[COL_INFO_LEN];
#else
static void dissect_syslog(const u_char *pd, int o, frame_data *fd, proto_tree *tree)
{
  gint num = -1, pri = -1, fac = -1;
  gint msg_off = 0, msg_len;
  proto_item *ti;
  proto_tree *syslog_tree;
  gchar msg_str[COL_INFO_LEN];

  tvbuff_t *tvb;
  packet_info *pinfo = &pi;
  tvb = tvb_new_subset(pinfo->compat_top_tvb, o, -1, -1);
#endif

  pinfo->current_proto = "Syslog";
  msg_len = tvb_length(tvb);
  if (tvb_get_guint8(tvb, 0) == '<') {
    msg_off++;
    num = 0;
    while (isdigit(tvb_get_guint8(tvb, msg_off)) && 
           tvb_length_remaining(tvb, msg_off)) {
      num = num * 10 + (tvb_get_guint8(tvb, msg_off) - '0');
      msg_off++;
    }
    if (tvb_get_guint8(tvb, msg_off) == '>')
      msg_off++;
    msg_len = tvb_length_remaining(tvb, msg_off);
    if (msg_len > ELL_LEN) {
      tvb_memcpy(tvb, msg_str, msg_off, ELL_LEN);
      strcpy (msg_str + ELL_LEN, ELLIPSIS);
      msg_str[COL_INFO_LEN] = '\0';
    } else {
      tvb_memcpy(tvb, msg_str, msg_off, msg_len);
      msg_str[msg_len] = '\0';
    }
    
    fac = (num & FACILITY_MASK) >> 3;
    pri = num & PRIORITY_MASK;
  }

  if (check_col(pinfo->fd, COL_PROTOCOL)) 
    col_add_str(pinfo->fd, COL_PROTOCOL, "Syslog");
    
  if (check_col(pinfo->fd, COL_INFO)) {
    if (num >= 0) {
      col_add_fstr(pinfo->fd, COL_INFO, "%s.%s: %s", 
        val_to_str(fac, short_fac, "UNKNOWN"),
        val_to_str(pri, short_pri, "UNKNOWN"), msg_str);
    } else {
      col_add_fstr(pinfo->fd, COL_INFO, "%s", msg_str);
    }
  }
  
  if (tree) {
    if (num >= 0) {
      ti = proto_tree_add_protocol_format(tree, proto_syslog, tvb, 0,
        tvb_length(tvb), "Syslog message: %s.%s: %s",
        val_to_str(fac, short_fac, "UNKNOWN"),
        val_to_str(pri, short_pri, "UNKNOWN"), msg_str);
    } else {
      ti = proto_tree_add_string(tree, proto_syslog, tvb, 0, tvb_length(tvb),
        msg_str);
    }
    syslog_tree = proto_item_add_subtree(ti, ett_syslog);
    if (num >= 0) {
      ti = proto_tree_add_uint(syslog_tree, hf_syslog_facility, tvb, 0,
        msg_off - 1, num);
      ti = proto_tree_add_uint(syslog_tree, hf_syslog_priority, tvb, 0,
        msg_off - 1, num);
    }
    proto_tree_add_uint_format(syslog_tree, hf_syslog_msg_len, tvb, msg_off,
      msg_len, msg_len, "Message (%d byte%s)", msg_len, plurality(msg_len, "", "s"));
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
      "Message facility" }
    },
    { &hf_syslog_priority,
      { "Priority",           "syslog.priority",
      FT_UINT8, BASE_DEC, VALS(long_pri), PRIORITY_MASK,
      "Message priority" }
    },
    { &hf_syslog_msg_len,
      { "Message length",     "syslog.msg_len",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Message length, excluding priority/facility descriptor" }
    },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_syslog,
  };

  /* Register the protocol name and description */
  proto_syslog = proto_register_protocol("Syslog message", "syslog");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_syslog, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
};

void
proto_reg_handoff_syslog(void)
{
  dissector_add("udp.port", UDP_PORT_SYSLOG, dissect_syslog);
}

