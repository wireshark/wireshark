/* packet-syslog.c
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

#include "config.h"


#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-syslog.h"
#include "packet-acdr.h"

#define UDP_PORT_SYSLOG 514

#define PRIORITY_MASK 0x0007  /* 0000 0111 */
#define FACILITY_MASK 0x03f8  /* 1111 1000 */

void proto_reg_handoff_syslog(void);
void proto_register_syslog(void);

/* The maximum number if priority digits to read in. */
#define MAX_DIGITS 3

static const value_string short_level_vals[] = {
  { LEVEL_EMERG,        "EMERG" },
  { LEVEL_ALERT,        "ALERT" },
  { LEVEL_CRIT,         "CRIT" },
  { LEVEL_ERR,          "ERR" },
  { LEVEL_WARNING,      "WARNING" },
  { LEVEL_NOTICE,       "NOTICE" },
  { LEVEL_INFO,         "INFO" },
  { LEVEL_DEBUG,        "DEBUG" },
  { 0, NULL }
};

static const value_string short_facility_vals[] = {
  { FAC_KERN,           "KERN" },
  { FAC_USER,           "USER" },
  { FAC_MAIL,           "MAIL" },
  { FAC_DAEMON,         "DAEMON" },
  { FAC_AUTH,           "AUTH" },
  { FAC_SYSLOG,         "SYSLOG" },
  { FAC_LPR,            "LPR" },
  { FAC_NEWS,           "NEWS" },
  { FAC_UUCP,           "UUCP" },
  { FAC_CRON,           "CRON" },       /* The BSDs, Linux, and others */
  { FAC_AUTHPRIV,       "AUTHPRIV" },
  { FAC_FTP,            "FTP" },
  { FAC_NTP,            "NTP" },
  { FAC_LOGAUDIT,       "LOGAUDIT" },
  { FAC_LOGALERT,       "LOGALERT" },
  { FAC_CRON_SOL,       "CRON" },       /* Solaris */
  { FAC_LOCAL0,         "LOCAL0" },
  { FAC_LOCAL1,         "LOCAL1" },
  { FAC_LOCAL2,         "LOCAL2" },
  { FAC_LOCAL3,         "LOCAL3" },
  { FAC_LOCAL4,         "LOCAL4" },
  { FAC_LOCAL5,         "LOCAL5" },
  { FAC_LOCAL6,         "LOCAL6" },
  { FAC_LOCAL7,         "LOCAL7" },
  { 0, NULL }
};

static int proto_syslog;
static int hf_syslog_level;
static int hf_syslog_facility;
static int hf_syslog_msg;
static int hf_syslog_msu_present;
static int hf_syslog_version;
static int hf_syslog_timestamp;
static int hf_syslog_timestamp_old;
static int hf_syslog_hostname;
static int hf_syslog_appname;
static int hf_syslog_procid;
static int hf_syslog_msgid;
static int hf_syslog_msgid_utf8;
static int hf_syslog_msgid_bom;

static int ett_syslog;
static int ett_syslog_msg;

static dissector_handle_t syslog_handle;

static dissector_handle_t mtp_handle;

/*  The Cisco ITP's packet logging facility allows selected (SS7) MSUs to be
 *  to be encapsulated in syslog UDP datagrams and sent to a monitoring tool.
 *  However, no actual tool to monitor/decode the MSUs is provided. The aim
 *  of this routine is to extract the hex dump of the MSU from the syslog
 *  packet so that it can be passed on to the mtp3 dissector for decoding.
 */
static tvbuff_t *
mtp3_msu_present(tvbuff_t *tvb, packet_info *pinfo, int fac, int level, const char *msg_str, int chars_truncated)
{
  size_t nbytes;
  size_t len;
  char **split_string, *msu_hex_dump;
  tvbuff_t *mtp3_tvb = NULL;
  uint8_t *byte_array;

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
        mtp3_tvb = tvb_new_child_real_data(tvb, byte_array, (unsigned)nbytes,
                                           (unsigned)nbytes + chars_truncated / 2);
        tvb_set_free_cb(mtp3_tvb, g_free);
        /* ...and add the encapsulated MSU as a new data source so that it gets
         * its own tab in the packet bytes pane.
         */
        add_new_data_source(pinfo, mtp3_tvb, "Encapsulated MSU");
    }
  }

  g_strfreev(split_string);

  return mtp3_tvb;
}

static bool dissect_syslog_info(proto_tree* tree, tvbuff_t* tvb, unsigned* offset, int hfindex)
{
  int end_offset = tvb_find_guint8(tvb, *offset, -1, ' ');
  if (end_offset == -1)
    return false;
  proto_tree_add_item(tree, hfindex, tvb, *offset, end_offset - *offset, ENC_NA);
  *offset = end_offset + 1;
  return true;
}

/* Dissect message as defined in RFC5424 */
static void
dissect_syslog_message(proto_tree* tree, tvbuff_t* tvb, unsigned offset)
{
  int end_offset;

  if (!dissect_syslog_info(tree, tvb, &offset, hf_syslog_version))
    return;

  end_offset = tvb_find_guint8(tvb, offset, -1, ' ');
  if (end_offset == -1)
    return;
  if ((unsigned)end_offset != offset) {
    /* do not call proto_tree_add_time_item with a length of 0 */
    proto_tree_add_time_item(tree, hf_syslog_timestamp, tvb, offset, end_offset - offset, ENC_ISO_8601_DATE_TIME,
      NULL, NULL, NULL);
  }
  offset = end_offset + 1;

  if (!dissect_syslog_info(tree, tvb, &offset, hf_syslog_hostname))
    return;
  if (!dissect_syslog_info(tree, tvb, &offset, hf_syslog_appname))
    return;
  if (!dissect_syslog_info(tree, tvb, &offset, hf_syslog_procid))
    return;
  if (tvb_get_uint24(tvb, offset, ENC_BIG_ENDIAN) == 0xefbbbf) {
    proto_tree_add_item(tree, hf_syslog_msgid_bom, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(tree, hf_syslog_msgid_utf8, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_UTF_8);
  } else {
    proto_tree_add_item(tree, hf_syslog_msgid, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_ASCII);
  }
}

/* Dissect message as defined in RFC3164 */
static void
dissect_rfc3164_syslog_message(proto_tree* tree, tvbuff_t* tvb, unsigned offset)
{
  unsigned tvb_offset = 0;

  /* Simple check if the first 16 bytes look like TIMESTAMP "Mmm dd hh:mm:ss"
   * by checking for spaces and colons. Otherwise return without processing
   * the message. */
  if (tvb_get_uint8(tvb, offset + 3) == ' ' && tvb_get_uint8(tvb, offset + 6) == ' ' &&
        tvb_get_uint8(tvb, offset + 9) == ':' && tvb_get_uint8(tvb, offset + 12) == ':' &&
        tvb_get_uint8(tvb, offset + 15) == ' ') {
    proto_tree_add_item(tree, hf_syslog_timestamp_old, tvb, offset, 15, ENC_ASCII);
    offset += 16;
  } else {
    return;
  }

  if (!dissect_syslog_info(tree, tvb, &offset, hf_syslog_hostname))
    return;
  for (tvb_offset=offset; tvb_offset < offset+32; tvb_offset++){
    uint8_t octet;
    octet = tvb_get_uint8(tvb, tvb_offset);
    if (!g_ascii_isalnum(octet)){
      proto_tree_add_item(tree, hf_syslog_procid, tvb, offset, tvb_offset - offset, ENC_ASCII);
      offset = tvb_offset;
      break;
    }
  }
  proto_tree_add_item(tree, hf_syslog_msgid, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_ASCII);
}

/* The message format is defined in RFC 3164 */
static int
dissect_syslog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  int pri = -1, lev = -1, fac = -1;
  int msg_off = 0, msg_len, reported_msg_len;
  proto_item *ti;
  proto_tree *syslog_tree;
  proto_tree *syslog_message_tree;
  const char *msg_str;
  tvbuff_t *mtp3_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Syslog");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tvb_get_uint8(tvb, msg_off) == '<') {
    /* A facility and level follow. */
    msg_off++;
    pri = 0;
    while (tvb_bytes_exist(tvb, msg_off, 1) &&
           g_ascii_isdigit(tvb_get_uint8(tvb, msg_off)) && msg_off <= MAX_DIGITS) {
      pri = pri * 10 + (tvb_get_uint8(tvb, msg_off) - '0');
      msg_off++;
    }
    if (tvb_get_uint8(tvb, msg_off) == '>')
      msg_off++;
    fac = (pri & FACILITY_MASK) >> 3;
    lev = pri & PRIORITY_MASK;
  }

  msg_len = tvb_ensure_captured_length_remaining(tvb, msg_off);
  msg_str = tvb_format_text(pinfo->pool, tvb, msg_off, msg_len);
  reported_msg_len = tvb_reported_length_remaining(tvb, msg_off);

  mtp3_tvb = mtp3_msu_present(tvb, pinfo, fac, lev, msg_str,
                              (reported_msg_len - msg_len));

  if (mtp3_tvb == NULL) {
    if (pri >= 0) {
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s.%s: %s",
        val_to_str_const(fac, short_facility_vals, "UNKNOWN"),
        val_to_str_const(lev, short_level_vals, "UNKNOWN"), msg_str);
    } else {
      col_add_str(pinfo->cinfo, COL_INFO, msg_str);
    }
  }

  if (tree) {
    if (pri >= 0) {
      ti = proto_tree_add_protocol_format(tree, proto_syslog, tvb, 0, -1,
        "Syslog message: %s.%s: %s",
        val_to_str_const(fac, short_facility_vals, "UNKNOWN"),
        val_to_str_const(lev, short_level_vals, "UNKNOWN"), msg_str);
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
    ti = proto_tree_add_item(syslog_tree, hf_syslog_msg, tvb, msg_off,
      msg_len, ENC_UTF_8);
    syslog_message_tree = proto_item_add_subtree(ti, ett_syslog_msg);

    /* RFC5424 defines a version field which is currently defined as '1'
     * followed by a space (0x3120). Otherwise the message is probable
     * a RFC3164 message.
     */
    if (msg_len > 2 && tvb_get_ntohs(tvb, msg_off) == 0x3120) {
      dissect_syslog_message(syslog_message_tree, tvb, msg_off);
    } else if ( msg_len > 15) {
      dissect_rfc3164_syslog_message(syslog_message_tree, tvb, msg_off);
    }

    if (mtp3_tvb) {
      proto_item *mtp3_item;
      mtp3_item = proto_tree_add_boolean(syslog_tree, hf_syslog_msu_present,
                                         tvb, msg_off, msg_len, true);
      proto_item_set_generated(mtp3_item);
    }
  }

  /* Call MTP dissector if encapsulated MSU was found... */
  if (mtp3_tvb) {
    call_dissector(mtp_handle, mtp3_tvb, pinfo, tree);
  }

  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void proto_register_syslog(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_syslog_facility,
      { "Facility",           "syslog.facility",
        FT_UINT16, BASE_DEC, VALS(syslog_facility_vals), FACILITY_MASK,
        "Message facility", HFILL }
    },
    { &hf_syslog_level,
      { "Level",              "syslog.level",
        FT_UINT16, BASE_DEC, VALS(syslog_level_vals), PRIORITY_MASK,
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
    },
    { &hf_syslog_version,
      { "Syslog version", "syslog.version",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL }
    },
    { &hf_syslog_timestamp,
      { "Syslog timestamp", "syslog.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
        NULL,
        HFILL }
    },
    { &hf_syslog_timestamp_old,
      { "Syslog timestamp (RFC3164)", "syslog.timestamp_rfc3164",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL }
    },
    { &hf_syslog_hostname,
      { "Syslog hostname", "syslog.hostname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL }
    },
    { &hf_syslog_appname,
      { "Syslog app name", "syslog.appname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "The name of the app that generated this message",
        HFILL }
    },
    { &hf_syslog_procid,
      { "Syslog process id", "syslog.procid",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL }
    },
    { &hf_syslog_msgid,
      { "Syslog message id", "syslog.msgid",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL }
    },
    { &hf_syslog_msgid_utf8,
      { "Syslog message id", "syslog.msgid",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL }
    },
    { &hf_syslog_msgid_bom,
      { "Syslog BOM", "syslog.msgid.bom",
        FT_UINT24, BASE_HEX, NULL, 0x0,
        NULL,
        HFILL }
    }
  };

  /* Setup protocol subtree array */
  static int *ett[] = {
    &ett_syslog,
    &ett_syslog_msg
  };

  /* Register the protocol name and description */
  proto_syslog = proto_register_protocol("Syslog message", "Syslog", "syslog");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_syslog, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  syslog_handle = register_dissector("syslog", dissect_syslog, proto_syslog);
}

void
proto_reg_handoff_syslog(void)
{
  dissector_add_uint_with_preference("udp.port", UDP_PORT_SYSLOG, syslog_handle);
  dissector_add_for_decode_as_with_preference("tcp.port", syslog_handle);

  dissector_add_uint("acdr.media_type", ACDR_Info, syslog_handle);

  /* Find the mtp3 dissector */
  mtp_handle = find_dissector_add_dependency("mtp3", proto_syslog);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
