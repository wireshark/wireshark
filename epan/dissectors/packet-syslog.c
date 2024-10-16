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
#include <epan/expert.h>
#include <epan/strutil.h>

#include "packet-syslog.h"
#include "packet-acdr.h"
#include "packet-tcp.h"

#define SYSLOG_PORT_UDP  514
#define SYSLOG_PORT_TLS 6514

#define PRIORITY_MASK 0x0007  /* 0000 0111 */
#define FACILITY_MASK 0x03F8  /* 1111 1000 */

#define MSG_BOM   0xEFBBBF
#define RFC5424_V 0x3120      /* '1 ' */
#define NIL_VALUE 0x2D        /* '-'  */
#define SD_START  0x5B        /* '['  */
#define SD_END    0x5D        /* ']'  */
#define SD_STOP   0x5D20      /* '] ' */
#define SD_DELIM  0x5D5B      /* '][' */
#define CHR_SPACE 0x20        /* ' '  */
#define CHR_COLON 0x3A        /* ':'  */
#define CHR_EQUAL 0x3D        /* '='  */
#define CHR_QUOTE 0x22        /* '"'  */
#define CHR_0     0x30        /* '0'  */

void proto_reg_handoff_syslog(void);
void proto_register_syslog(void);

/* The maximum number if priority digits to read in. */
#define MAX_DIGITS 3

/* The maximum chars for framing to read in */
#define MAX_FRAMING_DIGITS 5

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
static int hf_syslog_msglen;
static int hf_syslog_level;
static int hf_syslog_facility;
static int hf_syslog_msu_present;
static int hf_syslog_version;
static int hf_syslog_timestamp;
static int hf_syslog_timestamp_old;
static int hf_syslog_hostname;
static int hf_syslog_appname;
static int hf_syslog_procid;
static int hf_syslog_msg;
static int hf_syslog_msgid;
static int hf_syslog_bom;
static int hf_syslog_sd;
static int hf_syslog_sd_element;
static int hf_syslog_sd_element_name;
static int hf_syslog_sd_param;
static int hf_syslog_sd_param_name;
static int hf_syslog_sd_param_value;

static int ett_syslog;
static int ett_syslog_sd;
static int ett_syslog_sd_element;
static int ett_syslog_sd_param;

static expert_field ei_syslog_msg_nonconformant;

static dissector_handle_t syslog_handle;
static dissector_handle_t syslog_handle_tcp;

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
  int end_offset = tvb_find_uint8(tvb, *offset, -1, CHR_SPACE);
  if (end_offset == -1)
    return false;
  proto_tree_add_item(tree, hfindex, tvb, *offset, end_offset - *offset, ENC_NA);
  *offset = end_offset + 1;
  return true;
}

static bool dissect_syslog_sd(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, unsigned* offset)
{

  proto_item *ti;
  proto_tree *sd_tree;
  unsigned counter_parameters, counter_elements = 0;

  // Check for NIL value
  if(tvb_reported_length_remaining(tvb, *offset) >= 2) {
    if(tvb_get_uint8(tvb, *offset) == NIL_VALUE && tvb_get_uint8(tvb, *offset + 1) == CHR_SPACE) {
      ti = proto_tree_add_item(tree, hf_syslog_sd, tvb, *offset, 1, ENC_NA);
      proto_item_append_text(ti, ": -");
      *offset = *offset + 2;
      return true;
    }
  }

  /* Validate the start */
  if(tvb_get_uint8(tvb, *offset) != SD_START)
    return false;

  /* Search the end */
  int sd_end = tvb_find_uint16(tvb, *offset, -1, SD_STOP);
  if (sd_end == -1)
    return false;

  ti = proto_tree_add_item(tree, hf_syslog_sd, tvb, *offset, sd_end - *offset + 1, ENC_NA);
  sd_tree = proto_item_add_subtree(ti, ett_syslog_sd);

  /* SD-ELEMENTS */
  while(*offset < (unsigned)sd_end) {

    proto_item *ti_element;
    proto_tree *element_tree;

    /* Find the end of current element (finding is guaranteed, because we already checked for SD_STOP) */
    int element_end = tvb_find_uint8(tvb, *offset, -1, SD_END);
    ti_element = proto_tree_add_item(sd_tree, hf_syslog_sd_element, tvb, *offset, element_end - *offset + 1, ENC_NA);
    element_tree = proto_item_add_subtree(ti_element, ett_syslog_sd_element);

    /* First char is opening bracket, move offset */
    *offset = *offset + 1;

    /* SD-ELEMENT */
    while(*offset < (unsigned)element_end) {

      /* Find the first space char (=SD-NAME), move to next element if failed */
      int sdname_end = tvb_find_uint8(tvb, *offset, -1, CHR_SPACE);
      if(sdname_end == -1 || sdname_end >= element_end) {
        *offset = element_end + 1;
        break;
      }

      proto_tree_add_item(element_tree, hf_syslog_sd_element_name, tvb, *offset, sdname_end - *offset, ENC_ASCII);
      proto_item_append_text(ti_element, " (%s)", tvb_get_string_enc(pinfo->pool, tvb, *offset, sdname_end - *offset, ENC_ASCII));
      *offset = sdname_end + 1;

      /* PARAMETERS */
      counter_parameters = 0;
      while(*offset < (unsigned)element_end) {

        proto_item *ti_param;
        proto_tree *param_tree;

        /* Find the first equals char ('=') which delimits param name and value, move to next element if failed */
        int param_value_divide = tvb_find_uint8(tvb, *offset, -1, CHR_EQUAL);
        if(param_value_divide == -1 || param_value_divide >= element_end) {
          *offset = element_end + 1;
          break;
          break;
        }

        /* Parameter Tree */
        ti_param = proto_tree_add_item(element_tree, hf_syslog_sd_param, tvb, *offset, 0, ENC_NA);
        param_tree = proto_item_add_subtree(ti_param, ett_syslog_sd_param);

        /* Get parameter name */
        proto_tree_add_item(param_tree, hf_syslog_sd_param_name, tvb, *offset, param_value_divide - *offset, ENC_ASCII);
        proto_item_append_text(ti_param, " (%s)", tvb_get_string_enc(pinfo->pool, tvb, *offset, param_value_divide - *offset, ENC_ASCII));
        *offset = param_value_divide + 1;

        /* Find the first and second quote char which marks the start and end of a value */
        int value_start = tvb_find_uint8(tvb, *offset,   -1, CHR_QUOTE);
        int value_end   = tvb_find_uint8(tvb, *offset+1, -1, CHR_QUOTE);

        /* If start or end could not be determined, move to next element */
        if(value_start == -1 || value_end == -1 || value_start >= element_end || value_end >= element_end) {
          *offset = element_end + 1;
          break;
          break;
        }

        proto_tree_add_item(param_tree, hf_syslog_sd_param_value, tvb, value_start+1, value_end-value_start-1, ENC_ASCII);
        proto_item_set_end(ti_param, tvb, value_end+1);
        *offset = value_end + 2;

        counter_parameters++;
      }

      proto_item_append_text(ti_element, " (%d parameter%s)", counter_parameters, plurality(counter_parameters, "", "s"));
      counter_elements++;
    }
  }

  proto_item_append_text(ti, " (%d element%s)", counter_elements, plurality(counter_elements, "", "s"));

  /* Move offset by one byte because space char is expected */
  *offset = *offset + 1;
  return true;

}

/* Dissect message as defined in RFC5424 */
static unsigned
dissect_rfc5424_syslog_message(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, unsigned offset)
{
  int end_offset;

  if (!dissect_syslog_info(tree, tvb, &offset, hf_syslog_version))
    return offset;

  end_offset = tvb_find_uint8(tvb, offset, -1, CHR_SPACE);
  if (end_offset == -1)
    return offset;
  if ((unsigned)end_offset != offset) {
    /* do not call proto_tree_add_time_item with a length of 0 */
    proto_tree_add_time_item(tree, hf_syslog_timestamp, tvb, offset, end_offset - offset, ENC_ISO_8601_DATE_TIME,
      NULL, NULL, NULL);
  }
  offset = end_offset + 1;

  if (!dissect_syslog_info(tree, tvb, &offset, hf_syslog_hostname))
    return offset;
  if (!dissect_syslog_info(tree, tvb, &offset, hf_syslog_appname))
    return offset;
  if (!dissect_syslog_info(tree, tvb, &offset, hf_syslog_procid))
    return offset;
  if (!dissect_syslog_info(tree, tvb, &offset, hf_syslog_msgid))
    return offset;

  /* STRUCTURED DATA */
  if (!dissect_syslog_sd(tree, tvb, pinfo, &offset))
    return offset;

  /* Check for BOM and read in the rest of msg*/
  if (tvb_reported_length_remaining(tvb, offset) > 3 && tvb_get_uint24(tvb, offset, ENC_BIG_ENDIAN) == MSG_BOM) {
    proto_tree_add_item(tree, hf_syslog_bom, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(tree, hf_syslog_msg, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_UTF_8);
  } else {
    proto_tree_add_item(tree, hf_syslog_msg, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_ASCII);
  }
  return tvb_reported_length(tvb);
}

/* Dissect message as defined in RFC3164 */
static unsigned
dissect_rfc3164_syslog_message(proto_tree* tree, tvbuff_t* tvb, unsigned offset)
{
  unsigned tvb_offset = 0;

  /* RFC 3164 HEADER section */

  /* Simple check if the first 16 bytes look like TIMESTAMP "Mmm dd hh:mm:ss"
   * by checking for spaces and colons. Otherwise return without processing
   * the message. */
  if (tvb_get_uint8(tvb, offset + 3) == CHR_SPACE && tvb_get_uint8(tvb, offset + 6) == CHR_SPACE &&
        tvb_get_uint8(tvb, offset + 9) == CHR_COLON && tvb_get_uint8(tvb, offset + 12) == CHR_COLON &&
        tvb_get_uint8(tvb, offset + 15) == CHR_SPACE) {
    proto_tree_add_item(tree, hf_syslog_timestamp_old, tvb, offset, 15, ENC_ASCII);
    offset += 16;
  } else {
    return offset;
  }

  if (!dissect_syslog_info(tree, tvb, &offset, hf_syslog_hostname))
    return offset;

  /* RFC 3164 MSG section */

  /* TAG field (proc) */
  for (tvb_offset=offset; tvb_offset < offset+32; tvb_offset++){
    uint8_t octet;
    octet = tvb_get_uint8(tvb, tvb_offset);
    if (!g_ascii_isalnum(octet)){
      proto_tree_add_item(tree, hf_syslog_procid, tvb, offset, tvb_offset - offset, ENC_ASCII);
      offset = tvb_offset+1;
      break;
    }
  }

  /* CONTENT */
  /* Read in the rest as msg */
  proto_tree_add_item(tree, hf_syslog_msg, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_ASCII);
  return tvb_reported_length(tvb);
}

/* Checks if Octet Counting Framing is used and return entire PDU length */
static unsigned
get_framed_syslog_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_)
{
  /*
    RFC 6587: Octet Counting Framing can be assumed if the data starts with non-zero digits.
    SYSLOG-FRAME = MSG-LEN SP SYSLOG-MSG

    This function returns the length of the PDU (incl. leading <LEN><SPACE>)
  */

  /* Find leading integers */
  int digits_str_len = 0;
  while(tvb_bytes_exist(tvb, offset + digits_str_len, 1) && digits_str_len < MAX_FRAMING_DIGITS) {
    uint8_t current_char = tvb_get_uint8(tvb, offset + digits_str_len);
    if(!g_ascii_isdigit(current_char) || (digits_str_len == 0 && current_char == CHR_0))
      break;
    digits_str_len++;
  }

  /* Get the actual integer from string */
  unsigned msg_len = 0;
  unsigned multiplier = 1;
  if(digits_str_len > 0) {
    const uint8_t *digits_str = tvb_get_string_enc(pinfo->pool, tvb, offset, digits_str_len, ENC_ASCII);
    for (unsigned d = digits_str_len; d > 0; d--) {
      msg_len += ((digits_str[d-1] - CHR_0) * multiplier);
      multiplier *= 10;
    }
  }

  /*
    When a <space> is found after the length digits, it seems to be framed TCP
  */
  if(msg_len > 0 && tvb_bytes_exist(tvb, offset, digits_str_len+1)) {
    if(tvb_get_uint8(tvb, offset + digits_str_len) == CHR_SPACE) {
      return msg_len + 1 + digits_str_len;
    }
  }

  return 0;

}

/* Main dissection function */
static int
dissect_syslog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  int pri = -1, lev = -1, fac = -1;
  int msg_off = 0, pri_digits = 0, pri_chars = 0, msg_len, reported_msg_len, framing_leading_str_len = 0;
  unsigned framing_pdu_len;
  proto_item *ti;
  proto_tree *syslog_tree;
  const char *msg_str;
  tvbuff_t *mtp3_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Syslog");
  col_clear(pinfo->cinfo, COL_INFO);

  framing_pdu_len = get_framed_syslog_pdu_len(pinfo, tvb, msg_off, data);
  if(framing_pdu_len > 0) {
    framing_leading_str_len = snprintf(NULL, 0, "%d", framing_pdu_len) + 1;
    msg_off += framing_leading_str_len;
  }

  if (tvb_get_uint8(tvb, msg_off) == '<') {
    /* A facility and level follow. */
    msg_off++;
    pri_chars++;
    pri = 0;
    while (tvb_bytes_exist(tvb, msg_off, 1) &&
           g_ascii_isdigit(tvb_get_uint8(tvb, msg_off)) && pri_digits <= MAX_DIGITS) {
      pri = pri * 10 + (tvb_get_uint8(tvb, msg_off) - CHR_0);
      pri_digits++;
      pri_chars++;
      msg_off++;
    }
    if (tvb_get_uint8(tvb, msg_off) == '>') {
      msg_off++;
      pri_chars++;
    }
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

  if (framing_pdu_len)
    proto_tree_add_item(syslog_tree, hf_syslog_msglen, tvb, 0, framing_leading_str_len - 1, ENC_ASCII);

  if (pri >= 0) {
    proto_tree_add_uint(syslog_tree, hf_syslog_facility, tvb, framing_leading_str_len,
      pri_chars, pri);
    proto_tree_add_uint(syslog_tree, hf_syslog_level, tvb, framing_leading_str_len,
      pri_chars, pri);
  }

  /*
  *  RFC5424 defines a version field which is currently defined as '1'
  *  followed by a space (0x3120). Otherwise the message is probably
  *  a RFC3164 message.
  */
  unsigned offset = msg_off;
  if (msg_len > 2 && tvb_get_ntohs(tvb, msg_off) == RFC5424_V) {
    offset = dissect_rfc5424_syslog_message(syslog_tree, tvb, pinfo, msg_off);
  } else if ( msg_len > 15) {
    offset = dissect_rfc3164_syslog_message(syslog_tree, tvb, msg_off);
  }
  if (offset < tvb_reported_length(tvb)) {
    ti = proto_tree_add_item(syslog_tree, hf_syslog_msg, tvb, offset,
      tvb_reported_length_remaining(tvb, offset), ENC_ASCII);
    expert_add_info(pinfo, ti, &ei_syslog_msg_nonconformant);
  }

  if (mtp3_tvb) {
    proto_item *mtp3_item;
    mtp3_item = proto_tree_add_boolean(syslog_tree, hf_syslog_msu_present,
                                        tvb, msg_off, msg_len, true);
    proto_item_set_generated(mtp3_item);
  }

  /* Call MTP dissector if encapsulated MSU was found... */
  if (mtp3_tvb) {
    call_dissector(mtp_handle, mtp3_tvb, pinfo, tree);
  }

  return tvb_captured_length(tvb);
}

static int
dissect_syslog_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{

  /*
    When get_framed_syslog_pdu_len() returns >0, it has been checked for TCP Octet Counting Framing.
    It can be handed over to tcp_dissect_pdus().
  */
  if(get_framed_syslog_pdu_len(pinfo, tvb, 0, data) > 0) {
    tcp_dissect_pdus(tvb, pinfo, tree, true, MAX_FRAMING_DIGITS + 1, get_framed_syslog_pdu_len, dissect_syslog, data);
    return tvb_reported_length(tvb);
  }

  /* If no framing was detected, simply pass it to the syslog dissector function */
  return dissect_syslog(tvb, pinfo, tree, data);
}

/* Register the protocol with Wireshark */
void proto_register_syslog(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_syslog_msglen,
      { "Message Length", "syslog.msglen",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Length of message (without this field)", HFILL }
    },
    { &hf_syslog_facility,
      { "Facility", "syslog.facility",
        FT_UINT16, BASE_DEC, VALS(syslog_facility_vals), FACILITY_MASK,
        "Message facility", HFILL }
    },
    { &hf_syslog_level,
      { "Level", "syslog.level",
        FT_UINT16, BASE_DEC, VALS(syslog_level_vals), PRIORITY_MASK,
        "Message level", HFILL }
    },
    { &hf_syslog_msu_present,
      { "SS7 MSU present", "syslog.msu_present",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "True if an SS7 MSU was detected in the syslog message", HFILL }
    },
    { &hf_syslog_version,
      { "Version", "syslog.version",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Syslog version", HFILL }
    },
    { &hf_syslog_timestamp,
      { "Timestamp", "syslog.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_syslog_timestamp_old,
      { "Timestamp (RFC3164)", "syslog.timestamp_rfc3164",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_syslog_hostname,
      { "Hostname", "syslog.hostname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "The hostname that generated this message", HFILL }
    },
    { &hf_syslog_appname,
      { "App Name", "syslog.appname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "The name of the app that generated this message", HFILL }
    },
    { &hf_syslog_procid,
      { "Process ID", "syslog.procid",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "The ID of the process that generated this message", HFILL }
    },
    { &hf_syslog_msg,
      { "Message", "syslog.msg",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_syslog_msgid,
      { "Message ID", "syslog.msgid",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_syslog_bom,
      { "BOM", "syslog.msgid.bom",
        FT_UINT24, BASE_HEX, NULL, 0x0,
        "Byte Order Mark", HFILL }
    },
    { &hf_syslog_sd,
      { "Structured Data", "syslog.sd",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_syslog_sd_element,
      { "Element", "syslog.sd.element",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Structured Data Element", HFILL }
    },
    { &hf_syslog_sd_element_name,
      { "Element Name", "syslog.sd.element.name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Structured Data Element Name", HFILL }
    },
    { &hf_syslog_sd_param,
      { "Parameter", "syslog.sd.param",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Structured Data Parameter", HFILL }
    },
    { &hf_syslog_sd_param_name,
      { "Parameter Name", "syslog.sd.param.name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Structured Data Parameter Name", HFILL }
    },
    { &hf_syslog_sd_param_value,
      { "Parameter Value", "syslog.sd.param.value",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Structured Data Parameter Value", HFILL }
    }
  };

  /* Setup protocol subtree array */
  static int *ett[] = {
    &ett_syslog,
    &ett_syslog_sd,
    &ett_syslog_sd_element,
    &ett_syslog_sd_param
  };

  static ei_register_info ei[] = {
    { &ei_syslog_msg_nonconformant, { "syslog.msg.nonconformant", PI_PROTOCOL, PI_NOTE, "Message conforms to neither RFC 5424 nor RFC 3164; trailing data appended", EXPFILL }}
  };

  expert_module_t *expert_syslog;

  /* Register the protocol name and description */
  proto_syslog = proto_register_protocol("Syslog Message", "Syslog", "syslog");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_syslog, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_syslog = expert_register_protocol(proto_syslog);
  expert_register_field_array(expert_syslog, ei, array_length(ei));

  syslog_handle = register_dissector("syslog", dissect_syslog, proto_syslog);
  syslog_handle_tcp = register_dissector("syslog.tcp", dissect_syslog_tcp, proto_syslog);
}

void
proto_reg_handoff_syslog(void)
{
  dissector_add_uint_with_preference("udp.port", SYSLOG_PORT_UDP, syslog_handle);
  dissector_add_for_decode_as_with_preference("tcp.port", syslog_handle_tcp);
  dissector_add_uint_with_preference("tls.port", SYSLOG_PORT_TLS, syslog_handle_tcp);

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
