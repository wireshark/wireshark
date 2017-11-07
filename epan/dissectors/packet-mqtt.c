/* packet-mqtt.c
 * Routines for MQTT Protocol dissection
 *
 * MQTT v5.0 support sponsored by 1byt3 <customers at 1byt3.com>
 *
 * By Lakshmi Narayana Madala  <madalanarayana@outlook.com>
 *    Stig Bjorlykke  <stig@bjorlykke.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

/*
 * Protocol description:
 *
 * MQTT is a Client Server publish/subscribe messaging transport
 * protocol. The protocol runs over TCP/IP, or over other network
 * protocols that provide ordered, lossless, bi-directional
 * connections.
 *
 * MQTT v3.1 specification:
 * http://public.dhe.ibm.com/software/dw/webservices/ws-mqtt/mqtt-v3r1.html
 *
 * MQTT v3.1.1 specification:
 * http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/
 *
 * MQTT v5.0 specification:
 * http://docs.oasis-open.org/mqtt/mqtt/v5.0/
 *
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/uat.h>
#include <epan/dwarf.h>
#include "packet-tcp.h"
#include "packet-ssl.h"

#define MQTT_DEFAULT_PORT     1883 /* IANA registered under service name as mqtt */
#define MQTT_SSL_DEFAULT_PORT 8883 /* IANA registered under service name secure-mqtt */

/* MQTT Protocol Versions */
#define MQTT_PROTO_V31      3
#define MQTT_PROTO_V311     4
#define MQTT_PROTO_V50      5

#define MQTT_HDR_SIZE_BEFORE_LEN 1

/* MQTT Message Types */
#define MQTT_RESERVED        0
#define MQTT_CONNECT         1
#define MQTT_CONNACK         2
#define MQTT_PUBLISH         3
#define MQTT_PUBACK          4
#define MQTT_PUBREC          5
#define MQTT_PUBREL          6
#define MQTT_PUBCOMP         7
#define MQTT_SUBSCRIBE       8
#define MQTT_SUBACK          9
#define MQTT_UNSUBSCRIBE    10
#define MQTT_UNSUBACK       11
#define MQTT_PINGREQ        12
#define MQTT_PINGRESP       13
#define MQTT_DISCONNECT     14
#define MQTT_AUTH           15
#define MQTT_RESERVED_16    16

/* Flag Values to extract fields */
#define MQTT_MASK_MSG_TYPE          0xF0
#define MQTT_MASK_HDR_RESERVED      0x0F
#define MQTT_MASK_HDR_DUP_RESERVED  0x07
#define MQTT_MASK_QOS               0x06
#define MQTT_MASK_DUP_FLAG          0x08
#define MQTT_MASK_RETAIN            0x01

void proto_register_mqtt(void);
void proto_reg_handoff_mqtt(void);

static const value_string mqtt_protocol_version_vals[] = {
  { MQTT_PROTO_V31,        "MQTT v3.1" },
  { MQTT_PROTO_V311,       "MQTT v3.1.1" },
  { MQTT_PROTO_V50,        "MQTT v5.0" },
  { 0,                     NULL }
};

static const value_string mqtt_msgtype_vals[] = {
  { MQTT_RESERVED,          "Reserved" },
  { MQTT_CONNECT,           "Connect Command" },
  { MQTT_CONNACK,           "Connect Ack" },
  { MQTT_PUBLISH,           "Publish Message" },
  { MQTT_PUBACK,            "Publish Ack" },
  { MQTT_PUBREC,            "Publish Received" },
  { MQTT_PUBREL,            "Publish Release" },
  { MQTT_PUBCOMP,           "Publish Complete" },
  { MQTT_SUBSCRIBE,         "Subscribe Request" },
  { MQTT_SUBACK,            "Subscribe Ack" },
  { MQTT_UNSUBSCRIBE,       "Unsubscribe Request" },
  { MQTT_UNSUBACK,          "Unsubscribe Ack" },
  { MQTT_PINGREQ,           "Ping Request" },
  { MQTT_PINGRESP,          "Ping Response" },
  { MQTT_DISCONNECT,        "Disconnect Req" },
  { MQTT_AUTH,              "Authentication Exchange" },
  { MQTT_RESERVED_16,       "Reserved" },
  { 0,                      NULL }
};
static value_string_ext mqtt_msgtype_vals_ext = VALUE_STRING_EXT_INIT(mqtt_msgtype_vals);

#define MQTT_QOS_ATMOST_ONCE      0
#define MQTT_QOS_ATLEAST_ONCE     1
#define MQTT_QOS_EXACTLY_ONCE     2
#define MQTT_QOS_RESERVED         3

static const value_string mqtt_qos_vals[] = {
  { MQTT_QOS_ATMOST_ONCE,       "At most once delivery (Fire and Forget)" },
  { MQTT_QOS_ATLEAST_ONCE,      "At least once delivery (Acknowledged deliver)" },
  { MQTT_QOS_EXACTLY_ONCE,      "Exactly once delivery (Assured Delivery)" },
  { MQTT_QOS_RESERVED,          "Reserved" },
  { 0,                          NULL }
};

#define MQTT_SUBACK_FAILURE  128

static const value_string mqtt_subqos_vals[] = {
  { MQTT_QOS_ATMOST_ONCE,       "At most once delivery (Fire and Forget)" },
  { MQTT_QOS_ATLEAST_ONCE,      "At least once delivery (Acknowledged deliver)" },
  { MQTT_QOS_EXACTLY_ONCE,      "Exactly once delivery (Assured Delivery)" },
  { MQTT_QOS_RESERVED,          "Reserved" },
  { MQTT_SUBACK_FAILURE,        "Failure" },
  { 0,                          NULL }
};

#define MQTT_CON_ACCEPTED                   0
#define MQTT_CON_REFUSED_VERSION_MISMATCH   1
#define MQTT_CON_REFUSED_ID_REJECTED        2
#define MQTT_CON_REFUSED_SERVER_UNAVAILABLE 3
#define MQTT_CON_REFUSED_BAD_USER_PASSWD    4
#define MQTT_CON_REFUSED_UNAUTHORIZED       5

static const value_string mqtt_conack_vals[] = {
  { MQTT_CON_ACCEPTED,                   "Connection Accepted" },
  { MQTT_CON_REFUSED_VERSION_MISMATCH,   "Connection Refused: unacceptable protocol version" },
  { MQTT_CON_REFUSED_ID_REJECTED,        "Connection Refused: identifier rejected" },
  { MQTT_CON_REFUSED_SERVER_UNAVAILABLE, "Connection Refused: server unavailable" },
  { MQTT_CON_REFUSED_BAD_USER_PASSWD,    "Connection Refused: bad user name or password" },
  { MQTT_CON_REFUSED_UNAUTHORIZED,       "Connection Refused: not authorized" },
  { 0,                                   NULL }
};

#define MQTT_CONMASK_USER        0x80
#define MQTT_CONMASK_PASSWD      0x40
#define MQTT_CONMASK_RETAIN      0x20
#define MQTT_CONMASK_QOS         0x18
#define MQTT_CONMASK_WILLFLAG    0x04
#define MQTT_CONMASK_CLEANSESS   0x02
#define MQTT_CONMASK_RESERVED    0x01

#define MQTT_CONACKMASK_RESERVED 0xFE
#define MQTT_CONACKMASK_SP       0x01

/* The protocol version is present in the CONNECT message. */
typedef struct {
    guint8 runtime_proto_version;
} mqtt_conv;

typedef struct _mqtt_message_decode_t {
  guint   match_criteria;
  char   *topic_pattern;
  GRegex *topic_regex;
  char   *payload_proto_name;
  dissector_handle_t payload_proto;
} mqtt_message_decode_t;

#define MATCH_CRITERIA_EQUAL        0
#define MATCH_CRITERIA_CONTAINS     1
#define MATCH_CRITERIA_STARTS_WITH  2
#define MATCH_CRITERIA_ENDS_WITH    3
#define MATCH_CRITERIA_REGEX        4

static const value_string match_criteria[] = {
  { MATCH_CRITERIA_EQUAL,       "Equal to" },
  { MATCH_CRITERIA_CONTAINS,    "Contains" },
  { MATCH_CRITERIA_STARTS_WITH, "Starts with" },
  { MATCH_CRITERIA_ENDS_WITH,   "Ends with" },
  { MATCH_CRITERIA_REGEX,       "Regular Expression" },
  { 0, NULL }
};

static mqtt_message_decode_t *mqtt_message_decodes = NULL;
static guint num_mqtt_message_decodes = 0;

static dissector_handle_t mqtt_handle;

/* Initialize the protocol and registered fields */
static int proto_mqtt = -1;

/* Message */
static int hf_mqtt_hdrflags = -1;
static int hf_mqtt_msg_len = -1;
static int hf_mqtt_msg_type = -1;
static int hf_mqtt_reserved = -1;
static int hf_mqtt_dup_flag = -1;
static int hf_mqtt_qos_level = -1;
static int hf_mqtt_retain = -1;
static int hf_mqtt_retain_reserved = -1;
static int hf_mqtt_conack_reserved = -1;
static int hf_mqtt_conack_flags = -1;
static int hf_mqtt_conackflag_reserved = -1;
static int hf_mqtt_conackflag_sp = -1;
static int hf_mqtt_conack_code = -1;
static int hf_mqtt_msgid = -1;
static int hf_mqtt_sub_qos = -1;
static int hf_mqtt_suback_qos = -1;
static int hf_mqtt_topic_len = -1;
static int hf_mqtt_topic = -1;
static int hf_mqtt_will_topic_len = -1;
static int hf_mqtt_will_topic = -1;
static int hf_mqtt_will_msg_len = -1;
static int hf_mqtt_will_msg = -1;
static int hf_mqtt_username_len = -1;
static int hf_mqtt_username = -1;
static int hf_mqtt_passwd_len = -1;
static int hf_mqtt_passwd = -1;
static int hf_mqtt_pubmsg = -1;
static int hf_mqtt_pubmsg_decoded = -1;
static int hf_mqtt_proto_len = -1;
static int hf_mqtt_proto_name = -1;
static int hf_mqtt_client_id_len = -1;
static int hf_mqtt_client_id = -1;
static int hf_mqtt_proto_ver = -1;
static int hf_mqtt_conflags = -1;
static int hf_mqtt_conflag_user = -1;
static int hf_mqtt_conflag_passwd = -1;
static int hf_mqtt_conflag_will_retain = -1;
static int hf_mqtt_conflag_will_qos = -1;
static int hf_mqtt_conflag_will_flag = -1;
static int hf_mqtt_conflag_clean_sess = -1;
static int hf_mqtt_conflag_reserved = -1;
static int hf_mqtt_keep_alive = -1;
static int hf_mqtt_subscription_options = -1;
static int hf_mqtt_reason_code = -1;
static int hf_mqtt_property_len = -1;
static int hf_mqtt_property = -1;

/* Initialize the subtree pointers */
static gint ett_mqtt_hdr = -1;
static gint ett_mqtt_msg = -1;
static gint ett_mqtt_hdr_flags = -1;
static gint ett_mqtt_con_flags = -1;
static gint ett_mqtt_conack_flags = -1;

/* Reassemble SMPP TCP segments */
static gboolean reassemble_mqtt_over_tcp = TRUE;

#define GET_MQTT_PDU_LEN(msg_len, len_offset)    (msg_len + len_offset + MQTT_HDR_SIZE_BEFORE_LEN)

static guint get_mqtt_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                              int offset, void *data _U_)
{
  guint64 msg_len;
  guint len_offset;

  len_offset = dissect_uleb128(tvb, (offset + MQTT_HDR_SIZE_BEFORE_LEN), &msg_len);

  /* Explicitly downcast the value, because the length can never be more than 4 bytes */
  return (guint)(GET_MQTT_PDU_LEN(msg_len, len_offset));
}

static void *mqtt_message_decode_copy_cb(void *dest, const void *orig, size_t len _U_)
{
  const mqtt_message_decode_t *o = (const mqtt_message_decode_t *)orig;
  mqtt_message_decode_t *d = (mqtt_message_decode_t *)dest;

  d->topic_pattern = g_strdup(o->topic_pattern);
  d->payload_proto_name = g_strdup(o->payload_proto_name);

  return d;
}

static gboolean mqtt_message_decode_update_cb(void *record, char **error)
{
  mqtt_message_decode_t *u = (mqtt_message_decode_t *)record;

  if (u->topic_pattern == NULL || strlen(u->topic_pattern) == 0)
  {
    *error = g_strdup("Missing topic pattern");
    return FALSE;
  }

  if (u->match_criteria == MATCH_CRITERIA_REGEX)
  {
    u->topic_regex = g_regex_new(u->topic_pattern, (GRegexCompileFlags) G_REGEX_OPTIMIZE, (GRegexMatchFlags) 0, NULL);
    if (!u->topic_regex)
    {
      *error = g_strdup_printf("Invalid regex: %s", u->topic_pattern);
      return FALSE;
    }
  }

  return TRUE;
}

static void mqtt_message_decode_free_cb(void *record)
{
  mqtt_message_decode_t *u = (mqtt_message_decode_t *)record;

  g_free(u->topic_pattern);
  if (u->topic_regex)
  {
    g_regex_unref(u->topic_regex);
  }
  g_free(u->payload_proto_name);
}

UAT_VS_DEF(message_decode, match_criteria, mqtt_message_decode_t, guint, MATCH_CRITERIA_EQUAL, "Equal to")
UAT_CSTRING_CB_DEF(message_decode, topic_pattern, mqtt_message_decode_t)
UAT_PROTO_DEF(message_decode, payload_proto, payload_proto, payload_proto_name, mqtt_message_decode_t)

static void mqtt_user_decode_message(proto_tree *tree, proto_tree *mqtt_tree, packet_info *pinfo, const guint8 *topic_str, tvbuff_t *msg_tvb)
{
  mqtt_message_decode_t *message_decode_entry = NULL;
  size_t topic_str_len = strlen(topic_str);
  size_t topic_pattern_len;
  gboolean match_found = FALSE;

  if (topic_str_len == 0)
  {
    /* No topic to match */
    return;
  }

  for (guint i = 0; i < num_mqtt_message_decodes && !match_found; i++)
  {
    message_decode_entry = &mqtt_message_decodes[i];
    switch (message_decode_entry->match_criteria)
    {
      case MATCH_CRITERIA_EQUAL:
        match_found = (strcmp(topic_str, message_decode_entry->topic_pattern) == 0);
        break;
      case MATCH_CRITERIA_CONTAINS:
        match_found = (strstr(topic_str, message_decode_entry->topic_pattern) != NULL);
        break;
      case MATCH_CRITERIA_STARTS_WITH:
        topic_pattern_len = strlen(message_decode_entry->topic_pattern);
        match_found = ((topic_str_len >= topic_pattern_len) &&
                       (strncmp(topic_str, message_decode_entry->topic_pattern, topic_pattern_len) == 0));
        break;
      case MATCH_CRITERIA_ENDS_WITH:
        topic_pattern_len = strlen(message_decode_entry->topic_pattern);
        match_found = ((topic_str_len >= topic_pattern_len) &&
                       (strcmp(topic_str + (topic_str_len - topic_pattern_len), message_decode_entry->topic_pattern) == 0));
        break;
      case MATCH_CRITERIA_REGEX:
        if (message_decode_entry->topic_regex)
        {
          GMatchInfo *match_info = NULL;
          g_regex_match(message_decode_entry->topic_regex, topic_str, (GRegexMatchFlags) 0, &match_info);
          match_found = g_match_info_matches(match_info);
          g_match_info_free(match_info);
        }
        break;
      default:
        /* Unknown match criteria */
        break;
    }
  }

  if (match_found)
  {
    proto_item *ti = proto_tree_add_string(mqtt_tree, hf_mqtt_pubmsg_decoded, msg_tvb, 0, -1,
                                           message_decode_entry->payload_proto_name);
    PROTO_ITEM_SET_GENERATED(ti);

    call_dissector(message_decode_entry->payload_proto, msg_tvb, pinfo, tree);
  }
}

/* MQTT v5.0: dissect the MQTT properties */
static guint32 dissect_mqtt_properties(tvbuff_t *tvb, proto_tree *mqtt_tree, guint32 offset)
{
  guint32 mqtt_prop_offset;
  guint32 mqtt_prop_len;
  guint64 prop_len;

  mqtt_prop_offset = dissect_uleb128(tvb, offset, &prop_len);
  mqtt_prop_len = (guint32)prop_len;

  proto_tree_add_item(mqtt_tree, hf_mqtt_property_len, tvb, offset, mqtt_prop_offset, ENC_BIG_ENDIAN);
  if (mqtt_prop_len > 0)
  {
    proto_tree_add_item(mqtt_tree, hf_mqtt_property, tvb, offset + mqtt_prop_offset, mqtt_prop_len, ENC_UTF_8|ENC_NA);
    /* In this iteration we don't dissect the MQTT properties section */
  }

  return mqtt_prop_offset + mqtt_prop_len;
}

/* Dissect the MQTT message */
static int dissect_mqtt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint8  mqtt_fixed_hdr;
    guint8  mqtt_msg_type;
    proto_item *ti;
    int hf_version_selector;
    const guint8 *topic_str;

    proto_tree *mqtt_tree;

    guint64     mqtt_con_flags;
    guint64     msg_len      = 0;
    gint        mqtt_msg_len = 0;
    guint16     mqtt_str_len;
    guint16     mqtt_len_offset;
    conversation_t *conv;
    mqtt_conv   *mqtt;

    guint32 offset = 0;
    static const int *publish_fields[] = {
        &hf_mqtt_msg_type,
        &hf_mqtt_dup_flag,
        &hf_mqtt_qos_level,
        &hf_mqtt_retain,
        NULL
    };
    static const int *v31_pubrel_sub_unsub_fields[] = {
        &hf_mqtt_msg_type,
        &hf_mqtt_dup_flag,
        &hf_mqtt_qos_level,
        &hf_mqtt_retain_reserved,
        NULL
    };
    static const int *other_fields[] = {
        &hf_mqtt_msg_type,
        &hf_mqtt_reserved,
        NULL
    };
    static const int *connect_flags[] = {
        &hf_mqtt_conflag_user,
        &hf_mqtt_conflag_passwd,
        &hf_mqtt_conflag_will_retain,
        &hf_mqtt_conflag_will_qos,
        &hf_mqtt_conflag_will_flag,
        &hf_mqtt_conflag_clean_sess,
        &hf_mqtt_conflag_reserved,
        NULL
    };
    static const int *connack_flags[] = {
        &hf_mqtt_conackflag_reserved,
        &hf_mqtt_conackflag_sp,
        NULL
    };

    /* Extract the message ID */
    mqtt_fixed_hdr = tvb_get_guint8(tvb, offset);
    mqtt_msg_type = mqtt_fixed_hdr >> 4;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MQTT");
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str_ext(mqtt_msg_type, &mqtt_msgtype_vals_ext, "Unknown (0x%02x)"));

    /* Add the MQTT branch to the main tree */
    ti = proto_tree_add_item(tree, proto_mqtt, tvb, 0, -1, ENC_NA);
    mqtt_tree = proto_item_add_subtree(ti, ett_mqtt_hdr);

    conv = find_or_create_conversation(pinfo);
    mqtt = (mqtt_conv *)conversation_get_proto_data(conv, proto_mqtt);
    if (mqtt == NULL)
    {
      mqtt = wmem_new0(wmem_file_scope(), mqtt_conv);
      conversation_add_proto_data(conv, proto_mqtt, mqtt);
    }

    mqtt_len_offset = dissect_uleb128(tvb, (offset + MQTT_HDR_SIZE_BEFORE_LEN), &msg_len);

    /* Explicit downcast, typically maximum length of message could be 4 bytes */
    mqtt_msg_len = (gint) msg_len;

    /* Add the type to the MQTT tree item */
    proto_item_append_text(mqtt_tree, ", %s", val_to_str_ext(mqtt_msg_type, &mqtt_msgtype_vals_ext, "Unknown (0x%02x)"));

    if (mqtt_msg_type == MQTT_PUBLISH)
    {
      proto_tree_add_bitmask(mqtt_tree, tvb, offset, hf_mqtt_hdrflags, ett_mqtt_hdr_flags, publish_fields, ENC_BIG_ENDIAN);
    }
    else if (mqtt->runtime_proto_version == MQTT_PROTO_V31 &&
             (mqtt_msg_type == MQTT_PUBREL ||
              mqtt_msg_type == MQTT_SUBSCRIBE ||
              mqtt_msg_type == MQTT_UNSUBSCRIBE))
    {
      proto_tree_add_bitmask(mqtt_tree, tvb, offset, hf_mqtt_hdrflags, ett_mqtt_hdr_flags, v31_pubrel_sub_unsub_fields, ENC_BIG_ENDIAN);
    }
    else
    {
      proto_tree_add_bitmask(mqtt_tree, tvb, offset, hf_mqtt_hdrflags, ett_mqtt_hdr_flags, other_fields, ENC_BIG_ENDIAN);
    }

    offset += 1;

    /* Add the MQTT message length */
    proto_tree_add_uint64(mqtt_tree, hf_mqtt_msg_len, tvb, offset, mqtt_len_offset, msg_len);
    offset += mqtt_len_offset;

    switch(mqtt_msg_type)
    {
      case MQTT_CONNECT:
        mqtt_str_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(mqtt_tree, hf_mqtt_proto_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(mqtt_tree, hf_mqtt_proto_name, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA);
        offset += mqtt_str_len;

        mqtt->runtime_proto_version = tvb_get_guint8(tvb, offset);

        proto_tree_add_item(mqtt_tree, hf_mqtt_proto_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;


        proto_tree_add_bitmask_ret_uint64(mqtt_tree, tvb, offset, hf_mqtt_conflags,
                           ett_mqtt_con_flags, connect_flags, ENC_BIG_ENDIAN, &mqtt_con_flags);
        offset += 1;

        proto_tree_add_item(mqtt_tree, hf_mqtt_keep_alive, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
        {
          offset += dissect_mqtt_properties(tvb, mqtt_tree, offset);
        }

        mqtt_str_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(mqtt_tree, hf_mqtt_client_id_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(mqtt_tree, hf_mqtt_client_id, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA);
        offset += mqtt_str_len;

        if(mqtt_con_flags & MQTT_CONMASK_WILLFLAG)
        {
          mqtt_str_len = tvb_get_ntohs(tvb, offset);
          proto_tree_add_item(mqtt_tree, hf_mqtt_will_topic_len, tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;

          proto_tree_add_item(mqtt_tree, hf_mqtt_will_topic, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA);
          offset += mqtt_str_len;
        }
        if(mqtt_con_flags & MQTT_CONMASK_WILLFLAG)
        {
          mqtt_str_len = tvb_get_ntohs(tvb, offset);
          proto_tree_add_item(mqtt_tree, hf_mqtt_will_msg_len, tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;

          proto_tree_add_item(mqtt_tree, hf_mqtt_will_msg, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA);
          offset += mqtt_str_len;
        }
        if((mqtt_con_flags & MQTT_CONMASK_USER) && (tvb_reported_length_remaining(tvb, offset) > 0))
        {
          mqtt_str_len = tvb_get_ntohs(tvb, offset);
          proto_tree_add_item(mqtt_tree, hf_mqtt_username_len, tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;

          proto_tree_add_item(mqtt_tree, hf_mqtt_username, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA);
          offset += mqtt_str_len;
        }
        if((mqtt_con_flags & MQTT_CONMASK_PASSWD) && (tvb_reported_length_remaining(tvb, offset) > 0))
        {
          mqtt_str_len = tvb_get_ntohs(tvb, offset);
          proto_tree_add_item(mqtt_tree, hf_mqtt_passwd_len, tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;

          proto_tree_add_item(mqtt_tree, hf_mqtt_passwd, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA);
        }
        break;

      case MQTT_CONNACK:
        if (mqtt->runtime_proto_version == MQTT_PROTO_V31)
        {
          /* v3.1 Connection Ack only contains a reserved byte and the Return Code. */
          proto_tree_add_item(mqtt_tree, hf_mqtt_conack_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        else
        {
          /* v3.1.1 Conn Ack contains the Conn Ack Flags and the Return Code. */
          proto_tree_add_bitmask(mqtt_tree, tvb, offset, hf_mqtt_conack_flags,
                           ett_mqtt_conack_flags, connack_flags, ENC_BIG_ENDIAN);
        }
        offset += 1;

        proto_tree_add_item(mqtt_tree, hf_mqtt_conack_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
        {
          offset += dissect_mqtt_properties(tvb, mqtt_tree, offset);
        }
        break;
      case MQTT_PUBLISH:
        /* TopicName|MsgID|Message| */
        mqtt_str_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(mqtt_tree, hf_mqtt_topic_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        mqtt_msg_len -= 2;

        proto_tree_add_item_ret_string(mqtt_tree, hf_mqtt_topic, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA,
                                       wmem_epan_scope(), &topic_str);
        offset += mqtt_str_len;
        mqtt_msg_len -= mqtt_str_len;

        /* Message ID is included only when QoS > 0 */
        if(mqtt_fixed_hdr & MQTT_MASK_QOS)
        {
          proto_tree_add_item(mqtt_tree, hf_mqtt_msgid, tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;
          mqtt_msg_len -= 2;
        }

        if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
        {
          guint32 mqtt_prop_offset = dissect_mqtt_properties(tvb, mqtt_tree, offset);
          offset += mqtt_prop_offset;

          mqtt_msg_len -= mqtt_prop_offset;
        }

        proto_tree_add_item(mqtt_tree, hf_mqtt_pubmsg, tvb, offset, mqtt_msg_len, ENC_UTF_8|ENC_NA);

        if (num_mqtt_message_decodes > 0)
        {
          tvbuff_t *msg_tvb = tvb_new_subset_length(tvb, offset, mqtt_msg_len);
          mqtt_user_decode_message(tree, mqtt_tree, pinfo, topic_str, msg_tvb);
        }
        break;

      case MQTT_SUBSCRIBE:
        /* After the Message Id field is found, the following fields must appear
         * at least once:
         * |TopicName|QoS|
         */
        proto_tree_add_item(mqtt_tree, hf_mqtt_msgid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
        {
          offset += dissect_mqtt_properties(tvb, mqtt_tree, offset);
          hf_version_selector = hf_mqtt_subscription_options;
        }
        else
        {
          hf_version_selector = hf_mqtt_sub_qos;
        }

        for(mqtt_msg_len -= 2; mqtt_msg_len > 0;)
        {
          mqtt_str_len = tvb_get_ntohs(tvb, offset);
          proto_tree_add_item(mqtt_tree, hf_mqtt_topic_len, tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;
          mqtt_msg_len -= 2;

          proto_tree_add_item(mqtt_tree, hf_mqtt_topic, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA);
          offset += mqtt_str_len;
          mqtt_msg_len -= mqtt_str_len;

          proto_tree_add_item(mqtt_tree, hf_version_selector, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          mqtt_msg_len -= 1;
        }
        break;

      case MQTT_UNSUBSCRIBE:
        /* After the Message Id field is found, the following fields must appear
         * at least once:
         * |TopicName|
         */
        proto_tree_add_item(mqtt_tree, hf_mqtt_msgid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        for(mqtt_msg_len -= 2; mqtt_msg_len > 0;)
        {
          mqtt_str_len = tvb_get_ntohs(tvb, offset);
          proto_tree_add_item(mqtt_tree, hf_mqtt_topic_len, tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;
          mqtt_msg_len -= 2;

          proto_tree_add_item(mqtt_tree, hf_mqtt_topic, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA);
          offset += mqtt_str_len;
          mqtt_msg_len -= mqtt_str_len;
        }
        break;

      case MQTT_SUBACK:
        /* The SUBACK message contains a list of granted QoS levels that come
         * after the Message Id field. The size of each QoS entry is 1 byte.
         */
        proto_tree_add_item(mqtt_tree, hf_mqtt_msgid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
        {
          offset += dissect_mqtt_properties(tvb, mqtt_tree, offset);
        }

        for(mqtt_msg_len -= 2; mqtt_msg_len > 0; mqtt_msg_len--)
        {
          proto_tree_add_item(mqtt_tree, hf_mqtt_suback_qos, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
        }
        break;

      case MQTT_PUBACK:
      case MQTT_PUBREC:
      case MQTT_PUBREL:
      case MQTT_PUBCOMP:
        proto_tree_add_item(mqtt_tree, hf_mqtt_msgid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
        {
          proto_tree_add_item(mqtt_tree, hf_mqtt_reason_code, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          offset += dissect_mqtt_properties(tvb, mqtt_tree, offset);
        }
        break;

      case MQTT_UNSUBACK:
        proto_tree_add_item(mqtt_tree, hf_mqtt_msgid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
        {
          offset += dissect_mqtt_properties(tvb, mqtt_tree, offset);
        }
        break;

      /* The following messages don't have variable header */
      case MQTT_PINGREQ:
      case MQTT_PINGRESP:
        break;

      case MQTT_DISCONNECT:
        /* MQTT v5.0: Byte 1 in the Variable Header is the Disconnect Reason Code.
         * If the Remaining Length is less than 1 the value of 0x00
         * (Normal disconnection) is used.
         */
         /* FALLTHROUGH */
      case MQTT_AUTH:
        /* MQTT v5.0: The Reason Code and Property Length can be omitted if
         * the Reason Code is 0x00 (Success) and there are no Properties.
         * In this case the AUTH has a Remaining Length of 0.
         */
        if (mqtt->runtime_proto_version == MQTT_PROTO_V50 && mqtt_msg_len > 0)
        {
          proto_tree_add_item(mqtt_tree, hf_mqtt_reason_code, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          offset += dissect_mqtt_properties(tvb, mqtt_tree, offset);
        }

        break;
    }

    return tvb_captured_length(tvb);
}

/**
"The minimum size of MQTT Packet is 2 bytes(Ping Req, Ping Rsp,
Disconnect), and the maximum size is 256MB.  Hence minimum fixed
length should be 2 bytes for tcp_dissect_pdu.

If the length filed is spread across two TCP segments, then we have a
problem, because exception will be raised.  So long as MQTT length
field(although spread over 4 bytes) is present within single TCP
segment we shouldn't have any issue by calling tcp_dissect_pdu with
minimum length set to 2."

XXX: ToDo: Commit a fix for the case of the length field spread across TCP segments.
**/

static int dissect_mqtt_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  col_clear(pinfo->cinfo, COL_INFO);

  tcp_dissect_pdus(tvb, pinfo, tree,
                   reassemble_mqtt_over_tcp,
                   2,                           /* Length can be determined within 5 bytes */
                   get_mqtt_pdu_len,
                   dissect_mqtt, data);

  return tvb_captured_length(tvb);
}

/*
 * Register the protocol with Wireshark
 */
void proto_register_mqtt(void)
{
  static hf_register_info hf_mqtt[] = {
    { &hf_mqtt_msg_len,
      { "Msg Len", "mqtt.len",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_hdrflags,
      { "Header Flags", "mqtt.hdrflags",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_msg_type,
      { "Message Type", "mqtt.msgtype",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &mqtt_msgtype_vals_ext, MQTT_MASK_MSG_TYPE,
        NULL, HFILL }},
    { &hf_mqtt_reserved,
      { "Reserved", "mqtt.hdr_reserved",
        FT_UINT8, BASE_DEC, NULL, MQTT_MASK_HDR_RESERVED,
        "Fixed Header Reserved Field", HFILL }},
    { &hf_mqtt_retain_reserved,
      { "Reserved", "mqtt.retain_reserved",
        FT_UINT8, BASE_DEC, NULL, MQTT_MASK_RETAIN,
        "Fixed Header Reserved Field", HFILL }},
    { &hf_mqtt_dup_flag,
      { "DUP Flag", "mqtt.dupflag",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQTT_MASK_DUP_FLAG,
        NULL, HFILL }},
    { &hf_mqtt_qos_level,
      { "QoS Level", "mqtt.qos",
        FT_UINT8, BASE_DEC, VALS(mqtt_qos_vals), MQTT_MASK_QOS,
        NULL, HFILL }},
    { &hf_mqtt_retain,
      { "Retain", "mqtt.retain",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQTT_MASK_RETAIN,
        NULL, HFILL }},
    /* Conn-Ack */
    { &hf_mqtt_conack_reserved,
      { "Reserved", "mqtt.conack.flags.reserved",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0,
        NULL, HFILL }},
    { &hf_mqtt_conack_flags,
      { "Acknowledge Flags", "mqtt.conack.flags",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_conackflag_reserved,
      { "Reserved", "mqtt.conack.flags.reserved",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQTT_CONACKMASK_RESERVED,
        NULL, HFILL }},
    { &hf_mqtt_conackflag_sp,
      { "Session Present", "mqtt.conack.flags.sp",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQTT_CONACKMASK_SP,
        "Session Present (version 3.1.1)", HFILL }},
    { &hf_mqtt_conack_code,
      { "Return Code", "mqtt.conack.val",
        FT_UINT8, BASE_DEC, VALS(mqtt_conack_vals), 0,
        NULL, HFILL }},
    /* Publish-Ack / Publish-Rec / Publish-Rel / Publish-Comp / Unsubscribe-Ack */
    { &hf_mqtt_msgid,
      { "Message Identifier", "mqtt.msgid",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_sub_qos,
      { "Requested QoS", "mqtt.sub.qos",
        FT_UINT8, BASE_DEC, VALS(mqtt_qos_vals), 0,
        NULL, HFILL }},
    { &hf_mqtt_suback_qos,
      { "Granted QoS", "mqtt.suback.qos",
        FT_UINT8, BASE_DEC, VALS(mqtt_subqos_vals), 0,
        NULL, HFILL }},
      { &hf_mqtt_topic_len,
      { "Topic Length", "mqtt.topic_len",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_topic,
      { "Topic", "mqtt.topic",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_will_topic_len,
      { "Will Topic Length", "mqtt.willtopic_len",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_will_topic,
      { "Will Topic", "mqtt.willtopic",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_will_msg,
      { "Will Message", "mqtt.willmsg",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_will_msg_len,
      { "Will Message Length", "mqtt.willmsg_len",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_username_len,
      { "User Name Length", "mqtt.username_len",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_username,
      { "User Name", "mqtt.username",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_passwd_len,
      { "Password Length", "mqtt.passwd_len",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_passwd,
      { "Password", "mqtt.passwd",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_pubmsg,
      { "Message", "mqtt.msg",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_pubmsg_decoded,
      { "Message decoded as", "mqtt.msg_decoded_as",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_proto_len,
      { "Protocol Name Length", "mqtt.proto_len",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_proto_name,
      { "Protocol Name", "mqtt.protoname",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_client_id_len,
      { "Client ID Length", "mqtt.clientid_len",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_client_id,
      { "Client ID", "mqtt.clientid",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_proto_ver,
      { "Version", "mqtt.ver",
        FT_UINT8, BASE_DEC, VALS(mqtt_protocol_version_vals), 0,
        "MQTT version", HFILL }},
    /* Connect Flags */
    { &hf_mqtt_conflags,
      { "Connect Flags", "mqtt.conflags",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_conflag_user,
      { "User Name Flag", "mqtt.conflag.uname",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQTT_CONMASK_USER,
        NULL, HFILL }},
    { &hf_mqtt_conflag_passwd,
      { "Password Flag", "mqtt.conflag.passwd",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQTT_CONMASK_PASSWD,
        NULL, HFILL }},
    { &hf_mqtt_conflag_will_retain,
      { "Will Retain", "mqtt.conflag.retain",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQTT_CONMASK_RETAIN,
        NULL, HFILL }},
    { &hf_mqtt_conflag_will_qos,
      { "QoS Level", "mqtt.conflag.qos",
        FT_UINT8, BASE_DEC, VALS(mqtt_qos_vals), MQTT_CONMASK_QOS,
        NULL, HFILL }},
    { &hf_mqtt_conflag_will_flag,
      { "Will Flag", "mqtt.conflag.willflag",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQTT_CONMASK_WILLFLAG,
        NULL, HFILL }},
    { &hf_mqtt_conflag_clean_sess,
      { "Clean Session Flag", "mqtt.conflag.cleansess",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQTT_CONMASK_CLEANSESS,
        NULL, HFILL }},
    { &hf_mqtt_conflag_reserved,
      { "(Reserved)", "mqtt.conflag.reserved",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQTT_CONMASK_RESERVED,
        NULL, HFILL }},
    { &hf_mqtt_keep_alive,
      { "Keep Alive", "mqtt.kalive",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    /* xxx */
    { &hf_mqtt_subscription_options,
      { "Subscription Options", "mqtt.subscription_options",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_reason_code,
      { "Reason Code", "mqtt.reason_code",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_property_len,
      { "Property Length", "mqtt.property_len",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_property,
      { "Property", "mqtt.property",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* Setup protocol subtree arrays */
  static gint* ett_mqtt[] = {
    &ett_mqtt_hdr,
    &ett_mqtt_msg,
    &ett_mqtt_hdr_flags,
    &ett_mqtt_con_flags,
    &ett_mqtt_conack_flags
  };

  static uat_field_t mqtt_message_decode_flds[] = {
    UAT_FLD_VS(message_decode, match_criteria, "Match criteria", match_criteria, "Match criteria"),
    UAT_FLD_CSTRING(message_decode, topic_pattern, "Topic pattern", "Pattern to match for the topic"),
    UAT_FLD_PROTO(message_decode, payload_proto, "Payload protocol",
                  "Protocol to be used for the message part of the matching topic"),
    UAT_END_FIELDS
  };

  uat_t *message_uat = uat_new("Message Decoding",
                               sizeof(mqtt_message_decode_t),
                               "mqtt_message_decoding",
                               TRUE,
                               &mqtt_message_decodes,
                               &num_mqtt_message_decodes,
                               UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
                               "ChMQTTMessageDecoding",
                               mqtt_message_decode_copy_cb,
                               mqtt_message_decode_update_cb,
                               mqtt_message_decode_free_cb,
                               NULL,
                               NULL,
                               mqtt_message_decode_flds);

  module_t *mqtt_module;

  /* Register protocol names and descriptions */
  proto_mqtt = proto_register_protocol("MQ Telemetry Transport Protocol", "MQTT", "mqtt");

  /* Register the dissector */
  mqtt_handle = register_dissector("mqtt", dissect_mqtt_data, proto_mqtt);

  proto_register_field_array(proto_mqtt, hf_mqtt, array_length(hf_mqtt));
  proto_register_subtree_array(ett_mqtt, array_length(ett_mqtt));

  mqtt_module = prefs_register_protocol(proto_mqtt, NULL);

  prefs_register_uat_preference(mqtt_module, "message_decode_table",
                                "Message Decoding",
                                "A table that enumerates custom message decodes to be used for a certain topic",
                                message_uat);
}

/*
 *  Dissector Handoff
 */
void proto_reg_handoff_mqtt(void)
{
  dissector_add_uint_with_preference("tcp.port", MQTT_DEFAULT_PORT, mqtt_handle);
  ssl_dissector_add(MQTT_SSL_DEFAULT_PORT, mqtt_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
