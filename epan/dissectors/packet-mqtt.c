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
 * SPDX-License-Identifier: GPL-2.0-or-later
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
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/uat.h>
#include "packet-tcp.h"
#include "packet-tls.h"

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

/* MQTT v5.0 Flag Values for the Subscription Options @ Subscribe Packet */
#define MQTT_MASK_SUBS_QOS          0x03
#define MQTT_MASK_SUBS_NL           0x04
#define MQTT_MASK_SUBS_RAP          0x08
#define MQTT_MASK_SUBS_RETAIN       0x30
#define MQTT_MASK_SUBS_RESERVED     0xC0

void proto_register_mqtt(void);
void proto_reg_handoff_mqtt(void);

static dissector_table_t media_type_dissector_table;

static const value_string mqtt_protocol_version_vals[] = {
  { MQTT_PROTO_V31,        "MQTT v3.1" },
  { MQTT_PROTO_V311,       "MQTT v3.1.1" },
  { MQTT_PROTO_V50,        "MQTT v5.0" },
  { 0,                     NULL }
};

static const enum_val_t mqtt_protocol_version_enumvals[] = {
    { "none",  "None",         0 },
    { "v31",   "MQTT v3.1",    MQTT_PROTO_V31 },
    { "v311",  "MQTT v3.1.1",  MQTT_PROTO_V311 },
    { "v50",   "MQTT v5.0",    MQTT_PROTO_V50 },
    { NULL,    NULL,           0 }
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
    wmem_map_t *topic_alias_map;
} mqtt_conv_t;

typedef struct _mqtt_message_decode_t {
  guint   match_criteria;
  char   *topic_pattern;
  GRegex *topic_regex;
  guint   msg_decoding;
  char   *payload_proto_name;
  dissector_handle_t payload_proto;
} mqtt_message_decode_t;

typedef struct _mqtt_properties_t {
  const guint8 *content_type;
  guint32       topic_alias;
} mqtt_properties_t;

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

#define MSG_DECODING_NONE        0
#define MSG_DECODING_COMPRESSED  1

static const value_string msg_decoding[] = {
  { MSG_DECODING_NONE,       "none" },
  { MSG_DECODING_COMPRESSED, "compressed" },
  { 0, NULL }
};

#define PROP_PAYLOAD_FORMAT_INDICATOR          0x01
#define PROP_PUBLICATION_EXPIRY_INTERVAL       0x02
#define PROP_CONTENT_TYPE                      0x03
#define PROP_RESPONSE_TOPIC                    0x08
#define PROP_CORRELATION_DATA                  0x09
#define PROP_SUBSCRIPTION_IDENTIFIER           0x0B
#define PROP_SESSION_EXPIRY_INTERVAL           0x11
#define PROP_ASSIGNED_CLIENT_IDENTIFIER        0x12
#define PROP_SERVER_KEEP_ALIVE                 0x13
#define PROP_AUTH_METHOD                       0x15
#define PROP_AUTH_DATA                         0x16
#define PROP_REQUEST_PROBLEM_INFORMATION       0x17
#define PROP_WILL_DELAY_INTERVAL               0x18
#define PROP_REQUEST_RESPONSE_INFORMATION      0x19
#define PROP_RESPONSE_INFORMATION              0x1A
#define PROP_SERVER_REFERENCE                  0x1C
#define PROP_REASON_STRING                     0x1F
#define PROP_RECEIVE_MAXIMUM                   0x21
#define PROP_TOPIC_ALIAS_MAXIMUM               0x22
#define PROP_TOPIC_ALIAS                       0x23
#define PROP_MAXIMUM_QOS                       0x24
#define PROP_RETAIN_AVAILABLE                  0x25
#define PROP_USER_PROPERTY                     0x26
#define PROP_MAXIMUM_PACKET_SIZE               0x27
#define PROP_WILDCARD_SUBSCRIPTION_AVAILABLE   0x28
#define PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE 0x29
#define PROP_SHARED_SUBSCRIPTION_AVAILABLE     0x2A

static const value_string mqtt_property_vals[] = {
  { PROP_PAYLOAD_FORMAT_INDICATOR,          "Payload Format Indicator" },
  { PROP_PUBLICATION_EXPIRY_INTERVAL,       "Publication Expiry Interval" },
  { PROP_CONTENT_TYPE,                      "Content Type" },
  { PROP_RESPONSE_TOPIC,                    "Response Topic" },
  { PROP_CORRELATION_DATA,                  "Correlation Data" },
  { PROP_SUBSCRIPTION_IDENTIFIER,           "Subscription Identifier" },
  { PROP_SESSION_EXPIRY_INTERVAL,           "Session Expiry Interval" },
  { PROP_ASSIGNED_CLIENT_IDENTIFIER,        "Assigned Client Identifier" },
  { PROP_SERVER_KEEP_ALIVE,                 "Server Keep Alive" },
  { PROP_AUTH_METHOD,                       "Authentication Method" },
  { PROP_AUTH_DATA,                         "Authentication Data" },
  { PROP_REQUEST_PROBLEM_INFORMATION,       "Request Problem Information" },
  { PROP_WILL_DELAY_INTERVAL,               "Will Delay Interval" },
  { PROP_REQUEST_RESPONSE_INFORMATION,      "Request Response Information" },
  { PROP_RESPONSE_INFORMATION,              "Response Information" },
  { PROP_SERVER_REFERENCE,                  "Server Reference" },
  { PROP_REASON_STRING,                     "Reason String" },
  { PROP_RECEIVE_MAXIMUM,                   "Receive Maximum" },
  { PROP_TOPIC_ALIAS_MAXIMUM,               "Topic Alias Maximum" },
  { PROP_TOPIC_ALIAS,                       "Topic Alias" },
  { PROP_MAXIMUM_QOS,                       "Maximum QoS" },
  { PROP_RETAIN_AVAILABLE,                  "Retain Available" },
  { PROP_USER_PROPERTY,                     "User Property" },
  { PROP_MAXIMUM_PACKET_SIZE,               "Maximum Packet Size" },
  { PROP_WILDCARD_SUBSCRIPTION_AVAILABLE,   "Wildcard Subscription Available" },
  { PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE, "Subscription Identifier Available" },
  { PROP_SHARED_SUBSCRIPTION_AVAILABLE,     "Shared Subscription Available" },
  { 0, NULL }
};

/* MQTT v5.0 Subscription Options, Retain Handling option */
#define SUBSCRIPTION_RETAIN_SEND            0x00
#define SUBSCRIPTION_RETAIN_SEND_DONT_EXIST 0x01
#define SUBSCRIPTION_RETAIN_DONT_SEND       0x02
#define SUBSCRIPTION_RETAIN_RESERVED        0x03

static const value_string mqtt_subscription_retain_handling[] = {
  { SUBSCRIPTION_RETAIN_SEND,            "Send msgs at subscription time" },
  { SUBSCRIPTION_RETAIN_SEND_DONT_EXIST, "Send msgs if subscription does not exist" },
  { SUBSCRIPTION_RETAIN_DONT_SEND,       "Do not send msgs at subscription time" },
  { SUBSCRIPTION_RETAIN_RESERVED,        "Reserved" },
  { 0, NULL }
};

/* MQTT v5.0 Reason Codes */
#define RC_SUCCESS                                0x00
#define RC_NORMAL_DISCONNECTION                   0x00
#define RC_GRANTED_QOS0                           0x00
#define RC_GRANTED_QOS1                           0x01
#define RC_GRANTED_QOS2                           0x02
#define RC_DISCONNECT_WILL                        0x04
#define RC_NO_MATCHING_SUBSCRIBERS                0x10
#define RC_NO_SUBSCRIPTION_EXISTED                0x11
#define RC_CONTINUE_AUTHENTICATION                0x18
#define RC_RE_AUTHENTICATE                        0x19
#define RC_UNSPECIFIED_ERROR                      0x80
#define RC_MALFORMED_PACKET                       0x81
#define RC_PROTOCOL_ERROR                         0x82
#define RC_IMPLEMENTATION_SPECIFIC_ERROR          0x83
#define RC_UNSUPPORTED_PROTOCOL_VERSION           0x84
#define RC_CLIENT_IDENTIFIER_NOT_VALID            0x85
#define RC_BAD_USER_NAME_OR_PASSWORD              0x86
#define RC_NOT_AUTHORIZED                         0x87
#define RC_SERVER_UNAVAILABLE                     0x88
#define RC_SERVER_BUSY                            0x89
#define RC_BANNED                                 0x8A
#define RC_SERVER_SHUTTING_DOWN                   0x8B
#define RC_BAD_AUTHENTICATION_METHOD              0x8C
#define RC_KEEP_ALIVE_TIMEOUT                     0x8D
#define RC_SESSION_TAKEN_OVER                     0x8E
#define RC_TOPIC_FILTER_INVALID                   0x8F
#define RC_TOPIC_NAME_INVALID                     0x90
#define RC_PACKET_IDENTIFIER_IN_USE               0x91
#define RC_PACKET_IDENTIFIER_NOT_FOUND            0x92
#define RC_RECEIVE_MAXIMUM_EXCEEDED               0x93
#define RC_TOPIC_ALIAS_INVALID                    0x94
#define RC_PACKET_TOO_LARGE                       0x95
#define RC_MESSAGE_RATE_TOO_HIGH                  0x96
#define RC_QUOTA_EXCEEDED                         0x97
#define RC_ADMINISTRATIVE_ACTION                  0x98
#define RC_PAYLOAD_FORMAT_INVALID                 0x99
#define RC_RETAIN_NOT_SUPPORTED                   0x9A
#define RC_QOS_NOT_SUPPORTED                      0x9B
#define RC_USE_ANOTHER_SERVER                     0x9C
#define RC_SERVER_MOVED                           0x9D
#define RC_SHARED_SUBSCRIPTION_NOT_SUPPORTED      0x9E
#define RC_CONNECTION_RATE_EXCEEDED               0x9F
#define RC_MAXIMUM_CONNECT_TIME                   0xA0
#define RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED 0xA1
#define RC_WILDCARD_SUBSCRIPTION_NOT_SUPPORTED    0xA2

#define RC_SUCCESS_STR                                "Success"
#define RC_NORMAL_DISCONNECTION_STR                   "Normal disconnection"
#define RC_GRANTED_QOS0_STR                           "Granted QoS 0"
#define RC_GRANTED_QOS1_STR                           "Granted QoS 1"
#define RC_GRANTED_QOS2_STR                           "Granted QoS 2"
#define RC_DISCONNECT_WILL_STR                        "Disconnect with Will Message"
#define RC_NO_MATCHING_SUBSCRIBERS_STR                "No matching subscribers"
#define RC_NO_SUBSCRIPTION_EXISTED_STR                "No subscription existed"
#define RC_CONTINUE_AUTHENTICATION_STR                "Continue authentication"
#define RC_RE_AUTHENTICATE_STR                        "Re-authenticate"
#define RC_UNSPECIFIED_ERROR_STR                      "Unspecified error"
#define RC_MALFORMED_PACKET_STR                       "Malformed Packet"
#define RC_PROTOCOL_ERROR_STR                         "Protocol Error"
#define RC_IMPLEMENTATION_SPECIFIC_ERROR_STR          "Implementation specific error"
#define RC_UNSUPPORTED_PROTOCOL_VERSION_STR           "Unsupported Protocol Version"
#define RC_CLIENT_IDENTIFIER_NOT_VALID_STR            "Client Identifier not valid"
#define RC_BAD_USER_NAME_OR_PASSWORD_STR              "Bad User Name or Password"
#define RC_NOT_AUTHORIZED_STR                         "Not authorized"
#define RC_SERVER_UNAVAILABLE_STR                     "Server unavailable"
#define RC_SERVER_BUSY_STR                            "Server busy"
#define RC_BANNED_STR                                 "Banned"
#define RC_SERVER_SHUTTING_DOWN_STR                   "Server shutting down"
#define RC_BAD_AUTHENTICATION_METHOD_STR              "Bad authentication method"
#define RC_KEEP_ALIVE_TIMEOUT_STR                     "Keep Alive timeout"
#define RC_SESSION_TAKEN_OVER_STR                     "Session taken over"
#define RC_TOPIC_FILTER_INVALID_STR                   "Topic Filter invalid"
#define RC_TOPIC_NAME_INVALID_STR                     "Topic Name invalid"
#define RC_PACKET_IDENTIFIER_IN_USE_STR               "Packet Identifier in use"
#define RC_PACKET_IDENTIFIER_NOT_FOUND_STR            "Packet Identifier not found"
#define RC_RECEIVE_MAXIMUM_EXCEEDED_STR               "Receive Maximum exceeded"
#define RC_TOPIC_ALIAS_INVALID_STR                    "Topic Alias invalid"
#define RC_PACKET_TOO_LARGE_STR                       "Packet too large"
#define RC_MESSAGE_RATE_TOO_HIGH_STR                  "Message rate too high"
#define RC_QUOTA_EXCEEDED_STR                         "Quota exceeded"
#define RC_ADMINISTRATIVE_ACTION_STR                  "Administrative action"
#define RC_PAYLOAD_FORMAT_INVALID_STR                 "Payload format invalid"
#define RC_RETAIN_NOT_SUPPORTED_STR                   "Retain not supported"
#define RC_QOS_NOT_SUPPORTED_STR                      "QoS not supported"
#define RC_USE_ANOTHER_SERVER_STR                     "Use another server"
#define RC_SERVER_MOVED_STR                           "Server moved"
#define RC_SHARED_SUBSCRIPTION_NOT_SUPPORTED_STR      "Shared Subscription not supported"
#define RC_CONNECTION_RATE_EXCEEDED_STR               "Connection rate exceeded"
#define RC_MAXIMUM_CONNECT_TIME_STR                   "Maximum connect time"
#define RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED_STR "Subscription Identifiers not supported"
#define RC_WILDCARD_SUBSCRIPTION_NOT_SUPPORTED_STR    "Wildcard Subscription not supported"

static const value_string mqtt_reason_code_connack_vals[] = {
  { RC_SUCCESS,                                RC_SUCCESS_STR },
  { RC_UNSPECIFIED_ERROR,                      RC_UNSPECIFIED_ERROR_STR },
  { RC_MALFORMED_PACKET,                       RC_MALFORMED_PACKET_STR },
  { RC_PROTOCOL_ERROR,                         RC_PROTOCOL_ERROR_STR },
  { RC_IMPLEMENTATION_SPECIFIC_ERROR,          RC_IMPLEMENTATION_SPECIFIC_ERROR_STR },
  { RC_UNSUPPORTED_PROTOCOL_VERSION,           RC_UNSUPPORTED_PROTOCOL_VERSION_STR },
  { RC_CLIENT_IDENTIFIER_NOT_VALID,            RC_CLIENT_IDENTIFIER_NOT_VALID_STR },
  { RC_BAD_USER_NAME_OR_PASSWORD,              RC_BAD_USER_NAME_OR_PASSWORD_STR },
  { RC_NOT_AUTHORIZED,                         RC_NOT_AUTHORIZED_STR },
  { RC_SERVER_UNAVAILABLE,                     RC_SERVER_UNAVAILABLE_STR },
  { RC_SERVER_BUSY,                            RC_SERVER_BUSY_STR },
  { RC_BANNED,                                 RC_BANNED_STR },
  { RC_BAD_AUTHENTICATION_METHOD,              RC_BAD_AUTHENTICATION_METHOD_STR },
  { RC_TOPIC_NAME_INVALID,                     RC_TOPIC_NAME_INVALID_STR },
  { RC_PACKET_TOO_LARGE,                       RC_PACKET_TOO_LARGE_STR },
  { RC_QUOTA_EXCEEDED,                         RC_QUOTA_EXCEEDED_STR },
  { RC_RETAIN_NOT_SUPPORTED,                   RC_RETAIN_NOT_SUPPORTED_STR },
  { RC_QOS_NOT_SUPPORTED,                      RC_QOS_NOT_SUPPORTED_STR },
  { RC_USE_ANOTHER_SERVER,                     RC_USE_ANOTHER_SERVER_STR },
  { RC_SERVER_MOVED,                           RC_SERVER_MOVED_STR },
  { RC_CONNECTION_RATE_EXCEEDED,               RC_CONNECTION_RATE_EXCEEDED_STR },
  { 0, NULL }
};

static const value_string mqtt_reason_code_puback_vals[] = {
  { RC_SUCCESS,                                RC_SUCCESS_STR },
  { RC_NO_MATCHING_SUBSCRIBERS,                RC_NO_MATCHING_SUBSCRIBERS_STR },
  { RC_UNSPECIFIED_ERROR,                      RC_UNSPECIFIED_ERROR_STR },
  { RC_IMPLEMENTATION_SPECIFIC_ERROR,          RC_IMPLEMENTATION_SPECIFIC_ERROR_STR },
  { RC_NOT_AUTHORIZED,                         RC_NOT_AUTHORIZED_STR },
  { RC_TOPIC_NAME_INVALID,                     RC_TOPIC_NAME_INVALID_STR },
  { RC_PACKET_IDENTIFIER_IN_USE,               RC_PACKET_IDENTIFIER_IN_USE_STR },
  { RC_QUOTA_EXCEEDED,                         RC_QUOTA_EXCEEDED_STR },
  { RC_PAYLOAD_FORMAT_INVALID,                 RC_PAYLOAD_FORMAT_INVALID_STR },
  { 0, NULL }
};

static const value_string mqtt_reason_code_pubrel_vals[] = {
  { RC_SUCCESS,                                RC_SUCCESS_STR },
  { RC_PACKET_IDENTIFIER_NOT_FOUND,            RC_PACKET_IDENTIFIER_NOT_FOUND_STR },
  { 0, NULL }
};

static const value_string mqtt_reason_code_suback_vals[] = {
  { RC_GRANTED_QOS0,                           RC_GRANTED_QOS0_STR },
  { RC_GRANTED_QOS1,                           RC_GRANTED_QOS1_STR },
  { RC_GRANTED_QOS2,                           RC_GRANTED_QOS2_STR },
  { RC_UNSPECIFIED_ERROR,                      RC_UNSPECIFIED_ERROR_STR },
  { RC_IMPLEMENTATION_SPECIFIC_ERROR,          RC_IMPLEMENTATION_SPECIFIC_ERROR_STR },
  { RC_NOT_AUTHORIZED,                         RC_NOT_AUTHORIZED_STR },
  { RC_TOPIC_FILTER_INVALID,                   RC_TOPIC_FILTER_INVALID_STR },
  { RC_PACKET_IDENTIFIER_IN_USE,               RC_PACKET_IDENTIFIER_IN_USE_STR },
  { RC_QUOTA_EXCEEDED,                         RC_QUOTA_EXCEEDED_STR },
  { RC_SHARED_SUBSCRIPTION_NOT_SUPPORTED,      RC_SHARED_SUBSCRIPTION_NOT_SUPPORTED_STR },
  { RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED, RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED_STR },
  { RC_WILDCARD_SUBSCRIPTION_NOT_SUPPORTED,    RC_WILDCARD_SUBSCRIPTION_NOT_SUPPORTED_STR },
  { 0, NULL }
};

static const value_string mqtt_reason_code_unsuback_vals[] = {
  { RC_SUCCESS,                                RC_SUCCESS_STR },
  { RC_NO_SUBSCRIPTION_EXISTED,                RC_NO_SUBSCRIPTION_EXISTED_STR },
  { RC_IMPLEMENTATION_SPECIFIC_ERROR,          RC_IMPLEMENTATION_SPECIFIC_ERROR_STR },
  { RC_NOT_AUTHORIZED,                         RC_NOT_AUTHORIZED_STR },
  { RC_TOPIC_FILTER_INVALID,                   RC_TOPIC_FILTER_INVALID_STR },
  { RC_PACKET_IDENTIFIER_IN_USE,               RC_PACKET_IDENTIFIER_IN_USE_STR },
  { 0, NULL }
};

static const value_string mqtt_reason_code_disconnect_vals[] = {
  { RC_NORMAL_DISCONNECTION,                   RC_NORMAL_DISCONNECTION_STR },
  { RC_DISCONNECT_WILL,                        RC_DISCONNECT_WILL_STR },
  { RC_UNSPECIFIED_ERROR,                      RC_UNSPECIFIED_ERROR_STR },
  { RC_MALFORMED_PACKET,                       RC_MALFORMED_PACKET_STR },
  { RC_PROTOCOL_ERROR,                         RC_PROTOCOL_ERROR_STR },
  { RC_IMPLEMENTATION_SPECIFIC_ERROR,          RC_IMPLEMENTATION_SPECIFIC_ERROR_STR },
  { RC_NOT_AUTHORIZED,                         RC_NOT_AUTHORIZED_STR },
  { RC_SERVER_BUSY,                            RC_SERVER_BUSY_STR },
  { RC_SERVER_SHUTTING_DOWN,                   RC_SERVER_SHUTTING_DOWN_STR },
  /* Bad authentication method: check Table 2.6 and Table 3.13 */
  { RC_BAD_AUTHENTICATION_METHOD,              RC_BAD_AUTHENTICATION_METHOD_STR },
  { RC_KEEP_ALIVE_TIMEOUT,                     RC_KEEP_ALIVE_TIMEOUT_STR },
  { RC_SESSION_TAKEN_OVER,                     RC_SESSION_TAKEN_OVER_STR },
  { RC_TOPIC_FILTER_INVALID,                   RC_TOPIC_FILTER_INVALID_STR },
  { RC_TOPIC_NAME_INVALID,                     RC_TOPIC_NAME_INVALID_STR },
  { RC_RECEIVE_MAXIMUM_EXCEEDED,               RC_RECEIVE_MAXIMUM_EXCEEDED_STR },
  { RC_TOPIC_ALIAS_INVALID,                    RC_TOPIC_ALIAS_INVALID_STR },
  { RC_PACKET_TOO_LARGE,                       RC_PACKET_TOO_LARGE_STR },
  { RC_MESSAGE_RATE_TOO_HIGH,                  RC_MESSAGE_RATE_TOO_HIGH_STR },
  { RC_QUOTA_EXCEEDED,                         RC_QUOTA_EXCEEDED_STR },
  { RC_ADMINISTRATIVE_ACTION,                  RC_ADMINISTRATIVE_ACTION_STR },
  { RC_PAYLOAD_FORMAT_INVALID,                 RC_PAYLOAD_FORMAT_INVALID_STR },
  { RC_RETAIN_NOT_SUPPORTED,                   RC_RETAIN_NOT_SUPPORTED_STR },
  { RC_QOS_NOT_SUPPORTED,                      RC_QOS_NOT_SUPPORTED_STR },
  { RC_USE_ANOTHER_SERVER,                     RC_USE_ANOTHER_SERVER_STR },
  { RC_SERVER_MOVED,                           RC_SERVER_MOVED_STR },
  { RC_SHARED_SUBSCRIPTION_NOT_SUPPORTED,      RC_SHARED_SUBSCRIPTION_NOT_SUPPORTED_STR },
  { RC_CONNECTION_RATE_EXCEEDED,               RC_CONNECTION_RATE_EXCEEDED_STR },
  { RC_MAXIMUM_CONNECT_TIME,                   RC_MAXIMUM_CONNECT_TIME_STR },
  { RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED, RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED_STR },
  { RC_WILDCARD_SUBSCRIPTION_NOT_SUPPORTED,    RC_WILDCARD_SUBSCRIPTION_NOT_SUPPORTED_STR },
  { 0, NULL }
};

static const value_string mqtt_reason_code_auth_vals[] = {
  { RC_SUCCESS,                                RC_SUCCESS_STR },
  { RC_CONTINUE_AUTHENTICATION,                RC_CONTINUE_AUTHENTICATION_STR },
  { RC_RE_AUTHENTICATE,                        RC_RE_AUTHENTICATE_STR },
  { 0, NULL }
};

static mqtt_message_decode_t *mqtt_message_decodes;
static guint num_mqtt_message_decodes;
static gint default_protocol_version;

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
static int hf_mqtt_will_msg_text = -1;
static int hf_mqtt_username_len = -1;
static int hf_mqtt_username = -1;
static int hf_mqtt_passwd_len = -1;
static int hf_mqtt_passwd = -1;
static int hf_mqtt_pubmsg = -1;
static int hf_mqtt_pubmsg_text = -1;
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

/* MQTT v5.0 Reason Codes */
static int hf_mqtt_reason_code_connack = -1;
static int hf_mqtt_reason_code_puback = -1;
static int hf_mqtt_reason_code_pubrec = -1;
static int hf_mqtt_reason_code_pubrel = -1;
static int hf_mqtt_reason_code_pubcomp = -1;
static int hf_mqtt_reason_code_suback = -1;
static int hf_mqtt_reason_code_unsuback = -1;
static int hf_mqtt_reason_code_disconnect = -1;
static int hf_mqtt_reason_code_auth = -1;

/* MQTT v5.0 Subscribe Options */
static int hf_mqtt_subscription_qos = -1;
static int hf_mqtt_subscription_nl = -1;
static int hf_mqtt_subscription_rap = -1;
static int hf_mqtt_subscription_retain = -1;
static int hf_mqtt_subscription_reserved = -1;

/* MQTT v5.0 Properties */
static int hf_mqtt_property_len = -1;
static int hf_mqtt_property = -1;
static int hf_mqtt_will_property = -1;
static int hf_mqtt_property_id = -1;
static int hf_mqtt_prop_num = -1;
static int hf_mqtt_prop_content_type = -1;
static int hf_mqtt_prop_max_qos = -1;
static int hf_mqtt_prop_topic_alias = -1;
static int hf_mqtt_prop_unknown = -1;
static int hf_mqtt_prop_string_len = -1;
static int hf_mqtt_prop_string = -1;
static int hf_mqtt_prop_key_len = -1;
static int hf_mqtt_prop_key = -1;
static int hf_mqtt_prop_value_len = -1;
static int hf_mqtt_prop_value = -1;

/* Initialize the subtree pointers */
static gint ett_mqtt_hdr = -1;
static gint ett_mqtt_msg = -1;
static gint ett_mqtt_hdr_flags = -1;
static gint ett_mqtt_con_flags = -1;
static gint ett_mqtt_conack_flags = -1;
static gint ett_mqtt_property = -1;
static gint ett_mqtt_subscription_flags = -1;

/* Initialize the expert fields */
static expert_field ei_illegal_length = EI_INIT;
static expert_field ei_unknown_version = EI_INIT;
static expert_field ei_unknown_topic_alias = EI_INIT;

/* Reassemble SMPP TCP segments */
static gboolean reassemble_mqtt_over_tcp = TRUE;

/* Show Publish Message as text */
static gboolean show_msg_as_text;

static guint get_mqtt_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                              int offset, void *data _U_)
{
  guint64 msg_len;
  guint len_offset;

  len_offset = tvb_get_varint(tvb, (offset + MQTT_HDR_SIZE_BEFORE_LEN), FT_VARINT_MAX_LEN, &msg_len, ENC_VARINT_PROTOBUF);

  /* Explicitly downcast the value, because the length can never be more than 4 bytes */
  return (guint)(msg_len + len_offset + MQTT_HDR_SIZE_BEFORE_LEN);
}

static void *mqtt_message_decode_copy_cb(void *dest, const void *orig, size_t len _U_)
{
  const mqtt_message_decode_t *o = (const mqtt_message_decode_t *)orig;
  mqtt_message_decode_t *d = (mqtt_message_decode_t *)dest;

  d->match_criteria = o->match_criteria;
  d->topic_pattern = g_strdup(o->topic_pattern);
  d->msg_decoding = o->msg_decoding;
  d->payload_proto_name = g_strdup(o->payload_proto_name);
  d->payload_proto = o->payload_proto;

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

  if (u->payload_proto_name == NULL || strlen(u->payload_proto_name) == 0)
  {
    *error = g_strdup("Missing payload protocol");
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
UAT_VS_DEF(message_decode, msg_decoding, mqtt_message_decode_t, guint, MSG_DECODING_NONE, "none")
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
          /* DISSECTOR_ASSERT(g_utf8_validate(topic_str, -1, NULL)); */
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
    if (message_decode_entry->msg_decoding == MSG_DECODING_COMPRESSED)
    {
      msg_tvb = tvb_child_uncompress(msg_tvb, msg_tvb, 0, tvb_reported_length(msg_tvb));
      if (msg_tvb)
      {
        add_new_data_source(pinfo, msg_tvb, "Uncompressed Message");
      }
    }

    if (msg_tvb)
    {
      proto_item *ti = proto_tree_add_string(mqtt_tree, hf_mqtt_pubmsg_decoded, msg_tvb, 0, -1,
                                             message_decode_entry->payload_proto_name);
      proto_item_set_generated(ti);

      call_dissector(message_decode_entry->payload_proto, msg_tvb, pinfo, tree);
    }
  }
}

static guint dissect_string(tvbuff_t *tvb, proto_tree *tree, guint offset, int hf_len, int hf_value)
{
  guint32 prop_len;

  proto_tree_add_item_ret_uint(tree, hf_len, tvb, offset, 2, ENC_BIG_ENDIAN, &prop_len);
  proto_tree_add_item(tree, hf_value, tvb, offset + 2, prop_len, ENC_UTF_8|ENC_NA);

  return 2 + prop_len;
}

/* MQTT v5.0: Reason Codes */
static void dissect_mqtt_reason_code(proto_tree *mqtt_tree, tvbuff_t *tvb, guint offset, guint8 mqtt_msg_type)
{
  static int * const hf_rcode[] = {
    NULL, /* RESERVED */
    NULL, /* CONNECT */
    &hf_mqtt_reason_code_connack,
    NULL, /* PUBLISH */
    &hf_mqtt_reason_code_puback,
    &hf_mqtt_reason_code_pubrec,
    &hf_mqtt_reason_code_pubrel,
    &hf_mqtt_reason_code_pubcomp,
    NULL, /* SUBSCRIBE */
    &hf_mqtt_reason_code_suback,
    NULL, /* UNSUBSCRIBE */
    &hf_mqtt_reason_code_unsuback,
    NULL, /* PINGREQ */
    NULL, /* PINGRESP */
    &hf_mqtt_reason_code_disconnect,
    &hf_mqtt_reason_code_auth
  };

  if (mqtt_msg_type < (sizeof hf_rcode / sizeof hf_rcode[0]))
  {
    const int *hfindex = hf_rcode[mqtt_msg_type];
    if (hfindex)
    {
      proto_tree_add_item(mqtt_tree, *hfindex, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
  }
}

/* MQTT v5.0: dissect the MQTT properties */
static guint dissect_mqtt_properties(tvbuff_t *tvb, proto_tree *mqtt_tree, guint offset, int hf_property, mqtt_properties_t *mqtt_properties)
{
  proto_tree *mqtt_prop_tree;
  proto_item *ti;
  guint64 vbi;

  const guint mqtt_prop_offset = tvb_get_varint(tvb, offset, FT_VARINT_MAX_LEN, &vbi, ENC_VARINT_PROTOBUF);
  /* Property Length field can be stored in uint32 */
  const guint mqtt_prop_len = (gint)vbi;

  /* Add the MQTT branch to the main tree */
  /* hf_property is usually hf_mqtt_property, but can also be
   * hf_mqtt_will_property when a Will is provided in a CONNECT packet */
  ti = proto_tree_add_item(mqtt_tree, hf_property, tvb, offset, mqtt_prop_offset + mqtt_prop_len, ENC_NA);
  mqtt_prop_tree = proto_item_add_subtree(ti, ett_mqtt_property);

  proto_tree_add_item(mqtt_prop_tree, hf_mqtt_property_len, tvb, offset, mqtt_prop_offset, ENC_BIG_ENDIAN);
  offset += mqtt_prop_offset;

  const guint bytes_to_read = offset + mqtt_prop_len;
  while (offset < bytes_to_read)
  {
    guint32 prop_id;
    proto_tree_add_item_ret_uint(mqtt_prop_tree, hf_mqtt_property_id, tvb, offset, 1, ENC_BIG_ENDIAN, &prop_id);
    offset += 1;

    switch (prop_id)
    {
      case PROP_PAYLOAD_FORMAT_INDICATOR:
      case PROP_REQUEST_PROBLEM_INFORMATION:
      case PROP_REQUEST_RESPONSE_INFORMATION:
      case PROP_RETAIN_AVAILABLE:
      case PROP_WILDCARD_SUBSCRIPTION_AVAILABLE:
      case PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE:
      case PROP_SHARED_SUBSCRIPTION_AVAILABLE:
        proto_tree_add_item(mqtt_prop_tree, hf_mqtt_prop_num, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;

      case PROP_MAXIMUM_QOS:
        proto_tree_add_item(mqtt_prop_tree, hf_mqtt_prop_max_qos, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;

      case PROP_TOPIC_ALIAS:
        proto_tree_add_item_ret_uint(mqtt_prop_tree, hf_mqtt_prop_topic_alias, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_properties->topic_alias);
        offset += 2;
        break;

      case PROP_SERVER_KEEP_ALIVE:
      case PROP_RECEIVE_MAXIMUM:
      case PROP_TOPIC_ALIAS_MAXIMUM:
        proto_tree_add_item(mqtt_prop_tree, hf_mqtt_prop_num, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        break;

      case PROP_PUBLICATION_EXPIRY_INTERVAL:
      case PROP_SESSION_EXPIRY_INTERVAL:
      case PROP_WILL_DELAY_INTERVAL:
      case PROP_MAXIMUM_PACKET_SIZE:
        proto_tree_add_item(mqtt_prop_tree, hf_mqtt_prop_num, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

      case PROP_SUBSCRIPTION_IDENTIFIER:
      {
        gint vbi_len;
        proto_tree_add_item_ret_length(mqtt_prop_tree, hf_mqtt_prop_num, tvb, offset, -1, ENC_LITTLE_ENDIAN|ENC_VARINT_PROTOBUF, &vbi_len);
        offset += vbi_len;
        break;
      }

      case PROP_CONTENT_TYPE:
      {
        gint length;
        proto_tree_add_item_ret_string_and_length(mqtt_prop_tree, hf_mqtt_prop_content_type, tvb, offset, 2, ENC_UTF_8, wmem_packet_scope(), &mqtt_properties->content_type, &length);
        offset += length;
        break;
      }

      case PROP_RESPONSE_TOPIC:
      case PROP_CORRELATION_DATA:
      case PROP_ASSIGNED_CLIENT_IDENTIFIER:
      case PROP_AUTH_METHOD:
      case PROP_AUTH_DATA:
      case PROP_RESPONSE_INFORMATION:
      case PROP_SERVER_REFERENCE:
      case PROP_REASON_STRING:
        offset += dissect_string(tvb, mqtt_prop_tree, offset, hf_mqtt_prop_string_len, hf_mqtt_prop_string);
        break;

      case PROP_USER_PROPERTY:
        offset += dissect_string(tvb, mqtt_prop_tree, offset, hf_mqtt_prop_key_len, hf_mqtt_prop_key);
        offset += dissect_string(tvb, mqtt_prop_tree, offset, hf_mqtt_prop_value_len, hf_mqtt_prop_value);
        break;

      default:
        proto_tree_add_item(mqtt_prop_tree, hf_mqtt_prop_unknown, tvb, offset, bytes_to_read - offset, ENC_UTF_8|ENC_NA);
        offset += (bytes_to_read - offset);
        break;
    }
  }

  return mqtt_prop_offset + mqtt_prop_len;
}

/* Dissect the MQTT message */
static int dissect_mqtt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  guint8  mqtt_fixed_hdr;
  guint8  mqtt_msg_type;
  proto_item *ti;
  const guint8 *topic_str = "";
  proto_item *mqtt_ti;
  proto_tree *mqtt_tree;
  guint64     mqtt_con_flags;
  guint64     msg_len      = 0;
  gint        mqtt_msg_len = 0;
  guint32     mqtt_str_len;
  guint16     mqtt_len_offset;
  gint        mqtt_payload_len;
  guint32     mqtt_msgid;
  conversation_t *conv;
  mqtt_conv_t *mqtt;
  mqtt_properties_t mqtt_properties = { 0 };
  mqtt_properties_t mqtt_will_properties = { 0 };
  guint       offset = 0;

  static int * const publish_fields[] = {
    &hf_mqtt_msg_type,
    &hf_mqtt_dup_flag,
    &hf_mqtt_qos_level,
    &hf_mqtt_retain,
    NULL
  };

  static int * const v31_pubrel_sub_unsub_fields[] = {
    &hf_mqtt_msg_type,
    &hf_mqtt_dup_flag,
    &hf_mqtt_qos_level,
    &hf_mqtt_retain_reserved,
    NULL
  };

  static int * const other_fields[] = {
    &hf_mqtt_msg_type,
    &hf_mqtt_reserved,
    NULL
  };

  static int * const connect_flags[] = {
    &hf_mqtt_conflag_user,
    &hf_mqtt_conflag_passwd,
    &hf_mqtt_conflag_will_retain,
    &hf_mqtt_conflag_will_qos,
    &hf_mqtt_conflag_will_flag,
    &hf_mqtt_conflag_clean_sess,
    &hf_mqtt_conflag_reserved,
    NULL
  };

  static int * const connack_flags[] = {
    &hf_mqtt_conackflag_reserved,
    &hf_mqtt_conackflag_sp,
    NULL
  };

  static int * const v50_subscription_flags[] = {
    &hf_mqtt_subscription_reserved,
    &hf_mqtt_subscription_retain,
    &hf_mqtt_subscription_rap,
    &hf_mqtt_subscription_nl,
    &hf_mqtt_subscription_qos,
    NULL
  };

  /* Extract the message ID */
  mqtt_fixed_hdr = tvb_get_guint8(tvb, offset);
  mqtt_msg_type = mqtt_fixed_hdr >> 4;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "MQTT");
  col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str_ext(mqtt_msg_type, &mqtt_msgtype_vals_ext, "Unknown (0x%02x)"));

  /* Add the MQTT branch to the main tree */
  mqtt_ti = proto_tree_add_item(tree, proto_mqtt, tvb, 0, -1, ENC_NA);
  mqtt_tree = proto_item_add_subtree(mqtt_ti, ett_mqtt_hdr);

  conv = find_or_create_conversation(pinfo);
  mqtt = (mqtt_conv_t *)conversation_get_proto_data(conv, proto_mqtt);
  if (mqtt == NULL)
  {
    mqtt = wmem_new0(wmem_file_scope(), mqtt_conv_t);
    mqtt->runtime_proto_version = default_protocol_version;
    conversation_add_proto_data(conv, proto_mqtt, mqtt);
    mqtt->topic_alias_map = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
  }

  mqtt_len_offset = tvb_get_varint(tvb, (offset + MQTT_HDR_SIZE_BEFORE_LEN), FT_VARINT_MAX_LEN, &msg_len, ENC_VARINT_PROTOBUF);

  /* Explicit downcast, typically maximum length of message could be 4 bytes */
  mqtt_msg_len = (gint) msg_len;

  /* Add the type to the MQTT tree item */
  proto_item_append_text(mqtt_tree, ", %s", val_to_str_ext(mqtt_msg_type, &mqtt_msgtype_vals_ext, "Unknown (0x%02x)"));

  if ((mqtt_msg_type != MQTT_CONNECT) && (mqtt->runtime_proto_version == 0))
  {
    expert_add_info(pinfo, mqtt_ti, &ei_unknown_version);
  }

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

  switch (mqtt_msg_type)
  {
    case MQTT_CONNECT:
      proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_proto_len, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_str_len);
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
        offset += dissect_mqtt_properties(tvb, mqtt_tree, offset, hf_mqtt_property, &mqtt_properties);
      }

      proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_client_id_len, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_str_len);
      offset += 2;

      proto_tree_add_item(mqtt_tree, hf_mqtt_client_id, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA);
      offset += mqtt_str_len;

      if (mqtt_con_flags & MQTT_CONMASK_WILLFLAG)
      {
        if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
        {
          offset += dissect_mqtt_properties(tvb, mqtt_tree, offset, hf_mqtt_will_property, &mqtt_will_properties);
        }

        ti = proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_will_topic_len, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_str_len);
        offset += 2;

        if (mqtt_str_len > 0)
        {
          proto_tree_add_item(mqtt_tree, hf_mqtt_will_topic, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA);
          offset += mqtt_str_len;
        }
        else
        {
          expert_add_info(pinfo, ti, &ei_illegal_length);
        }

        proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_will_msg_len, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_str_len);
        offset += 2;

        if (show_msg_as_text)
        {
          proto_tree_add_item(mqtt_tree, hf_mqtt_will_msg_text, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA);
        }
        else
        {
          proto_tree_add_item(mqtt_tree, hf_mqtt_will_msg, tvb, offset, mqtt_str_len, ENC_NA);
        }
        offset += mqtt_str_len;
      }

      if ((mqtt_con_flags & MQTT_CONMASK_USER) && (tvb_reported_length_remaining(tvb, offset) > 0))
      {
        proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_username_len, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_str_len);
        offset += 2;

        proto_tree_add_item(mqtt_tree, hf_mqtt_username, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA);
        offset += mqtt_str_len;
      }

      if ((mqtt_con_flags & MQTT_CONMASK_PASSWD) && (tvb_reported_length_remaining(tvb, offset) > 0))
      {
        proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_passwd_len, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_str_len);
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

      if ((mqtt->runtime_proto_version == MQTT_PROTO_V31) ||
          (mqtt->runtime_proto_version == MQTT_PROTO_V311))
      {
        proto_tree_add_item(mqtt_tree, hf_mqtt_conack_code, tvb, offset, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        dissect_mqtt_reason_code(mqtt_tree, tvb, offset, mqtt_msg_type);
      }
      offset += 1;

      if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
      {
        offset += dissect_mqtt_properties(tvb, mqtt_tree, offset, hf_mqtt_property, &mqtt_properties);
      }
      break;

    case MQTT_PUBLISH:
      /* TopicName|MsgID|Message| */
      ti = proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_topic_len, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_str_len);
      offset += 2;

      if (mqtt_str_len > 0)
      {
        /* 'topic_regex' requires topic_str to be valid UTF-8. */
        proto_tree_add_item_ret_string(mqtt_tree, hf_mqtt_topic, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA,
                                       wmem_packet_scope(), &topic_str);
        offset += mqtt_str_len;
      }

      /* Message ID is included only when QoS > 0 */
      if (mqtt_fixed_hdr & MQTT_MASK_QOS)
      {
        proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_msgid, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_msgid);
        offset += 2;
        col_append_fstr(pinfo->cinfo, COL_INFO, " (id=%u)", mqtt_msgid);
      }

      if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
      {
        offset += dissect_mqtt_properties(tvb, mqtt_tree, offset, hf_mqtt_property, &mqtt_properties);

        if (mqtt_properties.topic_alias != 0)
        {
          if (!pinfo->fd->visited && mqtt_str_len > 0)
          {
            guint8 *topic = wmem_strdup(wmem_file_scope(), topic_str);
            wmem_map_insert(mqtt->topic_alias_map, GUINT_TO_POINTER(mqtt_properties.topic_alias), topic);
          }
          else
          {
            guint8 *topic = (guint8 *)wmem_map_lookup(mqtt->topic_alias_map, GUINT_TO_POINTER(mqtt_properties.topic_alias));
            if (topic != NULL)
            {
              topic_str = topic;
            }

            ti = proto_tree_add_string(mqtt_tree, hf_mqtt_topic, tvb, offset, 0, topic_str);
            PROTO_ITEM_SET_GENERATED(ti);

            if (topic == NULL)
            {
              expert_add_info(pinfo, ti, &ei_unknown_topic_alias);
            }
          }
        }
      }

      if ((mqtt_str_len == 0) && (mqtt_properties.topic_alias == 0))
      {
        expert_add_info(pinfo, ti, &ei_illegal_length);
      }

      col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", topic_str);

      mqtt_payload_len = tvb_reported_length(tvb) - offset;
      if (show_msg_as_text)
      {
        proto_tree_add_item(mqtt_tree, hf_mqtt_pubmsg_text, tvb, offset, mqtt_payload_len, ENC_UTF_8|ENC_NA);
      }
      else
      {
        proto_tree_add_item(mqtt_tree, hf_mqtt_pubmsg, tvb, offset, mqtt_payload_len, ENC_NA);
      }

      if (num_mqtt_message_decodes > 0)
      {
        tvbuff_t *msg_tvb = tvb_new_subset_length(tvb, offset, mqtt_payload_len);
        mqtt_user_decode_message(tree, mqtt_tree, pinfo, topic_str, msg_tvb);
      }

      if (mqtt_properties.content_type)
      {
        tvbuff_t *msg_tvb = tvb_new_subset_length(tvb, offset, mqtt_payload_len);
        dissector_try_string(media_type_dissector_table, mqtt_properties.content_type,
                             msg_tvb, pinfo, tree, NULL);
      }
      break;

    case MQTT_SUBSCRIBE:
      /* After the Message Id field is found, the following fields must appear
       * at least once:
       * |TopicName|QoS|
       */
      proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_msgid, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_msgid);
      offset += 2;
      col_append_fstr(pinfo->cinfo, COL_INFO, " (id=%u)", mqtt_msgid);

      if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
      {
        offset += dissect_mqtt_properties(tvb, mqtt_tree, offset, hf_mqtt_property, &mqtt_properties);
      }

      while (offset < tvb_reported_length(tvb))
      {
        ti = proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_topic_len, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_str_len);
        offset += 2;

        if (mqtt_str_len > 0)
        {
          proto_tree_add_item_ret_string(mqtt_tree, hf_mqtt_topic, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA,
                                         wmem_epan_scope(), &topic_str);
          offset += mqtt_str_len;
        }
        else
        {
          expert_add_info(pinfo, ti, &ei_illegal_length);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", topic_str);

        if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
        {
          proto_tree_add_bitmask(mqtt_tree, tvb, offset, hf_mqtt_subscription_options,
                                 ett_mqtt_subscription_flags, v50_subscription_flags, ENC_BIG_ENDIAN);
        }
        else
        {
          proto_tree_add_item(mqtt_tree, hf_mqtt_sub_qos, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        offset += 1;
      }
      break;

    case MQTT_UNSUBSCRIBE:
      /* After the Message Id field is found, the following fields must appear
       * at least once:
       * |TopicName|
       */
      proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_msgid, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_msgid);
      offset += 2;
      col_append_fstr(pinfo->cinfo, COL_INFO, " (id=%u)", mqtt_msgid);

      if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
      {
        offset += dissect_mqtt_properties(tvb, mqtt_tree, offset, hf_mqtt_property, &mqtt_properties);
      }

      while (offset < tvb_reported_length(tvb))
      {
        ti = proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_topic_len, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_str_len);
        offset += 2;

        if (mqtt_str_len > 0)
        {
          proto_tree_add_item(mqtt_tree, hf_mqtt_topic, tvb, offset, mqtt_str_len, ENC_UTF_8|ENC_NA);
          offset += mqtt_str_len;
        }
        else
        {
          expert_add_info(pinfo, ti, &ei_illegal_length);
        }
      }
      break;

    case MQTT_SUBACK:
      /* The SUBACK message contains a list of granted QoS levels that come
       * after the Message Id field. The size of each QoS entry is 1 byte.
       */
      proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_msgid, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_msgid);
      offset += 2;
      col_append_fstr(pinfo->cinfo, COL_INFO, " (id=%u)", mqtt_msgid);

      if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
      {
        offset += dissect_mqtt_properties(tvb, mqtt_tree, offset, hf_mqtt_property, &mqtt_properties);
      }

      while (offset < tvb_reported_length(tvb))
      {
        if ((mqtt->runtime_proto_version == MQTT_PROTO_V31) ||
            (mqtt->runtime_proto_version == MQTT_PROTO_V311))
        {
          proto_tree_add_item(mqtt_tree, hf_mqtt_suback_qos, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        else
        {
          dissect_mqtt_reason_code(mqtt_tree, tvb, offset, mqtt_msg_type);
        }
        offset += 1;
      }
      break;

    case MQTT_PUBACK:
    case MQTT_PUBREC:
    case MQTT_PUBREL:
    case MQTT_PUBCOMP:
      proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_msgid, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_msgid);
      offset += 2;
      col_append_fstr(pinfo->cinfo, COL_INFO, " (id=%u)", mqtt_msgid);

      /* MQTT v5.0: The Reason Code and Property Length can be omitted if the
       * Reason Code is 0x00 and there are no Properties.
       * In this case, the PUB* has a Remaining Length of 2.
       */
      if (mqtt->runtime_proto_version == MQTT_PROTO_V50 && mqtt_msg_len > 2)
      {
        dissect_mqtt_reason_code(mqtt_tree, tvb, offset, mqtt_msg_type);
        offset += 1;

        /* If the Remaining Length is less than 4, the Property Length is not
         * present and has a value of 0.
         */
        if (mqtt_msg_len > 3)
        {
          offset += dissect_mqtt_properties(tvb, mqtt_tree, offset, hf_mqtt_property, &mqtt_properties);
        }
      }
      break;

    case MQTT_UNSUBACK:
      proto_tree_add_item_ret_uint(mqtt_tree, hf_mqtt_msgid, tvb, offset, 2, ENC_BIG_ENDIAN, &mqtt_msgid);
      offset += 2;
      col_append_fstr(pinfo->cinfo, COL_INFO, " (id=%u)", mqtt_msgid);

      if (mqtt->runtime_proto_version == MQTT_PROTO_V50)
      {
        offset += dissect_mqtt_properties(tvb, mqtt_tree, offset, hf_mqtt_property, &mqtt_properties);

        while (offset < tvb_reported_length(tvb))
        {
          dissect_mqtt_reason_code(mqtt_tree, tvb, offset, mqtt_msg_type);
          offset += 1;
        }
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
        dissect_mqtt_reason_code(mqtt_tree, tvb, offset, mqtt_msg_type);
        offset += 1;

        /* 3.14.2.2 DISCONNECT Properties:
         * If the Remaining Length is less than 2, a value of 0 is used.
         * Let's assume that it also applies to AUTH, why? DISCONNECT and AUTH
         * share the same structure with no payload.
         */
        if (mqtt_msg_len >= 2)
        {
          offset += dissect_mqtt_properties(tvb, mqtt_tree, offset, hf_mqtt_property, &mqtt_properties);
        }
      }
      break;
  }

  return offset;
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
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_will_msg_text,
      { "Will Message", "mqtt.willmsg_text",
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
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_pubmsg_text,
      { "Message", "mqtt.msg_text",
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
    { &hf_mqtt_subscription_options,
      { "Subscription Options", "mqtt.subscription_options",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_subscription_qos,
      { "QoS", "mqtt.subscription_options_qos",
        FT_UINT8, BASE_DEC, VALS(mqtt_qos_vals), MQTT_MASK_SUBS_QOS,
        NULL, HFILL }},
    { &hf_mqtt_subscription_nl,
      { "No Local", "mqtt.subscription_options_nl",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQTT_MASK_SUBS_NL,
        NULL, HFILL }},
    { &hf_mqtt_subscription_rap,
      { "Retain As Published", "mqtt.subscription_options_rap",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), MQTT_MASK_SUBS_RAP,
        NULL, HFILL }},
    { &hf_mqtt_subscription_retain,
      { "Retain Handling", "mqtt.subscription_options_retain",
        FT_UINT8, BASE_DEC, VALS(mqtt_subscription_retain_handling), MQTT_MASK_SUBS_RETAIN,
        NULL, HFILL }},
    { &hf_mqtt_subscription_reserved,
      { "Reserved", "mqtt.subscription_options_reserved",
        FT_UINT8, BASE_HEX, NULL, MQTT_MASK_SUBS_RESERVED,
        NULL, HFILL }},

    /* v5.0 Reason Codes */
    { &hf_mqtt_reason_code_connack,
      { "Reason Code", "mqtt.connack.reason_code",
        FT_UINT8, BASE_DEC, VALS(mqtt_reason_code_connack_vals), 0,
        "MQTT Reason Code", HFILL }},
    { &hf_mqtt_reason_code_puback,
      { "Reason Code", "mqtt.puback.reason_code",
        FT_UINT8, BASE_DEC, VALS(mqtt_reason_code_puback_vals), 0,
        "MQTT Reason Code", HFILL }},
    { &hf_mqtt_reason_code_pubrec,
      { "Reason Code", "mqtt.pubrec.reason_code",
        FT_UINT8, BASE_DEC, VALS(mqtt_reason_code_puback_vals), 0,
        "MQTT Reason Code", HFILL }},
    { &hf_mqtt_reason_code_pubrel,
      { "Reason Code", "mqtt.pubrel.reason_code",
        FT_UINT8, BASE_DEC, VALS(mqtt_reason_code_pubrel_vals), 0,
        "MQTT Reason Code", HFILL }},
    { &hf_mqtt_reason_code_pubcomp,
      { "Reason Code", "mqtt.pubcomp.reason_code",
        FT_UINT8, BASE_DEC, VALS(mqtt_reason_code_pubrel_vals), 0,
        "MQTT Reason Code", HFILL }},
    { &hf_mqtt_reason_code_suback,
      { "Reason Code", "mqtt.suback.reason_code",
        FT_UINT8, BASE_DEC, VALS(mqtt_reason_code_suback_vals), 0,
        "MQTT Reason Code", HFILL }},
    { &hf_mqtt_reason_code_unsuback,
      { "Reason Code", "mqtt.unsuback.reason_code",
        FT_UINT8, BASE_DEC, VALS(mqtt_reason_code_unsuback_vals), 0,
        "MQTT Reason Code", HFILL }},
    { &hf_mqtt_reason_code_disconnect,
      { "Reason Code", "mqtt.disconnect.reason_code",
        FT_UINT8, BASE_DEC, VALS(mqtt_reason_code_disconnect_vals), 0,
        "MQTT Reason Code", HFILL }},
    { &hf_mqtt_reason_code_auth,
      { "Reason Code", "mqtt.auth.reason_code",
        FT_UINT8, BASE_DEC, VALS(mqtt_reason_code_auth_vals), 0,
        "MQTT Reason Code", HFILL }},

    /* Properties */
    { &hf_mqtt_property,
      { "Properties", "mqtt.properties",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_will_property,
      { "Will Properties", "mqtt.will_properties",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_property_len,
      { "Total Length", "mqtt.property_len",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_property_id,
      { "ID", "mqtt.property_id",
        FT_UINT8, BASE_HEX, VALS(mqtt_property_vals), 0,
        "Property Id", HFILL }},
    { &hf_mqtt_prop_num,
      { "Value", "mqtt.prop_number",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_prop_content_type,
      { "Content Type", "mqtt.property.content_type",
        FT_UINT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_prop_max_qos,
      { "QoS", "mqtt.property.max_qos",
        FT_UINT8, BASE_DEC, VALS(mqtt_qos_vals), 0,
        NULL, HFILL }},
    { &hf_mqtt_prop_topic_alias,
      { "Topic Alias", "mqtt.property.topic_alias",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_prop_unknown,
      { "Unknown Property", "mqtt.prop_unknown",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_prop_string_len,
      { "Length", "mqtt.prop_string_len",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_prop_string,
      { "Value", "mqtt.prop_string",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_prop_key_len,
      { "Key Length", "mqtt.prop_key_len",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_prop_key,
      { "Key", "mqtt.prop_key",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_prop_value_len,
      { "Value Length", "mqtt.prop_value_len",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mqtt_prop_value,
      { "Value", "mqtt.prop_value",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* Setup protocol subtree arrays */
  static gint* ett_mqtt[] = {
    &ett_mqtt_hdr,
    &ett_mqtt_msg,
    &ett_mqtt_hdr_flags,
    &ett_mqtt_con_flags,
    &ett_mqtt_conack_flags,
    &ett_mqtt_property,
    &ett_mqtt_subscription_flags,
  };

  static ei_register_info ei[] = {
    { &ei_illegal_length,
      { "mqtt.illegal_topic_length", PI_PROTOCOL, PI_WARN, "Length cannot be 0", EXPFILL } },
    { &ei_unknown_version,
      { "mqtt.unknown_version", PI_PROTOCOL, PI_NOTE, "Unknown version (missing the CONNECT packet?)", EXPFILL } },
    { &ei_unknown_topic_alias,
      { "mqtt.unknown_topic_alias", PI_PROTOCOL, PI_NOTE, "Unknown topic alias", EXPFILL } }
  };

  static uat_field_t mqtt_message_decode_flds[] = {
    UAT_FLD_VS(message_decode, match_criteria, "Match criteria", match_criteria, "Match criteria"),
    UAT_FLD_CSTRING(message_decode, topic_pattern, "Topic pattern", "Pattern to match for the topic"),
    UAT_FLD_VS(message_decode, msg_decoding, "Decoding", msg_decoding, "Decode message before dissecting as protocol"),
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
  expert_module_t* expert_mqtt;

  /* Register protocol names and descriptions */
  proto_mqtt = proto_register_protocol("MQ Telemetry Transport Protocol", "MQTT", "mqtt");

  /* Register the dissector */
  mqtt_handle = register_dissector("mqtt", dissect_mqtt_data, proto_mqtt);

  proto_register_field_array(proto_mqtt, hf_mqtt, array_length(hf_mqtt));
  proto_register_subtree_array(ett_mqtt, array_length(ett_mqtt));

  expert_mqtt = expert_register_protocol(proto_mqtt);
  expert_register_field_array(expert_mqtt, ei, array_length(ei));

  mqtt_module = prefs_register_protocol(proto_mqtt, NULL);

  prefs_register_uat_preference(mqtt_module, "message_decode_table",
                                "Message Decoding",
                                "A table that enumerates custom message decodes to be used for a certain topic",
                                message_uat);

  prefs_register_enum_preference(mqtt_module, "default_version",
                                 "Default Version",
                                 "Select the MQTT version to use as protocol version if the CONNECT packet is not captured",
                                 &default_protocol_version, mqtt_protocol_version_enumvals, FALSE);

  prefs_register_bool_preference(mqtt_module, "show_msg_as_text",
                                 "Show Message as text",
                                 "Show Publish Message as text",
                                 &show_msg_as_text);

}

/*
 *  Dissector Handoff
 */
void proto_reg_handoff_mqtt(void)
{
  dissector_add_uint_with_preference("tcp.port", MQTT_DEFAULT_PORT, mqtt_handle);
  ssl_dissector_add(MQTT_SSL_DEFAULT_PORT, mqtt_handle);

  media_type_dissector_table = find_dissector_table("media_type");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
