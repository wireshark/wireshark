/* packet-rtitcp.c
 * Dissector for the RTI TCP Transport Protocol.
 * Layer on top of TCP used to send Control messages
 * to establish and maintain the connections as well as
 * send RTPS data.
 *
 * (c) 2005-2015 Copyright, Real-Time Innovations, Inc.
 * Real-Time Innovations, Inc.
 * 232 East Java Drive
 * Sunnyvale, CA 94089
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/wmem/wmem.h>
#include <epan/conversation.h>
#include <epan/g_int64_hash_routines.h>
#include <epan/dissectors/packet-tcp.h>

#define RTITCP_MAGIC_NUMBER             0xdd54dd55
#define RTPS_MAGIC_NUMBER               0x52545053
#define RTITCP_CONTROL_MAGIC_COOKIE     0x2112A442
#define RTITCP_CRC_MAGIC_NUMBER         0x43524332

/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define RTITCP_MIN_LENGTH 8
#define NUMBER_2E30 1073741824

#define IDENTITY_BIND_REQUEST                           (0x0C01)
#define IDENTITY_BIND_INDICATION                        (0x0C11)
#define IDENTITY_BIND_RESPONSE                          (0x0D01)
#define IDENTITY_BIND_ERROR                             (0x0D11)

#define SERVER_LOGICAL_PORT_REQUEST                     (0x0C02)
#define SERVER_LOGICAL_PORT_INDICATION                  (0x0C12)
#define SERVER_LOGICAL_PORT_RESPONSE                    (0x0D02)
#define SERVER_LOGICAL_PORT_ERROR                       (0x0D12)

#define CLIENT_LOGICAL_PORT_REQUEST                     (0x0C03)
#define CLIENT_LOGICAL_PORT_INDICATION                  (0x0C13)
#define CLIENT_LOGICAL_PORT_RESPONSE                    (0x0D03)
#define CLIENT_LOGICAL_PORT_ERROR                       (0x0D13)

#define CONNECTION_BIND_REQUEST                         (0x0C04)
#define CONNECTION_BIND_INDICATION                      (0x0C14)
#define CONNECTION_BIND_RESPONSE                        (0x0D04)
#define CONNECTION_BIND_ERROR                           (0x0D14)

#define SESSION_ID_REQUEST                              (0x0C05)
#define SESSION_ID_INDICATION                           (0x0C15)
#define SESSION_ID_RESPONSE                             (0x0D05)
#define SESSION_ID_ERROR                                (0x0D15)

#define LIVELINESS_REQUEST                              (0x0C06)
#define LIVELINESS_RESPONSE                             (0x0D06)

#define FINALIZE_SESSION_REQUEST                        (0x0C0F)
#define FINALIZE_SESSION_INDICATION                     (0x0C1F)
#define FINALIZE_SESSION_RESPONSE                       (0x0D0F)
#define FINALIZE_SESSION_ERRROR                         (0x0D1F)

#define LOCATOR_KIND_IPV4                               (1)
#define LOCATOR_KIND_IPV6                               (2)

#define RTPS_LOCATOR_ADDRESS_ATTRIBUTE_TYPE             (0x3D01)
#define RTPS_LOCATOR_PORT_ATTRIBUTE_TYPE                (0x3D02)
#define CONNECTION_TYPE_ATTRIBUTE_TYPE                  (0x3D03)
#define CONNECTION_COOKIE_ATTRIBUTE_TYPE                (0x3D04)
#define PORT_OPTIONS_ATTRIBUTE_TYPE                     (0x3D05)
#define TRANSPORT_PRIORITY_ATTRIBUTE_TYPE               (0x3D06)
#define SESSION_ID_ATTRIBUTE_TYPE                       (0x3D07)

#define MAPPED_ADDRESS_ATTRIBUTE_TYPE                   (0x0001)
#define XOR_MAPPED_ADDRESS_ATTRIBUTE_TYPE               (0x0020)
#define ERROR_CODE_ATTRIBUTE_TYPE                       (0x0009)
#define UNKNOWN_ATTRIBUTES_ATTRIBUTE_TYPE               (0x000A)

#define SOFTWARE_ATTRIBUTE_TYPE                         (0x8022)
#define ALTERNATE_SERVER_ATTRIBUTE_TYPE                 (0x8023)

#define CLASS_ID_TCPV4_LAN                              (0x00)
#define CLASS_ID_TCPV4_WAN                              (0x40)
#define CLASS_ID_TLSV4_LAN                              (0x80)
#define CLASS_ID_TLSV4_WAN                              (0xC0)


#define NDDS_TRANSPORT_TCPV4_CONTROL_PROTOCOL_OK                                              0
/* client requested a transport class not supported by the server */
#define NDDS_TRANSPORT_TCPV4_CONTROL_PROTOCOL_ERROR_TRANSPORT_CLASS_MISMATCH                  1
/* required attribute is missing */
#define NDDS_TRANSPORT_TCPV4_CONTROL_PROTOCOL_ERROR_ATTRIBUTE_MISSING                         2
/* no matching receive resource for requested port */
#define NDDS_TRANSPORT_TCPV4_CONTROL_PROTOCOL_ERROR_NO_MATCHING_RECVRESOURCE                  3
/* no matching cookie found on server */
#define NDDS_TRANSPORT_TCPV4_CONTROL_PROTOCOL_ERROR_NO_MATCH_COOKIE                           4
/* fatal internal processing error (caller is not responsible) */
#define NDDS_TRANSPORT_TCPV4_CONTROL_PROTOCOL_ERROR_INTERNAL                                  5
/* the operation should be retried at the first occurence */
#define NDDS_TRANSPORT_TCPV4_CONTROL_PROTOCOL_ERROR_RETRY                                     6
#define NDDS_TRANSPORT_TCP_CONTROL_ERROR_CODE_ATTRIBUTE_BAD_REQUEST_ID                        400
#define NDDS_TRANSPORT_TCP_CONTROL_ERROR_CODE_ATTRIBUTE_UNKNOWN_ATTRIBUTE_ID                  420
#define NDDS_TRANSPORT_TCP_CONTROL_ERROR_CODE_ATTRIBUTE_ALLOCATION_MISMATCH_ID                437
#define NDDS_TRANSPORT_TCP_CONTROL_ERROR_CODE_ATTRIBUTE_UNSUPPORTED_TRANSPORT_PROTOCOL_ID     442
#define NDDS_TRANSPORT_TCP_CONTROL_ERROR_CODE_ATTRIBUTE_CONNECTION_ALREADY_EXISTS_ID          446
#define NDDS_TRANSPORT_TCP_CONTROL_ERROR_CODE_ATTRIBUTE_SERVER_ERROR_ID                       500

/* Forward declaration that is needed below if using the
 * proto_reg_handoff_rtitcp function as a callback for when protocol
 * preferences get changed. For now we don't have preferences but we
 * may have them in the future.*/

void proto_reg_handoff_rtitcp(void);
void proto_register_rtitcp(void);

/* Initialize the protocol and registered fields */
static gint proto_rtitcp                                         = -1;
static gint hf_rtitcp_header_control_byte                        = -1;
static gint hf_rtitcp_header_magic_number                        = -1;
static gint hf_rtitcp_header_message_length                      = -1;
static gint hf_rtitcp_control_transaction_id                     = -1;
static gint hf_rtitcp_control_kind                               = -1;
static gint hf_rtitcp_control_attribute_type                     = -1;
static gint hf_rtitcp_control_attribute_length                   = -1;
static gint hf_rtitcp_control_attribute_port                     = -1;
static gint hf_rtitcp_attributes_list_length                     = -1;
static gint hf_rtitcp_control_magic_cookie                       = -1;
static gint hf_rtitcp_control_attribute_connection_cookie        = -1;
static gint hf_rtitcp_control_attribute_connection_type          = -1;
static gint hf_rtitcp_control_attribute_session_id               = -1;
static gint hf_rtitcp_control_attribute_error_code_value         = -1;
static gint hf_rtitcp_control_attribute_error_code_description   = -1;
static gint hf_rtitcp_locator_ipv4                               = -1;
static gint hf_rtitcp_locator_port                               = -1;
static gint hf_rtitcp_locator_ipv6                               = -1;
static gint hf_rtitcp_locator_kind                               = -1;
static gint hf_rtitcp_crc_magic_cookie                           = -1;
static gint hf_rtitcp_control_crc_value                          = -1;

static gint hf_rtitcp_response_in                                = -1;
static gint hf_rtitcp_response_to                                = -1;
static gint hf_rtitcp_response_time                              = -1;

#define RTITCP_FLAG_NOT_REQUEST 0x0100

typedef struct _rtitcp_transaction_t {
    guint32 req_frame;
    guint32 rep_frame;
    nstime_t req_time;
} rtitcp_transaction_t;

typedef struct _rtitcp_conv_info_t {
    wmem_map_t *pdus;
} rtitcp_conv_info_t;

/* Subtree pointers */
static gint ett_rtitcp                              = -1;
static gint ett_rtitcp_signalling_protocol          = -1;
static gint ett_rtitcp_message                      = -1;
static gint ett_rtitcp_attributes_list              = -1;
static gint ett_rtitcp_attribute                    = -1;

static header_field_info *hfi_rtitcp                = NULL;
static heur_dissector_list_t heur_subdissector_list;

static const value_string ctrl_message_types_vals[] = {
    { IDENTITY_BIND_REQUEST,                    "Identity Bind Request" },
    { IDENTITY_BIND_INDICATION,                 "Identity Bind Indication" },
    { IDENTITY_BIND_RESPONSE,                   "Identity Bind Response" },
    { IDENTITY_BIND_ERROR,                      "Identity Bind Error" },
    { SERVER_LOGICAL_PORT_REQUEST,              "Server Logical Port Request" },
    { SERVER_LOGICAL_PORT_RESPONSE,             "Server Logical Port Response" },
    { SERVER_LOGICAL_PORT_ERROR,                "Server Logical Port Error" },
    { CLIENT_LOGICAL_PORT_REQUEST,              "Client Logical Port Request" },
    { CLIENT_LOGICAL_PORT_RESPONSE,             "Client Logical Port Response" },
    { CLIENT_LOGICAL_PORT_ERROR,                "Client Logical Port Error" },
    { CONNECTION_BIND_REQUEST,                  "Connection Bind Request" },
    { CONNECTION_BIND_RESPONSE,                 "Connection Bind Response" },
    { CONNECTION_BIND_ERROR,                    "Connection Bind Error" },
    { SESSION_ID_REQUEST,                       "Session ID Request" },
    { SESSION_ID_INDICATION,                    "Session ID Indication" },
    { SESSION_ID_RESPONSE,                      "Session ID Response" },
    { SESSION_ID_ERROR,                         "Session ID Error" },
    { LIVELINESS_REQUEST,                       "Liveliness Request" },
    { LIVELINESS_RESPONSE,                      "Liveliness Response" },
    { FINALIZE_SESSION_INDICATION,              "Finalize Session Indication" },
    { 0, NULL }
};

static const value_string attribute_types_vals[] = {
    { RTPS_LOCATOR_ADDRESS_ATTRIBUTE_TYPE,    "Locator Address" },
    { RTPS_LOCATOR_PORT_ATTRIBUTE_TYPE,       "Locator Port" },
    { CONNECTION_TYPE_ATTRIBUTE_TYPE,         "Connection Type" },
    { CONNECTION_COOKIE_ATTRIBUTE_TYPE,       "Connection Cookie" },
    { PORT_OPTIONS_ATTRIBUTE_TYPE,            "Port options" },
    { TRANSPORT_PRIORITY_ATTRIBUTE_TYPE,      "Transport priority" },
    { SESSION_ID_ATTRIBUTE_TYPE,              "Session ID" },
    { MAPPED_ADDRESS_ATTRIBUTE_TYPE,          "Mapped Address" },
    { XOR_MAPPED_ADDRESS_ATTRIBUTE_TYPE,      "XOR Mapped Address" },
    { ERROR_CODE_ATTRIBUTE_TYPE,              "Error Code" },
    { UNKNOWN_ATTRIBUTES_ATTRIBUTE_TYPE,      "Unknown attribute" },
    { SOFTWARE_ATTRIBUTE_TYPE,                "Software" },
    { ALTERNATE_SERVER_ATTRIBUTE_TYPE,        "Alternate Server" },
    { 0, NULL }
};

static const value_string error_code_kind_vals[] = {
    { NDDS_TRANSPORT_TCPV4_CONTROL_PROTOCOL_OK,
      "PROTOCOL_OK" },
    { NDDS_TRANSPORT_TCPV4_CONTROL_PROTOCOL_ERROR_TRANSPORT_CLASS_MISMATCH,
      "PROTOCOL_ERROR_TRANSPORT_CLASS_MISMATCH" },
    { NDDS_TRANSPORT_TCPV4_CONTROL_PROTOCOL_ERROR_ATTRIBUTE_MISSING,
      "PROTOCOL_ERROR_ATTRIBUTE_MISSING" },
    { NDDS_TRANSPORT_TCPV4_CONTROL_PROTOCOL_ERROR_NO_MATCHING_RECVRESOURCE,
      "PROTOCOL_ERROR_NO_MATCHING_RECVRESOURCE" },
    { NDDS_TRANSPORT_TCPV4_CONTROL_PROTOCOL_ERROR_NO_MATCH_COOKIE,
      "PROTOCOL_ERROR_NO_MATCH_COOKIE" },
    { NDDS_TRANSPORT_TCPV4_CONTROL_PROTOCOL_ERROR_INTERNAL,
      "PROTOCOL_ERROR_INTERNAL" },
    { NDDS_TRANSPORT_TCPV4_CONTROL_PROTOCOL_ERROR_RETRY,
      "PROTOCOL_ERROR_RETRY" },
    { NDDS_TRANSPORT_TCP_CONTROL_ERROR_CODE_ATTRIBUTE_BAD_REQUEST_ID,
      "ERROR_CODE_ATTRIBUTE_BAD_REQUEST_ID" },
    { NDDS_TRANSPORT_TCP_CONTROL_ERROR_CODE_ATTRIBUTE_UNKNOWN_ATTRIBUTE_ID,
      "ERROR_CODE_ATTRIBUTE_UNKNOWN_ATTRIBUTE_ID" },
    { NDDS_TRANSPORT_TCP_CONTROL_ERROR_CODE_ATTRIBUTE_ALLOCATION_MISMATCH_ID,
      "ERROR_CODE_ATTRIBUTE_ALLOCATION_MISMATCH_ID" },
    { NDDS_TRANSPORT_TCP_CONTROL_ERROR_CODE_ATTRIBUTE_UNSUPPORTED_TRANSPORT_PROTOCOL_ID,
      "ERROR_CODE_ATTRIBUTE_UNSUPPORTED_TRANSPORT_PROTOCOL_ID" },
    { NDDS_TRANSPORT_TCP_CONTROL_ERROR_CODE_ATTRIBUTE_CONNECTION_ALREADY_EXISTS_ID,
      "ERROR_CODE_ATTRIBUTE_CONNECTION_ALREADY_EXISTS_ID" },
    { NDDS_TRANSPORT_TCP_CONTROL_ERROR_CODE_ATTRIBUTE_SERVER_ERROR_ID,
      "ERROR_CODE_ATTRIBUTE_SERVER_ERROR_ID" },
    { 0, NULL }
};

static const value_string rtitcp_locator_kind_vals[] = {
    { LOCATOR_KIND_IPV4,        "IPV4" },
    { LOCATOR_KIND_IPV6,        "Unreachable peer" },
    { 0, NULL }
};

static const value_string rtitcp_attribute_connection_type_vals[] = {
    { CLASS_ID_TCPV4_LAN,        "TCPV4_LAN" },
    { CLASS_ID_TCPV4_WAN,        "TCPV4_WAN" },
    { CLASS_ID_TLSV4_LAN,        "TLSV4_LAN" },
    { CLASS_ID_TLSV4_WAN,        "TLSV4_WAN" },
    { 0, NULL }
};

static void rtitcp_util_add_error_attribute(proto_tree *attribute, tvbuff_t* tvb,
                             gint offset, guint size) {
    proto_tree_add_item(attribute, hf_rtitcp_control_attribute_error_code_value, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(attribute, hf_rtitcp_control_attribute_error_code_description, tvb, offset + 4,
            size - 4, ENC_ASCII|ENC_NA);
}

static void rtitcp_util_add_locator_t(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t * tvb,
                             gint offset, gboolean little_endian,
                             proto_item * rtitcp_message, gboolean * first_attribute) {
    gint32  kind;
    guint16 port;
    kind = tvb_get_guint16(tvb, offset+8, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);

    if (kind == 0xFFFF) {
        kind = LOCATOR_KIND_IPV4;
    } else {
        kind = LOCATOR_KIND_IPV6;
    }
    proto_tree_add_uint(tree, hf_rtitcp_locator_kind, tvb, offset+8, 2, kind);

    if (kind == LOCATOR_KIND_IPV4) {
        proto_tree_add_item(tree, hf_rtitcp_locator_port, tvb, offset+10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_rtitcp_locator_ipv4, tvb, offset+12, 4, ENC_BIG_ENDIAN);

        port = tvb_get_guint16(tvb, offset+10, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
        if (*first_attribute) {
            proto_item_append_text(rtitcp_message," (");
            col_append_str(pinfo->cinfo, COL_INFO, " (");
        }
        proto_item_append_text(rtitcp_message, "%s%s:%u",
            *first_attribute ? "" : ", ", tvb_ip_to_str(tvb, offset + 12), port);
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s:%u",
                *first_attribute ? "" : ", ", tvb_ip_to_str(tvb, offset + 12), port);
    } else {
        proto_tree_add_item(tree, hf_rtitcp_locator_ipv6, tvb, offset, 16, ENC_NA);
        if (*first_attribute) {
            proto_item_append_text(rtitcp_message," (");
            col_append_str(pinfo->cinfo, COL_INFO, " (");
        }
        proto_item_append_text(rtitcp_message, "%s%s",
            *first_attribute ? "" : ", ", tvb_ip6_to_str(tvb, offset));
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s",
                *first_attribute ? "" : ", ", tvb_ip6_to_str(tvb, offset));
    }
}

static guint dissect_attribute(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *attributes_list, guint offset, guint attributes_list_offset,
        proto_item * rtitcp_message, gboolean * first_attribute) {

    guint16 attribute_length, attribute_type;
    guint padding;
    proto_item *attribute;

    attribute_type = tvb_get_guint16(tvb, attributes_list_offset+offset, ENC_BIG_ENDIAN);
    attribute_length = tvb_get_guint16(tvb, attributes_list_offset+offset+2, ENC_BIG_ENDIAN);

    attribute = proto_tree_add_subtree_format(attributes_list, tvb,
            attributes_list_offset+offset, attribute_length+4,
            ett_rtitcp_attribute, NULL, "Unknown Attribute");

    proto_tree_add_item(attribute, hf_rtitcp_control_attribute_type, tvb,
            attributes_list_offset+offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(attribute, hf_rtitcp_control_attribute_length, tvb,
            attributes_list_offset+offset+2, 2, ENC_BIG_ENDIAN);
    proto_item_set_text(attribute,"%s", val_to_str(attribute_type, attribute_types_vals, "Unknown attribute"));

    switch (attribute_type) {
        case RTPS_LOCATOR_PORT_ATTRIBUTE_TYPE: {
            guint32 port;
            port = tvb_get_guint32(tvb, attributes_list_offset+offset+4, ENC_BIG_ENDIAN);
            if (*first_attribute) {
                proto_item_append_text(rtitcp_message," (");
                col_append_str(pinfo->cinfo, COL_INFO, " (");
            }
            proto_item_append_text(rtitcp_message, "%s%u",
                    *first_attribute ? "" : ", ", port);
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s%u",
                    *first_attribute ? "" : ", ", port);
            (*first_attribute) = FALSE;
            proto_item_append_text(attribute, " (Port = %u)", port);
            proto_tree_add_item(attribute, hf_rtitcp_control_attribute_port, tvb,
                    attributes_list_offset+offset+4, attribute_length, ENC_BIG_ENDIAN);
            break;
        }
        case RTPS_LOCATOR_ADDRESS_ATTRIBUTE_TYPE: {
            rtitcp_util_add_locator_t(attribute, pinfo, tvb, attributes_list_offset+offset+4,
                                ENC_BIG_ENDIAN, rtitcp_message, first_attribute);
            (*first_attribute) = FALSE;
            break;
        }

        case CONNECTION_COOKIE_ATTRIBUTE_TYPE: {
            proto_tree_add_item(attribute, hf_rtitcp_control_attribute_connection_cookie,
                    tvb, attributes_list_offset+offset+4, attribute_length, ENC_NA);
            if (*first_attribute) {
                proto_item_append_text(rtitcp_message," (");
                col_append_str(pinfo->cinfo, COL_INFO, " (");
            }
            proto_item_append_text(rtitcp_message, "%s%s",
                (*first_attribute) ? "" : ", ",
                tvb_bytes_to_str(wmem_packet_scope(), tvb, attributes_list_offset+offset+4, 16));
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s",
                (*first_attribute) ? "" : ", ",
                tvb_bytes_to_str(wmem_packet_scope(), tvb, attributes_list_offset+offset+4, 16));
            (*first_attribute) = FALSE;
            break;
        }
        case CONNECTION_TYPE_ATTRIBUTE_TYPE: {
            guint8 attribute_connection_type = tvb_get_guint8(tvb, attributes_list_offset+offset+4);
            proto_tree_add_item(attribute, hf_rtitcp_control_attribute_connection_type, tvb,
                    attributes_list_offset+offset+4, attribute_length, ENC_BIG_ENDIAN);
            if (*first_attribute) {
                proto_item_append_text(rtitcp_message," (");
                col_append_str(pinfo->cinfo, COL_INFO, " (");
            }
            proto_item_append_text(rtitcp_message, "%s%s",
                (*first_attribute) ? "" : ", ",
                val_to_str(attribute_connection_type, rtitcp_attribute_connection_type_vals, "Unknown attribute"));
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s",
                (*first_attribute) ? "" : ", ",
                val_to_str(attribute_connection_type, rtitcp_attribute_connection_type_vals, "Unknown attribute"));
            (*first_attribute) = FALSE;
            break;
        }
        case SESSION_ID_ATTRIBUTE_TYPE: {
            proto_tree_add_item(attribute, hf_rtitcp_control_attribute_session_id, tvb,
                    attributes_list_offset+offset+4, attribute_length, ENC_NA);
            break;
        }
        case ERROR_CODE_ATTRIBUTE_TYPE: {
            rtitcp_util_add_error_attribute(attribute, tvb, attributes_list_offset+offset+4, attribute_length);
            break;
        }
        default:
            break;
    }

    padding = (4 - attribute_length%4)%4;
    return (attribute_length+padding+4);
}
static proto_tree* print_header(proto_tree *tree, proto_tree *rtitcp_message, tvbuff_t *tvb, guint offset,
                                    guint16 msg_length, gboolean printCRC, gboolean is_data) {
    proto_item *ti;

    if (is_data) {
        rtitcp_message = proto_tree_add_subtree_format(tree, tvb, offset, msg_length,
            ett_rtitcp_message, NULL, "RTI TCP Data Message");
    } else {
        rtitcp_message = proto_tree_add_subtree_format(tree, tvb, offset, msg_length,
            ett_rtitcp_message, NULL, "RTI TCP Control Message");
    }
    if (is_data) {
        guint32 msg_length32;
        proto_tree_add_item(rtitcp_message, hf_rtitcp_header_control_byte, tvb, offset, 1, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(rtitcp_message, hf_rtitcp_header_message_length,
                tvb, offset+1, 3, ENC_BIG_ENDIAN);
        msg_length32 = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
        msg_length32 = msg_length32 % NUMBER_2E30;
        proto_item_set_text(ti,"RTI TCP Message Length: %d", msg_length32);
    } else {
        proto_tree_add_item(rtitcp_message, hf_rtitcp_header_control_byte, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rtitcp_message, hf_rtitcp_header_message_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    }
    proto_tree_add_item(rtitcp_message, hf_rtitcp_header_magic_number, tvb, offset+4, 4, ENC_BIG_ENDIAN);
    if (printCRC) {
        proto_tree_add_item(rtitcp_message, hf_rtitcp_crc_magic_cookie, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(rtitcp_message, hf_rtitcp_control_crc_value, tvb, offset+12, 4, ENC_BIG_ENDIAN);
    }

    return rtitcp_message;
}
static guint16 dissect_control_message(proto_tree *rtitcp_tree, tvbuff_t *tvb, packet_info *pinfo,
                                  guint offset) {

   /* 0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |            Not Used           |           msg_length          |
   * +---------------+---------------+---------------+---------------+
   * |                      RTITCP_MAGIC_NUMBER                      |
   * +---------------+---------------+---------------+---------------+
   * |      control_message_kind     |    attributes_list_length     |
   * +---------------+---------------+---------------+---------------+
   * |                   RTITCP_CONTROL_MAGIC_COOKIE                 |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * |-                                                             -|
   * |                         TRANSACTION_ID                        |
   * |-                                                             -|
   * |                                                               |
   * +---------------+---------------+---------------+---------------+   ---------------------------------
   * |       attribute_type          |       attribute_length ..         Repeat                          |
   * +---------------+---------------+---------------+---------------+   until                           |
   * |                       ATTRIBUTE (length)                      |   attributes_list_length expires  |
   * +---------------+---------------+---------------+---------------+   --------------------------------*/

    proto_tree  *attributes_list, *rtitcp_message = NULL;
    guint16 msg_length, control_message_kind, attributes_list_length, header_length;
    guint attributes_list_offset, attribute_offset, offset_header = offset;
    guint attributes_count;
    gboolean is_data = FALSE, printCRC = FALSE, first_attribute;
    gchar * transaction_id_str;
    guint64 seq_num;
    conversation_t *conversation;
    rtitcp_conv_info_t *rtitcp_info;
    rtitcp_transaction_t *rtitcp_trans;
    guint64 * conversation_info_key = NULL;

    /* The header length is 8 if it doesn't contain optional fields */
    header_length = 8;

    msg_length = tvb_get_guint16(tvb, offset+2, ENC_BIG_ENDIAN);
    offset += 8;

    /* Check if CRC is present */
    if (tvb_get_ntohl(tvb, offset) == RTITCP_CRC_MAGIC_NUMBER) {
        printCRC = TRUE;
        header_length += 8;
        offset += 8; /* Because of 0xCRC32 + actual CRC (4 bytes) */
    }

    /* Time to print the header */
    rtitcp_message = print_header(rtitcp_tree, rtitcp_message, tvb, offset_header, msg_length + header_length, printCRC, is_data);

    /* Check the control message kind */
    control_message_kind = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
                val_to_str(control_message_kind,ctrl_message_types_vals, "Unknown control message"));
    proto_tree_add_uint(rtitcp_message, hf_rtitcp_control_kind, tvb, offset, 2, control_message_kind);
    proto_item_set_text(rtitcp_message,"RTI TCP Control Message , Kind: %s",
            val_to_str(control_message_kind,ctrl_message_types_vals, "Unknown control message"));
    offset += 2;

    /* Take the length in bytes of the attributes list */
    attributes_list_length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(rtitcp_message, hf_rtitcp_attributes_list_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* We expect now the RTI TCP Control Magic Cookie */
    if (tvb_get_ntohl(tvb, offset) != RTITCP_CONTROL_MAGIC_COOKIE) {
        return msg_length + header_length;
    }
    proto_tree_add_item(rtitcp_message, hf_rtitcp_control_magic_cookie, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Now we dissect the transaction id */
    proto_tree_add_item(rtitcp_message, hf_rtitcp_control_transaction_id, tvb, offset, 12, ENC_NA);
    transaction_id_str = tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, 12);

    /* Get the transaction identifier. Not the whole transaction but the middle part, which
     * shouldn't coincide */
    seq_num = tvb_get_ntoh64(tvb, offset);

    /*
     * We need to track some state for this protocol on a per conversation
     * basis so we can do neat things like request/response tracking
     */
    conversation = find_or_create_conversation(pinfo);

    rtitcp_info = (rtitcp_conv_info_t *)conversation_get_proto_data(conversation, proto_rtitcp);
    if (!rtitcp_info) {
        /*
         * No.  Attach that information to the conversation, and add
         * it to the list of information structures.
         */
        rtitcp_info = wmem_new(wmem_file_scope(), rtitcp_conv_info_t);
        rtitcp_info->pdus=wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);

        conversation_add_proto_data(conversation, proto_rtitcp, rtitcp_info);
    }
    if (!pinfo->fd->flags.visited) {
        if (!(control_message_kind & RTITCP_FLAG_NOT_REQUEST)) {
            /* This is a request */
            rtitcp_trans=wmem_new(wmem_file_scope(), rtitcp_transaction_t);
            rtitcp_trans->req_frame = pinfo->num;
            rtitcp_trans->rep_frame = 0;
            rtitcp_trans->req_time = pinfo->abs_ts;
            conversation_info_key = (guint64*)wmem_alloc0(wmem_file_scope(), sizeof(guint64));
            *conversation_info_key = seq_num;
            wmem_map_insert(rtitcp_info->pdus, conversation_info_key, (void *)rtitcp_trans);
        } else {
            conversation_info_key = &seq_num;
            rtitcp_trans=(rtitcp_transaction_t *)wmem_map_lookup(rtitcp_info->pdus, conversation_info_key);
            if (rtitcp_trans) {
                rtitcp_trans->rep_frame = pinfo->num;
            }
        }
    } else {
        conversation_info_key = &seq_num;
        rtitcp_trans=(rtitcp_transaction_t *)wmem_map_lookup(rtitcp_info->pdus, conversation_info_key);
    }
    if (!rtitcp_trans) {
            /* create a "fake" rtitcp_trans structure */
            rtitcp_trans=wmem_new(wmem_packet_scope(), rtitcp_transaction_t);
            rtitcp_trans->req_frame = 0;
            rtitcp_trans->rep_frame = 0;
            rtitcp_trans->req_time = pinfo->abs_ts;
    }

    /* print state tracking in the tree */
    if (!(control_message_kind & RTITCP_FLAG_NOT_REQUEST)) {
        /* This is a request */
        if (rtitcp_trans->rep_frame) {
            proto_item *it;
            it = proto_tree_add_uint(rtitcp_message, hf_rtitcp_response_in,
                            tvb, 0, 0, rtitcp_trans->rep_frame);
            PROTO_ITEM_SET_GENERATED(it);
        }
    } else {
        /* This is a reply */
        if (rtitcp_trans->req_frame) {
            proto_item *it;
            nstime_t ns;
            it = proto_tree_add_uint(rtitcp_message, hf_rtitcp_response_to,
                            tvb, 0, 0, rtitcp_trans->req_frame);
            PROTO_ITEM_SET_GENERATED(it);

            nstime_delta(&ns, &pinfo->abs_ts, &rtitcp_trans->req_time);
            it = proto_tree_add_time(rtitcp_message, hf_rtitcp_response_time, tvb, 0, 0, &ns);
            PROTO_ITEM_SET_GENERATED(it);
        }
    }

    /* End of feature */
    offset += 12;

    /* Finally, dissect the list of attributes */
    attributes_list_offset = 0;
    attributes_list = proto_tree_add_subtree_format(rtitcp_message, tvb,
            attributes_list_offset+offset, attributes_list_length,
            ett_rtitcp_attributes_list, NULL, "Attributes List");

    attributes_count = 0;
    first_attribute = TRUE;
    while (attributes_list_offset < attributes_list_length) {
        ++attributes_count;
        attribute_offset = dissect_attribute(tvb, pinfo, attributes_list,
          offset, attributes_list_offset, rtitcp_message, &first_attribute);
        attributes_list_offset += attribute_offset;
    }
    if (!first_attribute) {
        proto_item_append_text(rtitcp_message,")");
        col_append_str(pinfo->cinfo, COL_INFO, ")");
    }
    /* Now that we have the number of attributes, update the text to show it */
    proto_item_set_text(attributes_list, "Attributes list [%d attribute%s",
        attributes_count, attributes_count > 1 ? "s]" : "]");

    proto_item_append_text(rtitcp_message,", Transaction ID: %s, Len: %d",
            transaction_id_str, msg_length);

    return msg_length + header_length;
}

/* This function dissects all the control messages found */
static guint dissect_rtitcp_control_protocol(proto_tree *rtitcp_tree, tvbuff_t *tvb, packet_info *pinfo) {
    guint messages_count, offset;
    guint16 msg_length;
    guint32 tvb_len;

    offset = 0;
    tvb_len = tvb_reported_length(tvb);

    messages_count = 0;

    while (offset < tvb_len) {
        msg_length = dissect_control_message(rtitcp_tree, tvb, pinfo, offset);
        offset += msg_length;
        ++messages_count;
    }

    return offset;
}

static gint dissect_rtitcp_common(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, void *data _U_) {

   /*                   FORMAT OF THE CONTROL MESSAGE

     0...2...........7...............15.............23...............31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |         control bytes         |    RTI TCP message length     |
   * +---------------+---------------+---------------+---------------+
   * |                     RTITCP_MAGIC_NUMBER                       |
   * +---------------+---------------+---------------+---------------+
   * |      control_message_kind     |    attributes_list_length     |
   * +---------------+---------------+---------------+---------------+
   * |                    RTITCP_CONTROL_MAGIC_COOKIE                |
   * +---------------+---------------+---------------+---------------+
   * |                                                               |
   * |-                                                             -|
   * |                         TRANSACTION_ID                        |
   * |-                                                             -|
   * |                                                               |
   * +---------------+---------------+---------------+---------------+   ---------------------------------
   * |       attribute_type          |       attribute_length ..         Repeat                          |
   * +---------------+---------------+---------------+---------------+   until                           |
   * |                       ATTRIBUTE (length)                      |   attributes_list_length expires  |
   * +---------------+---------------+---------------+---------------+   --------------------------------*/

    proto_item   *ti;
    proto_tree   *rtitcp_tree, *rtitcp_message = NULL;
    guint offset, offset_header;
    guint16 rtitcp_msg_length, header_length;
    guint32 tvb_len, rtitcp_rtps_msg_length;
    gboolean printCRC = FALSE, is_data = FALSE;
    tvbuff_t *next_tvb;
    heur_dtbl_entry_t *hdtbl_entry;

    offset = 0;
    tvb_len = tvb_reported_length(tvb);

    /* From this point, we can consider that this is a RTI TCP message */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTI-TCP");

    rtitcp_msg_length = tvb_get_guint16(tvb, offset+2, ENC_BIG_ENDIAN);

    ti = proto_tree_add_item(tree, proto_rtitcp, tvb, offset, -1, ENC_NA);
    rtitcp_tree = proto_item_add_subtree(ti, ett_rtitcp);

    offset_header = 0; /* Remember the offset that delimits the header */
    header_length = 8; /* the header is 8 bytes length + 8 optional (CRC) */
    offset += 2; /* First two bytes are CTRL bytes */
    offset += 2; /* rtitcp_msg_length */
    offset += 4; /* RTITCP_MAGIC_NUMBER has already been checked */

    /* if bytes 8 to 12 are RTITCP_CRC_MAGIC_NUMBER, we got a CRC */
    if (tvb_get_ntohl(tvb, offset) == RTITCP_CRC_MAGIC_NUMBER) {
        printCRC = TRUE; /* To specify later that CRC must be printed */
        header_length += 8; /* header increases in 8 bytes */
        offset += 8; /* Because of 0xCRC32 + actual CRC (4 bytes) */
    }
    proto_item_set_len(ti, rtitcp_msg_length + header_length);

    /* At this point, offset is 8 or 16 bytes and we have now data.
       This data can be RTPS or RTI TCP Signaling messages */
    if (tvb_get_ntohl(tvb, offset) == RTPS_MAGIC_NUMBER) {

        /* IMPORTANT NOTE: We assume always one RTPS message per RTITCP message */
        /* If the TCP layer has provided us with garbage at the end of the buffer,
           process only the length specified by rtitcp_msg_length */
        if (tvb_len > (guint32)(rtitcp_msg_length + header_length)) {
            tvb_set_reported_length(tvb, (rtitcp_msg_length + header_length));
        }

        /* When we encapsulate RTPS, packet length is given by the 30 less
           significant bits of the first four bytes */
        rtitcp_rtps_msg_length = tvb_get_guint32(tvb, 0, ENC_BIG_ENDIAN);
        rtitcp_rtps_msg_length = rtitcp_rtps_msg_length % NUMBER_2E30;
        /* Add RTI TCP Data Message subtree and print header */
        is_data = TRUE;
        rtitcp_message = print_header(rtitcp_tree, rtitcp_message, tvb, offset_header,
                                        rtitcp_rtps_msg_length + header_length, printCRC, is_data);

        proto_item_set_text(rtitcp_message,"RTI TCP Data Message, Len: %d",
                                rtitcp_rtps_msg_length);

        /* Take the payload and call the registered sub-dissectors. So far, RTPS */
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, NULL);
        return tvb_captured_length(tvb);

    } else {
        return dissect_rtitcp_control_protocol(rtitcp_tree, tvb, pinfo);
    }
}

static guint get_rtitcp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
        gint offset, void * data _U_) {
    guint16 plen;
    guint16 header_length = 8;
    /*
    * Get the length of the RTITCP packet.
    */
    plen = tvb_get_guint16(tvb, offset+2, ENC_BIG_ENDIAN);
    /*
    * That length doesn't include the header field itself; add that in.
    */
    if (tvb_get_ntohl(tvb, offset+8) == RTITCP_CRC_MAGIC_NUMBER)
        header_length += 8;
    /* We don't expect plen to be greater than 0xfff8 since adding the header
     * exceeds the size */
    if (plen >= 0xfff8)
        return 1;

    return plen + header_length;
}
static gint dissect_rtitcp(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, void *data _U_) {

    gboolean desegmentation = TRUE;

    if (tvb_captured_length(tvb) < 8)
        return 0;

    /* Check if the RTITCP_MAGIC_NUMBER is here */
    if (tvb_get_ntohl(tvb, 4) != RTITCP_MAGIC_NUMBER)
        return 0;

    col_clear(pinfo->cinfo, COL_INFO);

    tcp_dissect_pdus(tvb, pinfo, tree, desegmentation, RTITCP_MIN_LENGTH,
            get_rtitcp_pdu_len, dissect_rtitcp_common, data);

    return tvb_captured_length(tvb);

}


/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_rtitcp(void)
{
    /* module_t *rtitcp_module; */
    /* expert_module_t* expert_rtitcp; */

    static hf_register_info hf[] = {

        { &hf_rtitcp_header_control_byte, {
            "Control Byte", "rtitcp.header.control_byte",
            FT_UINT8, BASE_HEX, NULL, 0,
            0, HFILL }
        },

        { &hf_rtitcp_header_message_length, {
            "Message Length", "rtitcp.header.message_length",
            FT_UINT16, BASE_DEC, NULL, 0,
            0, HFILL }
        },

        { &hf_rtitcp_header_magic_number, {
            "Magic Cookie", "rtitcp.header.magic_cookie",
            FT_UINT32, BASE_HEX, NULL, 0,
            0, HFILL }
        },

        { &hf_rtitcp_crc_magic_cookie, {
            "CRC Magic Cookie", "rtitcp.header.crc_magic_cookie",
            FT_UINT32, BASE_HEX, NULL, 0,
            0, HFILL }
        },

        { &hf_rtitcp_control_kind,
          { "Kind", "rtitcp.control.kind",
            FT_UINT16, BASE_HEX, VALS(ctrl_message_types_vals), 0,
            NULL, HFILL }
        },

        { &hf_rtitcp_control_magic_cookie, {
            "Control Magic Cookie", "rtitcp.control.magic_cookie",
            FT_UINT32, BASE_HEX, NULL, 0,
            0, HFILL }
        },

        { &hf_rtitcp_control_transaction_id, {
            "Transaction ID", "rtitcp.control.transaction_id",
            FT_BYTES, BASE_NONE, NULL, 0,
            0, HFILL }
        },

        { &hf_rtitcp_control_attribute_session_id, {
            "Session ID", "rtitcp.control.attribute.session_id",
            FT_BYTES, BASE_NONE, NULL, 0,
            0, HFILL }
        },

        { &hf_rtitcp_control_attribute_type,
          { "Attribute Type", "rtitcp.control.attribute_type",
            FT_UINT16, BASE_HEX, VALS(attribute_types_vals), 0,
            NULL, HFILL }
        },

        { &hf_rtitcp_control_attribute_error_code_value,
          { "Kind", "rtitcp.control.attribute.error_code",
            FT_UINT32, BASE_HEX, VALS(error_code_kind_vals), 0,
            NULL, HFILL }
        },

        { &hf_rtitcp_control_attribute_error_code_description, {
            "Description", "rtitcp.control.attribute.error_code.description",
            FT_STRING, BASE_NONE, NULL, 0,
            0, HFILL }
        },

        { &hf_rtitcp_control_attribute_connection_cookie, {
            "Connection Cookie", "rtitcp.control.attribute.connection_cookie",
            FT_BYTES, BASE_NONE, NULL, 0,
            0, HFILL }
        },

        { &hf_rtitcp_control_attribute_connection_type, {
            "Class ID", "rtitcp.control_attribute.connection_type",
            FT_UINT8, BASE_HEX, VALS(rtitcp_attribute_connection_type_vals), 0,
            0, HFILL }
        },

        { &hf_rtitcp_attributes_list_length, {
            "Attributes list length", "rtitcp.attributes_list_length",
            FT_UINT16, BASE_DEC, NULL, 0,
            0,
            HFILL }
        },

        { &hf_rtitcp_control_attribute_length, {
            "Attribute Length", "rtitcp.control.attribute.length",
            FT_UINT16, BASE_DEC, NULL, 0,
            0, HFILL }
        },

        { &hf_rtitcp_control_attribute_port, {
            "Port", "rtitcp.control.attribute_port",
            FT_UINT32, BASE_DEC, NULL, 0,
            0, HFILL }
        },

        { &hf_rtitcp_locator_kind,
          { "Kind", "rtitcp.locator.kind",
            FT_UINT16, BASE_DEC, VALS(rtitcp_locator_kind_vals), 0,
            NULL, HFILL }
        },

        { &hf_rtitcp_locator_ipv4,
          { "Address", "rtitcp.locator.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },

        { &hf_rtitcp_locator_port,
          { "Port", "rtitcp.locator.port",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },

        { &hf_rtitcp_locator_ipv6,
          { "Address", "rtitcp.locator.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },

        { &hf_rtitcp_control_crc_value, {
         "CRC", "rtitcp.control.crc",
         FT_UINT32, BASE_HEX, NULL, 0,
         0, HFILL }
        },

        { &hf_rtitcp_response_in, {
         "Response In", "rtitcp.response_in",
         FT_FRAMENUM, BASE_NONE, NULL, 0x0,
         "The response to this RTITCP request is in this frame", HFILL }
        },

        { &hf_rtitcp_response_to, {
         "Request In", "rtitcp.response_to",
         FT_FRAMENUM, BASE_NONE, NULL, 0x0,
         "This is a response to the RTITCP request in this frame", HFILL }
        },

        { &hf_rtitcp_response_time, {
         "Response Time", "rtitcp.response_time",
         FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
         "The time between the Request and the Reply", HFILL }
        },

    };

    static gint *ett[] = {
        &ett_rtitcp,
        &ett_rtitcp_signalling_protocol,
        &ett_rtitcp_message,
        &ett_rtitcp_attributes_list,
        &ett_rtitcp_attribute
    };

    /* Setup protocol expert items */
    /* static ei_register_info ei[] = {}; */

    /* Register the protocol name and description */
    proto_rtitcp = proto_register_protocol("RTI TCP Transport Protocol",
            "RTITCP", "rtitcp");

    hfi_rtitcp = proto_registrar_get_nth(proto_rtitcp);
    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_rtitcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    /* expert_rtitcp = expert_register_protocol(proto_rtitcp);
     expert_register_field_array(expert_rtitcp, ei, array_length(ei)); */

    register_dissector("rtitcp", dissect_rtitcp, proto_rtitcp);
    heur_subdissector_list = register_heur_dissector_list("rtitcp", proto_rtitcp);

}

/* Simpler form of proto_reg_handoff_rtitcp which can be used if there are
 * no prefs-dependent registration function calls. */
void
proto_reg_handoff_rtitcp(void)
{
    heur_dissector_add("tcp", dissect_rtitcp, "RTI TCP Layer" , "rtitcp", proto_rtitcp, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
