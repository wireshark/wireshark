/* packet-xmcp.c
 * Routines for eXtensible Messaging Client Protocol (XMCP) dissection
 * Copyright 2011, Glenn Matthews <glenn.matthews@cisco.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-stun.c
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *
 * XMCP is a proprietary Cisco protocol based very loosely on the
 * Session Traversal Utilities for NAT (STUN) protocol.
 * This dissector is capable of understanding XMCP versions 1.0 and 2.0.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include <packet-tcp.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/expert.h>

static dissector_table_t media_type_dissector_table;

/* Initialize the protocol and registered fields */
static int proto_xmcp = -1;

static int hf_xmcp_response_in = -1;
static int hf_xmcp_response_to = -1;
static int hf_xmcp_time = -1;

typedef struct _xmcp_transaction_t {
  guint32 request_frame;
  guint32 response_frame;
  nstime_t request_time;
  gboolean request_is_keepalive;
} xmcp_transaction_t;

typedef struct _xmcp_conv_info_t {
  emem_tree_t *transaction_pdus;
} xmcp_conv_info_t;

static int hf_xmcp_type = -1;
static int hf_xmcp_type_reserved = -1;
static int hf_xmcp_type_class = -1;
static int hf_xmcp_type_method = -1;
static int hf_xmcp_length = -1;
static int hf_xmcp_cookie = -1;
static int hf_xmcp_id = -1;
static int hf_xmcp_attributes = -1;
static int hf_xmcp_attr = -1;
static int hf_xmcp_msg_is_keepalive = -1;

static int xmcp_attr_type = -1;
static int xmcp_attr_length = -1;
static int xmcp_attr_value = -1; /* generic value for unrecognized attrs */
static int xmcp_attr_padding = -1; /* generic value for TLV padding bytes */
static int xmcp_attr_reserved = -1;
static int xmcp_attr_username = -1;
static int xmcp_attr_message_integrity = -1;
static int xmcp_attr_error_reserved = -1;
static int xmcp_attr_error_class = -1;
static int xmcp_attr_error_number = -1;
static int xmcp_attr_error_code = -1;
static int xmcp_attr_error_reason = -1;
static int xmcp_attr_realm = -1;
static int xmcp_attr_nonce = -1;
static int xmcp_attr_client_name = -1;
static int xmcp_attr_client_handle = -1;
static int xmcp_attr_version_major = -1;
static int xmcp_attr_version_minor = -1;
static int xmcp_attr_page_size = -1;
static int xmcp_attr_client_label = -1;
static int xmcp_attr_keepalive = -1;
static int xmcp_attr_serv_service = -1;
static int xmcp_attr_serv_subservice = -1;
static int xmcp_attr_serv_instance = -1;
static int xmcp_attr_servtrans_family = -1;
static int xmcp_attr_servtrans_port = -1;
static int xmcp_attr_servtrans_ipv4 = -1;
static int xmcp_attr_servtrans_ipv6 = -1;
static int xmcp_attr_service_protocol = -1;
static int xmcp_attr_flag = -1;
static int xmcp_attr_flag_type = -1;
static int xmcp_attr_flag_value = -1;
static int xmcp_attr_flag_removal_reason_network_withdraw = -1;
static int xmcp_attr_flag_removal_reason_reserved = -1;
static int xmcp_attr_flag_trust = -1;
static int xmcp_attr_flag_visibility_unauthenticated = -1;
static int xmcp_attr_flag_visibility_reserved = -1;
static int xmcp_attr_service_version = -1;
static int xmcp_attr_service_data = -1;
static int xmcp_attr_subscription_id = -1;
static int xmcp_attr_service_removed_reason = -1;
static int xmcp_attr_domain = -1;

static gint ett_xmcp = -1;
static gint ett_xmcp_type = -1;
static gint ett_xmcp_attr_all = -1;
static gint ett_xmcp_attr = -1;
static gint ett_xmcp_attr_flag = -1;

#define TCP_PORT_XMCP 4788
#define XMCP_MAGIC_COOKIE 0x7f5a9bc7

void proto_reg_handoff_xmcp(void);
static guint global_xmcp_tcp_port = TCP_PORT_XMCP;

#define XMCP_HDR_LEN ((guint)20)
#define XMCP_ATTR_HDR_LEN 4

#define XMCP_TYPE_RESERVED      0xc000
#define XMCP_TYPE_CLASS         0x0110
#define XMCP_TYPE_METHOD        0x3eef

static const int *xmcp_type_fields[] = {
  &hf_xmcp_type_reserved,
  &hf_xmcp_type_method,
  &hf_xmcp_type_class,
  NULL
};

#define XMCP_CLASS_REQUEST              0x00
#define XMCP_CLASS_RESERVED             0x01
#define XMCP_CLASS_RESPONSE_SUCCESS     0x10
#define XMCP_CLASS_RESPONSE_ERROR       0x11

static const value_string classes[] = {
  {XMCP_CLASS_REQUEST,          "Request"},
  {XMCP_CLASS_RESERVED,         "RESERVED-CLASS"},
  {XMCP_CLASS_RESPONSE_SUCCESS, "Success Response"},
  {XMCP_CLASS_RESPONSE_ERROR,   "Error Response"},
  {0,   NULL}
};

#define XMCP_METHOD_ILLEGAL     0x000
#define XMCP_METHOD_REGISTER    0x001
#define XMCP_METHOD_UNREGISTER  0x002
#define XMCP_METHOD_REG_REVOKE  0x003
#define XMCP_METHOD_PUBLISH     0x004
#define XMCP_METHOD_UNPUBLISH   0x005
#define XMCP_METHOD_PUB_REVOKE  0x006
#define XMCP_METHOD_SUBSCRIBE   0x007
#define XMCP_METHOD_UNSUBSCRIBE 0x008
#define XMCP_METHOD_WITHDRAW    0x009
#define XMCP_METHOD_NOTIFY      0x00a
#define XMCP_METHOD_KEEPALIVE   0x00b

static const value_string methods[] = {
  {XMCP_METHOD_ILLEGAL,         "Illegal"},
  {XMCP_METHOD_REGISTER,        "Register"},
  {XMCP_METHOD_UNREGISTER,      "Unregister"},
  {XMCP_METHOD_REG_REVOKE,      "RegisterRevoke"},
  {XMCP_METHOD_PUBLISH,         "Publish"},
  {XMCP_METHOD_UNPUBLISH,       "Unpublish"},
  {XMCP_METHOD_PUB_REVOKE,      "PublishRevoke"},
  {XMCP_METHOD_SUBSCRIBE,       "Subscribe"},
  {XMCP_METHOD_UNSUBSCRIBE,     "Unsubscribe"},
  {XMCP_METHOD_WITHDRAW,        "Withdraw"},
  {XMCP_METHOD_NOTIFY,          "Notify"},
  {XMCP_METHOD_KEEPALIVE,       "Keepalive"},
  {0,   NULL}
};

#define XMCP_USERNAME                   0x0006
#define XMCP_MESSAGE_INTEGRITY          0x0008
#define XMCP_ERROR_CODE                 0x0009
#define XMCP_REALM                      0x0014
#define XMCP_NONCE                      0x0015
#define XMCP_CLIENT_NAME                0x1001
#define XMCP_CLIENT_HANDLE              0x1002
#define XMCP_PROTOCOL_VERSION           0x1003
#define XMCP_PAGE_SIZE                  0x1004
#define XMCP_CLIENT_LABEL               0x1005
#define XMCP_KEEPALIVE                  0x1006
#define XMCP_SERVICE_IDENTITY           0x1007
#define XMCP_SERVICE_TRANSPORT          0x1008
#define XMCP_SERVICE_PROTOCOL           0x1009
#define XMCP_FLAGS                      0x100a
#define XMCP_SERVICE_VERSION            0x100b
#define XMCP_SERVICE_DATA               0x100c
#define XMCP_SUBSCRIPTION_ID            0x100e
#define XMCP_SERVICE_REMOVED_REASON     0x100f
#define XMCP_DOMAIN                     0x1011

static const value_string attributes[] = {
  /* Attributes inherited from STUN */
  {XMCP_USERNAME,               "Username"},
  {XMCP_MESSAGE_INTEGRITY,      "Message-Integrity"},
  {XMCP_ERROR_CODE,             "Error-Code"},
  {XMCP_REALM,                  "Realm"},
  {XMCP_NONCE,                  "Nonce"},
  /* Attributes specific to XMCP */
  {XMCP_CLIENT_NAME,            "Client-Name"},
  {XMCP_CLIENT_HANDLE,          "Client-Handle"},
  {XMCP_PROTOCOL_VERSION,       "Protocol-Version"},
  {XMCP_PAGE_SIZE,              "PageSize"},
  {XMCP_CLIENT_LABEL,           "ClientLabel"},
  {XMCP_KEEPALIVE,              "Keepalive"},
  {XMCP_SERVICE_IDENTITY,       "ServiceIdentity"},
  {XMCP_SERVICE_TRANSPORT,      "ServiceTransportAddr"},
  {XMCP_SERVICE_PROTOCOL,       "ServiceProtocol"},
  {XMCP_FLAGS,                  "Flags"},
  {XMCP_SERVICE_VERSION,        "ServiceVersion"},
  {XMCP_SERVICE_DATA,           "ServiceData"},
  {XMCP_SUBSCRIPTION_ID,        "SubscriptionID"},
  {XMCP_SERVICE_REMOVED_REASON, "ServiceRemovedReason"},
  {XMCP_DOMAIN,                 "Domain"},
  {0,   NULL}
};

static const value_string error_codes[] = {
  {400, "Bad Request"},
  {401, "Unauthorized"},
  {413, "Request Too Large"},
  {431, "Integrity Check Failure"},
  {435, "Nonce Required"},
  {436, "Unknown Username"},
  {438, "Stale Nonce"},
  {471, "Bad Client Handle"},
  {472, "Version Number Too Low"},
  {473, "Unknown Service"},
  {474, "Unregistered"},
  {475, "Invalid ServiceIdentity"},
  {476, "Unknown Subscription"},
  {477, "Already Registered"},
  {478, "Unsupported Protocol Version"},
  {479, "Unknown or Forbidden Domain"},
  {499, "Miscellaneous Request Error"},
  {500, "Responder Error"},
  {501, "Not Implemented"},
  {0,   NULL}
};

static const value_string address_families[] = {
  {0x01, "IPv4"},
  {0x02, "IPv6"},
  {0, NULL}
};

#define XMCP_FLAG_REMOVAL_REASON        0x0001
#define XMCP_FLAG_TRUST         0x0002
#define XMCP_FLAG_SERVICE_VISIBILITY    0x0003

static const value_string flag_types[] = {
  {XMCP_FLAG_REMOVAL_REASON,            "Removal Reason"},
  {XMCP_FLAG_TRUST,                     "Trust"},
  {XMCP_FLAG_SERVICE_VISIBILITY,        "Service Visibility"},
  {0, NULL}
};

/* Values for specific flag types */
#define XMCP_REMOVAL_REASON_NETWORK_WITHDRAW    0x0001
#define XMCP_REMOVAL_REASON_RESERVED            0xfffe

#define XMCP_TRUST_LOCAL 0
#define XMCP_TRUST_LEARNED 1

static const value_string flag_trust_values[] = {
  {XMCP_TRUST_LOCAL,    "Local"},
  {XMCP_TRUST_LEARNED,  "Learned"},
  {0, NULL}
};

#define XMCP_SERVICE_VISIBILITY_UNAUTHENTICATED 0x0001
#define XMCP_SERVICE_VISIBILITY_RESERVED        0xfffe

static const value_string service_removed_reasons[] = {
  {0,   "Network withdraw"},
  {1,   "Source withdraw"},
  {0,   NULL}
};

/* Dissector state variables */
static guint16 xmcp_msg_type_method = XMCP_METHOD_ILLEGAL;
static guint16 xmcp_msg_type_class = XMCP_CLASS_RESERVED;
static gboolean xmcp_msg_is_keepalive = FALSE;
static gint16 xmcp_service_protocol = -1;
static gint32 xmcp_service_port = -1;
static proto_item *xmcp_it_service_port = NULL;

static guint
get_xmcp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  return(XMCP_HDR_LEN + tvb_get_ntohs(tvb, offset+2));
}

static guint16
get_xmcp_attr_padded_len(guint16 attr_length)
{
  /*
   * As in STUN, all XMCP attributes report their length in bytes,
   * but are padded to the next 4-byte multiple.
   */
  return((attr_length + 3) & 0xfffc);
}

static guint16
get_xmcp_attr_fixed_len(guint16 xmcp_attr)
{
  /*
   * For fixed-length attributes, return their length.
   * For variable-length attributes, return 0.
   */
  switch (xmcp_attr) {
  case XMCP_CLIENT_HANDLE:
  case XMCP_PROTOCOL_VERSION:
  case XMCP_PAGE_SIZE:
  case XMCP_KEEPALIVE:
  case XMCP_SERVICE_PROTOCOL:
  case XMCP_SERVICE_VERSION:
  case XMCP_SUBSCRIPTION_ID:
  case XMCP_SERVICE_REMOVED_REASON:
  case XMCP_DOMAIN:
    return(4);
  case XMCP_SERVICE_IDENTITY:
    return(20);
  default:
    return(0);
  }
}

static guint16
get_xmcp_attr_min_len(guint16 xmcp_attr)
{
  switch (xmcp_attr) {
  case XMCP_USERNAME:
  case XMCP_NONCE:
  case XMCP_CLIENT_NAME:
  case XMCP_CLIENT_LABEL:
    return(1);
  case XMCP_ERROR_CODE:
    return(4);
  case XMCP_SERVICE_TRANSPORT:
    return(8); /* 4-byte fixed plus an IPv4 address */
  case XMCP_MESSAGE_INTEGRITY:
    return(20); /* HMAC-SHA1 */
  default:
    return(get_xmcp_attr_fixed_len(xmcp_attr));
  }
}

static guint16
get_xmcp_attr_max_len(guint16 xmcp_attr) {
  guint16 fixed_len;

  switch (xmcp_attr) {
  case XMCP_SERVICE_TRANSPORT:
    return(20); /* 4-byte fixed plus an IPv6 address */
  case XMCP_MESSAGE_INTEGRITY:
    return(32); /* HMAC-SHA-256 */
  case XMCP_NONCE:
  case XMCP_CLIENT_NAME:
  case XMCP_CLIENT_LABEL:
    return(255);
  default:
    fixed_len = get_xmcp_attr_fixed_len(xmcp_attr);
    return(fixed_len ? fixed_len : 0xffff);
  }
}

static void
add_xmcp_port_name (void)
{
  if (!xmcp_it_service_port || xmcp_service_port == -1)
    return;

  switch(xmcp_service_protocol) {
  case IP_PROTO_TCP:
    proto_item_append_text(xmcp_it_service_port, " (TCP: %s)",
                           get_tcp_port(xmcp_service_port));
    break;
  case IP_PROTO_UDP:
    proto_item_append_text(xmcp_it_service_port, " (UDP: %s)",
                           get_udp_port(xmcp_service_port));
    break;
  case IP_PROTO_DCCP:
    proto_item_append_text(xmcp_it_service_port, " (DCCP: %s)",
                           get_dccp_port(xmcp_service_port));
    break;
  case IP_PROTO_SCTP:
    proto_item_append_text(xmcp_it_service_port, " (SCTP: %s)",
                           get_sctp_port(xmcp_service_port));
    break;
  default:
    break;
  }
}

static void
decode_xmcp_attr_value (proto_tree *attr_tree, guint16 attr_type,
                        guint16 attr_length, tvbuff_t *tvb, guint16 offset,
                        packet_info *pinfo)
{
  proto_item *it;

  switch (attr_type) {
  case XMCP_USERNAME:
    proto_tree_add_item(attr_tree, xmcp_attr_username, tvb, offset,
                        attr_length, FALSE);
    proto_item_append_text(attr_tree, ": %s",
                           tvb_get_ephemeral_string(tvb, offset, attr_length));
    /*
     * Many message methods may include this attribute,
     * but it's only interesting when Registering at first
     */
    if (xmcp_msg_type_method == XMCP_METHOD_REGISTER &&
        check_col(pinfo->cinfo, COL_INFO)) {
      col_append_fstr(pinfo->cinfo, COL_INFO, ", user \"%s\"",
                      tvb_get_ephemeral_string(tvb, offset, attr_length));
    }
    break;
  case XMCP_MESSAGE_INTEGRITY:
    proto_tree_add_item(attr_tree, xmcp_attr_message_integrity, tvb, offset,
                        attr_length, FALSE);
    /* Message-integrity should be the last attribute in the message */
    if (offset + get_xmcp_attr_padded_len(attr_length) <
        tvb_reported_length(tvb)) {
      expert_add_info_format(pinfo, attr_tree, PI_PROTOCOL, PI_WARN,
                             "Data following message-integrity");
    }
    break;
  case XMCP_ERROR_CODE:
    if (attr_length < 4)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_error_reserved, tvb, offset,
                        3, FALSE);
    proto_tree_add_item(attr_tree, xmcp_attr_error_class, tvb, offset,
                        3, FALSE);
    {
      guint8 error_class, error_number;
      guint16 error_code;
      it = proto_tree_add_item(attr_tree, xmcp_attr_error_number, tvb,
                               (offset+3), 1, FALSE);

      error_class = tvb_get_guint8(tvb, offset+2) & 0x07;
      error_number = tvb_get_guint8(tvb, offset+3);

      if (error_number > 99) {
        expert_add_info_format(pinfo, it, PI_PROTOCOL, PI_WARN,
                               "Error number out of 0-99 range");
      } else {
        /* Error code = error class + (error num % 100) */
        error_code = (error_class * 100) + error_number;
        it = proto_tree_add_uint_format(attr_tree, xmcp_attr_error_code, tvb,
                                        (offset+2), 2, error_code,
                                        "Error Code: %d (%s)", error_code,
                                        val_to_str(error_code, error_codes,
                                                   "Unknown"));
        PROTO_ITEM_SET_GENERATED(it);
        proto_item_append_text(attr_tree, ": %d", error_code);
        if (check_col(pinfo->cinfo, COL_INFO)) {
          col_append_fstr(pinfo->cinfo, COL_INFO, ", error %d (%s)", error_code,
                          val_to_str(error_code, error_codes, "Unknown"));
        }

        /*
         * All error responses default to a PI_NOTE severity.
         * Some specific error codes are more significant, so mark them up.
         */
        switch (error_code) {
        case 400: /* Bad Request */
        case 431: /* Integrity Check Failure */
        case 473: /* Unknown Service */
        case 476: /* Unknown Subscription */
        case 477: /* Already Registered */
        case 499: /* Miscellaneous Request Error */
        case 500: /* Responder Error */
          expert_add_info_format(pinfo, it, PI_RESPONSE_CODE, PI_WARN,
                                 "Unusual error code (%u, %s)", error_code,
                                 val_to_str(error_code, error_codes,
                                            "Unknown"));
          break;
        default:
          break;
        }
      }
    }
    if (attr_length < 5)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_error_reason, tvb, (offset+4),
                        (attr_length - 4), FALSE);
    proto_item_append_text(attr_tree, " (%s)",
                           tvb_get_ephemeral_string(tvb, (offset+4),
                                                    (attr_length-4)));
    break;
  case XMCP_REALM:
    proto_tree_add_item(attr_tree, xmcp_attr_realm, tvb, offset,
                        attr_length, FALSE);
    {
      guint8 *realm;
      realm = tvb_get_ephemeral_string(tvb, offset, attr_length);
      proto_item_append_text(attr_tree, ": %s", realm);
      /* In XMCP the REALM string should always be "SAF" including the quotes */
      if (attr_length != 5 || strncmp(realm, "\"SAF\"", attr_length)) {
        expert_add_info_format(pinfo, attr_tree, PI_PROTOCOL, PI_WARN,
                               "Incorrect Realm");
      }
    }
    break;
  case XMCP_NONCE:
    proto_tree_add_item(attr_tree, xmcp_attr_nonce, tvb, offset,
                        attr_length, FALSE);
    proto_item_append_text(attr_tree, ": %s",
                           tvb_get_ephemeral_string(tvb, offset, attr_length));
    break;
  case XMCP_CLIENT_NAME:
    proto_tree_add_item(attr_tree, xmcp_attr_client_name, tvb, offset,
                        attr_length, FALSE);
    proto_item_append_text(attr_tree, ": %s",
                           tvb_get_ephemeral_string(tvb, offset, attr_length));
    if (check_col(pinfo->cinfo, COL_INFO)) {
      col_append_fstr(pinfo->cinfo, COL_INFO, ", name \"%s\"",
                      tvb_get_ephemeral_string(tvb, offset, attr_length));
    }
    break;
  case XMCP_CLIENT_HANDLE:
    if (attr_length < 4)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_client_handle, tvb, offset,
                        4, FALSE);
    proto_item_append_text(attr_tree, ": %u", tvb_get_ntohl(tvb, offset));
    if (check_col(pinfo->cinfo, COL_INFO)) {
      col_append_fstr(pinfo->cinfo, COL_INFO, ", handle %u",
                      tvb_get_ntohl(tvb, offset));
    }
    /*
     * A Register request containing a Client-Handle is considered
     * to be a Keepalive.
     */
    if (xmcp_msg_type_method == XMCP_METHOD_REGISTER &&
        xmcp_msg_type_class == XMCP_CLASS_REQUEST) {
      xmcp_msg_is_keepalive = TRUE;
    }
    break;
  case XMCP_PROTOCOL_VERSION:
    if (attr_length < 2)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_version_major, tvb, offset,
                        2, FALSE);
    if (attr_length < 4)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_version_minor, tvb, (offset+2),
                        2, FALSE);
    proto_item_append_text(attr_tree, ": %u.%u", tvb_get_ntohs(tvb, offset),
                           tvb_get_ntohs(tvb, (offset+2)));
    break;
  case XMCP_PAGE_SIZE:
    if (attr_length < 4)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_page_size, tvb, offset, 4, FALSE);
    proto_item_append_text(attr_tree, ": %u", tvb_get_ntohl(tvb, offset));
    break;
  case XMCP_CLIENT_LABEL:
    proto_tree_add_item(attr_tree, xmcp_attr_client_label, tvb, offset,
                        attr_length, FALSE);
    proto_item_append_text(attr_tree, ": %s",
                           tvb_get_ephemeral_string(tvb, offset, attr_length));
    if (check_col(pinfo->cinfo, COL_INFO)) {
      col_append_fstr(pinfo->cinfo, COL_INFO, ", label \"%s\"",
                      tvb_get_ephemeral_string(tvb, offset, attr_length));
    }
    break;
  case XMCP_KEEPALIVE:
    if (attr_length < 4)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_keepalive, tvb, offset, 4, FALSE);
    proto_item_append_text(attr_tree, ": %u", tvb_get_ntohl(tvb, offset));
    break;
  case XMCP_SERVICE_IDENTITY:
    if (attr_length < 2)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_serv_service, tvb, offset,
                        2, FALSE);
    if (attr_length < 4)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_serv_subservice, tvb, (offset+2),
                        2, FALSE);
    if (attr_length < 20)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_serv_instance, tvb, (offset+4),
                        16, FALSE);
    {
      e_guid_t guid;
      char buf[GUID_STR_LEN];
      tvb_get_guid(tvb, (offset+4), &guid, FALSE);
      guid_to_str_buf(&guid, buf, sizeof(buf));
      proto_item_append_text(attr_tree, ": %u:%u:%s",
                             tvb_get_ntohs(tvb, offset),
                             tvb_get_ntohs(tvb, (offset+2)), buf);
      if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", service %u:%u:%s",
                        tvb_get_ntohs(tvb, offset),
                        tvb_get_ntohs(tvb, (offset+2)), buf);
      }
    }
    break;
  case XMCP_SERVICE_TRANSPORT:
    /*
     * One byte of padding, one byte indicating family,
     * two bytes for port, followed by addr
     */
    if (attr_length < 1)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_reserved, tvb, offset, 1, FALSE);
    if (attr_length < 2)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_servtrans_family, tvb,
                        (offset+1), 1, FALSE);
    if (attr_length < 4)
      break;
    xmcp_service_port = tvb_get_ntohs(tvb, (offset+2));
    xmcp_it_service_port = proto_tree_add_item(attr_tree,
                                               xmcp_attr_servtrans_port,
                                               tvb, (offset+2), 2, FALSE);
    /* If we now know both port and protocol number, fill in the port name */
    if (xmcp_service_protocol != -1) {
      add_xmcp_port_name();
    }
    switch (tvb_get_guint8(tvb, (offset+1))) {
    case 0x01: /* IPv4 */
      if (attr_length != 8) {
        expert_add_info_format(pinfo, attr_tree, PI_PROTOCOL, PI_WARN,
                               "Malformed IPv4 address");
      } else {
        guint32 ip;
        proto_tree_add_item(attr_tree, xmcp_attr_servtrans_ipv4, tvb,
                            (offset+4), 4, FALSE);
        ip = tvb_get_ipv4(tvb, (offset+4));
        proto_item_append_text(attr_tree, ": %s:%u", ip_to_str((guint8 *)&ip),
                               tvb_get_ntohs(tvb, (offset+2)));
      }
      break;
    case 0x02: /* IPv6 */
      if (attr_length != 20) {
        expert_add_info_format(pinfo, attr_tree, PI_PROTOCOL, PI_WARN,
                               "Malformed IPv6 address");
      } else {
        struct e_in6_addr ipv6;
        proto_tree_add_item(attr_tree, xmcp_attr_servtrans_ipv6, tvb,
                            (offset+4), 16, FALSE);
        tvb_get_ipv6(tvb, (offset+4), &ipv6);
        proto_item_append_text(attr_tree, ": [%s]:%u", ip6_to_str(&ipv6),
                               tvb_get_ntohs(tvb, (offset+2)));
      }
      break;
    default:
      expert_add_info_format(pinfo, attr_tree, PI_PROTOCOL, PI_WARN,
                             "Unknown transport type");
      break;
    }
    break;
  case XMCP_SERVICE_PROTOCOL:
    /* Three bytes of padding followed by a 1-byte protocol number */
    if (attr_length < 4)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_reserved, tvb, offset, 3, FALSE);
    proto_tree_add_item(attr_tree, xmcp_attr_service_protocol, tvb,
                        (offset+3), 1, FALSE);
    xmcp_service_protocol = tvb_get_guint8(tvb, (offset+3));
    proto_item_append_text(attr_tree, ": %u (%s)", xmcp_service_protocol,
                           val_to_str_ext(xmcp_service_protocol,
                                          &ipproto_val_ext, "Unknown"));
    /* If we now know both port and protocol number, fill in the port name */
    if (xmcp_service_port != -1 && xmcp_it_service_port != NULL) {
      add_xmcp_port_name();
    }
    break;
  case XMCP_FLAGS:
    /* Flags is a series of type-value pairs */
    if (attr_length % 4 != 0) {
      expert_add_info_format(pinfo, attr_tree, PI_PROTOCOL, PI_WARN,
                             "Malformed Flags - length not divisible by 4");
    }
    {
      guint16 flag_type, flag_value, current_offset = offset;
      proto_item *ti;
      proto_tree *flag_tree;
      while ((current_offset-offset)+3 < attr_length) {
        flag_type = tvb_get_ntohs(tvb, (current_offset));
        flag_value = tvb_get_ntohs(tvb, (current_offset+2));
        ti = proto_tree_add_none_format(attr_tree, xmcp_attr_flag, tvb,
                                        current_offset, 4,
                                        "Flag: %s:",
                                        val_to_str_const(flag_type, flag_types,
                                                         "Unknown"));
        flag_tree = proto_item_add_subtree(ti, ett_xmcp_attr_flag);
        proto_tree_add_item(flag_tree, xmcp_attr_flag_type, tvb,
                            current_offset, 2, FALSE);

        current_offset += 2;
        switch (flag_type) {
        case XMCP_FLAG_REMOVAL_REASON:
          proto_tree_add_item(flag_tree, xmcp_attr_flag_removal_reason_reserved,
                              tvb, current_offset, 2, FALSE);
          proto_tree_add_item(flag_tree,
                              xmcp_attr_flag_removal_reason_network_withdraw,
                              tvb, current_offset, 2, FALSE);
          if (flag_value & XMCP_REMOVAL_REASON_NETWORK_WITHDRAW) {
            proto_item_append_text(flag_tree, " (network withdraw)");
          }
          if (!flag_value) {
            proto_item_append_text(flag_tree, " (source withdraw)");
          }
          break;
        case XMCP_FLAG_TRUST:
          proto_tree_add_item(flag_tree, xmcp_attr_flag_trust, tvb,
                              current_offset, 2, FALSE);
          proto_item_append_text(flag_tree, " %s",
                                 val_to_str_const(flag_value, flag_trust_values,
                                                  "Unknown"));
          break;
        case XMCP_FLAG_SERVICE_VISIBILITY:
          proto_tree_add_item(flag_tree, xmcp_attr_flag_visibility_reserved,
                              tvb, current_offset, 2, FALSE);
          proto_tree_add_item(flag_tree,
                              xmcp_attr_flag_visibility_unauthenticated,
                              tvb, current_offset, 2, FALSE);
          if (flag_value & XMCP_SERVICE_VISIBILITY_UNAUTHENTICATED) {
            proto_item_append_text(flag_tree,
                                   " (visible to unauthenticated clients)");
          }
          if (!flag_value) {
            proto_item_append_text(flag_tree, " (default)");
          }
          break;
        default:
          proto_tree_add_item(flag_tree, xmcp_attr_flag_value, tvb,
                              current_offset, 2, FALSE);
          proto_item_append_text(flag_tree, " 0x%04x", flag_value);
          break;
        }
        current_offset += 2;
      }
    }
    break;
  case XMCP_SERVICE_VERSION:
    if (attr_length < 4)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_service_version, tvb, offset,
                        4, FALSE);
    proto_item_append_text(attr_tree, ": %u", tvb_get_ntohl(tvb, offset));
    break;
  case XMCP_SERVICE_DATA:
    proto_tree_add_item(attr_tree, xmcp_attr_service_data, tvb, offset,
                        attr_length, FALSE);
    if (attr_length > 0) {
      tvbuff_t *next_tvb;
      guint8 *test_string, *tok;

      next_tvb = tvb_new_subset(tvb, offset, attr_length, attr_length);
      /*
       * Service-Data is usually (but not always) plain text, specifically XML.
       * If it "looks like" XML (begins with optional whitespace followed by
       * a '<'), try XML.
       * Otherwise, try plain-text.
       */
      test_string = tvb_get_ephemeral_string(next_tvb, 0, (attr_length < 32 ?
                                                           attr_length : 32));
      tok = strtok(test_string, " \t\r\n");
      if (tok && tok[0] == '<') {
        /* Looks like XML */
        dissector_try_string(media_type_dissector_table, "application/xml",
                             next_tvb, pinfo, attr_tree);
      } else {
        /* Try plain text */
        dissector_try_string(media_type_dissector_table, "text/plain",
                             next_tvb, pinfo, attr_tree);
      }
    }
    break;
  case XMCP_SUBSCRIPTION_ID:
    if (attr_length < 4)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_subscription_id, tvb, offset,
                        4, FALSE);
    proto_item_append_text(attr_tree, ": %u", tvb_get_ntohl(tvb, offset));
    if (check_col(pinfo->cinfo, COL_INFO)) {
      col_append_fstr(pinfo->cinfo, COL_INFO, ", subscription %u",
                      tvb_get_ntohl(tvb, offset));
    }
    break;
  case XMCP_SERVICE_REMOVED_REASON:
    if (attr_length < 4)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_service_removed_reason, tvb,
                        offset, 4, FALSE);
    proto_item_append_text(attr_tree, ": %s",
                           val_to_str_const(tvb_get_ntohl(tvb, offset),
                                            service_removed_reasons,
                                            "Unknown"));
    break;
  case XMCP_DOMAIN:
    if (attr_length < 4)
      break;
    proto_tree_add_item(attr_tree, xmcp_attr_domain, tvb, offset, 4, FALSE);
    proto_item_append_text(attr_tree, ": %u", tvb_get_ntohl(tvb, offset));
    break;
  default:
    proto_tree_add_item(attr_tree, xmcp_attr_value, tvb, offset,
                        attr_length, FALSE);
    expert_add_info_format(pinfo, attr_tree, PI_PROTOCOL, PI_NOTE,
                           "Unrecognized attribute type 0x%x", attr_type);
    break;
  }
  if (attr_length % 4 != 0) {
    proto_tree_add_item(attr_tree, xmcp_attr_padding, tvb, (offset+attr_length),
                        (4 - (attr_length % 4)), FALSE);
  }
  if (attr_length < get_xmcp_attr_min_len(attr_type)) {
    expert_add_info_format(pinfo, attr_tree, PI_PROTOCOL, PI_WARN,
                           "Length less than minimum for this attribute type");
  } else if (attr_length > get_xmcp_attr_max_len(attr_type)) {
    expert_add_info_format(pinfo, attr_tree, PI_PROTOCOL, PI_WARN,
                           "Length exceeds maximum for this attribute type");
  }
}

static void
dissect_xmcp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint16 msg_type, msg_length;
  proto_item *ti = NULL;
  proto_tree *xmcp_tree, *attr_all_tree, *attr_tree;
  guint16 offset, attr_type, attr_length;

  /* For request/response association */
  guint32 transaction_id[3];
  emem_tree_key_t transaction_id_key[2];
  conversation_t *conversation;
  xmcp_conv_info_t *xmcp_conv_info;
  xmcp_transaction_t *xmcp_trans;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "XMCP");
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo, COL_INFO);

  if (tvb_reported_length(tvb) < XMCP_HDR_LEN) {
    return;
  }

  /* As in STUN, the first 2 bytes contain the message class and method */
  msg_type = tvb_get_ntohs(tvb, 0);
  xmcp_msg_type_class = ((msg_type & XMCP_TYPE_CLASS) >> 4);
  xmcp_msg_type_method = (msg_type & XMCP_TYPE_METHOD);
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                val_to_str_const(xmcp_msg_type_method, methods, "Unknown"),
                val_to_str_const(xmcp_msg_type_class, classes, "Unknown"));
  }

  /* Get the transaction ID */
  transaction_id[0] = tvb_get_ntohl(tvb, 8);
  transaction_id[1] = tvb_get_ntohl(tvb, 12);
  transaction_id[2] = tvb_get_ntohl(tvb, 16);

  transaction_id_key[0].length = 3;
  transaction_id_key[0].key = transaction_id;
  transaction_id_key[1].length = 0;
  transaction_id_key[1].key = NULL;

  conversation = find_or_create_conversation(pinfo);

  /* Do we already have XMCP state for this conversation? */
  xmcp_conv_info = conversation_get_proto_data(conversation, proto_xmcp);
  if (!xmcp_conv_info) {
    xmcp_conv_info = se_alloc(sizeof(xmcp_conv_info_t));
    xmcp_conv_info->transaction_pdus =
      se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK,
                                    "xmcp_pdus");
    conversation_add_proto_data(conversation, proto_xmcp, xmcp_conv_info);
  }

  /* Find existing transaction entry or create a new one */
  xmcp_trans = se_tree_lookup32_array(xmcp_conv_info->transaction_pdus,
                                      transaction_id_key);
  if (!xmcp_trans) {
      xmcp_trans = se_alloc(sizeof(xmcp_transaction_t));
      xmcp_trans->request_frame = 0;
      xmcp_trans->response_frame = 0;
      xmcp_trans->request_time = pinfo->fd->abs_ts;
      xmcp_trans->request_is_keepalive = FALSE;
      se_tree_insert32_array(xmcp_conv_info->transaction_pdus,
                             transaction_id_key, (void *)xmcp_trans);
  }

  /* Update transaction entry */
  if (!pinfo->fd->flags.visited) {
    if (xmcp_msg_type_class == XMCP_CLASS_REQUEST) {
      if (xmcp_trans->request_frame == 0) {
        xmcp_trans->request_frame = pinfo->fd->num;
        xmcp_trans->request_time = pinfo->fd->abs_ts;
      }
    } else if (xmcp_msg_type_class != XMCP_CLASS_RESERVED) {
      if (xmcp_trans->response_frame == 0) {
        xmcp_trans->response_frame = pinfo->fd->num;
      }
    }
  }

  if (!tree) { /* no details requested */
    return;
  }

  ti = proto_tree_add_item(tree, proto_xmcp, tvb, 0, -1, FALSE);
  xmcp_tree = proto_item_add_subtree(ti, ett_xmcp);

  ti = proto_tree_add_bitmask(xmcp_tree, tvb, 0, hf_xmcp_type, ett_xmcp_type,
                              xmcp_type_fields, FALSE);

  if (msg_type & XMCP_TYPE_RESERVED) {
    expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN,
                           "First two bits not zero");
  }
  if (xmcp_msg_type_class == XMCP_CLASS_RESERVED) {
    expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN,
                           "Reserved message class");
  } else if (xmcp_msg_type_class == XMCP_CLASS_RESPONSE_ERROR) {
    expert_add_info_format(pinfo, ti, PI_RESPONSE_CODE, PI_NOTE,
                           "Error Response");
  }

  if (xmcp_msg_type_method < 0x001 || xmcp_msg_type_method > 0x00b) {
    expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN,
                           "Reserved message method");
  }

  /*
   * Some forms of XMCP overload the Register method for Keepalive packets
   * rather than using a separate Keepalive method. We'll try to determine from
   * the message contents whether this message is a Keepalive. Initialize first.
   */
  xmcp_msg_is_keepalive = (xmcp_trans->request_is_keepalive ||
                           (xmcp_msg_type_method == XMCP_METHOD_KEEPALIVE));

  /* After the class/method, we have a 2 byte length...*/
  ti = proto_tree_add_item(xmcp_tree, hf_xmcp_length, tvb, 2, 2, FALSE);
  msg_length = tvb_get_ntohs(tvb, 2);
  if (msg_length + XMCP_HDR_LEN > tvb_reported_length(tvb)) {
    expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_ERROR,
                           "XMCP message length (%u-byte header + %u) exceeds "
                           "packet length (%u)",
                           XMCP_HDR_LEN, msg_length, tvb_reported_length(tvb));
    return;
  }

  /* ...a 4 byte magic cookie... */
  ti = proto_tree_add_item(xmcp_tree, hf_xmcp_cookie, tvb, 4, 4, FALSE);
  if (tvb_get_ntohl(tvb, 4) != XMCP_MAGIC_COOKIE) {
    expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN,
                           "Magic cookie not correct for XMCP");
  }

  /* ...and a 12-byte transaction id */
  ti = proto_tree_add_item(xmcp_tree, hf_xmcp_id, tvb, 8, 12, FALSE);

  /* Print state tracking in the tree */
  if (xmcp_msg_type_class == XMCP_CLASS_REQUEST) {
    if (xmcp_trans->response_frame) {
      ti = proto_tree_add_uint(xmcp_tree, hf_xmcp_response_in, tvb, 0, 0,
                               xmcp_trans->response_frame);
      PROTO_ITEM_SET_GENERATED(ti);
    }
  } else if (xmcp_msg_type_class != XMCP_CLASS_RESERVED) {
    if (xmcp_trans->request_frame) {
      nstime_t ns;

      ti = proto_tree_add_uint(xmcp_tree, hf_xmcp_response_to, tvb, 0, 0,
                               xmcp_trans->request_frame);
      PROTO_ITEM_SET_GENERATED(ti);

      nstime_delta(&ns, &pinfo->fd->abs_ts, &xmcp_trans->request_time);
      ti = proto_tree_add_time(xmcp_tree, hf_xmcp_time, tvb, 0, 0, &ns);
      PROTO_ITEM_SET_GENERATED(ti);
    } else {
      /* This is a response, but we don't know about a request for this response? */
      expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_NOTE,
                             "Response without corresponding request");
    }
  }

  xmcp_service_protocol = -1;
  xmcp_service_port = -1;
  xmcp_it_service_port = NULL;

  /* The header is then followed by "msg_length" bytes of TLV attributes */
  if (msg_length > 0) {
    ti = proto_tree_add_item(xmcp_tree, hf_xmcp_attributes, tvb,
                             XMCP_HDR_LEN, msg_length, FALSE);
    attr_all_tree = proto_item_add_subtree(ti, ett_xmcp_attr_all);

    offset = XMCP_HDR_LEN;

    while (offset < (msg_length + XMCP_HDR_LEN)) {
      /* Get type/length of next TLV */
      attr_type = tvb_get_ntohs(tvb, offset);
      attr_length = tvb_get_ntohs(tvb, offset+2);
      ti = proto_tree_add_none_format(attr_all_tree, hf_xmcp_attr, tvb, offset,
                                      (XMCP_ATTR_HDR_LEN +
                                       get_xmcp_attr_padded_len(attr_length)),
                                      "%s, length %u",
                                      val_to_str(attr_type, attributes,
                                                 "Unknown"),
                                      attr_length);

      /* Add subtree for this TLV */
      attr_tree = proto_item_add_subtree(ti, ett_xmcp_attr);

      proto_tree_add_item(attr_tree, xmcp_attr_type, tvb,
                          offset, 2, FALSE);
      offset += 2;
      ti = proto_tree_add_item(attr_tree, xmcp_attr_length, tvb,
                               offset, 2, FALSE);
      offset += 2;

      if ((offset + attr_length) > (XMCP_HDR_LEN + msg_length)) {
        proto_item_append_text(ti, " (bogus, exceeds message length)");
        expert_add_info_format(pinfo, attr_tree, PI_MALFORMED, PI_ERROR,
                               "Attribute length exceeds message length");
        break;
      }

      decode_xmcp_attr_value(attr_tree, attr_type, attr_length, tvb,
                             offset, pinfo);

      offset += get_xmcp_attr_padded_len(attr_length);
    }
  }

  /*
   * Flag this message as a keepalive if the attribute analysis
   * suggested that it is one
   */
  if (xmcp_msg_is_keepalive) {
    ti = proto_tree_add_none_format(xmcp_tree, hf_xmcp_msg_is_keepalive, tvb,
                                    0, 0, "This is a Keepalive message");
    PROTO_ITEM_SET_GENERATED(ti);
    if ((xmcp_msg_type_method != XMCP_METHOD_KEEPALIVE) &&
        check_col(pinfo->cinfo, COL_INFO)) {
      col_prepend_fstr(pinfo->cinfo, COL_INFO, "[Keepalive] ");
    }
    if (xmcp_msg_type_class == XMCP_CLASS_REQUEST) {
      xmcp_trans->request_is_keepalive = TRUE;
    }
  } else if (xmcp_msg_type_class == XMCP_CLASS_REQUEST ||
             xmcp_msg_type_class == XMCP_CLASS_RESPONSE_SUCCESS) {
    if (xmcp_msg_type_method == XMCP_METHOD_REGISTER) {
      expert_add_info_format(pinfo, xmcp_tree, PI_SEQUENCE, PI_CHAT,
                             "New session - Register %s",
                             val_to_str(xmcp_msg_type_class, classes, ""));
    } else if (xmcp_msg_type_method == XMCP_METHOD_UNREGISTER ||
               xmcp_msg_type_method == XMCP_METHOD_REG_REVOKE) {
      expert_add_info_format(pinfo, xmcp_tree, PI_SEQUENCE, PI_CHAT,
                             "Session termination - %s %s",
                             val_to_str(xmcp_msg_type_method, methods, ""),
                             val_to_str(xmcp_msg_type_class, classes, ""));
    }
  }
}

static void
dissect_xmcp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, XMCP_HDR_LEN,
                   get_xmcp_message_len, dissect_xmcp_message);
}

static gboolean
dissect_xmcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /* See if this looks like a real XMCP packet */
  if (tvb_length(tvb) < XMCP_HDR_LEN) {
    return FALSE;
  }
  /* Check for valid message type field */
  if (tvb_get_ntohs(tvb, 0) & XMCP_TYPE_RESERVED) { /* First 2 bits must be 0 */
    return FALSE;
  }
  /* Check for valid "magic cookie" field */
  if (tvb_get_ntohl(tvb, 4) != XMCP_MAGIC_COOKIE) {
    return FALSE;
  }

  /* Good enough to consider a match! */
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, XMCP_HDR_LEN,
                   get_xmcp_message_len, dissect_xmcp_message);
  return TRUE;
}

void
proto_register_xmcp(void)
{
  static hf_register_info hf[] = {
    { &hf_xmcp_type,
      { "Message Type",         "xmcp.type",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
    },
    { &hf_xmcp_type_reserved,
      { "Reserved",             "xmcp.type.reserved",
        FT_UINT16, BASE_HEX, NULL, XMCP_TYPE_RESERVED, NULL, HFILL }
    },
    { &hf_xmcp_type_class,
      { "Class",                "xmcp.type.class",
        FT_UINT16, BASE_HEX, VALS(classes), XMCP_TYPE_CLASS, NULL, HFILL }
    },
    { &hf_xmcp_type_method,
      { "Method",               "xmcp.type.method",
        FT_UINT16, BASE_HEX, VALS(methods), XMCP_TYPE_METHOD, NULL, HFILL }
    },
    { &hf_xmcp_msg_is_keepalive,
      { "Message is Keepalive", "xmcp.analysis.keepalive",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_xmcp_length,
      { "Message Length",       "xmcp.length",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_xmcp_cookie,
      { "XMCP Magic Cookie",    "xmcp.cookie",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &hf_xmcp_id,
      { "Transaction ID",       "xmcp.id",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_xmcp_response_in,
      { "Response In",          "xmcp.response-in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "The response to this XMCP request is in this frame",   HFILL }
    },
    { &hf_xmcp_response_to,
      { "Response To",          "xmcp.response-to",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "This is a response to the XMCP request in this frame", HFILL }
    },
    { &hf_xmcp_time,
      { "Elapsed Time",         "xmcp.time",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "The time between the Request and the Response",        HFILL }
    },
    { &hf_xmcp_attributes,
      { "Attributes",           "xmcp.attributes",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_xmcp_attr,
      { "Attribute",            "xmcp.attr",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_type,
      { "Attribute Type",       "xmcp.attr.type",
        FT_UINT16, BASE_HEX, VALS(attributes), 0x0, NULL, HFILL }
    },
    { &xmcp_attr_length,
      { "Attribute Length",     "xmcp.attr.length",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_value,
      { "Attribute Value",      "xmcp.attr.value",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &xmcp_attr_padding,
      { "Padding",              "xmcp.attr.padding",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_reserved,
      { "Reserved",             "xmcp.attr.reserved",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_username,
      { "Username",             "xmcp.attr.username",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_message_integrity,
      { "Message-Integrity",    "xmcp.attr.hmac",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_error_reserved,
      { "Reserved",             "xmcp.attr.error.reserved",
        FT_UINT24, BASE_HEX, NULL, 0xFFFFF8, NULL, HFILL }
    },
    { &xmcp_attr_error_class,
      { "Error Class",          "xmcp.attr.error.class",
        FT_UINT24, BASE_DEC, NULL, 0x000007, NULL, HFILL}
    },
    { &xmcp_attr_error_number,
      { "Error Number",         "xmcp.attr.error.number",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &xmcp_attr_error_code,
      { "Error Code",           "xmcp.attr.error",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    { &xmcp_attr_error_reason,
      { "Error Reason Phrase",  "xmcp.attr.error.reason",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    { &xmcp_attr_realm,
      { "Realm",                "xmcp.attr.realm",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_nonce,
      { "Nonce",                "xmcp.attr.nonce",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_client_name,
      { "Client-Name",          "xmcp.attr.client-name",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_client_handle,
      { "Client-Handle",        "xmcp.attr.client-handle",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_version_major,
      { "Protocol Major Version", "xmcp.attr.version.major",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_version_minor,
      { "Protocol Minor Version", "xmcp.attr.version.minor",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_page_size,
      { "Page-Size",            "xmcp.attr.page-size",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_client_label,
      { "Client-Label",         "xmcp.attr.client-label",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_keepalive,
      { "Keepalive",            "xmcp.attr.keepalive",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_serv_service,
      { "Service ID",           "xmcp.attr.service.service",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_serv_subservice,
      { "Subservice ID",        "xmcp.attr.service.subservice",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_serv_instance,
      { "Instance ID",          "xmcp.attr.service.instance",
        FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_servtrans_family,
      { "Family",               "xmcp.attr.service.transport.family",
        FT_UINT8, BASE_HEX, VALS(address_families), 0x0, NULL, HFILL }
    },
    { &xmcp_attr_servtrans_port,
      { "Port",                 "xmcp.attr.service.transport.port",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_servtrans_ipv4,
      { "IPv4 Address",         "xmcp.attr.service.transport.ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_servtrans_ipv6,
      { "IPv6 Address",         "xmcp.attr.service.transport.ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_service_protocol,
      { "Protocol",             "xmcp.attr.service.transport.protocol",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, (&ipproto_val_ext),
        0x0, NULL, HFILL }
    },
    { &xmcp_attr_flag,
      { "Flag",                 "xmcp.attr.flag",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_flag_type,
      { "Flag Type",            "xmcp.attr.flag.type",
        FT_UINT16, BASE_HEX, VALS(flag_types), 0x0, NULL, HFILL }
    },
    { &xmcp_attr_flag_value,
      { "Flag Value",           "xmcp.attr.flag.value",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_flag_removal_reason_network_withdraw,
      { "Network Withdraw",
        "xmcp.attr.flag.removal-reason.network-withdraw",
        FT_BOOLEAN, 16, TFS(&tfs_true_false),
        XMCP_REMOVAL_REASON_NETWORK_WITHDRAW, NULL, HFILL }
    },
    { &xmcp_attr_flag_removal_reason_reserved,
      { "Reserved",             "xmcp.attr.flag.removal-reason.reserved",
        FT_UINT16, BASE_HEX, NULL, XMCP_REMOVAL_REASON_RESERVED, NULL, HFILL }
    },
    { &xmcp_attr_flag_trust,
      { "Trust",                "xmcp.attr.flag.trust",
        FT_UINT16, BASE_HEX, VALS(flag_trust_values), 0x0, NULL,    HFILL }
    },
    { &xmcp_attr_flag_visibility_unauthenticated,
      { "Visible to Unauthenticated Clients",
        "xmcp.attr.flag.service-visibility.unauthenticated",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no),
        XMCP_SERVICE_VISIBILITY_UNAUTHENTICATED, NULL, HFILL }
    },
    { &xmcp_attr_flag_visibility_reserved,
      { "Reserved",             "xmcp.attr.flag.service-visibility.reserved",
        FT_UINT16, BASE_HEX, NULL,
        XMCP_SERVICE_VISIBILITY_RESERVED, NULL, HFILL }
    },
    { &xmcp_attr_service_version,
      { "Service Version",      "xmcp.attr.service.version",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_service_data,
      { "Service Data",         "xmcp.attr.service.data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_subscription_id,
      { "Subscription ID",      "xmcp.attr.subscription-id",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &xmcp_attr_service_removed_reason,
      { "Service Removed Reason", "xmcp.attr.service-removed-reason",
        FT_UINT32, BASE_DEC, VALS(service_removed_reasons), 0x0, NULL, HFILL }
    },
    { &xmcp_attr_domain,
      { "Domain",               "xmcp.attr.domain",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_xmcp,
    &ett_xmcp_type,
    &ett_xmcp_attr_all,
    &ett_xmcp_attr,
    &ett_xmcp_attr_flag
  };
  module_t *xmcp_module;

  proto_xmcp = proto_register_protocol("eXtensible Messaging Client Protocol",
                                       "XMCP", "xmcp");

  proto_register_field_array(proto_xmcp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register XMCP configuration options */
  xmcp_module = prefs_register_protocol(proto_xmcp, proto_reg_handoff_xmcp);

  prefs_register_uint_preference(xmcp_module, "tcp.port", "XMCP TCP Port",
                                 "Set the port for XMCP messages (if other"
                                 " than the default of 4788)",
                                 10, &global_xmcp_tcp_port);

}

void
proto_reg_handoff_xmcp(void)
{
  static gboolean xmcp_prefs_initialized = FALSE;
  static dissector_handle_t xmcp_tcp_handle;
  static guint xmcp_tcp_port;

  if (!xmcp_prefs_initialized) {
    xmcp_tcp_handle = create_dissector_handle(dissect_xmcp_tcp, proto_xmcp);
    heur_dissector_add("tcp", dissect_xmcp_heur, proto_xmcp);
    media_type_dissector_table = find_dissector_table("media_type");
    xmcp_prefs_initialized = TRUE;
  } else {
    dissector_delete_uint("tcp.port", xmcp_tcp_port, xmcp_tcp_handle);
  }

  xmcp_tcp_port = global_xmcp_tcp_port;
  dissector_add_uint("tcp.port", global_xmcp_tcp_port, xmcp_tcp_handle);
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
 * vi: set shiftwidth=2 tabstop=8 expandtab
 * :indentSize=2:tabSize=8:noTabs=true:
 */
