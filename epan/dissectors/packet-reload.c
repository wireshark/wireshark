/* packet-reload.c
 * Routines forREsource LOcation And Discovery (RELOAD) Base Protocol
 * Author: Stephane Bryant <sbryant@glycon.org>
 * Copyright 2010 Stonyfish Inc.
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Please refer to the following specs for protocol detail:
 * - draft-ietf-p2psip-base-15
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/asn1.h>
#include <epan/dissectors/packet-x509af.h>
#include <packet-tcp.h>
#include <packet-ssl-utils.h>

/* Initialize the protocol and registered fields */
static int proto_reload = -1;

static gboolean reload_defragment = TRUE;
static guint reload_nodeid_length = 16;

static int hf_reload_response_in = -1;
static int hf_reload_response_to = -1;
static int hf_reload_time = -1;
static int hf_reload_duplicate = -1;
static int hf_reload_token = -1;
static int hf_reload_forwarding = -1;
static int hf_reload_overlay = -1;
static int hf_reload_configuration_sequence = -1;
static int hf_reload_version = -1;
static int hf_reload_ttl = -1;
static int hf_reload_fragment_flag = -1;
static int hf_reload_fragment_fragmented = -1;
static int hf_reload_fragment_last_fragment = -1;
static int hf_reload_fragment_reserved = -1;
static int hf_reload_fragment_offset = -1;
static int hf_reload_length = -1;
static int hf_reload_trans_id = -1;
static int hf_reload_max_response_length = -1;
static int hf_reload_via_list_length = -1;
static int hf_reload_destination_list_length = -1;
static int hf_reload_options_length = -1;
static int hf_reload_via_list = -1;
static int hf_reload_destination = -1;
static int hf_reload_destination_compressed = -1;
static int hf_reload_destination_type = -1;
static int hf_reload_destination_length = -1;
static int hf_reload_nodeid = -1;
static int hf_reload_resource_id = -1;
static int hf_reload_destination_data_compressed_id = -1;
static int hf_reload_destination_list = -1;
static int hf_reload_forwarding_option = -1;
static int hf_reload_forwarding_option_type = -1;
static int hf_reload_forwarding_option_flags = -1;
static int hf_reload_forwarding_option_flag_response_copy = -1;
static int hf_reload_forwarding_option_flag_destination_critical = -1;
static int hf_reload_forwarding_option_flag_forward_critical = -1;
static int hf_reload_forwarding_option_length = -1;
static int hf_reload_forwarding_option_data = -1;
static int hf_reload_attachreqans = -1;
static int hf_reload_ufrag = -1;
static int hf_reload_password = -1;
static int hf_reload_role = -1;
static int hf_reload_sendupdate = -1;
static int hf_reload_icecandidates = -1;
static int hf_reload_icecandidates_length = -1;
static int hf_reload_icecandidate = -1;
static int hf_reload_icecandidate_srflx_addr = -1;
static int hf_reload_icecandidate_prflx_addr = -1;
static int hf_reload_icecandidate_relay_addr = -1;
static int hf_reload_icecandidate_foundation = -1;
static int hf_reload_icecandidate_priority = -1;
static int hf_reload_icecandidate_type = -1;
static int hf_reload_overlaylink_type = -1;
static int hf_reload_icecandidate_extensions_length = -1;
static int hf_reload_iceextension = -1;
static int hf_reload_iceextension_name = -1;
static int hf_reload_iceextension_value = -1;
static int hf_reload_ipaddressport = -1;
static int hf_reload_ipaddressport_type = -1;
static int hf_reload_ipaddressport_length = -1;
static int hf_reload_ipv4addr = -1;
static int hf_reload_port = -1;
static int hf_reload_ipv6addr = -1;
static int hf_reload_message_contents = -1;
static int hf_reload_message_code = -1;
static int hf_reload_message_body = -1;
static int hf_reload_message_extensions_length = -1;
static int hf_reload_message_extension = -1;
static int hf_reload_message_extension_type = -1;
static int hf_reload_message_extension_critical = -1;
static int hf_reload_message_extension_content = -1;
static int hf_reload_error_response = -1;
static int hf_reload_error_response_code = -1;
static int hf_reload_error_response_info = -1;
static int hf_reload_security_block = -1;
static int hf_reload_certificates_length = -1;
static int hf_reload_certificates = -1;
static int hf_reload_certificate_type = -1;
static int hf_reload_certificate = -1;
static int hf_reload_signature = -1;
static int hf_reload_hash_algorithm = -1;
static int hf_reload_signature_algorithm = -1;
static int hf_reload_signature_identity = -1;
static int hf_reload_signature_identity_type = -1;
static int hf_reload_signature_identity_length = -1;
static int hf_reload_signature_identity_value = -1;
static int hf_reload_signature_identity_value_certificate_hash = -1;
static int hf_reload_signature_value = -1;
static int hf_reload_opaque_length_uint8 = -1;
static int hf_reload_opaque_length_uint16 = -1;
static int hf_reload_opaque_length_uint32 = -1;
static int hf_reload_opaque_data = -1;
static int hf_reload_routequeryreq = -1;
static int hf_reload_overlay_specific = -1;
static int hf_reload_probereq = -1;
static int hf_reload_probe_information_type = -1;
static int hf_reload_probe_information = -1;
static int hf_reload_responsible_set = -1;
static int hf_reload_num_resources = -1;
static int hf_reload_uptime = -1;
static int hf_reload_probeans = -1;
static int hf_reload_appattach = -1;
static int hf_reload_application = -1;
static int hf_reload_ping_response_id = -1;
static int hf_reload_ping_time = -1;
static int hf_reload_storeddata = -1;
static int hf_reload_storeddata_length = -1;
static int hf_reload_storeddata_storage_time =  -1;
static int hf_reload_storeddata_lifetime = -1;
static int hf_reload_kinddata = -1;
static int hf_reload_kindid = -1;
static int hf_reload_kinddata_generation_counter = -1;
static int hf_reload_kinddata_values_length = -1;
static int hf_reload_storereq = -1;
static int hf_reload_store_replica_num = -1;
static int hf_reload_store_kind_data_length = -1;
static int hf_reload_storeans_kind_responses = -1;
static int hf_reload_storeans_kind_responses_length = -1;
static int hf_reload_storekindresponse = -1;
static int hf_reload_storekindresponse_replicas = -1;
static int hf_reload_storeddataspecifiers = -1;
static int hf_reload_fetchans = -1;
static int hf_reload_kind_responses_length = -1;
static int hf_reload_statans = -1;
static int hf_reload_findreq_kinds_length = -1;
static int hf_reload_findkinddata = -1;
static int hf_reload_findans_results_length = -1;
static int hf_reload_fragments = -1;
static int hf_reload_fragment = -1;
static int hf_reload_fragment_overlap = -1;
static int hf_reload_fragment_overlap_conflict = -1;
static int hf_reload_fragment_multiple_tails = -1;
static int hf_reload_fragment_too_long_fragment = -1;
static int hf_reload_fragment_error = -1;
static int hf_reload_fragment_count = -1;
static int hf_reload_reassembled_in = -1;
static int hf_reload_reassembled_length = -1;
static int hf_reload_configupdatereq = -1;
static int hf_reload_configupdatereq_type = -1;
static int hf_reload_configupdatereq_length = -1;
static int hf_reload_configupdatereq_configdata = -1;
static int hf_reload_configupdatereq_kinds = -1;
static int hf_reload_padding = -1;


static dissector_handle_t data_handle;

/* Structure containing transaction specific information */
typedef struct _reload_transaction_t {
  guint32 req_frame;
  guint32 rep_frame;
  nstime_t req_time;
} reload_transaction_t;

/* Structure containing conversation specific information */
typedef struct _reload_conv_info_t {
  emem_tree_t *transaction_pdus;
} reload_conv_info_t;


/* RELOAD Message classes = (message_code & 0x1) (response = request +1) */
#define RELOAD_REQUEST         0x0001
#define RELOAD_RESPONSE        0x0000

#define RELOAD_ERROR           0xffff

/* RELOAD Message Methods = (message_code +1) & 0xfffe*/
#define METHOD_INVALID           0
#define METHOD_PROBE             2
#define METHOD_ATTACH            4
#define METHOD_STORE             8
#define METHOD_FETCH            10
#define METHOD_REMOVE           12
#define METHOD_FIND             14
#define METHOD_JOIN             16
#define METHOD_LEAVE            18
#define METHOD_UPDATE           20
#define METHOD_ROUTEQUERY       22
#define METHOD_PING             24
#define METHOD_STAT             26
#define METHOD_APPATTACH        30
#define METHOD_CONFIGUPDATE     34


/* RELOAD Destinationtype */
#define DESTINATIONTYPE_RESERVED            0
#define DESTINATIONTYPE_NODE                1
#define DESTINATIONTYPE_RESOURCE            2
#define DESTINATIONTYPE_COMPRESSED          3

/* RELOAD forwarding option type */
#define OPTIONTYPE_RESERVED                  0

/* RELOAD CandTypes */
#define CANDTYPE_RESERVED        0
#define CANDTYPE_HOST            1
#define CANDTYPE_SRFLX           2
#define CANDTYPE_PRFLX           3
#define CANDTYPE_RELAY           4

/* IpAddressPort types */
#define IPADDRESSPORTTYPE_RESERVED 0
#define IPADDRESSPORTTYPE_IPV4     1
#define IPADDRESSPORTTYPE_IPV6     2

/* OverlayLink types */
#define OVERLAYLINKTYPE_RESERVEDOVERLAYLINK                             0
#define OVERLAYLINKTYPE_DTLS_UDP_SR                                     1
#define OVERLAYLINKTYPE_DTLS_UDP_SR_NO_ICE                              3
#define OVERLAYLINKTYPE_TLS_TCP_FH_NO_ICE                               4

#define ERRORCODE_INVALID                                               0
#define ERRORCODE_UNUSED                                                1
#define ERRORCODE_FORBIDDEN                                             2
#define ERRORCODE_NOTFOUND                                              3
#define ERRORCODE_REQUESTTIMEOUT                                        4
#define ERRORCODE_GENERATIONCOUNTERTOOLOW                               5
#define ERRORCODE_INCOMPATIBLEWITHOVERLAY                               6
#define ERRORCODE_UNSUPPORTEDFORWARDINGOPTION                           7
#define ERRORCODE_DATATOOLARGE                                          8
#define ERRORCODE_DATATOOOLD                                            9
#define ERRORCODE_TTLEXCEEDED                                           10
#define ERRORCODE_MESSAGETOOLARGE                                       11
#define ERRORCODE_UNKNOWNKIND                                           12
#define ERRORCODE_UNKNOWNEXTENSION                                      13
#define ERRORCODE_RESPONSETOOLARGE                                      14
#define ERRORCODE_CONFIGTOOOLD                                          15
#define ERRORCODE_CONFIGTOONEW                                          16

#define SIGNATUREIDENTITYTYPE_RESERVED                                  0
#define SIGNATUREIDENTITYTYPE_CERTHASH                                  1
#define SIGNATUREIDENTITYTYPE_CERTHASHNODEID                            2
#define SIGNATUREIDENTITYTYPE_NONE                                      3

/* Probe information type */
#define PROBEINFORMATIONTYPE_RESERVED                                   0
#define PROBEINFORMATIONTYPE_RESPONSIBLESET                             1
#define PROBEINFORMATIONTYPE_NUMRESOURCES                               2
#define PROBEINFORMATIONTYPE_UPTIME                                     3

/* Data Kind ID */
#define DATAKINDID_INVALID                                              0
#define DATAKINDID_TURNSERVICE                                          2
#define DATAKINDID_CERTIFICATE_BY_NODE                                  3
#define DATAKINDID_CERTIFICATE_BY_USER                                  16

/* Message Extension Type */
#define MESSAGEEXTENSIONTYPE_RESERVED                                   0

/* Config Update Type */
#define CONFIGUPDATETYPE_RESERVED                                       0
#define CONFIGUPDATETYPE_CONFIG                                         1
#define CONFIGUPDATETYPE_KIND                                           2

/* Initialize the subtree pointers */
static gint ett_reload = -1;
static gint ett_reload_forwarding = -1;
static gint ett_reload_message = -1;
static gint ett_reload_security=-1;
static gint ett_reload_fragment_flag=-1;
static gint ett_reload_destination = -1;
static gint ett_reload_via_list = -1;
static gint ett_reload_destination_list = -1;
static gint ett_reload_forwarding_option = -1;
static gint ett_reload_forwarding_option_flags = -1;
static gint ett_reload_forwarding_option_directresponseforwarding = -1;
static gint ett_reload_attachreqans = -1;
static gint ett_reload_icecandidates = -1;
static gint ett_reload_icecandidate = -1;
static gint ett_reload_icecandidate_computed_address = -1;
static gint ett_reload_iceextension = -1;
static gint ett_reload_ipaddressport = -1;
static gint ett_reload_message_contents = -1;
static gint ett_reload_message_extension = -1;
static gint ett_reload_error_response = -1;
static gint ett_reload_security_block = -1;
static gint ett_reload_certificate = -1;
static gint ett_reload_signature = -1;
static gint ett_reload_signature_identity = -1;
static gint ett_reload_signature_identity_value = -1;
static gint ett_reload_opaque = -1;
static gint ett_reload_message_body = -1;
static gint ett_reload_routequeryreq = -1;
static gint ett_reload_probereq = -1;
static gint ett_reload_probe_information = -1;
static gint ett_reload_probeans = -1;
static gint ett_reload_appattach = -1;
static gint ett_reload_storeddata = -1;
static gint ett_reload_kinddata = -1;
static gint ett_reload_storereq = -1;
static gint ett_reload_storeans_kind_responses = -1;
static gint ett_reload_storekindresponse = -1;
static gint ett_reload_fetchans = -1;
static gint ett_reload_statans = -1;
static gint ett_reload_findkinddata = -1;
static gint ett_reload_fragments = -1;
static gint ett_reload_fragment  = -1;
static gint ett_reload_configupdatereq = -1;
static gint ett_reload_storekindresponse_replicas = -1;

static const fragment_items reload_frag_items = {
  &ett_reload_fragment,
  &ett_reload_fragments,
  &hf_reload_fragments,
  &hf_reload_fragment,
  &hf_reload_fragment_overlap,
  &hf_reload_fragment_overlap_conflict,
  &hf_reload_fragment_multiple_tails,
  &hf_reload_fragment_too_long_fragment,
  &hf_reload_fragment_error,
  &hf_reload_fragment_count,
  &hf_reload_reassembled_in,
  &hf_reload_reassembled_length,
  "RELOAD fragments"
};


#define MSG_LENGH_OFFSET                16
#define MIN_HDR_LENGTH                  38      /* Forwarding header till options_length member (included) */

#define RELOAD_TOKEN                    0xd2454c4f

#define IS_REQUEST(code)                (code & 0x0001)
#define MSGCODE_TO_METHOD(code)         ((code + 1) & 0xfffe)
#define MSGCODE_TO_CLASS(code)          (code & 0x0001)


static const value_string classes[] = {
  {RELOAD_REQUEST,                              "Request"},
  {RELOAD_RESPONSE,                             "Answer"},
  {0x00, NULL}
};

static const value_string methods[] = {
  {METHOD_INVALID,                              "invalid"},
  {METHOD_PROBE,                                "Probe"},
  {METHOD_ATTACH,                               "Attach"},
  {METHOD_STORE,                                "Store"},
  {METHOD_FETCH,                                "Fetch"},
  {METHOD_REMOVE,                               "Remove"},
  {METHOD_FIND,                                 "Find"},
  {METHOD_JOIN,                                 "Join"},
  {METHOD_LEAVE,                                "Leave"},
  {METHOD_UPDATE,                               "Update"},
  {METHOD_ROUTEQUERY,                           "RouteQuery"},
  {METHOD_PING,                                 "Ping"},
  {METHOD_STAT,                                 "Stat"},
  {METHOD_APPATTACH,                            "AppAttach"},
  {METHOD_CONFIGUPDATE,                         "ConfigUpdate"},
  {0x00, NULL}
};

static const value_string destinationtypes[] = {
  {DESTINATIONTYPE_RESERVED,                    "reserved"},
  {DESTINATIONTYPE_NODE,                        "Node"},
  {DESTINATIONTYPE_RESOURCE,                    "Resource"},
  {DESTINATIONTYPE_COMPRESSED,                  "Compressed"},
  {0x00, NULL}
};

static const value_string forwardingoptiontypes[] = {
  {OPTIONTYPE_RESERVED,                         "reserved"},
  {0x00, NULL}
};

static const value_string candtypes[] = {
  {CANDTYPE_RESERVED,                           "reserved"},
  {CANDTYPE_HOST,                               "host"},
  {CANDTYPE_SRFLX,                              "srflx"},
  {CANDTYPE_PRFLX,                              "prflx"},
  {CANDTYPE_RELAY,                              "relay"},
  {0x00, NULL}
};

static const value_string ipaddressporttypes [] = {
  {IPADDRESSPORTTYPE_RESERVED,                  "reserved"},
  {IPADDRESSPORTTYPE_IPV4,                      "IPV4"},
  {IPADDRESSPORTTYPE_IPV6,                      "IPV6"},
  {0x00, NULL}
};

static const value_string overlaylinktypes [] ={
  {OVERLAYLINKTYPE_RESERVEDOVERLAYLINK,         "reserved"},
  {OVERLAYLINKTYPE_DTLS_UDP_SR,                 "DTLS-UDP-SR"},
  {OVERLAYLINKTYPE_DTLS_UDP_SR_NO_ICE,          "DTLS-UDP-SR-NO-ICE"},
  {OVERLAYLINKTYPE_TLS_TCP_FH_NO_ICE,           "TLS-TCP-FH-NO-ICE"},
  {0x00, NULL}
};

static const value_string errorcodes [] ={
  {ERRORCODE_INVALID,                           "invalid"},
  {ERRORCODE_UNUSED,                            "Unused"},
  {ERRORCODE_FORBIDDEN,                         "Forbidden"},
  {ERRORCODE_NOTFOUND,                          "Not Found"},
  {ERRORCODE_REQUESTTIMEOUT,                    "Request Timeout"},
  {ERRORCODE_GENERATIONCOUNTERTOOLOW,           "Generation Counter Too Low"},
  {ERRORCODE_INCOMPATIBLEWITHOVERLAY,           "Incompatible with Overlay"},
  {ERRORCODE_UNSUPPORTEDFORWARDINGOPTION,       "Unsupported Forwarding Option"},
  {ERRORCODE_DATATOOLARGE,                      "Data Too Large"},
  {ERRORCODE_DATATOOOLD,                        "Data Too Old"},
  {ERRORCODE_TTLEXCEEDED,                       "TTL Exceeded"},
  {ERRORCODE_MESSAGETOOLARGE,                   "Message Too Large"},
  {ERRORCODE_UNKNOWNKIND,                       "Unknown Kind"},
  {ERRORCODE_UNKNOWNEXTENSION,                  "Unknown Extension"},
  {ERRORCODE_RESPONSETOOLARGE,                  "Response Too Large"},
  {ERRORCODE_CONFIGTOOOLD,                      "Config Too Old"},
  {ERRORCODE_CONFIGTOONEW,                      "Config Too New"},
  {0x00, NULL}
};

static const value_string signatureidentitytypes[] = {
  {SIGNATUREIDENTITYTYPE_RESERVED,              "reserved"},
  {SIGNATUREIDENTITYTYPE_CERTHASH,              "CERT_HASH"},
  {SIGNATUREIDENTITYTYPE_CERTHASHNODEID,        "CERT_HASH_NODE_ID"},
  {SIGNATUREIDENTITYTYPE_NONE,                  "NONE"},
  {0x00, NULL}
};

static const value_string probeinformationtypes[] = {
  {PROBEINFORMATIONTYPE_RESERVED,               "reserved"},
  {PROBEINFORMATIONTYPE_RESPONSIBLESET,         "responsible_set"},
  {PROBEINFORMATIONTYPE_NUMRESOURCES,           "num_resources"},
  {PROBEINFORMATIONTYPE_UPTIME,                 "uptime"},
  {0x00, NULL}
};

static const value_string datakindids[] = {
  {DATAKINDID_INVALID,                          "invalid"},
  {DATAKINDID_TURNSERVICE,                      "TURN-SERVICE"},
  {DATAKINDID_CERTIFICATE_BY_NODE,              "CERTIFICATE_BY_NODE"},
  {DATAKINDID_CERTIFICATE_BY_USER,              "CERTIFICATE_BY_USER"},
  {0x00, NULL}
};

static const value_string messageextensiontypes[] = {
  {MESSAGEEXTENSIONTYPE_RESERVED,               "reserved"},
  {0x00, NULL}
};

static const value_string configupdatetypes[] = {
  {CONFIGUPDATETYPE_RESERVED,                   "reserved"},
  {CONFIGUPDATETYPE_CONFIG,                     "config"},
  {CONFIGUPDATETYPE_KIND,                       "kind"},
  {0x00, NULL}
};
/*
 * defragmentation of IPv4
 */
static GHashTable *reload_fragment_table = NULL;
static GHashTable *reload_reassembled_table = NULL;

static void
reload_defragment_init(void)
{
  fragment_table_init(&reload_fragment_table);
  reassembled_table_init(&reload_reassembled_table);
}


static guint
get_reload_message_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint32 length = tvb_get_ntohl(tvb, offset + MSG_LENGH_OFFSET);
  return length;
}

static int
get_opaque_length(tvbuff_t *tvb, guint16 offset, guint16 length_size)
{
  int length = -1;

  switch (length_size) {
  case 1:
    length = (gint32)tvb_get_guint8(tvb,offset);
    break;
  case 2:
    length = (gint32)tvb_get_ntohs(tvb, offset);
    break;
  case 4:
    length = (gint32)tvb_get_ntohl(tvb, offset);
    break;

  default:
    break;
  }

  return length;
}

static int
dissect_opaque(tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int anchor_index, guint16 offset, guint16 length_size, gint32 max_field_length)
{
  proto_tree *opaque_tree;
  proto_item *ti_anchor;
  gint length_index = -1;
  gint32 length = -1;

  switch (length_size) {
  case 1:
    length_index = hf_reload_opaque_length_uint8;
    length = (gint32)tvb_get_guint8(tvb,offset);
    break;
  case 2:
    length_index = hf_reload_opaque_length_uint16;
    length = (gint32)tvb_get_ntohs(tvb, offset);
    break;
  case 3:
    length_index = hf_reload_opaque_length_uint32;
    length = ((gint32) (tvb_get_ntohs(tvb, offset) <<8) + (tvb_get_guint8(tvb, offset+2)));
    break;
  case 4:
    length_index = hf_reload_opaque_length_uint32;
    length = (gint32)tvb_get_ntohl(tvb, offset);
    break;

  default:
    break;
  }

  if (length_index < 0) return 0;

  ti_anchor = proto_tree_add_item(tree, anchor_index, tvb, offset, length_size + length, FALSE);

  if (max_field_length > 0) {
    if ((length + length_size) > max_field_length) {
      expert_add_info_format(pinfo, ti_anchor, PI_PROTOCOL, PI_ERROR, "Computed length > max_field length");
      length = max_field_length - length_size;
    }
  }

  opaque_tree = proto_item_add_subtree(ti_anchor, ett_reload_opaque);
  proto_tree_add_uint(opaque_tree, length_index, tvb, offset, length_size, (guint)length);
  proto_tree_add_item(opaque_tree, hf_reload_opaque_data, tvb, offset + length_size, length, ENC_NA);

  return (length_size + length);
}

static int
dissect_destination(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  guint8 destination_length;
  guint8 destination_type;

  destination_type = tvb_get_guint8(tvb,offset);

  if (destination_type & 0x80) {
    /* simple compressed case */
    destination_length = 2;
    proto_tree_add_item(tree, hf_reload_destination_compressed, tvb, offset, 2, ENC_BIG_ENDIAN);
    return 2;
  }
  else {
    /* normal case */
    proto_tree *destination_tree;
    proto_item *ti_destination;

    destination_length = tvb_get_guint8(tvb,offset+1);
    ti_destination = proto_tree_add_item(tree, hf_reload_destination, tvb, offset, 2+destination_length, ENC_NA);
    destination_tree = proto_item_add_subtree(ti_destination, ett_reload_destination);
    proto_item_append_text(ti_destination, " (%s)", val_to_str(destination_type, destinationtypes, "Unknown"));

    proto_tree_add_item(destination_tree, hf_reload_destination_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_uint(destination_tree, hf_reload_destination_length, tvb, offset+1, 1, destination_length);
    if (2 + destination_length > length) {
      expert_add_info_format(pinfo, ti_destination, PI_PROTOCOL, PI_ERROR, "Truncated destination field");
      return length;
    }
    switch(destination_type) {
    case DESTINATIONTYPE_NODE:
      {
        proto_item *ti_nodeid;
        guint nodeid_length = destination_length;
        /* We don't know the node ID. Just assume that all the data is part of it */
        if (nodeid_length < reload_nodeid_length) {
          expert_add_info_format(pinfo, ti_destination, PI_PROTOCOL, PI_ERROR, "Truncated node id");
        }
        else {
          nodeid_length = reload_nodeid_length;
        }
        ti_nodeid = proto_tree_add_item(destination_tree, hf_reload_nodeid, tvb, offset+ 2, nodeid_length, ENC_NA);
        if ((nodeid_length < 16) || (nodeid_length > 20)) {
          expert_add_info_format(pinfo, ti_nodeid, PI_PROTOCOL, PI_ERROR, "Node ID length is not in the correct range");
        }
      }
      break;

    case DESTINATIONTYPE_RESOURCE:
      dissect_opaque(tvb, pinfo, destination_tree, hf_reload_resource_id, offset +2, 1, destination_length);
      break;

    case DESTINATIONTYPE_COMPRESSED:
      dissect_opaque(tvb, pinfo, destination_tree, hf_reload_destination_data_compressed_id, offset+2, 1, destination_length);
      break;
    default:
      break;
    }
  }
  return (2+destination_length);
}


static int
dissect_destination_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *list_tree, guint16 offset, guint16 length)
{
  gint local_offset = 0;
  gint local_increment;
  while (local_offset +2 <= length) {
    local_increment = dissect_destination(tvb, pinfo, list_tree, offset + local_offset, length-local_offset);
    if (local_increment == 0) break;
    local_offset += local_increment;
  }
  return local_offset;
}

static int
dissect_probe_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_probe_information;
  proto_tree *probe_information_tree;
  guint8 type;
  guint8 probe_length;

  type = tvb_get_guint8(tvb, offset);
  probe_length = tvb_get_guint8(tvb, offset + 1);

  if (probe_length + 2 > length) {
    ti_probe_information = proto_tree_add_item(tree, hf_reload_probe_information, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_probe_information, PI_PROTOCOL, PI_ERROR, "Truncated probe information");
    return length;
  }
  ti_probe_information = proto_tree_add_item(tree, hf_reload_probe_information, tvb, offset, 2 + probe_length, ENC_NA);
  probe_information_tree = proto_item_add_subtree(ti_probe_information, ett_reload_probe_information);

  proto_tree_add_item(probe_information_tree, hf_reload_probe_information_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_uint(probe_information_tree, hf_reload_opaque_length_uint8, tvb, offset + 1, 1, probe_length);

  switch(type) {
  case   PROBEINFORMATIONTYPE_RESPONSIBLESET:
    if (probe_length < 4) {
      expert_add_info_format(pinfo, ti_probe_information, PI_PROTOCOL, PI_ERROR, "Truncated responsible set info");
      return 2 + probe_length;
    }
    proto_tree_add_item(probe_information_tree, hf_reload_responsible_set, tvb, offset + 2, 4, ENC_BIG_ENDIAN);
    break;
  case PROBEINFORMATIONTYPE_NUMRESOURCES:
    if (probe_length < 4) {
      expert_add_info_format(pinfo, ti_probe_information, PI_PROTOCOL, PI_ERROR, "Truncated num resource info");
      return 2 + probe_length;
    }
    proto_tree_add_item(probe_information_tree, hf_reload_num_resources, tvb, offset + 2, 4, ENC_BIG_ENDIAN);
    break;
  case PROBEINFORMATIONTYPE_UPTIME:
    if (probe_length < 4) {
      expert_add_info_format(pinfo, ti_probe_information, PI_PROTOCOL, PI_ERROR, "Truncated uptime info");
      return 2 + probe_length;
    }
    proto_tree_add_item(probe_information_tree, hf_reload_uptime, tvb, offset + 2, 4, ENC_BIG_ENDIAN);
    break;
  default:
    break;
  }

  return probe_length + 2;
}



static int
dissect_ipaddressport(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
  proto_item *ti_ipaddressport;
  proto_tree *ipaddressport_tree;
  guint8 ipaddressport_type;
  guint8 ipaddressport_length;

  ipaddressport_length = tvb_get_guint8(tvb, offset+1);
  ti_ipaddressport = proto_tree_add_item(tree, hf_reload_ipaddressport, tvb, offset, ipaddressport_length+2, ENC_NA);
  ipaddressport_type = tvb_get_guint8(tvb, offset);
  proto_item_append_text(ti_ipaddressport, " %s ", val_to_str(ipaddressport_type, ipaddressporttypes,"Unknown Type"));
  ipaddressport_tree = proto_item_add_subtree(ti_ipaddressport, ett_reload_ipaddressport);
  proto_tree_add_item(ipaddressport_tree, hf_reload_ipaddressport_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset +=1;
  proto_tree_add_uint(ipaddressport_tree, hf_reload_ipaddressport_length, tvb, offset, 1, ipaddressport_length);
  offset +=1;
  switch (ipaddressport_type) {
  case IPADDRESSPORTTYPE_IPV4:
    proto_tree_add_item(ipaddressport_tree, hf_reload_ipv4addr, tvb, offset, 4, FALSE);
    proto_tree_add_item(ipaddressport_tree, hf_reload_port, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
    break;

  case IPADDRESSPORTTYPE_IPV6:
    proto_tree_add_item(ipaddressport_tree, hf_reload_ipv6addr, tvb, offset, 16, FALSE);
    proto_tree_add_item(ipaddressport_tree, hf_reload_port, tvb, offset + 16, 2, ENC_BIG_ENDIAN);
    break;

  default:
    break;
  }

  return (int) (2 + ipaddressport_length);
}

static int
dissect_icecandidates(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_icecandidates;
  proto_tree *icecandidates_tree;
  guint16 icecandidates_offset = 0;
  guint16 icecandidates_length;
  guint16 local_offset = 0;

  icecandidates_length = tvb_get_ntohs(tvb, offset);
  /* Precalculate the length of the icecandidate list */
  if (2+icecandidates_length > length) {
    ti_icecandidates = proto_tree_add_item(tree, hf_reload_icecandidates, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_icecandidates, PI_PROTOCOL, PI_ERROR, "Truncated ice candidates");
    return length;
  }

  ti_icecandidates = proto_tree_add_item(tree, hf_reload_icecandidates, tvb, offset, 2+icecandidates_length, ENC_NA);
  icecandidates_tree = proto_item_add_subtree(ti_icecandidates, ett_reload_icecandidates);
  proto_tree_add_uint(icecandidates_tree, hf_reload_icecandidates_length, tvb, offset+local_offset, 2, icecandidates_length);
  local_offset += 2;
  while (icecandidates_offset < icecandidates_length) {
    proto_item *ti_icecandidate;
    proto_tree *icecandidate_tree;
    guint8 ipaddressport_length;
    guint8 computed_ipaddressport_length;
    guint16 iceextensions_length;
    guint8 foundation_length;
    guint8 candtype;
    guint16 icecandidate_offset = 0;
    /* compute the length */
    ipaddressport_length = tvb_get_guint8(tvb, offset+local_offset+icecandidates_offset+icecandidate_offset+1);
    icecandidate_offset += 2 + ipaddressport_length;
    icecandidate_offset += 1;/* OverlayLink */
    foundation_length = tvb_get_guint8(tvb, offset+local_offset+icecandidates_offset+icecandidate_offset);
    icecandidate_offset += 1 + foundation_length;
    icecandidate_offset += 4;/* priority */
    candtype = tvb_get_guint8(tvb, offset+local_offset+icecandidates_offset+icecandidate_offset);
    icecandidate_offset += 1;/* candType */
    computed_ipaddressport_length = 0;
    switch (candtype) {
    case CANDTYPE_HOST:
      break;
    case CANDTYPE_SRFLX:
    case CANDTYPE_PRFLX:
    case CANDTYPE_RELAY:
      /* IpAddressPort */
      computed_ipaddressport_length = tvb_get_guint8(tvb, offset+local_offset+icecandidates_offset+icecandidate_offset+1);
      icecandidate_offset += computed_ipaddressport_length+2;
      break;
    default:
      break;
    }

    iceextensions_length = tvb_get_ntohs(tvb, offset+local_offset+icecandidates_offset+icecandidate_offset);
    icecandidate_offset += iceextensions_length + 2;

    /* icecandidate_offset is now equal to the length of this icecandicate */
    if (icecandidates_offset + icecandidate_offset > icecandidates_length) {
      expert_add_info_format(pinfo, ti_icecandidates, PI_PROTOCOL, PI_ERROR, "Truncated ice candidate");
      break;
    }
    ti_icecandidate = proto_tree_add_item(icecandidates_tree, hf_reload_icecandidate, tvb, offset+local_offset+ icecandidates_offset, icecandidate_offset, ENC_NA);
    icecandidate_tree = proto_item_add_subtree(ti_icecandidate, ett_reload_icecandidate);
    /* parse from start */
    icecandidate_offset = 0;
    dissect_ipaddressport(tvb, icecandidate_tree, offset+local_offset+icecandidates_offset+icecandidate_offset);
    icecandidate_offset += 2 + ipaddressport_length;

    proto_tree_add_item(icecandidate_tree, hf_reload_overlaylink_type, tvb,
                        offset+local_offset+icecandidates_offset+icecandidate_offset, 1, ENC_BIG_ENDIAN);

    icecandidate_offset += 1;
    icecandidate_offset += dissect_opaque(tvb, pinfo,icecandidate_tree,  hf_reload_icecandidate_foundation,offset+local_offset+icecandidates_offset + icecandidate_offset, 1, -1);

    {
      guint32 priority;

      priority = tvb_get_ntohl(tvb, offset+local_offset + icecandidates_offset);
      proto_tree_add_item(icecandidate_tree, hf_reload_icecandidate_priority, tvb, offset+local_offset + icecandidates_offset, 4, ENC_BIG_ENDIAN);
      icecandidate_offset += 4;
      proto_tree_add_item(icecandidate_tree, hf_reload_icecandidate_type, tvb,
                          offset+local_offset+icecandidates_offset+icecandidate_offset, 1, ENC_BIG_ENDIAN);
      proto_item_append_text(ti_icecandidate, ": %s, priority=%d", val_to_str(candtype, candtypes, "Unknown"), priority);
    }
    icecandidate_offset += 1;
    {
      int item_index = -1;
      switch (candtype) {
      case CANDTYPE_HOST:
        break;
      case CANDTYPE_SRFLX:
        item_index = hf_reload_icecandidate_srflx_addr;
        break;
      case CANDTYPE_PRFLX:
        item_index = hf_reload_icecandidate_prflx_addr;
        break;
      case CANDTYPE_RELAY:
        item_index = hf_reload_icecandidate_relay_addr;
        break;

      default:
        break;
      }
      if (item_index != -1) {
        proto_item *ti_computed_address;
        proto_tree *computed_address_tree;
        ti_computed_address =
          proto_tree_add_item(icecandidate_tree, item_index, tvb,
                              offset+local_offset+icecandidates_offset+icecandidate_offset, computed_ipaddressport_length + 2, FALSE);
        computed_address_tree = proto_item_add_subtree(ti_computed_address, ett_reload_icecandidate_computed_address);
        dissect_ipaddressport(tvb, computed_address_tree,
                              offset+local_offset+icecandidates_offset+icecandidate_offset);
        icecandidate_offset += computed_ipaddressport_length + 2;
      }
    }
    /* Ice extensions */
    {
      guint16 iceextensions_offset = 0;
      proto_item *ti_iceextension, *ti_iceextensions_length;
      proto_tree *iceextension_tree;
      guint16 iceextension_name_length;
      guint16 iceextension_value_length;
      ti_iceextensions_length =
        proto_tree_add_uint(icecandidate_tree, hf_reload_icecandidate_extensions_length, tvb,
                            offset+local_offset+icecandidates_offset+icecandidate_offset, 2,
                            iceextensions_length);
      icecandidate_offset += 2;
      while (iceextensions_offset < iceextensions_length) {
        iceextension_name_length =
          tvb_get_ntohs(tvb, offset+local_offset+icecandidates_offset+icecandidate_offset+iceextensions_offset);
        iceextension_value_length =
          tvb_get_ntohs(tvb, offset+local_offset+icecandidates_offset+icecandidate_offset+iceextensions_offset+iceextension_name_length + 2);
        if ((iceextensions_offset + 4 + iceextension_name_length + iceextension_value_length) > iceextensions_length) {
          expert_add_info_format(pinfo, ti_iceextensions_length, PI_PROTOCOL, PI_ERROR, "Truncated ice extension");
          break;
        }
        ti_iceextension =
          proto_tree_add_item(icecandidate_tree, hf_reload_iceextension, tvb,
                              offset+local_offset + icecandidates_offset + icecandidate_offset + iceextensions_offset, 4 + iceextension_name_length + iceextension_value_length, ENC_NA);
        iceextension_tree = proto_item_add_subtree(ti_iceextension, ett_reload_iceextension);
        proto_tree_add_item(iceextension_tree, hf_reload_iceextension_name, tvb,
                            offset+local_offset+ icecandidates_offset + icecandidate_offset + iceextensions_offset, 2 + iceextension_name_length, ENC_NA);
        proto_tree_add_item(iceextension_tree, hf_reload_iceextension_value, tvb,
                            offset+local_offset + icecandidates_offset + icecandidate_offset + iceextensions_offset +2 + iceextension_name_length, 2 + iceextension_value_length, ENC_NA);
        iceextensions_offset += 4 + iceextension_name_length + iceextension_value_length;
      }
    }
    icecandidate_offset += iceextensions_length;
    icecandidates_offset += icecandidate_offset;
  }
  return (2 + icecandidates_length);
}

static int
dissect_attachreqans(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_attachreqans;
  proto_tree *attachreqans_tree;
  guint8 ufrag_length;
  guint8 password_length;
  guint8 role_length;
  guint16 icecandidates_length;
  guint16 local_offset = 0;

  /* variable length structures: must 1st compute the length ... */
  ufrag_length = tvb_get_guint8(tvb,offset+local_offset);
  local_offset += 1;
  if (local_offset + ufrag_length > length) {
    ti_attachreqans = proto_tree_add_item(tree, hf_reload_attachreqans, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_attachreqans, PI_PROTOCOL, PI_ERROR, "Truncated attach_reqans");
    return length;
  }
  local_offset += ufrag_length;
  password_length = tvb_get_guint8(tvb,offset+local_offset);
  local_offset += 1;
  if (local_offset + password_length > length) {
    ti_attachreqans = proto_tree_add_item(tree, hf_reload_attachreqans, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_attachreqans, PI_PROTOCOL, PI_ERROR, "Truncated attach_reqans");
    return length;
  }
  local_offset += password_length;
  role_length = tvb_get_guint8(tvb,offset+local_offset);
  local_offset += 1;
  if (local_offset + role_length > length) {
    ti_attachreqans = proto_tree_add_item(tree, hf_reload_attachreqans, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_attachreqans, PI_PROTOCOL, PI_ERROR, "Truncated attach_reqans");
    return length;
  }
  local_offset += role_length;
  icecandidates_length = tvb_get_ntohs(tvb, offset+local_offset);
  local_offset += 2;
  if (local_offset +icecandidates_length > length) {
    ti_attachreqans = proto_tree_add_item(tree, hf_reload_attachreqans, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_attachreqans, PI_PROTOCOL, PI_ERROR, "Truncated attach_reqans");
    return length;
  }
  local_offset += icecandidates_length;

  ti_attachreqans = proto_tree_add_item(tree, hf_reload_attachreqans, tvb, offset, local_offset, ENC_NA);
  attachreqans_tree  = proto_item_add_subtree(ti_attachreqans, ett_reload_attachreqans);

  /* restart parsing, field by field */
  local_offset = 0;
  local_offset += dissect_opaque(tvb, pinfo,attachreqans_tree, hf_reload_ufrag,offset+local_offset, 1, -1);
  local_offset += dissect_opaque(tvb, pinfo,attachreqans_tree, hf_reload_password,offset+local_offset, 1, -1);
  local_offset += dissect_opaque(tvb, pinfo,attachreqans_tree, hf_reload_role,offset+local_offset, 1, -1);
  local_offset += dissect_icecandidates(tvb, pinfo, attachreqans_tree, offset + local_offset, 2+icecandidates_length);

  proto_tree_add_item(attachreqans_tree, hf_reload_sendupdate, tvb, offset+local_offset, 1, FALSE);
  local_offset += 1;

  return local_offset;
}

static int
dissect_storeddata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_storeddata;
  proto_item *storeddata_tree;
  guint32 storeddata_length;
  guint32 local_offset = 0;

  storeddata_length = tvb_get_ntohl(tvb, offset);
  local_offset += 4;

  if (storeddata_length + 4 > length) {
    ti_storeddata = proto_tree_add_item(tree, hf_reload_storeddata, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_storeddata, PI_PROTOCOL, PI_ERROR, "Truncated storeddata");
    return length;
  }

  local_offset = 0;
  ti_storeddata = proto_tree_add_item(tree, hf_reload_storeddata, tvb, offset, 4 + storeddata_length, ENC_NA);
  storeddata_tree = proto_item_add_subtree(ti_storeddata, ett_reload_storeddata);

  proto_tree_add_uint(storeddata_tree, hf_reload_storeddata_length, tvb, offset + local_offset, 4, storeddata_length);
  local_offset += 4;
  proto_tree_add_item(storeddata_tree, hf_reload_storeddata_storage_time, tvb, offset + local_offset, 8, ENC_BIG_ENDIAN);
  local_offset += 8;
  proto_tree_add_item(storeddata_tree, hf_reload_storeddata_lifetime, tvb, offset + local_offset, 4, ENC_BIG_ENDIAN);
  /* Can not parse the value and signature fields, as we do not know what is the data model for
     a given kind id */
  return (storeddata_length + 4);
}

static int
dissect_kinddata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_kinddata;
  proto_item *kinddata_tree;
  guint32 values_length;
  guint32 local_offset = 0;

  values_length = tvb_get_ntohl(tvb, offset + 4 + 8);
  if (12 + values_length > length) {
    ti_kinddata = proto_tree_add_item(tree, hf_reload_kinddata, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_kinddata, PI_PROTOCOL, PI_ERROR, "Truncated kind data");
    return length;
  }
  ti_kinddata = proto_tree_add_item(tree, hf_reload_kinddata, tvb, offset, 12+values_length, ENC_NA);
  kinddata_tree = proto_item_add_subtree(ti_kinddata, ett_reload_kinddata);

  proto_tree_add_item(kinddata_tree, hf_reload_kindid, tvb, offset+local_offset, 4, ENC_BIG_ENDIAN);
  local_offset += 4;
  proto_tree_add_item(kinddata_tree, hf_reload_kinddata_generation_counter, tvb, offset+local_offset, 8, ENC_BIG_ENDIAN);
  local_offset += 8;
  proto_tree_add_uint(kinddata_tree, hf_reload_kinddata_values_length, tvb, offset +local_offset, 4, values_length);
  local_offset += 4;
  {
    guint32 values_offset = 0;
    guint32 values_increment;
    while (values_offset < values_length) {
      values_increment = dissect_storeddata(tvb, pinfo, kinddata_tree, offset+local_offset+values_offset, values_length - values_offset);
      if (values_increment == 0) {
        break;
      }
      values_offset += values_increment;
    }
  }
  local_offset += values_length;
  return local_offset;
}

static int
dissect_storereq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item * ti_storereq;
  proto_tree * storereq_tree;
  guint32 local_offset = 0;
  guint32 kind_data_length;


  local_offset += get_opaque_length(tvb, offset, 1) + 1; /* resource id length */
  if (local_offset > length) {
    ti_storereq = proto_tree_add_item(tree, hf_reload_storereq, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_storereq, PI_PROTOCOL, PI_ERROR, "Truncated storereq: resource too long");
    return length;
  }

  local_offset += 1; /* replica_num */
  if (local_offset > length) {
    ti_storereq = proto_tree_add_item(tree, hf_reload_storereq, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_storereq, PI_PROTOCOL, PI_ERROR, "Truncated storereq: no room for replica_number");
    return length;
  }

  kind_data_length = tvb_get_ntohl(tvb, offset + local_offset);
  local_offset += 4;
  if (local_offset + kind_data_length > length) {
    ti_storereq = proto_tree_add_item(tree, hf_reload_storereq, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_storereq, PI_PROTOCOL, PI_ERROR, "Truncated storereq: kind_date too long");
    return length;
  }
  local_offset += kind_data_length;

  ti_storereq = proto_tree_add_item(tree, hf_reload_storereq, tvb, offset, local_offset, ENC_NA);
  storereq_tree = proto_item_add_subtree(ti_storereq, ett_reload_storereq);

  /* Parse from start */
  local_offset = 0;
  local_offset += dissect_opaque(tvb, pinfo, storereq_tree, hf_reload_resource_id, offset +local_offset, 1, length);
  proto_tree_add_item(storereq_tree, hf_reload_store_replica_num, tvb, offset + local_offset, 1, ENC_BIG_ENDIAN);
  local_offset += 1;
  proto_tree_add_item(storereq_tree, hf_reload_store_kind_data_length, tvb, offset + local_offset, 4, ENC_BIG_ENDIAN);
  local_offset += 4;
  {
    guint32 kind_data_offset = 0;
    guint32 kind_data_increment;
    while (kind_data_offset < kind_data_length) {
      kind_data_increment = dissect_kinddata(tvb, pinfo, storereq_tree, offset+local_offset+kind_data_offset, kind_data_length - kind_data_offset);
      if (kind_data_increment == 0) {
        break;
      }
      kind_data_offset += kind_data_increment;
    }
  }
  local_offset += kind_data_length;

  return local_offset;
}

static int
dissect_fetchans(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_fetchans;
  proto_tree *fetchans_tree;
  guint32 kind_responses_length;
  guint32 kind_responses_offset = 0;

  kind_responses_length = tvb_get_ntohl(tvb, offset);
  if (4 + kind_responses_length > length) {
    ti_fetchans = proto_tree_add_item(tree, hf_reload_fetchans, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_fetchans, PI_PROTOCOL, PI_ERROR, "Truncated storereq");
    return length;
  }
  ti_fetchans = proto_tree_add_item(tree, hf_reload_fetchans, tvb, offset, 4 + kind_responses_length, ENC_NA);
  fetchans_tree = proto_item_add_subtree(ti_fetchans, ett_reload_fetchans);

  proto_tree_add_uint(fetchans_tree, hf_reload_kind_responses_length, tvb, offset, 4, FALSE);

  while (kind_responses_offset < kind_responses_length) {
    guint32 kind_responses_increment;
    kind_responses_increment = dissect_kinddata(tvb, pinfo, fetchans_tree, offset + 4 + kind_responses_offset, kind_responses_length - kind_responses_offset);
    if (kind_responses_increment == 0) {
      break;
    }
    kind_responses_offset += kind_responses_increment;
  }

  return 4 + kind_responses_length;
}


static int
dissect_statans(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_statans;
  proto_tree *statans_tree;
  guint32 kind_responses_length;
  guint32 kind_responses_offset = 0;

  kind_responses_length = tvb_get_ntohl(tvb, offset);
  if (4 + kind_responses_length > length) {
    ti_statans = proto_tree_add_item(tree, hf_reload_statans, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_statans, PI_PROTOCOL, PI_ERROR, "Truncated statans");
    return length;
  }
  ti_statans = proto_tree_add_item(tree, hf_reload_statans, tvb, offset, 4 + kind_responses_length, ENC_NA);
  statans_tree = proto_item_add_subtree(ti_statans, ett_reload_statans);

  proto_tree_add_uint(statans_tree, hf_reload_kind_responses_length, tvb, offset, 4, FALSE);

  while (kind_responses_offset < kind_responses_length) {
    /* assume metadata is a form of stored data */
    guint32 kind_responses_increment;
    kind_responses_increment = dissect_kinddata(tvb, pinfo, statans_tree, offset + 4 + kind_responses_offset, kind_responses_length - kind_responses_offset);
    if (kind_responses_increment == 0) {
      break;
    }
    kind_responses_offset += kind_responses_increment;
  }

  return 4 + kind_responses_length;
}

static int
dissect_reload_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *reload_tree;
  guint32 relo_token;
  guint effective_length;
  guint msg_length;
  guint16 offset;
  conversation_t *conversation;
  reload_conv_info_t *reload_info;
  reload_transaction_t * reload_trans;
  emem_tree_key_t transaction_id_key[2];
  guint32 transaction_id[2];
  guint16 options_length;
  guint16 via_list_length;
  guint16 destination_list_length;
  guint16 message_code;
  guint16 error_code = 0;
  guint32 forwarding_length;
  proto_tree *reload_forwarding_tree;
  const char *msg_class_str;
  const char *msg_method_str = NULL;
  gboolean fragmented = FALSE;
  gboolean last_fragment = FALSE;
  fragment_data *reload_fd_head = NULL;
  gboolean save_fragmented;
  guint32 fragment = 0;
  gboolean update_col_info = TRUE;

  offset = 0;
  effective_length = tvb_length(tvb);

  /* First, make sure we have enough data to do the check. */
  if (effective_length < MIN_HDR_LENGTH)
    return 0;

  /*
   * First check if the frame is really meant for us.
   */
  relo_token = tvb_get_ntohl(tvb,0);

  if (relo_token != RELOAD_TOKEN) {
    return 0;
  }

  msg_length = get_reload_message_length(pinfo, tvb, offset);

  if (effective_length < msg_length) {
    /* The effective length is too small for the packet */
    expert_add_info_format(pinfo, NULL, PI_PROTOCOL, PI_ERROR, "Truncated RELOAD packet");
    return 0;
  }

  /* The message seems to be a valid reLOAD message! */

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RELOAD");
  col_clear(pinfo->cinfo, COL_INFO);

  /* Create the transaction key which may be used to track the conversation */
  transaction_id[0] = tvb_get_ntohl(tvb, 20);
  transaction_id[1] = tvb_get_ntohl(tvb, 24);

  transaction_id_key[0].length = 2;
  transaction_id_key[0].key =  transaction_id;
  transaction_id_key[1].length = 0;
  transaction_id_key[1].key = NULL;

  via_list_length = tvb_get_ntohs(tvb, 32);
  destination_list_length = tvb_get_ntohs(tvb, 34);
  options_length = tvb_get_ntohs(tvb, 36);

  forwarding_length = MIN_HDR_LENGTH + (via_list_length + destination_list_length + options_length);

  message_code = tvb_get_ntohs(tvb, forwarding_length);

  /* Do we already have a conversation ? */
  conversation = find_or_create_conversation(pinfo);

  /*
   * Do we already have a state structure for this conv
   */
  reload_info = conversation_get_proto_data(conversation, proto_reload);
  if (!reload_info) {
    /* No.  Attach that information to the conversation, and add
     * it to the list of information structures.
     */
    reload_info = se_alloc(sizeof(reload_conv_info_t));
    reload_info->transaction_pdus = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "reload_transaction_pdus");
    conversation_add_proto_data(conversation, proto_reload, reload_info);
  }

  if (!pinfo->fd->flags.visited) {
    if ((reload_trans =
         se_tree_lookup32_array(reload_info->transaction_pdus, transaction_id_key)) == NULL) {
      reload_trans = se_alloc(sizeof(reload_transaction_t));
      reload_trans->req_frame = 0;
      reload_trans->rep_frame = 0;
      reload_trans->req_time = pinfo->fd->abs_ts;
      se_tree_insert32_array(reload_info->transaction_pdus, transaction_id_key, (void *)reload_trans);
    }

    /* check whether the message is a request or a response */

    if (IS_REQUEST(message_code) && (message_code != RELOAD_ERROR)) {
      /* This is a request */
      if (reload_trans->req_frame == 0) {
        reload_trans->req_frame = pinfo->fd->num;
      }
    }
    else {
      /* This is a catch-all for all non-request messages */
      if (reload_trans->rep_frame == 0) {
        reload_trans->rep_frame = pinfo->fd->num;
      }
    }
  }
  else {
    reload_trans=se_tree_lookup32_array(reload_info->transaction_pdus, transaction_id_key);
  }

  if (!reload_trans) {
    /* create a "fake" pana_trans structure */
    reload_trans = ep_alloc(sizeof(reload_transaction_t));
    reload_trans->req_frame = 0;
    reload_trans->rep_frame = 0;
    reload_trans->req_time = pinfo->fd->abs_ts;
  }

  ti = proto_tree_add_item(tree, proto_reload, tvb, 0, -1, FALSE);

  if (message_code == RELOAD_ERROR) {
    error_code = tvb_get_ntohs(tvb, forwarding_length + 2);
    msg_class_str = "ERROR Response";
    col_add_fstr(pinfo->cinfo, COL_INFO, " %s %s", msg_class_str, val_to_str(error_code, errorcodes, "Unknown"));
    proto_item_append_text(ti, ": %s %s", msg_class_str, val_to_str(error_code, errorcodes, "Unknown"));
  }
  else {
    msg_class_str = val_to_str(MSGCODE_TO_CLASS(message_code), classes, "Unknown %d");
    msg_method_str = val_to_str(MSGCODE_TO_METHOD(message_code), methods, "Unknown %d");

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                 msg_method_str, msg_class_str);
    proto_item_append_text(ti, ": %s %s", msg_method_str, msg_class_str);
  }

  reload_tree = proto_item_add_subtree(ti, ett_reload);

  /* Retransmission control */
  if (IS_REQUEST(message_code) && (message_code != RELOAD_ERROR)) {
    if (reload_trans->req_frame != pinfo->fd->num) {
      proto_item *it;
      it = proto_tree_add_uint(reload_tree, hf_reload_duplicate, tvb, 0, 0, reload_trans->req_frame);
      PROTO_ITEM_SET_GENERATED(it);
    }
    if (reload_trans->rep_frame) {
      proto_item *it;
      it = proto_tree_add_uint(reload_tree, hf_reload_response_in, tvb, 0, 0, reload_trans->rep_frame);
      PROTO_ITEM_SET_GENERATED(it);
    }
  }
  else {
    /* This is a response */
    if (reload_trans->rep_frame != pinfo->fd->num) {
      proto_item *it;
      it = proto_tree_add_uint(reload_tree, hf_reload_duplicate, tvb, 0, 0, reload_trans->rep_frame);
      PROTO_ITEM_SET_GENERATED(it);
    }

    if (reload_trans->req_frame) {
      proto_item *it;
      nstime_t ns;

      it = proto_tree_add_uint(reload_tree, hf_reload_response_to, tvb, 0, 0, reload_trans->req_frame);
      PROTO_ITEM_SET_GENERATED(it);

      nstime_delta(&ns, &pinfo->fd->abs_ts, &reload_trans->req_time);
      it = proto_tree_add_time(reload_tree, hf_reload_time, tvb, 0, 0, &ns);
      PROTO_ITEM_SET_GENERATED(it);
    }
  }

  /*
   * Message dissection
   */

  /*
   * Forwarding Header
   */
  ti = proto_tree_add_item(reload_tree, hf_reload_forwarding, tvb, 0, forwarding_length, ENC_NA);
  reload_forwarding_tree = proto_item_add_subtree(ti, ett_reload_forwarding);

  proto_tree_add_uint(reload_forwarding_tree, hf_reload_token, tvb, 0, 4, relo_token);
  proto_tree_add_item(reload_forwarding_tree, hf_reload_overlay, tvb, 4, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(reload_forwarding_tree, hf_reload_configuration_sequence, tvb, 8, 2, ENC_BIG_ENDIAN);
  {
    guint8 version =
      tvb_get_guint8(tvb,10);
    proto_tree_add_uint_format_value(reload_forwarding_tree, hf_reload_version, tvb, 10, 1,
                                     version, "%u.%u", (version & 0xF0)>>4, (version & 0xF));
  }
  proto_tree_add_item(reload_forwarding_tree, hf_reload_ttl, tvb, 11, 1, ENC_BIG_ENDIAN);
  {
    proto_item *ti_fragment;
    proto_tree *fragment_tree;
    guint32 bit_offset;

    fragment = tvb_get_ntohl(tvb,12);

    ti_fragment = proto_tree_add_uint(reload_forwarding_tree, hf_reload_fragment_flag, tvb, 12, 4, fragment);
    fragment_tree = proto_item_add_subtree(ti_fragment, ett_reload_fragment_flag);
    bit_offset = (12) * 8;

    if (fragment & 0x80000000) {
      proto_item_append_text(ti_fragment, " (Fragment)");
      fragmented = TRUE;
    }
    if (fragment & 0x40000000) {
      proto_item_append_text(ti_fragment, " (Last)");
      last_fragment = TRUE;
    }
    proto_tree_add_bits_item(fragment_tree, hf_reload_fragment_fragmented, tvb, bit_offset, 1, FALSE);
    proto_tree_add_bits_item(fragment_tree, hf_reload_fragment_last_fragment, tvb, bit_offset+1, 1, FALSE);
    proto_tree_add_bits_item(fragment_tree, hf_reload_fragment_reserved, tvb, bit_offset+2, 6, FALSE);
    fragment = fragment & 0x00ffffff;
    proto_tree_add_uint(fragment_tree, hf_reload_fragment_offset, tvb, 13, 3, fragment);
  }

  /* msg_length is already parsed */
  proto_tree_add_uint(reload_forwarding_tree, hf_reload_length, tvb, 16, 4, msg_length);
  proto_tree_add_item(reload_forwarding_tree, hf_reload_trans_id, tvb, 20, 8, ENC_BIG_ENDIAN);
  proto_tree_add_item(reload_forwarding_tree, hf_reload_max_response_length, tvb, 28, 4, ENC_BIG_ENDIAN);
  /* variable lengths fields lengths are already parsed */
  proto_tree_add_uint(reload_forwarding_tree, hf_reload_via_list_length, tvb, 32, 2, via_list_length);
  proto_tree_add_uint(reload_forwarding_tree, hf_reload_destination_list_length, tvb, 34, 2, destination_list_length);
  proto_tree_add_uint(reload_forwarding_tree, hf_reload_options_length, tvb, 36, 2, options_length);

  offset += MIN_HDR_LENGTH;

  if (((guint)offset + via_list_length) > msg_length) {
    expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_ERROR, "Truncated RELOAD packet");
    return MIN_HDR_LENGTH;
  }

  if (via_list_length > 0) {
    proto_item *ti_vialist;
    proto_tree *vialist_tree;
    ti_vialist = proto_tree_add_item(reload_forwarding_tree, hf_reload_via_list, tvb, offset, via_list_length, ENC_NA);
    vialist_tree = proto_item_add_subtree(ti_vialist, ett_reload_via_list);

    dissect_destination_list(tvb, pinfo, vialist_tree, offset, via_list_length);
  }
  offset += via_list_length;

  if (((guint)offset + destination_list_length) > msg_length) {
    expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_ERROR, "Truncated RELOAD packet");
    return offset;
  }

  if (destination_list_length > 0) {
    proto_item *ti_destination_list;
    proto_tree *destination_list_tree;
    ti_destination_list = proto_tree_add_item(reload_forwarding_tree, hf_reload_destination_list, tvb, offset, destination_list_length, ENC_NA);
    destination_list_tree = proto_item_add_subtree(ti_destination_list, ett_reload_destination_list);

    dissect_destination_list(tvb, pinfo, destination_list_tree, offset, destination_list_length);
  }
  offset += destination_list_length;

  if (((guint)offset + options_length) > msg_length) {
    expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_ERROR, "Truncated RELOAD packet");
    return offset;
  }

  if (options_length > 0) {
    guint16 local_offset = 0;
    while ((local_offset +4) <= options_length) {
      proto_item *ti_option;
      guint8 option_type = tvb_get_guint8(tvb,offset+local_offset);
      guint8 option_flags = tvb_get_guint8(tvb, offset+local_offset + 1);
      guint16 option_length = tvb_get_ntohs(tvb, offset+local_offset + 2);
      proto_tree *option_tree;

      ti_option = proto_tree_add_item(reload_forwarding_tree, hf_reload_forwarding_option, tvb, offset+local_offset, option_length + 4, ENC_NA);
      proto_item_append_text(ti_option, " type=%s, flags=%02x, length=%d", val_to_str(option_type, forwardingoptiontypes, "Unknown"), option_flags, option_length);

      option_tree = proto_item_add_subtree(ti_option, ett_reload_forwarding_option);
      proto_tree_add_item(option_tree, hf_reload_forwarding_option_type, tvb, offset+local_offset, 1, ENC_BIG_ENDIAN);
      {
        proto_item *ti_flags;
        proto_tree *flags_tree;
        guint32 bit_offset;
        ti_flags = proto_tree_add_uint(option_tree, hf_reload_forwarding_option_flags, tvb, offset+local_offset+1, 1, option_flags);
        flags_tree = proto_item_add_subtree(ti_flags, ett_reload_forwarding_option_flags);
        bit_offset = 8*(offset+local_offset+1);
        proto_tree_add_bits_item(flags_tree, hf_reload_forwarding_option_flag_response_copy, tvb, bit_offset+5, 1, FALSE);
        proto_tree_add_bits_item(flags_tree, hf_reload_forwarding_option_flag_destination_critical, tvb, bit_offset+6, 1, FALSE);
        proto_tree_add_bits_item(flags_tree, hf_reload_forwarding_option_flag_forward_critical, tvb, bit_offset+7, 1, FALSE);
      }
      proto_tree_add_uint(option_tree, hf_reload_forwarding_option_length, tvb, offset+local_offset+2, 2, option_length);
      local_offset += 4;
      if (local_offset + option_length > options_length) {
        expert_add_info_format(pinfo, ti_option, PI_PROTOCOL, PI_ERROR, "Bad option len");
        break;
      }

      switch (option_type) {
      default:
        proto_tree_add_item(option_tree, hf_reload_forwarding_option_data, tvb, offset+local_offset, option_length, ENC_NA);
        break;
      }
      local_offset += option_length;
    }
  }
  offset += options_length;

  save_fragmented = pinfo->fragmented;
  if ((reload_defragment) && ((fragmented != FALSE) && !((fragment == 0) && (last_fragment)))) {
    tvbuff_t   *next_tvb = NULL;

    pinfo->fragmented = TRUE;
    if (tvb_bytes_exist(tvb, offset, msg_length - offset)) {
      fragment_add_check(tvb, offset, pinfo,
                         transaction_id[0]^transaction_id[1],
                         reload_fragment_table,
                         reload_reassembled_table,
                         fragment,
                         msg_length - offset,
                         !last_fragment);

      next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled RELOAD",
                                          reload_fd_head, &reload_frag_items, &update_col_info, reload_tree);
    }
    if (next_tvb == NULL) {
      /* Just show this as a fragment. */
      col_add_fstr(pinfo->cinfo, COL_INFO, "Fragmented RELOAD protocol (trans id=%x%x off=%u)",
                   transaction_id[0],transaction_id[1], fragment);
      if (reload_fd_head && reload_fd_head->reassembled_in != pinfo->fd->num) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " [Reassembled in #%u]",
                        reload_fd_head->reassembled_in);
      }
      call_dissector(data_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree);
      pinfo->fragmented = save_fragmented;
      return effective_length;
    }
    tvb = next_tvb;
    offset = 0;
  }
  else {
    pinfo->fragmented = FALSE;
  }



  /* Message Contents */
  {
    guint32 message_body_length;
    guint32 extensions_length;
    proto_item *ti_message_contents;
    proto_tree *message_contents_tree;

    message_body_length = tvb_get_ntohl(tvb, offset + 2);
    extensions_length = tvb_get_ntohl(tvb, offset + 2 + 4 + message_body_length);
    if (forwarding_length + 2 + 4 + message_body_length + 4 + extensions_length > msg_length) {
      ti_message_contents = proto_tree_add_item(reload_tree, hf_reload_message_contents, tvb, offset, (msg_length - forwarding_length), ENC_NA);
      expert_add_info_format(pinfo, ti_message_contents, PI_PROTOCOL, PI_ERROR, "Truncated message contents");
      return msg_length;
    }

    ti_message_contents = proto_tree_add_item(reload_tree, hf_reload_message_contents, tvb, offset, 2 + 4 + message_body_length + 4 + extensions_length, ENC_NA);
    message_contents_tree = proto_item_add_subtree(ti_message_contents, ett_reload_message_contents);

    if (message_code != RELOAD_ERROR) {
      proto_item *ti_message_body;
      proto_tree *message_body_tree;

      /* message_code was already parsed */
      proto_tree_add_uint_format_value(message_contents_tree, hf_reload_message_code, tvb,
                                       offset, 2,
                                       message_code,
                                       "%s-%s", msg_method_str, msg_class_str);
      offset += 2;
      /* Message body */
      ti_message_body = proto_tree_add_item(message_contents_tree, hf_reload_message_body, tvb, offset, 4 + message_body_length, ENC_NA);
      message_body_tree = proto_item_add_subtree(ti_message_body, ett_reload_message_body);
      proto_tree_add_uint(message_body_tree, hf_reload_opaque_length_uint32, tvb, offset, 4, message_body_length);
      offset +=4;

      switch(MSGCODE_TO_METHOD(message_code)) {
      case METHOD_ROUTEQUERY:
        {
          if (IS_REQUEST(message_code)) {
            {
              proto_item * ti_routequeryreq;
              proto_tree * routequeryreq_tree;
              int destination_length;
              ti_routequeryreq = proto_tree_add_item(message_body_tree, hf_reload_routequeryreq, tvb, offset, message_body_length, ENC_NA);
              routequeryreq_tree = proto_item_add_subtree(ti_routequeryreq, ett_reload_routequeryreq);
              proto_tree_add_item(routequeryreq_tree, hf_reload_sendupdate, tvb, offset, 1, FALSE);
              destination_length = dissect_destination(tvb, pinfo, routequeryreq_tree, offset + 1, message_body_length - 1 - 2);
              dissect_opaque(tvb, pinfo, routequeryreq_tree, hf_reload_overlay_specific, offset + 1 + destination_length, 2, (message_body_length - 1 - destination_length));
            }
          }
          /* Answer is entirely Overlay-specific */
        }
        break;

      case METHOD_PROBE:
        {
          if (IS_REQUEST(message_code)) {
            proto_item * ti_probereq;
            proto_tree * probereq_tree;
            guint8 info_list_length = 0;
            ti_probereq = proto_tree_add_item(message_body_tree, hf_reload_probereq, tvb, offset, message_body_length, ENC_NA);
            probereq_tree = proto_item_add_subtree(ti_probereq, ett_reload_probereq);
            info_list_length = tvb_get_guint8(tvb, offset);

            proto_tree_add_uint(probereq_tree, hf_reload_opaque_length_uint8, tvb, offset, 1, info_list_length);

            if (info_list_length > message_body_length - 1) {
              expert_add_info_format(pinfo, ti_probereq, PI_PROTOCOL, PI_ERROR, "Requested info list too long for field size");
              info_list_length = message_body_length - 1;
            }
            {
              int probe_offset = 0;
              while (probe_offset < info_list_length) {
                proto_tree_add_item(probereq_tree, hf_reload_probe_information_type, tvb, offset + 1 + probe_offset, 1, ENC_BIG_ENDIAN);
                probe_offset += 1;
              }
            }
          }
          else {
            /* response */
            proto_item * ti_probeans;
            proto_tree * probeans_tree;
            guint16 info_list_length = 0;

            ti_probeans = proto_tree_add_item(message_body_tree, hf_reload_probeans, tvb, offset, message_body_length, ENC_NA);
            probeans_tree = proto_item_add_subtree(ti_probeans, ett_reload_probeans);
            info_list_length = tvb_get_ntohs(tvb, offset);

            proto_tree_add_uint(probeans_tree, hf_reload_opaque_length_uint16, tvb, offset, 2, info_list_length);

            if (info_list_length > message_body_length - 2) {
              expert_add_info_format(pinfo, ti_probeans, PI_PROTOCOL, PI_ERROR, "Requested info list too long for field size");
              info_list_length = message_body_length - 2;
            }
            {
              int probe_offset = 0;
              int probe_increment;
              while (probe_offset < info_list_length) {
                probe_increment = dissect_probe_information(tvb, pinfo, probeans_tree, offset + 2 + probe_offset, info_list_length - probe_offset);
                if (probe_increment == 0) {
                  break;
                }
              probe_offset += probe_increment;
              }
            }
          }
        }
        break;

      case METHOD_ATTACH:
        {
          dissect_attachreqans(tvb, pinfo, message_body_tree, offset, message_body_length);
        }
        break;

      case METHOD_APPATTACH:
        {
          /* Parse AppAttachReq/Ans */

          {
            guint16 local_offset = 0;
            proto_item *ti_appattach;
            proto_tree *appattach_tree;
            ti_appattach = proto_tree_add_item(message_body_tree, hf_reload_appattach, tvb, offset+local_offset, message_body_length, ENC_NA);
            appattach_tree  = proto_item_add_subtree(ti_appattach, ett_reload_appattach);
            local_offset += dissect_opaque(tvb, pinfo,appattach_tree, hf_reload_ufrag,offset+local_offset, 1, message_body_length-local_offset);
            local_offset += dissect_opaque(tvb, pinfo,appattach_tree, hf_reload_password,offset+local_offset, 1, message_body_length-local_offset);
            proto_tree_add_item(appattach_tree, hf_reload_application, tvb, offset+local_offset, 2, ENC_BIG_ENDIAN);
            local_offset += 2;
            local_offset += dissect_opaque(tvb, pinfo,appattach_tree, hf_reload_role,offset+local_offset, 1, message_body_length-local_offset);
            dissect_icecandidates(tvb, pinfo, appattach_tree, offset+local_offset, message_body_length-local_offset);
          }
        }
        break;

      case METHOD_PING:
        {
          if (IS_REQUEST(message_code)) {
            dissect_opaque(tvb, pinfo, message_body_tree, hf_reload_padding, offset, 2, message_body_length);
          }
          else {
            if (message_body_length < 16) {
              expert_add_info_format(pinfo, ti_message_contents, PI_PROTOCOL, PI_ERROR, "Truncated ping answer");
            }
            else {
              proto_tree_add_item(message_body_tree, hf_reload_ping_response_id, tvb, offset, 8, ENC_BIG_ENDIAN);
              proto_tree_add_item(message_body_tree, hf_reload_ping_time, tvb, offset + 8, 8, ENC_BIG_ENDIAN);
            }
          }
        }
        break;

      case METHOD_CONFIGUPDATE:
        {
          if (IS_REQUEST(message_code)) {
            guint16 local_offset = 0;
            proto_item *ti_configupdate;
            proto_tree *configupdate_tree;
            guint8 configupdate_type;
            guint32 configupdate_length;
            ti_configupdate = proto_tree_add_item(message_body_tree, hf_reload_configupdatereq, tvb, offset+local_offset, message_body_length, ENC_NA);
            configupdate_tree  = proto_item_add_subtree(ti_configupdate, ett_reload_configupdatereq);
            configupdate_type = tvb_get_guint8(tvb, offset + local_offset);
            proto_tree_add_uint(configupdate_tree, hf_reload_configupdatereq_type, tvb, offset+local_offset, 1, configupdate_type);
            local_offset += 1;
            configupdate_length = tvb_get_ntohl(tvb, offset + local_offset);
            proto_tree_add_uint(configupdate_tree, hf_reload_configupdatereq_length, tvb,  offset + local_offset, 4, configupdate_length);
            if (5 + configupdate_length > message_body_length) {
              expert_add_info_format(pinfo, ti_configupdate, PI_PROTOCOL, PI_ERROR, "Truncated ConfigUpdateReq");
              break;
            }
            local_offset += 4;
            switch(configupdate_type) {
            case CONFIGUPDATETYPE_CONFIG:
              local_offset +=
                dissect_opaque(tvb, pinfo, configupdate_tree, hf_reload_configupdatereq_configdata,
                               offset + local_offset, 3, configupdate_length);

              break;

            case CONFIGUPDATETYPE_KIND:
              local_offset +=
                dissect_opaque(tvb, pinfo, configupdate_tree, hf_reload_configupdatereq_kinds,
                               offset + local_offset, 3, configupdate_length);
              break;
            }

          }
          break;
        }

      case METHOD_STORE:
        {
          if (IS_REQUEST(message_code)) {
            dissect_storereq(tvb, pinfo, message_body_tree, offset, message_body_length);
          }
          else {
            guint16 storeans_kind_responses_length;
            guint32 local_offset = 0;
            proto_item *ti_storeans_kind_responses;
            proto_tree *storeans_kind_responses_tree;
            ti_storeans_kind_responses = proto_tree_add_item(message_body_tree, hf_reload_storeans_kind_responses, tvb, offset, message_body_length, ENC_NA);
            storeans_kind_responses_tree = proto_item_add_subtree(ti_storeans_kind_responses, ett_reload_storeans_kind_responses);
            storeans_kind_responses_length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(storeans_kind_responses_tree, hf_reload_storeans_kind_responses_length, tvb, offset, 2, storeans_kind_responses_length);
            if ((guint32)storeans_kind_responses_length + 2 > message_body_length) {
              expert_add_info_format(pinfo, ti_storeans_kind_responses, PI_PROTOCOL, PI_ERROR, "Truncated StoreAns");
              break;
            }
            while (local_offset + 4 + 8 + 2< storeans_kind_responses_length) {
              proto_item *ti_storekindresponse;
              proto_tree *storekindresponse_tree;
              guint16 replicas_length;
              replicas_length = tvb_get_ntohs(tvb, offset + 2 + local_offset +4 + 8);
              if (local_offset + 4/*kindId*/ + 8/*generationcounter*/ + 2 +replicas_length > storeans_kind_responses_length) {
                expert_add_info_format(pinfo, ti_storeans_kind_responses, PI_PROTOCOL, PI_ERROR, "Truncated StoreKindResponse");
                break;
              }
              ti_storekindresponse =
              proto_tree_add_item(storeans_kind_responses_tree, hf_reload_storekindresponse, tvb, offset+2+local_offset, 4+ 8 + 2 + replicas_length, ENC_NA);
              storekindresponse_tree = proto_item_add_subtree(ti_storekindresponse, ett_reload_storekindresponse);
              proto_tree_add_item(storekindresponse_tree, hf_reload_kindid, tvb, offset+2+local_offset, 4, ENC_BIG_ENDIAN);
              local_offset += 4;
              proto_tree_add_item(storekindresponse_tree, hf_reload_kinddata_generation_counter, tvb, offset+2+local_offset, 8, ENC_BIG_ENDIAN);
              local_offset += 8;
              {
                guint16 replicas_length;
                proto_item *ti_replicas;
                proto_tree *replicas_tree;
                guint16 replicas_offset = 0;
                replicas_length = tvb_get_ntohs(tvb, offset + 2 + local_offset);
                ti_replicas = proto_tree_add_item(storekindresponse_tree, hf_reload_storekindresponse_replicas, tvb,
                                                  offset+2+local_offset, 2 + replicas_length, ENC_NA);
                replicas_tree = proto_item_add_subtree(storekindresponse_tree, ett_reload_storekindresponse_replicas);
                proto_tree_add_uint(replicas_tree, hf_reload_opaque_length_uint16, tvb, offset + 2+local_offset, 2, replicas_length);
                local_offset +=2;
                while (replicas_offset < replicas_length) {
                  if ((replicas_offset + reload_nodeid_length) > replicas_length) {
                    expert_add_info_format(pinfo, ti_replicas, PI_PROTOCOL, PI_ERROR, "Truncated NodeID");
                    break;
                  }
                  proto_tree_add_item(replicas_tree, hf_reload_nodeid, tvb, offset+2+local_offset+replicas_offset,
                                      reload_nodeid_length, ENC_NA);
                  replicas_offset += reload_nodeid_length;
                }
                local_offset += replicas_length;
              }
            }
          }
        }
        break;

      case METHOD_FETCH:
        {
          if (IS_REQUEST(message_code)) {
            guint16 fetch_offset = 0;
            fetch_offset += dissect_opaque(tvb, pinfo, message_body_tree, hf_reload_resource_id, offset, 1, message_body_length);
            fetch_offset += dissect_opaque(tvb, pinfo, message_body_tree, hf_reload_storeddataspecifiers, offset + fetch_offset,
                                           2, message_body_length - fetch_offset);
          }
          else {
            /* response */
            dissect_fetchans(tvb, pinfo, message_body_tree, offset, message_body_length);
          }
        }
        break;

      case METHOD_STAT:
        {
          if (IS_REQUEST(message_code)) {
            guint16 stat_offset = 0;
            stat_offset += dissect_opaque(tvb, pinfo, message_body_tree, hf_reload_resource_id, offset, 1, message_body_length);
            stat_offset += dissect_opaque(tvb, pinfo, message_body_tree, hf_reload_storeddataspecifiers, offset + stat_offset,
                                          2, message_body_length - stat_offset);
          }
          else {
            dissect_statans(tvb, pinfo, message_body_tree, offset, message_body_length);
          }

        }
        break;

      case METHOD_FIND:
        {
          if (IS_REQUEST(message_code)) {
            guint32 find_offset = 0;
            guint8 kinds_length;
            find_offset += dissect_opaque(tvb, pinfo, message_body_tree, hf_reload_resource_id, offset, 1, message_body_length);
            kinds_length = tvb_get_guint8(tvb, offset + find_offset);
            if (find_offset + 1 + kinds_length > message_body_length) {
              expert_add_info_format(pinfo, ti_message_body, PI_PROTOCOL, PI_ERROR, "Truncated FindRequest");
              break;
            }
            proto_tree_add_uint(message_body_tree, hf_reload_findreq_kinds_length, tvb, offset + find_offset, 1, kinds_length);
            find_offset += 1;
            {
              guint8 kinds_offset = 0;
              while (kinds_offset < kinds_length) {
                proto_tree_add_item(message_body_tree, hf_reload_kindid, tvb, offset+find_offset+kinds_offset, 4, ENC_BIG_ENDIAN);

                kinds_offset += 4;
              }
            }
          }
          else {
            guint16 results_length;

            results_length = tvb_get_ntohs(tvb, offset);
            if ((guint32)results_length + 2 > message_body_length) {
              expert_add_info_format(pinfo, ti_message_body, PI_PROTOCOL, PI_ERROR, "Truncated FindAnswer");
              break;
            }
            proto_tree_add_uint(message_body_tree, hf_reload_findans_results_length, tvb, offset, 2, results_length);
            {
              guint16 results_offset = 0;
              while (results_offset < results_length) {
                proto_item *ti_findkinddata;
                proto_tree *findkinddata_tree;
                guint16 findkinddata_length;
                findkinddata_length = 4/*kind id */ + 1 + get_opaque_length(tvb,offset + 2 + results_offset + 4, 1)/* resourceId */;
                if (results_offset + findkinddata_length > results_length) {
                  ti_findkinddata = proto_tree_add_item(message_body_tree, hf_reload_findkinddata, tvb, offset + results_offset, results_length - results_offset, ENC_NA);
                  expert_add_info_format(pinfo, ti_findkinddata, PI_PROTOCOL, PI_ERROR, "Truncated FindKindData");
                  break;
                }
                ti_findkinddata = proto_tree_add_item(message_body_tree, hf_reload_findkinddata, tvb, offset + 2 + results_offset, findkinddata_length, ENC_NA);
                findkinddata_tree = proto_item_add_subtree(ti_findkinddata, ett_reload_findkinddata);

                proto_tree_add_item(findkinddata_tree, hf_reload_kindid, tvb, offset + 2 + results_offset, 4, ENC_BIG_ENDIAN);
                dissect_opaque(tvb, pinfo, findkinddata_tree, hf_reload_resource_id, offset + 2 + results_offset + 4, 1, results_length - 4 - results_offset);

                results_offset += findkinddata_length;
              }
            }
          }
        }
        break;

      case METHOD_LEAVE:
      case METHOD_JOIN:
        {
          if (IS_REQUEST(message_code)) {
            proto_tree_add_item(message_body_tree, hf_reload_nodeid, tvb, offset, reload_nodeid_length, ENC_NA);
            dissect_opaque(tvb, pinfo, message_body_tree, hf_reload_overlay_specific, offset + reload_nodeid_length, 2,
                           message_body_length - reload_nodeid_length);
          }
          else {
            dissect_opaque(tvb, pinfo, message_body_tree, hf_reload_overlay_specific, offset, 2, message_body_length);
          }
        }
        break;

      default:
        break;
      }
    }
    else {
      /* Error Response */
      guint16 error_length;
      proto_item *ti_message_body;
      proto_tree *message_body_tree;
      proto_item *ti_error;
      proto_tree *error_tree;

      /* message_code was already parsed */
      proto_tree_add_uint_format_value(message_contents_tree, hf_reload_message_code, tvb, offset, 2, message_code, "ERROR Response");
      offset += 2;

      /* Message body */
      ti_message_body = proto_tree_add_item(message_contents_tree, hf_reload_message_body, tvb, offset, 4 + message_body_length, ENC_NA);
      message_body_tree = proto_item_add_subtree(ti_message_body, ett_reload_message_body);
      proto_tree_add_uint(message_body_tree, hf_reload_opaque_length_uint32, tvb, offset, 4, message_body_length);
      offset +=4;

      error_length = tvb_get_ntohs(tvb, offset + 2);
      if ((guint)offset + 2 + 2 + error_length > msg_length) {
        expert_add_info_format(pinfo, ti_message_body, PI_PROTOCOL, PI_ERROR, "Truncated error message");
        return msg_length;
      }

      ti_error = proto_tree_add_item(message_body_tree, hf_reload_error_response, tvb, offset, 2 + 2 + error_length, ENC_NA);
      error_tree = proto_item_add_subtree(ti_error, ett_reload_error_response);
      proto_tree_add_item(error_tree, hf_reload_error_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
      dissect_opaque(tvb, pinfo, error_tree, hf_reload_error_response_info, offset+2, 2, -1);
      proto_item_append_text(error_tree, ": %s (%s)", val_to_str(error_code, errorcodes, "Unknown"), tvb_get_ephemeral_string(tvb, offset+4, error_length));
    }
    offset += message_body_length;
    {
      proto_tree *extension_tree;
      guint16 extension_offset = 0;

      proto_tree_add_item(message_contents_tree, hf_reload_message_extensions_length, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      while (extension_offset < extensions_length) {
        proto_item *ti_extension;
        guint32 extension_content_length = tvb_get_ntohl(tvb, offset + extension_offset + 3);
        if ((extension_offset + 3 + 4 + extension_content_length) > extensions_length) {
          expert_add_info_format(pinfo, ti_message_contents, PI_PROTOCOL, PI_ERROR, "Truncated message extensions");
          break;
        }
        ti_extension = proto_tree_add_item(message_contents_tree, hf_reload_message_extension, tvb, offset+ extension_offset, 3 + 4 + extension_content_length, ENC_NA);
        extension_tree = proto_item_add_subtree(ti_extension, ett_reload_message_extension);
        proto_tree_add_item(extension_tree, hf_reload_message_extension_type, tvb, offset+ extension_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(extension_tree, hf_reload_message_extension_critical, tvb, offset+ extension_offset + 2, 1, FALSE);
          dissect_opaque(tvb, pinfo, extension_tree, hf_reload_message_extension_content, offset + extension_offset + 3, 4, -1);
          extension_offset += 3 + 4 + extension_content_length;
      }
    }
    offset += extensions_length;
  }

  /* Security Block */
  {
    proto_item *ti_security_block;
    proto_tree *security_block_tree;
    guint16 certificates_length;
    guint16 signatureidentityvalue_length;
    guint16 signaturevalue_length;
    guint16 security_block_offset = 0;

    certificates_length = tvb_get_ntohs(tvb, offset);
    security_block_offset += 2 + certificates_length;
    security_block_offset += 2; /* SignatureAndHashAlgorithm     algorithm; */
    security_block_offset += 1; /* SignerIdentityType     identity_type; */
    signatureidentityvalue_length = tvb_get_ntohs(tvb, offset +security_block_offset);
    security_block_offset += 2;
    security_block_offset += signatureidentityvalue_length;
    signaturevalue_length = tvb_get_ntohs(tvb, offset +security_block_offset);
    security_block_offset += 2;
    security_block_offset += signaturevalue_length;

    ti_security_block = proto_tree_add_item(reload_tree, hf_reload_security_block, tvb, offset,
                                            security_block_offset, ENC_NA);
    security_block_tree = proto_item_add_subtree(ti_security_block, ett_reload_security_block);
    /* start parsing from the beginning */
    security_block_offset = 0;
    proto_tree_add_uint(security_block_tree, hf_reload_certificates_length, tvb, offset, 2, certificates_length);
    security_block_offset += 2;
    /* certificates */
    {
      guint16 certificate_offset = 0;
      while (certificate_offset < certificates_length) {
        proto_item *ti_certificate;
        proto_tree *certificate_tree;
        guint16 certificate_length;

        certificate_length = tvb_get_ntohs(tvb, offset + security_block_offset + certificate_offset + 1);
        if (certificate_offset + 1 + 2 + certificate_length > certificates_length) {
          expert_add_info_format(pinfo, ti_security_block, PI_PROTOCOL, PI_ERROR, "Truncated certificate");
          break;
        }
        ti_certificate = proto_tree_add_item(security_block_tree,
                                             hf_reload_certificates, tvb, offset + security_block_offset + certificate_offset,
                                             1 + 2 + certificate_length,
                                             ENC_NA);
        certificate_tree = proto_item_add_subtree(ti_certificate, ett_reload_certificate);

        proto_tree_add_item(certificate_tree, hf_reload_certificate_type, tvb,
                            offset + security_block_offset + certificate_offset, 1, ENC_BIG_ENDIAN);
        switch (tvb_get_guint8(tvb, offset + security_block_offset + certificate_offset)) {
          case 0: {
            asn1_ctx_t asn1_ctx;

            asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
            dissect_x509af_Certificate(FALSE, tvb, offset + security_block_offset + certificate_offset + 1 + 2, &asn1_ctx,
                                       certificate_tree, hf_reload_certificate);
          }
          break;

          default:
            dissect_opaque(tvb, pinfo, certificate_tree, hf_reload_certificate, offset + security_block_offset + certificate_offset + 1,
                           2, -1);
        }
        certificate_offset += 1 + 2 + certificate_length;
      }
    }
    security_block_offset += certificates_length;

    /* Signature */
    {
      proto_item *ti_signature;
      proto_tree *signature_tree;

      ti_signature = proto_tree_add_item(security_block_tree,
                                         hf_reload_signature, tvb, offset+security_block_offset ,
                                         2 +/* SignatureAndHashAlgorithm */
                                         1 + 2 + signatureidentityvalue_length +/* SignatureIdenty length*/
                                         2 + signaturevalue_length,
                                         ENC_NA);
      signature_tree = proto_item_add_subtree(ti_signature, ett_reload_signature);
      proto_tree_add_item(signature_tree, hf_reload_hash_algorithm, tvb,
                                 offset + security_block_offset, 1, ENC_BIG_ENDIAN);
      security_block_offset += 1;
      proto_tree_add_item(signature_tree, hf_reload_signature_algorithm, tvb,
                                 offset + security_block_offset, 1, ENC_BIG_ENDIAN);
      security_block_offset += 1;
      /* SignatureIdentity */
      {
        proto_item *ti_signatureidentity;
        proto_tree *signatureidentity_tree;
        guint8 identity_type;
        ti_signatureidentity = proto_tree_add_item(signature_tree,
                                                   hf_reload_signature_identity,
                                                   tvb, offset+security_block_offset,
                                                   1 + 2 + signatureidentityvalue_length,
                                                   ENC_NA);
        signatureidentity_tree = proto_item_add_subtree(ti_signatureidentity, ett_reload_signature_identity);
        identity_type = tvb_get_guint8(tvb, offset + security_block_offset);
        proto_tree_add_item(signatureidentity_tree, hf_reload_signature_identity_type, tvb,
                            offset + security_block_offset, 1, ENC_BIG_ENDIAN);
        security_block_offset += 1;
        proto_tree_add_uint(signatureidentity_tree, hf_reload_signature_identity_length, tvb,
                            offset + security_block_offset, 2, signatureidentityvalue_length);
        security_block_offset += 2;
        {
          guint16 signatureidentityvalue_offset = 0;
          while (signatureidentityvalue_offset < signatureidentityvalue_length) {
            proto_item *ti_signatureidentityvalue;
            proto_tree *signatureidentityvalue_tree;
            if (identity_type == SIGNATUREIDENTITYTYPE_CERTHASH) {
              guint8 certificate_hash_length;

              certificate_hash_length = tvb_get_guint8(tvb, offset + security_block_offset + signatureidentityvalue_offset + 1);
              if (signatureidentityvalue_offset + 1 + 1 + certificate_hash_length > signatureidentityvalue_length) {
                expert_add_info_format(pinfo, ti_signatureidentity, PI_PROTOCOL, PI_ERROR, "Truncated signature identity value");
                break;
              }
              ti_signatureidentityvalue= proto_tree_add_item(signatureidentity_tree,
                                                             hf_reload_signature_identity_value,
                                                             tvb, offset + security_block_offset + signatureidentityvalue_offset,
                                                             1 + 1 + certificate_hash_length,
                                                             ENC_NA);
              signatureidentityvalue_tree = proto_item_add_subtree(ti_signatureidentityvalue, ett_reload_signature_identity_value);
              proto_tree_add_item(signatureidentityvalue_tree, hf_reload_hash_algorithm, tvb,
                                  offset + security_block_offset +signatureidentityvalue_offset, 1, ENC_BIG_ENDIAN);
              dissect_opaque(tvb, pinfo, signatureidentityvalue_tree, hf_reload_signature_identity_value_certificate_hash, offset + security_block_offset + signatureidentityvalue_offset+1, 1, -1);
              signatureidentityvalue_offset += 1 + 1 + certificate_hash_length;
            }
            else {
              expert_add_info_format(pinfo, ti_signatureidentity, PI_PROTOCOL, PI_ERROR, "Unknown identity type");
              break;
            }
          }
        }
        security_block_offset += signatureidentityvalue_length;
      }
      dissect_opaque(tvb, pinfo, signature_tree, hf_reload_signature_value, offset + security_block_offset, 2, -1);
    }
  }


  return msg_length;
}

static void
dissect_reload_message_no_return(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_reload_message(tvb, pinfo, tree);
}

static gboolean
dissect_reload_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (dissect_reload_message(tvb, pinfo, tree) == 0) {
    /*
     * It wasn't a valid RELOAD message, and wasn't
     * dissected as such.
     */
    return FALSE;
  }
  return TRUE;
}

void
proto_register_reload(void)
{
  module_t *reload_module;
  static hf_register_info hf[] = {
    { &hf_reload_response_in,
      { "Response in",  "reload.response-in", FT_FRAMENUM,
        BASE_NONE, NULL, 0x0, "The response to this RELOAD Request is in this frame", HFILL }
    },
    { &hf_reload_response_to,
      { "Request in", "reload.response-to", FT_FRAMENUM,
        BASE_NONE, NULL, 0x0, "This is a response to the RELOAD Request in this frame", HFILL }
    },
    { &hf_reload_time,
      { "Time", "reload.time", FT_RELATIVE_TIME,
        BASE_NONE, NULL, 0x0, "The time between the Request and the Response", HFILL }
    },
    { &hf_reload_duplicate,
      { "Duplicated original message in", "reload.duplicate", FT_FRAMENUM,
        BASE_NONE, NULL, 0x0, "This is a duplicate of RELOAD message in this frame", HFILL }
    },
    { &hf_reload_forwarding,
      { "Forwarding header",    "reload.forwarding",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_token,
      { "RELOAD token", "reload.forwarding.token",  FT_UINT32,
        BASE_HEX, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_overlay,
      { "Overlay",  "reload.forwarding.overlay",  FT_UINT32,
        BASE_HEX, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_configuration_sequence,
      { "Configuration sequence", "reload.forwarding.configuration_sequence", FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_version,
      { "Version",  "reload.forwarding.version",  FT_UINT8,
        BASE_HEX, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_ttl,
      { "TTL",  "reload.forwarding.ttl",  FT_UINT8,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_fragment_flag,
      { "Fragment", "reload.forwarding.fragment", FT_UINT32,
        BASE_HEX, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_fragment_fragmented,
      { "Fragmented bit", "reload.forwarding.fragment.fragmented", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL }
    },
    { &hf_reload_fragment_last_fragment,
      { "Last fragment bit", "reload.forwarding.fragment.last", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL }
    },
    { &hf_reload_fragment_reserved,
      { "Reserved", "reload.forwarding.fragment.reserved", FT_BOOLEAN, 1, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_reload_fragment_offset,
      { "Fragment offset","reload.forwarding.fragment.offset",  FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_length,
      { "Length", "reload.forwarding.length", FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_trans_id,
      { "Transaction ID", "reload.forwarding.trans_id", FT_UINT64,
        BASE_HEX, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_max_response_length,
      { "Max response length",  "reload.forwarding.max_response_length",  FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_via_list_length,
      { "Via-list length",  "reload.forwarding.via_list.length",  FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_destination_list_length,
      { "Destination list length",  "reload.forwarding.destination_list.length",  FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_options_length,
      { "Options length", "reload.forwarding.options.length", FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_via_list,
      { "via list",   "reload.forwarding.via_list", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_destination,
      { "Destination",    "reload.forwarding.destination",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_destination_compressed,
      { "Destination (compressed)", "reload.forwarding.destination.compressed_id",  FT_UINT16,
        BASE_HEX, NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_destination_type,
      { "Destination type",    "reload.forwarding.destination.type",  FT_UINT8,
        BASE_HEX, VALS(destinationtypes), 0x0,  NULL, HFILL }
    },
    { &hf_reload_destination_length,
      { "Destination length",   "reload.forwarding.destination.length", FT_UINT8,
        BASE_DEC, NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_nodeid,
      { "Node ID",    "reload.nodeid", FT_BYTES,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_resource_id,
      { "Resource ID",    "reload.resource_id", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_destination_data_compressed_id,
      { "Compressed ID",    "reload.destination.data.compressed_id",  FT_BYTES,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_destination_list,
      { "Destination list",   "reload.forwarding.destination_list", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_forwarding_option,
      { "Forwarding option",    "reload.forwarding.option", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_forwarding_option_type,
      { "Forwarding option type", "reload.forwarding.option.type",  FT_UINT8,
        BASE_DEC, VALS(forwardingoptiontypes),  0x0,  NULL, HFILL }
    },
    { &hf_reload_forwarding_option_flags,
      { "Forwarding option flags",  "reload.forwarding.option.flags", FT_UINT8,
        BASE_HEX, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_forwarding_option_length,
      { "Forwarding option length", "forwarding.option.length", FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_forwarding_option_data,
      { "Forwarding option data", "reload.forwarding.option.data",  FT_BYTES,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_forwarding_option_flag_response_copy,
      { "Response copy", "reload.forwarding.option.flag.response_copy", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL }
    },
    { &hf_reload_forwarding_option_flag_destination_critical,
      { "Response destination critical", "reload.forwarding.option.flags.destination_critical", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL }
    },
    { &hf_reload_forwarding_option_flag_forward_critical,
      { "Forward critical", "reload.forwarding.option.flags.forward_critical", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL }
    },
    { &hf_reload_attachreqans,
      { "AttachReqAns", "reload.attachreqans",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_ufrag,
      { "Ufrag",  "reload.ufrag", FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_password,
      { "Password", "reload.password",  FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_role,
      { "Role", "reload.role",  FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_icecandidates,
      { "Ice candidates",   "reload.icecandidates", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_icecandidates_length,
      { "Ice candidates length",  "reload.icecandidates.length",  FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_icecandidate,
      { "Ice candidate",    "reload.icecandidate",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_icecandidate_relay_addr,
      { "Relay address",    "reload.icecandidate.relay_addr", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_icecandidate_srflx_addr,
      { "Srflx address",    "reload.icecandidate.srflx_addr", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_icecandidate_prflx_addr,
      { "Prfkx address",    "reload.icecandidate.prflx_addr", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_ipaddressport,
      { "IP address port",    "reload.ipaddressport", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_ipaddressport_type,
      { "IP address-port type", "reload.ipaddressport.type",  FT_UINT8,
        BASE_HEX, VALS(ipaddressporttypes), 0x0,  NULL, HFILL }
    },
    { &hf_reload_ipaddressport_length,
      { "IP address-port length", "reload.ipaddressport.length",  FT_UINT8,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_ipv4addr,
      { "IPv4 address", "reload.ipv4addr",  FT_IPv4,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_ipv6addr,
      { "IPv6 address", "reload.ipv6addr",  FT_IPv6,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_port,
      { "Port", "reload.port",  FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_overlaylink_type,
      { "Overlay Link Type",  "reload.overlaylink.type",  FT_UINT8,
        BASE_DEC, VALS(overlaylinktypes), 0x0,  NULL, HFILL }
    },
    { &hf_reload_icecandidate_foundation,
      { "Ice candidate foundation", "reload.icecandidate.foundation", FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_icecandidate_priority,
      { "Ice candidate priority", "reload.icecandidate.priority", FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_icecandidate_type,
      { "Ice candidate type", "reload.icecandidate.type", FT_UINT8,
        BASE_DEC, VALS(candtypes),  0x0,  NULL, HFILL }
    },
    { &hf_reload_icecandidate_extensions_length,
      { "Ice candidate extensions length",  "reload.icecandidate.extensions_length",  FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_iceextension,
      { "Ice extension",    "reload.iceextension",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_iceextension_name,
      { "Ice extension name", "reload.iceextension.name", FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_iceextension_value,
      { "Ice extension value",  "reload.iceextension.value",  FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_sendupdate,
      { "SendUpdate", "reload.sendupdate",  FT_BOOLEAN,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_message_contents,
      { "Message contents",   "reload.message.contents",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_message_code,
      { "Message code", "reload.message.code",  FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_message_body,
      { "Message body", "reload.message.body",  FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_message_extensions_length,
      { "Message extensions length",  "reload.message.extensions.length", FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_message_extension,
      { "Message extension",    "reload.message_extension", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL }
    },
    { &hf_reload_message_extension_type,
      { "Message extension type", "reload.message_extension.type",  FT_UINT16,
        BASE_DEC, VALS(messageextensiontypes), 0x0,  NULL, HFILL }
    },
    { &hf_reload_message_extension_critical,
      { "Message extension critical", "reload.message_extension.critical",  FT_BOOLEAN,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_message_extension_content,
      { "Message extension content",  "reload.message_extension.content", FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_error_response,
      { "Error response", "reload.error_response",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_error_response_code,
      { "Error code", "reload.error_response.code", FT_UINT16,
        BASE_DEC, VALS(errorcodes), 0x0,  NULL, HFILL }
    },
    { &hf_reload_error_response_info,
      { "Error info", "reload.error_response_info", FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_security_block,
      { "Security block", "reload.security_block",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_certificates_length,
      { "Certificates length",  "reload.certificates.length", FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_certificates,
      { "Certificates",  "reload.certificates", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_certificate_type,
      { "Certificate type", "reload.certificate.type",  FT_UINT8,
        BASE_DEC, VALS(tls_certificate_type), 0x0,  NULL, HFILL }
    },
    { &hf_reload_certificate,
      { "Certificate", "reload.certificate",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_signature,
      { "Signature",  "reload.signature", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_hash_algorithm,
      { "Hash algorithm", "reload.hash_algorithm",  FT_UINT8,
        BASE_DEC, VALS(tls_hash_algorithm), 0x0,  NULL, HFILL }
    },
    { &hf_reload_signature_algorithm,
      { "Signature algorithm",  "reload.signature_algorithm", FT_UINT8,
        BASE_DEC, VALS(tls_signature_algorithm),  0x0,  NULL, HFILL }
    },
    { &hf_reload_signature_identity,
      { "Signature identity", "reload.signature.identity",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_signature_identity_type,
      { "Signature identity type",  "reload.signature.identity.type", FT_UINT8,
        BASE_DEC, VALS(signatureidentitytypes), 0x0,  NULL, HFILL }
    },
    { &hf_reload_signature_identity_length,
      { "Signature identity length",  "reload.signature.identity.length", FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_signature_identity_value,
      { "Signature identity value", "reload.signature.identity.value",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_signature_identity_value_certificate_hash,
      { "Signature identity value certificate hash",  "reload.signature.identity.value.certificate_hash", FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_signature_value,
      { "Signature value",  "reload.signature.value.",  FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_opaque_length_uint8,
      { "Opaque length", "reload.opaque.length.8", FT_UINT8,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_opaque_length_uint16,
      { "Opaque length", "reload.opaque.length.16", FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_opaque_length_uint32,
      { "Opaque length", "reload.opaque.length.32",  FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_opaque_data,
      { "Data", "reload.opaque.length.8", FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_routequeryreq,
      { "RouteQueryReq",  "reload.routequeryreq", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_overlay_specific,
      { "Overlay specific data",  "reload.overlay.specific.data", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_probereq,
      { "ProbeReq", "reload.probereq",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_probe_information,
      { "Probe information",  "reload.probe_information", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_probe_information_type,
      { "Probe information type", "reload.probe_information.type", FT_UINT8,
        BASE_HEX, VALS(probeinformationtypes),  0x0,  NULL, HFILL }
    },
    { &hf_reload_responsible_set,
      { "Responsible set",  "reload.responsible_set", FT_UINT32,
        BASE_HEX, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_num_resources,
      { "Num resources",  "reload.num_resources", FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_uptime,
      { "Uptime", "reload.uptime", FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_probeans,
      { "Probe ans",  "reload.probeans", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_appattach,
      { "App attach req/ans", "reload.appattach", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_application,
      { "Application", "reload.application", FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_ping_response_id,
      { "Ping response ID", "reload.ping.response_id",  FT_UINT64,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_ping_time,
      { "Ping time",  "reload.ping.time", FT_UINT64,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_storeddata,
      { "Stored data",  "reload.storeddata", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_storeddata_length,
      { "Stored data length", "reload.storeddata.length", FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_storeddata_storage_time,
      { "Stored data storage time", "reload.storeddata.storage_time", FT_UINT64,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_storeddata_lifetime,
      { "Stored lifetime",  "reload.storeddata.lifetime", FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_kinddata,
      { "Kind data",  "reload.kinddata", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_kindid,
      { "Kind ID",  "reload.kindid",  FT_UINT32,
        BASE_DEC, VALS(datakindids),  0x0,  NULL, HFILL }
    },
    { &hf_reload_kinddata_generation_counter,
      { "Generation counter", "reload.kinddata.generation_counter", FT_UINT64,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_kinddata_values_length,
      { "Values length",  "reload.kinddata.values_length",  FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_storereq,
      { "StoreReq", "reload.storereq", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_store_replica_num,
      { "Replica num",  "reload.store.replica_num", FT_UINT8,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_store_kind_data_length,
      { "StoreReq kind data length",  "reload.store.kind_data.length",  FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_storeans_kind_responses,
      { "Kind responses", "reload.storeans.kind_responses", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_storeans_kind_responses_length,
      { "Kind responses length", "reload.storeans.kind_responses.length", FT_UINT16,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_storekindresponse,
      { "Store kind response", "reload.storekindresponse", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_storekindresponse_replicas,
      { "Store kind response replicas", "reload.storekindresponse.replicas", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_storeddataspecifiers,
      { "StoredDataSpecifiers", "reload.storeddataspecifiers", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_fetchans,
      { "FetchAns", "reload.fetchans", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_kind_responses_length,
      { "Kind responses length", "reload.fetchans.kind_responses.length", FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_statans,
      { "StatAns",  "reload.statans", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_findreq_kinds_length,
      { "Kinds length", "reload.findreq.kindslength", FT_UINT8,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_findans_results_length,
      { "Results length", "reload.findans.resultsslength", FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_findkinddata,
      { "FindKindData", "reload.findkinddata", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },
    { &hf_reload_fragment_overlap,
      { "Fragment overlap", "reload.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Fragment overlaps with other fragments", HFILL }},

    { &hf_reload_fragment_overlap_conflict,
      { "Conflicting data in fragment overlap", "reload.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Overlapping fragments contained conflicting data", HFILL }},

    { &hf_reload_fragment_multiple_tails,
      { "Multiple tail fragments found",  "reload.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Several tails were found when defragmenting the packet", HFILL }},

    { &hf_reload_fragment_too_long_fragment,
      { "Fragment too long",  "reload.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Fragment contained data past end of packet", HFILL }},

    { &hf_reload_fragment_error,
      { "Defragmentation error", "reload.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "Defragmentation error due to illegal fragments", HFILL }},

    { &hf_reload_fragment_count,
      { "Fragment count", "reload.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

    { &hf_reload_fragment,
      { "RELOAD fragment", "reload.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_reload_fragments,
      { "RELOAD fragments", "reload.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_reload_reassembled_in,
      { "Reassembled RELOAD in frame", "reload.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "This RELOAD packet is reassembled in this frame", HFILL }},

    { &hf_reload_reassembled_length,
      { "Reassembled RELOAD length", "reload.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
        "The total length of the reassembled payload", HFILL}},

    { &hf_reload_configupdatereq,
      { "ConfigUpdate req",  "reload.configupdatereq.",  FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },

    { &hf_reload_configupdatereq_type,
      { "ConfigUpdate req type", "reload.configupdatereq.type", FT_UINT8,
        BASE_DEC, VALS(configupdatetypes),  0x0,  NULL, HFILL }
    },

    { &hf_reload_configupdatereq_length,
      { "ConfigUpdate req length", "reload.configupdatereq.length", FT_UINT32,
        BASE_DEC, NULL,  0x0,  NULL, HFILL }
    },

    { &hf_reload_configupdatereq_configdata,
      { "ConfigUpdate req config data",  "reload.configupdatereq.config_data",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },

    { &hf_reload_configupdatereq_kinds,
      { "ConfigUpdate req kinds",  "reload.configupdatereq.kinds",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },

    { &hf_reload_padding,
      { "Padding",  "reload.padding",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL }
    },

  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_reload,
    &ett_reload_forwarding,
    &ett_reload_message,
    &ett_reload_security,
    &ett_reload_fragment_flag,
    &ett_reload_destination,
    &ett_reload_via_list,
    &ett_reload_destination_list,
    &ett_reload_forwarding_option,
    &ett_reload_forwarding_option_flags,
    &ett_reload_forwarding_option_directresponseforwarding,
    &ett_reload_attachreqans,
    &ett_reload_icecandidates,
    &ett_reload_icecandidate,
    &ett_reload_icecandidate_computed_address,
    &ett_reload_iceextension,
    &ett_reload_ipaddressport,
    &ett_reload_message_contents,
    &ett_reload_message_extension,
    &ett_reload_error_response,
    &ett_reload_security_block,
    &ett_reload_certificate,
    &ett_reload_signature,
    &ett_reload_signature_identity,
    &ett_reload_signature_identity_value,
    &ett_reload_opaque,
    &ett_reload_message_body,
    &ett_reload_routequeryreq,
    &ett_reload_probereq,
    &ett_reload_probe_information,
    &ett_reload_probeans,
    &ett_reload_appattach,
    &ett_reload_storeddata,
    &ett_reload_kinddata,
    &ett_reload_storereq,
    &ett_reload_storeans_kind_responses,
    &ett_reload_storekindresponse,
    &ett_reload_fetchans,
    &ett_reload_statans,
    &ett_reload_findkinddata,
    &ett_reload_fragments,
    &ett_reload_fragment,
    &ett_reload_configupdatereq,
    &ett_reload_storekindresponse_replicas,
  };

  /* Register the protocol name and description */
  proto_reload = proto_register_protocol("REsource LOcation And Discovery", "RELOAD", "reload");
  register_dissector("reload", dissect_reload_message_no_return, proto_reload);
  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_reload, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  reload_module = prefs_register_protocol(proto_reload, NULL);
  prefs_register_bool_preference(reload_module, "defragment",
                                 "Reassemble fragmented reload datagrams",
                                 "Whether fragmented RELOAD datagrams should be reassembled",
                                 &reload_defragment);
  prefs_register_uint_preference(reload_module, "nodeid_length",
                                 "NodeId Length",
                                 "Length of the NodeId as defined in the overlay.",
                                 10,
                                 &reload_nodeid_length);


  register_init_routine(reload_defragment_init);
}

void
proto_reg_handoff_reload(void)
{

  data_handle = find_dissector("data");

  heur_dissector_add("udp", dissect_reload_heur, proto_reload);
  heur_dissector_add("tcp", dissect_reload_heur, proto_reload);

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 2
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=2 expandtab:
 * :indentSize=2:tabSize=2:noTabs=true:
 */
