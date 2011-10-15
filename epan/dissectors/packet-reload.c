/* packet-reload.c
 * Routines for REsource LOcation And Discovery (RELOAD) Base Protocol
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
 * - draft-ietf-p2psip-base-18
 * - draft-ietf-p2psip-sip-06
 * - draft-ietf-p2psip-service-discovery-03
 * - draft-ietf-p2psip-self-tuning-04
 * - draft-ietf-p2psip-diagnostics-06
 * - draft-zong-p2psip-drr-01
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/asn1.h>
#include <epan/uat.h>
#include <epan/dissectors/packet-x509af.h>
#include <packet-tcp.h>
#include <packet-ssl-utils.h>
#include <packet-reload.h>


/* Initialize the protocol and registered fields */
static int proto_reload = -1;


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
static int hf_reload_trans_id = -1;
static int hf_reload_max_response_length = -1;
static int hf_reload_via_list_length = -1;
static int hf_reload_destination_list_length = -1;
static int hf_reload_options_length = -1;
static int hf_reload_via_list = -1;
static int hf_reload_destination = -1;
static int hf_reload_destination_compressed_id = -1;
static int hf_reload_destination_type = -1;
static int hf_reload_nodeid = -1;
static int hf_reload_resourceid = -1;
static int hf_reload_value = -1;
static int hf_reload_destination_data_node_id = -1;
static int hf_reload_destination_data_resource_id = -1;
static int hf_reload_destination_data_compressed_id = -1;
static int hf_reload_destination_list = -1;
static int hf_reload_forwarding_options = -1;
static int hf_reload_forwarding_option = -1;
static int hf_reload_forwarding_option_type = -1;
static int hf_reload_forwarding_option_flags = -1;
static int hf_reload_forwarding_option_flag_response_copy = -1;
static int hf_reload_forwarding_option_flag_destination_critical = -1;
static int hf_reload_forwarding_option_flag_forward_critical = -1;
static int hf_reload_forwarding_option_flag_ignore_state_keeping = -1;
static int hf_reload_attachreqans = -1;
static int hf_reload_ufrag = -1;
static int hf_reload_password = -1;
static int hf_reload_role = -1;
static int hf_reload_sendupdate = -1;
static int hf_reload_icecandidates = -1;
static int hf_reload_icecandidate = -1;
static int hf_reload_icecandidate_addr_port = -1;
static int hf_reload_icecandidate_relay_addr = -1;
static int hf_reload_icecandidate_foundation = -1;
static int hf_reload_icecandidate_priority = -1;
static int hf_reload_icecandidate_type = -1;
static int hf_reload_overlaylink_type = -1;
static int hf_reload_iceextension = -1;
static int hf_reload_iceextensions = -1;
static int hf_reload_iceextension_name = -1;
static int hf_reload_iceextension_value = -1;
static int hf_reload_ipaddressport = -1;
static int hf_reload_ipaddressport_type = -1;
static int hf_reload_ipv4addrport = -1;
static int hf_reload_ipv4addr = -1;
static int hf_reload_port = -1;
static int hf_reload_ipv6addrport = -1;
static int hf_reload_ipv6addr = -1;
static int hf_reload_message_contents = -1;
static int hf_reload_message_code = -1;
static int hf_reload_message_body = -1;
static int hf_reload_message_extensions = -1;
static int hf_reload_message_extension = -1;
static int hf_reload_message_extension_type = -1;
static int hf_reload_message_extension_critical = -1;
static int hf_reload_message_extension_content = -1;
static int hf_reload_error_response = -1;
static int hf_reload_error_response_code = -1;
static int hf_reload_error_response_info = -1;
static int hf_reload_security_block = -1;
static int hf_reload_certificates = -1;
static int hf_reload_genericcertificate = -1;
static int hf_reload_certificate_type = -1;
static int hf_reload_certificate = -1;
static int hf_reload_signature = -1;
static int hf_reload_signatureandhashalgorithm = -1;
static int hf_reload_hash_algorithm = -1;
static int hf_reload_signature_algorithm = -1;
static int hf_reload_signeridentity = -1;
static int hf_reload_signeridentity_type = -1;
static int hf_reload_signeridentity_identity = -1;
static int hf_reload_signeridentity_value = -1;
static int hf_reload_signeridentity_value_hash_alg = -1;
static int hf_reload_signeridentity_value_certificate_hash = -1;
static int hf_reload_signeridentity_value_certificate_node_id_hash = -1;
static int hf_reload_signature_value = -1;
static int hf_reload_length_uint8 = -1;
static int hf_reload_length_uint16 = -1;
static int hf_reload_length_uint24 = -1;
static int hf_reload_length_uint32 = -1;
static int hf_reload_opaque = -1;
static int hf_reload_opaque_data = -1;
static int hf_reload_opaque_string = -1;
static int hf_reload_routequeryreq = -1;
static int hf_reload_routequeryreq_destination = -1;
static int hf_reload_overlay_specific = -1;
static int hf_reload_probereq = -1;
static int hf_reload_probereq_requested_info = -1;
static int hf_reload_probe_information_type = -1;
static int hf_reload_probe_information = -1;
static int hf_reload_probe_information_data = -1;
static int hf_reload_responsible_set = -1;
static int hf_reload_num_resources = -1;
static int hf_reload_uptime = -1;
static int hf_reload_probeans = -1;
static int hf_reload_probeans_probe_info = -1;
static int hf_reload_appattachreq = -1;
static int hf_reload_appattachans = -1;
static int hf_reload_application = -1;
static int hf_reload_pingreq = -1;
static int hf_reload_pingans = -1;
static int hf_reload_ping_response_id = -1;
static int hf_reload_ping_time = -1;
static int hf_reload_storeddata = -1;
static int hf_reload_storedmetadata = -1;
static int hf_reload_storeddata_storage_time =  -1;
static int hf_reload_storeddata_lifetime = -1;
static int hf_reload_datavalue = -1;
static int hf_reload_metadata = -1;
static int hf_reload_datavalue_exists = -1;
static int hf_reload_datavalue_value = -1;
static int hf_reload_metadata_value_length = -1;
static int hf_reload_metadata_hash_value = -1;
static int hf_reload_arrayentry = -1;
static int hf_reload_arrayentry_value = -1;
static int hf_reload_arrayentry_index = -1;
static int hf_reload_dictionaryentry = -1;
static int hf_reload_dictionarykey = -1;
static int hf_reload_dictionary_value = -1;
static int hf_reload_kinddata = -1;
static int hf_reload_findkinddata_closest = -1;
static int hf_reload_kinddata_kind = -1;
static int hf_reload_statkindresponse = -1;
static int hf_reload_kindid = -1;
static int hf_reload_kindid_list = -1;
static int hf_reload_generation_counter = -1;
static int hf_reload_values = -1;
static int hf_reload_storereq = -1;
static int hf_reload_resource = -1;
static int hf_reload_store_replica_num = -1;
static int hf_reload_store_kind_data = -1;
static int hf_reload_storeans = -1;
static int hf_reload_storeans_kind_responses = -1;
static int hf_reload_storekindresponse = -1;
static int hf_reload_replicas = -1;
static int hf_reload_statreq = -1;
static int hf_reload_fetchreq = -1;
static int hf_reload_fetchreq_specifiers = -1;
static int hf_reload_storeddataspecifier = -1;
static int hf_reload_storeddataspecifier_indices = -1;
static int hf_reload_storeddataspecifier_keys = -1;
static int hf_reload_arrayrange = -1;
static int hf_reload_fetchans = -1;
static int hf_reload_statans = -1;
static int hf_reload_findreq = -1;
static int hf_reload_findans = -1;
static int hf_reload_findkinddata = -1;
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
static int hf_reload_configupdatereq_configdata = -1;
static int hf_reload_configupdatereq_kinds = -1;
static int hf_reload_kinddescription = -1;
static int hf_reload_chordupdate = -1;
static int hf_reload_chordupdate_type = -1;
static int hf_reload_chordupdate_predecessors = -1;
static int hf_reload_chordupdate_successors = -1;
static int hf_reload_chordupdate_fingers = -1;
static int hf_reload_chordroutequeryans = -1;
static int hf_reload_chordroutequeryans_next_peer = -1;
static int hf_reload_chordleave = -1;
static int hf_reload_chordleave_type = -1;
static int hf_reload_chordleave_predecessors = -1;
static int hf_reload_chordleave_successors = -1;
static int hf_reload_turnserver = -1;
static int hf_reload_turnserver_iteration = -1;
static int hf_reload_turnserver_server_address = -1;
static int hf_reload_sipregistration = -1;
static int hf_reload_sipregistration_type = -1;
static int hf_reload_sipregistration_data = -1;
static int hf_reload_sipregistration_data_uri = -1;
static int hf_reload_sipregistration_data_contact_prefs = -1;
static int hf_reload_sipregistration_data_destination_list = -1;
static int hf_reload_padding = -1;
static int hf_reload_redirserviceproviderdata = -1;
static int hf_reload_redirserviceproviderdata_serviceprovider = -1;
static int hf_reload_redirserviceproviderdata_namespace = -1;
static int hf_reload_redirserviceproviderdata_level = -1;
static int hf_reload_redirserviceproviderdata_node = -1;
static int hf_reload_redirserviceprovider = -1;
static int hf_reload_self_tuning_data = -1;
static int hf_reload_self_tuning_data_join_rate = -1;
static int hf_reload_self_tuning_data_leave_rate = -1;
static int hf_reload_self_tuning_data_network_size = -1;
static int hf_reload_dmflags = -1;
static int hf_reload_dmflag_status_info = -1;
static int hf_reload_dmflag_routing_table_size = -1;
static int hf_reload_dmflag_process_power = -1;
static int hf_reload_dmflag_bandwidth = -1;
static int hf_reload_dmflag_software_version = -1;
static int hf_reload_dmflag_machine_uptime = -1;
static int hf_reload_dmflag_app_uptime = -1;
static int hf_reload_dmflag_memory_footprint = -1;
static int hf_reload_dmflag_datasize_stored = -1;
static int hf_reload_dmflag_instances_stored = -1;
static int hf_reload_dmflag_messages_sent_rcvd = -1;
static int hf_reload_dmflag_ewma_bytes_sent = -1;
static int hf_reload_dmflag_ewma_bytes_rcvd = -1;
static int hf_reload_dmflag_underlay_hop = -1;
static int hf_reload_dmflag_battery_status = -1;
static int hf_reload_diagnosticrequest = -1;
static int hf_reload_diagnosticresponse = -1;
static int hf_reload_diagnosticextension = -1;
static int hf_reload_diagnosticextension_type = -1;
static int hf_reload_diagnosticextension_contents = -1;
static int hf_reload_diagnostic_expiration = -1;
static int hf_reload_diagnosticrequest_timestampinitiated = -1;
static int hf_reload_diagnosticrequest_extensions = -1;
static int hf_reload_pathtrackreq = -1;
static int hf_reload_pathtrackreq_destination = -1;
static int hf_reload_pathtrackreq_request = -1;
static int hf_reload_diagnosticinfo = -1;
static int hf_reload_diagnosticinfo_kind = -1;
static int hf_reload_diagnosticinfo_congestion_status = -1;
static int hf_reload_diagnosticinfo_number_peers = -1;
static int hf_reload_diagnosticinfo_processing_power = -1;
static int hf_reload_diagnosticinfo_bandwidth = -1;
static int hf_reload_diagnosticinfo_software_version = -1;
static int hf_reload_diagnosticinfo_machine_uptime = -1;
static int hf_reload_diagnosticinfo_app_uptime = -1;
static int hf_reload_diagnosticinfo_memory_footprint = -1;
static int hf_reload_diagnosticinfo_datasize_stored = -1;
static int hf_reload_diagnosticinfo_instances_stored = -1;
static int hf_reload_diagnosticinfo_instancesstored_info = -1;
static int hf_reload_diagnosticinfo_instancesstored_instances = -1;
static int hf_reload_diagnosticinfo_messages_sent_rcvd = -1;
static int hf_reload_diagnosticinfo_messages_sent_rcvd_info = -1;
static int hf_reload_diagnosticinfo_message_code = -1;
static int hf_reload_diagnosticinfo_messages_sent = -1;
static int hf_reload_diagnosticinfo_messages_rcvd = -1;
static int hf_reload_diagnosticinfo_ewma_bytes_sent = -1;
static int hf_reload_diagnosticinfo_ewma_bytes_rcvd = -1;
static int hf_reload_diagnosticinfo_underlay_hops = -1;
static int hf_reload_diagnosticinfo_battery_status = -1;
static int hf_reload_diagnosticresponse_timestampreceived = -1;
static int hf_reload_diagnosticresponse_hopcounter = -1;
static int hf_reload_diagnosticresponse_diagnostic_info_list = -1;
static int hf_reload_pathtrackans = -1;
static int hf_reload_pathtrackans_next_hop = -1;
static int hf_reload_pathtrackans_response = -1;
static int hf_reload_extensiveroutingmodeoption = -1;
static int hf_reload_routemode = -1;
static int hf_reload_extensiveroutingmode_transport = -1;
static int hf_reload_extensiveroutingmode_ipaddressport = -1;
static int hf_reload_extensiveroutingmode_destination = -1;
static int hf_reload_joinreq = -1;
static int hf_reload_joinreq_joining_peer_id = -1;
static int hf_reload_joinans = -1;
static int hf_reload_leavereq = -1;
static int hf_reload_leavereq_leaving_peer_id = -1;

static dissector_handle_t data_handle;
static dissector_handle_t xml_handle;


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

#define VERSION_DRAFT          0x01

/* RELOAD Message Methods = (message_code +1) & 0xfffe*/
#define METHOD_INVALID                   0
#define METHOD_PROBE                     2
#define METHOD_ATTACH                    4
#define METHOD_STORE                     8
#define METHOD_FETCH                     10
#define METHOD_UNUSED_REMOVE             12
#define METHOD_FIND                      14
#define METHOD_JOIN                      16
#define METHOD_LEAVE                     18
#define METHOD_UPDATE                    20
#define METHOD_ROUTEQUERY                22
#define METHOD_PING                      24
#define METHOD_STAT                      26
#define METHOD_UNUSED_ATTACHLIGHT        28
#define METHOD_APPATTACH                 30
#define METHOD_UNUSED_APP_ATTACHLIGHT    32
#define METHOD_CONFIGUPDATE              34
#define METHOD_EXP_A                     36
#define METHOD_EXP_B                     38
#define METHOD_PATH_TRACK                102
#define METHOD_ERROR                     0xfffe


/* RELOAD Destinationtype */
#define DESTINATIONTYPE_RESERVED            0
#define DESTINATIONTYPE_NODE                1
#define DESTINATIONTYPE_RESOURCE            2
#define DESTINATIONTYPE_COMPRESSED          3

/* RELOAD forwarding option type */
#define OPTIONTYPE_RESERVED                  0
#define OPTIONTYPE_EXTENSIVE_ROUTING_MODE    2

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
#define OVERLAYLINKTYPE_RESERVED                                        0
#define OVERLAYLINKTYPE_DTLS_UDP_SR                                     1
#define OVERLAYLINKTYPE_DTLS_UDP_SR_NO_ICE                              3
#define OVERLAYLINKTYPE_TLS_TCP_FH_NO_ICE                               4
#define OVERLAYLINKTYPE_EXP_LINK                                        5

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
#define ERRORCODE_INPROGRESS                                            17
#define ERRORCODE_EXP_A                                                 18
#define ERRORCODE_EXP_B                                                 19
#define ERRORCODE_UNDERLAY_DESTINATION_UNREACHABLE                      101
#define ERRORCODE_UNDERLAY_TIME_EXCEEDED                                102
#define ERRORCODE_MESSAGE_EXPIRED                                       103
#define ERRORCODE_MISROUTING                                            104
#define ERRORCODE_LOOP_DETECTED                                         105
#define ERRORCODE_TTL_HOPS_EXCEEDED                                     106


/* Signer identity types */
#define SIGNERIDENTITYTYPE_RESERVED                                  0
#define SIGNERIDENTITYTYPE_CERTHASH                                  1
#define SIGNERIDENTITYTYPE_CERTHASHNODEID                            2
#define SIGNERIDENTITYTYPE_NONE                                      3

/* Probe information type */
#define PROBEINFORMATIONTYPE_RESERVED                                   0
#define PROBEINFORMATIONTYPE_RESPONSIBLESET                             1
#define PROBEINFORMATIONTYPE_NUMRESOURCES                               2
#define PROBEINFORMATIONTYPE_UPTIME                                     3
#define PROBEINFORMATIONTYPE_EXP_PROBE                                  4

/* Data Kind ID */
#define DATAKINDID_INVALID                                              0
#define DATAKINDID_SIP_REGISTRATION                                     1
#define DATAKINDID_TURNSERVICE                                          2
#define DATAKINDID_CERTIFICATE_BY_NODE                                  3
#define DATAKINDID_RESERVED_ROUTING_TABLE_SIZE                          4
#define DATAKINDID_RESERVED_SOFTWARE_VERSION                            5
#define DATAKINDID_RESERVED_MACHINE_UPTIME                              6
#define DATAKINDID_RESERVED_APP_UPTIME                                  7
#define DATAKINDID_RESERVED_MEMORY_FOOTPRINT                            8
#define DATAKINDID_RESERVED_DATASIZE_STORED                             9
#define DATAKINDID_RESERVED_INSTANCES_STORED                            10
#define DATAKINDID_RESERVED_MESSAGES_SENT_RCVD                          11
#define DATAKINDID_RESERVED_EWMA_BYTES_SENT                             12
#define DATAKINDID_RESERVED_EWMA_BYTES_RCVD                             13
#define DATAKINDID_RESERVED_LAST_CONTACT                                14
#define DATAKINDID_RESERVED_RTT                                         15
#define DATAKINDID_CERTIFICATE_BY_USER                                  16
#define DATAKINDID_REDIR                                                104

/* Data model */
#define DATAMODEL_SINGLE                                                1
#define DATAMODEL_ARRAY                                                 2
#define DATAMODEL_DICTIONARY                                            3

/* Message Extension Type */
#define MESSAGEEXTENSIONTYPE_RESERVED                                   0
#define MESSAGEEXTENSIONTYPE_EXP_EXT                                    1
#define MESSAGEEXTENSIONTYPE_SELF_TUNING_DATA                           2 /* is 1 */
#define MESSAGEEXTENSIONTYPE_DIAGNOSTIC_PING                            3 /* is 1 */

/* Config Update Type */
#define CONFIGUPDATETYPE_RESERVED                                       0
#define CONFIGUPDATETYPE_CONFIG                                         1
#define CONFIGUPDATETYPE_KIND                                           2

/* Chord Update Type */
#define CHORDUPDATETYPE_RESERVED                                        0
#define CHORDUPDATETYPE_PEER_READY                                      1
#define CHORDUPDATETYPE_NEIGHBORS                                       2
#define CHORDUPDATETYPE_FULL                                            3

/* Chord Leave Type */
#define CHORDLEAVETYPE_RESERVED                                         0
#define CHORDLEAVETYPE_FROM_SUCC                                        1
#define CHORDLEAVETYPE_FROM_PRED                                        2

/* Chord Leave Type */
#define SIPREGISTRATIONTYPE_URI                                         1
#define SIPREGISTRATIONTYPE_ROUTE                                       2

/* Diagnostic Kind Id Type */
#define DIAGNOSTICKINDID_RESERVED                                       0x0000
#define DIAGNOSTICKINDID_STATUS_INFO                                    0x0001
#define DIAGNOSTICKINDID_ROUTING_TABLE_SIZE                             0x0002
#define DIAGNOSTICKINDID_PROCESS_POWER                                  0x0003
#define DIAGNOSTICKINDID_BANDWIDTH                                      0x0004
#define DIAGNOSTICKINDID_SOFTWARE_VERSION                               0x0005
#define DIAGNOSTICKINDID_MACHINE_UPTIME                                 0x0006
#define DIAGNOSTICKINDID_APP_UPTIME                                     0x0007
#define DIAGNOSTICKINDID_MEMORY_FOOTPRINT                               0x0008
#define DIAGNOSTICKINDID_DATASIZE_STORED                                0x0009
#define DIAGNOSTICKINDID_INSTANCES_STORED                               0x000A
#define DIAGNOSTICKINDID_MESSAGES_SENT_RCVD                             0x000B
#define DIAGNOSTICKINDID_EWMA_BYTES_SENT                                0x000C
#define DIAGNOSTICKINDID_EWMA_BYTES_RCVD                                0x000D
#define DIAGNOSTICKINDID_UNDERLAY_HOP                                   0x000E
#define DIAGNOSTICKINDID_BATTERY_STATUS                                 0x000F

/* route modes */
#define ROUTEMODE_RESERVED                                              0
#define ROUTEMODE_DDR                                                   1
#define ROUTEMODE_RPR                                                   2

/* Application IDs */
#define APPLICATIONID_INVALID                                           0
#define APPLICATIONID_SIP_5060                                          5060
#define APPLICATIONID_SIP_5061                                          5061
#define APPLICATIONID_RESERVED                                          0xFFFF


#define TOPOLOGY_PLUGIN_CHORD_RELOAD "CHORD-RELOAD"

/* reload user configuration variables */
static gboolean reload_defragment = TRUE;
static guint reload_nodeid_length = 16;
static const char *reload_topology_plugin= TOPOLOGY_PLUGIN_CHORD_RELOAD;


/* Initialize the subtree pointers */
static gint ett_reload = -1;
static gint ett_reload_forwarding = -1;
static gint ett_reload_message = -1;
static gint ett_reload_security=-1;
static gint ett_reload_fragment_flag=-1;
static gint ett_reload_destination = -1;
static gint ett_reload_via_list = -1;
static gint ett_reload_destination_list = -1;
static gint ett_reload_resourceid = -1;
static gint ett_reload_forwarding_options = -1;
static gint ett_reload_forwarding_option = -1;
static gint ett_reload_forwarding_option_flags = -1;
static gint ett_reload_forwarding_option_directresponseforwarding = -1;
static gint ett_reload_attachreqans = -1;
static gint ett_reload_icecandidates = -1;
static gint ett_reload_icecandidate = -1;
static gint ett_reload_icecandidate_computed_address = -1;
static gint ett_reload_iceextension = -1;
static gint ett_reload_iceextensions = -1;
static gint ett_reload_ipaddressport = -1;
static gint ett_reload_ipv4addrport = -1;
static gint ett_reload_ipv6addrport = -1;
static gint ett_reload_message_contents = -1;
static gint ett_reload_message_extensions = -1;
static gint ett_reload_message_extension = -1;
static gint ett_reload_error_response = -1;
static gint ett_reload_security_block = -1;
static gint ett_reload_genericcertificate = -1;
static gint ett_reload_certificates = -1;
static gint ett_reload_signature = -1;
static gint ett_reload_signatureandhashalgorithm = -1;
static gint ett_reload_signeridentity = -1;
static gint ett_reload_signeridentity_identity = -1;
static gint ett_reload_signeridentity_value = -1;
static gint ett_reload_opaque = -1;
static gint ett_reload_message_body = -1;
static gint ett_reload_routequeryreq = -1;
static gint ett_reload_probereq = -1;
static gint ett_reload_probereq_requested_info = -1;
static gint ett_reload_probe_information = -1;
static gint ett_reload_probe_information_data = -1;
static gint ett_reload_probeans = -1;
static gint ett_reload_probeans_probe_info = -1;
static gint ett_reload_appattach = -1;
static gint ett_reload_pingreq = -1;
static gint ett_reload_pingans = -1;
static gint ett_reload_storeddata = -1;
static gint ett_reload_kinddata = -1;
static gint ett_reload_values = -1;
static gint ett_reload_datavalue = -1;
static gint ett_reload_arrayentry = -1;
static gint ett_reload_dictionaryentry = -1;
static gint ett_reload_storereq = -1;
static gint ett_reload_store_kind_data = -1;
static gint ett_reload_storeans = -1;
static gint ett_reload_storekindresponse = -1;
static gint ett_reload_storeans_kind_responses = -1;
static gint ett_reload_fetchreq = -1;
static gint ett_reload_fetchreq_specifiers = -1;
static gint ett_reload_storeddataspecifier = -1;
static gint ett_reload_storeddataspecifier_indices = -1;
static gint ett_reload_storeddataspecifier_keys = -1;
static gint ett_reload_fetchans = -1;
static gint ett_reload_statans = -1;
static gint ett_reload_findkinddata = -1;
static gint ett_reload_fragments = -1;
static gint ett_reload_fragment  = -1;
static gint ett_reload_configupdatereq = -1;
static gint ett_reload_configupdatereq_config_data = -1;
static gint ett_reload_kinddescription = -1;
static gint ett_reload_configupdatereq_kinds = -1;
static gint ett_reload_storekindresponse_replicas = -1;
static gint ett_reload_nodeid_list = -1;
static gint ett_reload_chordupdate = -1;
static gint ett_reload_chordroutequeryans = -1;
static gint ett_reload_chordleave = -1;
static gint ett_reload_turnserver = -1;
static gint ett_reload_sipregistration = -1;
static gint ett_reload_sipregistration_data = -1;
static gint ett_reload_sipregistration_destination_list = -1;
static gint ett_reload_dictionaryentry_key = -1;
static gint ett_reload_overlay_specific = -1;
static gint ett_reload_kindid_list = -1;
static gint ett_reload_redirserviceproviderdata = -1;
static gint ett_reload_redirserviceprovider = -1;
static gint ett_reload_self_tuning_data = -1;
static gint ett_reload_findreq = -1;
static gint ett_reload_findans = -1;
static gint ett_reload_dmflags = -1;
static gint ett_reload_diagnosticextension = -1;
static gint ett_reload_diagnosticrequest = -1;
static gint ett_reload_diagnosticrequest_extensions = -1;
static gint ett_reload_pathtrackreq = -1;
static gint ett_reload_diagnosticinfo = -1;
static gint ett_reload_diagnosticinfo_instances_stored = -1;
static gint ett_reload_diagnosticinfo_instancesstored_info = -1;
static gint ett_reload_diagnosticinfo_messages_sent_rcvd = -1;
static gint ett_reload_diagnosticinfo_messages_sent_rcvd_info = -1;
static gint ett_reload_diagnosticresponse = -1;
static gint ett_reload_diagnosticresponse_diagnostic_info_list = -1;
static gint ett_reload_pathtrackans = -1;
static gint ett_reload_extensiveroutingmodeoption = -1;
static gint ett_reload_extensiveroutingmode_destination = -1;
static gint ett_reload_joinreq = -1;
static gint ett_reload_joinans = -1;
static gint ett_reload_leavereq = -1;

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

static const gint * reload_dmflag_items[] = {
  &hf_reload_dmflag_status_info,
  &hf_reload_dmflag_routing_table_size,
  &hf_reload_dmflag_process_power,
  &hf_reload_dmflag_bandwidth,
  &hf_reload_dmflag_software_version,
  &hf_reload_dmflag_machine_uptime,
  &hf_reload_dmflag_app_uptime,
  &hf_reload_dmflag_memory_footprint,
  &hf_reload_dmflag_datasize_stored,
  &hf_reload_dmflag_instances_stored,
  &hf_reload_dmflag_messages_sent_rcvd,
  &hf_reload_dmflag_ewma_bytes_sent,
  &hf_reload_dmflag_ewma_bytes_rcvd,
  &hf_reload_dmflag_underlay_hop,
  &hf_reload_dmflag_battery_status,
};

static uat_t *reloadkindids_uat = NULL;

typedef struct _Kind {
  gchar *name;
  guint32 id;
  guint data_model;

} kind_t;

static kind_t predefined_kinds[] = {
  {"INVALID", DATAKINDID_INVALID, -1},
  {"SIP-REGISTRATION",DATAKINDID_SIP_REGISTRATION,DATAMODEL_DICTIONARY},
  {"TURN-SERVICE",DATAKINDID_TURNSERVICE,DATAMODEL_SINGLE},
  {"CERTIFICATE_BY_NODE",DATAKINDID_CERTIFICATE_BY_NODE,DATAMODEL_ARRAY},
  {"RESERVED_ROUTING_TABLE_SIZE",DATAKINDID_RESERVED_ROUTING_TABLE_SIZE,-1},
  {"RESERVED_SOFTWARE_VERSION",DATAKINDID_RESERVED_SOFTWARE_VERSION,-1},
  {"RESERVED_MACHINE_UPTIME",DATAKINDID_RESERVED_MACHINE_UPTIME,-1},
  {"DATAKINDID_RESERVED_APP_UPTIME",DATAKINDID_RESERVED_APP_UPTIME,-1},
  {"RESERVED_MEMORY_FOOTPRINT",DATAKINDID_RESERVED_MEMORY_FOOTPRINT,-1},
  {"RESERVED_DATASIZE_STORED",DATAKINDID_RESERVED_DATASIZE_STORED,-1},
  {"RESERVED_INSTANCES_STORED",DATAKINDID_RESERVED_INSTANCES_STORED,-1},
  {"RESERVED_MESSAGES_SENT_RCVD",DATAKINDID_RESERVED_MESSAGES_SENT_RCVD,-1},
  {"RESERVED_EWMA_BYTES_SENT",DATAKINDID_RESERVED_EWMA_BYTES_SENT,-1},
  {"RESERVED_EWMA_BYTES_RCVD",DATAKINDID_RESERVED_EWMA_BYTES_RCVD,-1},
  {"RESERVED_LAST_CONTACT",DATAKINDID_RESERVED_LAST_CONTACT,-1},
  {"RESERVED_RTT",DATAKINDID_RESERVED_RTT,-1},
  {"CERTIFICATE_BY_USER",DATAKINDID_CERTIFICATE_BY_USER,DATAMODEL_ARRAY},
  {"REDIR",DATAKINDID_REDIR,DATAMODEL_DICTIONARY},
};


static kind_t * kindidlist_uats=NULL;

static guint nreloadkinds = 0;

kind_t * getKindFromId(guint32 id) {
  guint i;
  /* user defined kinds have precedence */
  for (i = 0; i < nreloadkinds; i++) {
    if (id == kindidlist_uats[i].id) {
      return (kindidlist_uats+i);
    }
  }

  /* then pre-defined kinds */
  {
    guint npredefinedkinds = sizeof(predefined_kinds) / sizeof(kind_t);
    for (i = 0; i < npredefinedkinds; i++) {
      if (id == predefined_kinds[i].id) {
        return (predefined_kinds+i);
      }
    }
  }
  return NULL;
}

/*-------------------------------------
 * UAT for Kind-IDs
 *-------------------------------------
 */


static void* uat_kindid_copy_cb(void* n, const void* o, size_t siz _U_) {
  kind_t * new_record = (kind_t *)n;
  const kind_t* old_record = (kind_t *)o;

  if (old_record->name) {
    new_record->name = g_strdup(old_record->name);
  } else {
    new_record->name = NULL;
  }

  return new_record;
}

static void uat_kindid_record_free_cb(void*r) {
  kind_t* rec = (kind_t *)r;

  if (rec->name) g_free(rec->name);
}

UAT_DEC_CB_DEF(kindidlist_uats,id,kind_t)
UAT_CSTRING_CB_DEF(kindidlist_uats,name,kind_t)
UAT_VS_DEF(kindidlist_uats,data_model,kind_t,0,"string")


#define MSG_LENGH_OFFSET                16
#define MIN_HDR_LENGTH                  38      /* Forwarding header till options_length member (included) */

#define RELOAD_TOKEN                    0xd2454c4f

#define IS_REQUEST(code)                (code & 0x0001)
#define MSGCODE_TO_METHOD(code)         ((code + 1) & 0xfffe)
#define MSGCODE_TO_CLASS(code)          (code & 0x0001)


static const value_string versions[] = {
  {VERSION_DRAFT,                               "0.1 DRAFT"},
  {0x00, NULL}
};

static const value_string classes[] = {
  {RELOAD_REQUEST,                              "Request"},
  {RELOAD_RESPONSE,                             "Response"},
  {0x00, NULL}
};

static const value_string methods[] = {
  {METHOD_INVALID,                              "invalid"},
  {METHOD_PROBE,                                "Probe"},
  {METHOD_ATTACH,                               "Attach"},
  {METHOD_STORE,                                "Store"},
  {METHOD_FETCH,                                "Fetch"},
  {METHOD_UNUSED_REMOVE,                        "Remove (Unused)"},
  {METHOD_FIND,                                 "Find"},
  {METHOD_JOIN,                                 "Join"},
  {METHOD_LEAVE,                                "Leave"},
  {METHOD_UPDATE,                               "Update"},
  {METHOD_ROUTEQUERY,                           "RouteQuery"},
  {METHOD_PING,                                 "Ping"},
  {METHOD_STAT,                                 "Stat"},
  {METHOD_UNUSED_ATTACHLIGHT,                   "AttachLight (Unused)"},
  {METHOD_APPATTACH,                            "AppAttach"},
  {METHOD_UNUSED_APP_ATTACHLIGHT,               "AppAttachLight (Unused)"},
  {METHOD_CONFIGUPDATE,                         "ConfigUpdate"},
  {METHOD_EXP_A,                                "Exp_B"},
  {METHOD_EXP_B,                                "Exp_A"},
  {METHOD_PATH_TRACK,                           "Path_Track"},
  {METHOD_ERROR,                                "Error"},
  {0x00, NULL}
};

static const value_string classes_short[] = {
  {RELOAD_REQUEST,                              "req"},
  {RELOAD_RESPONSE,                             "ans"},
  {0x00, NULL}
};

static const value_string classes_Short[] = {
  {RELOAD_REQUEST,                              "Req"},
  {RELOAD_RESPONSE,                             "Ans"},
  {0x00, NULL}
};

static const value_string methods_short[] = {
  {METHOD_INVALID,                              "invalid"},
  {METHOD_PROBE,                                "probe"},
  {METHOD_ATTACH,                               "attach"},
  {METHOD_STORE,                                "store"},
  {METHOD_FETCH,                                "fetch"},
  {METHOD_UNUSED_REMOVE,                        "unused_remove"},
  {METHOD_FIND,                                 "find"},
  {METHOD_JOIN,                                 "join"},
  {METHOD_LEAVE,                                "leave"},
  {METHOD_UPDATE,                               "update"},
  {METHOD_ROUTEQUERY,                           "route_query"},
  {METHOD_PING,                                 "ping"},
  {METHOD_STAT,                                 "stat"},
  {METHOD_UNUSED_ATTACHLIGHT,                   "unused_attachlight"},
  {METHOD_APPATTACH,                            "app_attach"},
  {METHOD_UNUSED_APP_ATTACHLIGHT,               "unused_app_attachlight"},
  {METHOD_CONFIGUPDATE,                         "config_update"},
  {METHOD_EXP_A,                                "exp_a"},
  {METHOD_EXP_B,                                "exp_b"},
  {METHOD_PATH_TRACK,                           "path_track"},
  {METHOD_ERROR,                                "error"},
  {0x00, NULL}
};



static const value_string destinationtypes[] = {
  {DESTINATIONTYPE_RESERVED,                    "reserved"},
  {DESTINATIONTYPE_NODE,                        "node"},
  {DESTINATIONTYPE_RESOURCE,                    "resource"},
  {DESTINATIONTYPE_COMPRESSED,                  "compressed"},
  {0x00, NULL}
};

static const value_string forwardingoptiontypes[] = {
  {OPTIONTYPE_RESERVED,                         "reserved"},
  {OPTIONTYPE_EXTENSIVE_ROUTING_MODE,           "extensive_routing_mode"},
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

static const value_string overlaylinktypes [] = {
  {OVERLAYLINKTYPE_RESERVED,                    "reserved"},
  {OVERLAYLINKTYPE_DTLS_UDP_SR,                 "DTLS-UDP-SR"},
  {OVERLAYLINKTYPE_DTLS_UDP_SR_NO_ICE,          "DTLS-UDP-SR-NO-ICE"},
  {OVERLAYLINKTYPE_TLS_TCP_FH_NO_ICE,           "TLS-TCP-FH-NO-ICE"},
  {OVERLAYLINKTYPE_EXP_LINK,                    "EXP_LINK"},
  {0x00, NULL}
};

static const value_string errorcodes [] = {
  {ERRORCODE_INVALID,                           "invalid"},
  {ERRORCODE_UNUSED,                            "Unused"},
  {ERRORCODE_FORBIDDEN,                         "Error_Forbidden"},
  {ERRORCODE_NOTFOUND,                          "Error_Not_Found"},
  {ERRORCODE_REQUESTTIMEOUT,                    "Error_Request_Timeout"},
  {ERRORCODE_GENERATIONCOUNTERTOOLOW,           "Error_Generation_Counter_Too_Low"},
  {ERRORCODE_INCOMPATIBLEWITHOVERLAY,           "Error_Incompatible_with_Overlay"},
  {ERRORCODE_UNSUPPORTEDFORWARDINGOPTION,       "Error_Unsupported_Forwarding_Option"},
  {ERRORCODE_DATATOOLARGE,                      "Error_Data_Too_Large"},
  {ERRORCODE_DATATOOOLD,                        "Error_Data_Too_Old"},
  {ERRORCODE_TTLEXCEEDED,                       "Error_TTL_Exceeded"},
  {ERRORCODE_MESSAGETOOLARGE,                   "Error_Message_Too_Large"},
  {ERRORCODE_UNKNOWNKIND,                       "Error_Unknown_Kind"},
  {ERRORCODE_UNKNOWNEXTENSION,                  "Error_Unknown_Extension"},
  {ERRORCODE_RESPONSETOOLARGE,                  "Error_Response_Too_Large"},
  {ERRORCODE_CONFIGTOOOLD,                      "Error_Config_Too_Old"},
  {ERRORCODE_CONFIGTOONEW,                      "Error_Config_Too_New"},
  {ERRORCODE_CONFIGTOONEW,                      "Error_Config_Too_New"},
  {ERRORCODE_INPROGRESS,                        "Error_In_Progress"},
  {ERRORCODE_EXP_A,                             "Error_Exp_A"},
  {ERRORCODE_EXP_B,                             "Error_Exp_B"},
  {ERRORCODE_UNDERLAY_DESTINATION_UNREACHABLE,  "Error_Underlay_Destination_Unreachable"},
  {ERRORCODE_UNDERLAY_TIME_EXCEEDED,            "Error_Underlay_Time_Exceeded"},
  {ERRORCODE_MESSAGE_EXPIRED,                   "Error_Message_Expired"},
  {ERRORCODE_MISROUTING,                        "Error_Upstream_Misrouting"},
  {ERRORCODE_LOOP_DETECTED,                     "Error_Loop_Detected"},
  {ERRORCODE_TTL_HOPS_EXCEEDED,                 "Error_TTL_Hops_Exceeded"},
  {0x00, NULL}
};

static const value_string signeridentitytypes[] = {
  {SIGNERIDENTITYTYPE_RESERVED,              "reserved"},
  {SIGNERIDENTITYTYPE_CERTHASH,              "cert_hash"},
  {SIGNERIDENTITYTYPE_CERTHASHNODEID,        "cert_hash_node_id"},
  {SIGNERIDENTITYTYPE_NONE,                  "none"},
  {0x00, NULL}
};

static const value_string probeinformationtypes[] = {
  {PROBEINFORMATIONTYPE_RESERVED,               "reserved"},
  {PROBEINFORMATIONTYPE_RESPONSIBLESET,         "responsible_set"},
  {PROBEINFORMATIONTYPE_NUMRESOURCES,           "num_resources"},
  {PROBEINFORMATIONTYPE_UPTIME,                 "uptime"},
  {PROBEINFORMATIONTYPE_EXP_PROBE,                 "exp-probe"},
  {0x00, NULL}
};


static const value_string datamodels[] = {
  {DATAMODEL_SINGLE, "SINGLE"},
  {DATAMODEL_ARRAY, "ARRAY"},
  {DATAMODEL_DICTIONARY, "DICTIONARY"},
  {0x00, NULL}
};

static const value_string messageextensiontypes[] = {
  {MESSAGEEXTENSIONTYPE_RESERVED,               "reserved"},
  {MESSAGEEXTENSIONTYPE_SELF_TUNING_DATA,       "exp-ext"},
  {MESSAGEEXTENSIONTYPE_SELF_TUNING_DATA,       "sip_tuning_data"},
  {MESSAGEEXTENSIONTYPE_SELF_TUNING_DATA,       "Diagnostic_Ping"},
  {0x00, NULL}
};


static const value_string configupdatetypes[] = {
  {CONFIGUPDATETYPE_RESERVED,                   "reserved"},
  {CONFIGUPDATETYPE_CONFIG,                     "config"},
  {CONFIGUPDATETYPE_KIND,                       "kind"},
  {0x00, NULL}
};

static const value_string chordupdatetypes[] = {
  {CHORDUPDATETYPE_RESERVED,                    "reserved"},
  {CHORDUPDATETYPE_PEER_READY,                  "peer_ready"},
  {CHORDUPDATETYPE_NEIGHBORS,                   "neighbors"},
  {CHORDUPDATETYPE_FULL,                        "full"},
  {0x00, NULL}
};

static const value_string chordleavetypes[] = {
  {CHORDLEAVETYPE_RESERVED,                    "reserved"},
  {CHORDLEAVETYPE_FROM_SUCC,                   "from_succ"},
  {CHORDLEAVETYPE_FROM_PRED,                   "from_pred"},
  {0x00, NULL}
};

static const value_string sipregistrationtypes[] = {
  {SIPREGISTRATIONTYPE_URI,                    "sip_registration_uri"},
  {SIPREGISTRATIONTYPE_ROUTE,                  "sip_registration_route"},
  {0x00, NULL}
};

static const value_string diagnostickindids[] = {
  {DIAGNOSTICKINDID_RESERVED,                   "reserved"},
  {DIAGNOSTICKINDID_STATUS_INFO,                "STATUS_INFO"},
  {DIAGNOSTICKINDID_ROUTING_TABLE_SIZE,         "ROUTING_TABLE_SIZ"},
  {DIAGNOSTICKINDID_PROCESS_POWER,              "PROCESS_POWER"},
  {DIAGNOSTICKINDID_BANDWIDTH,                  "BANDWIDTH"},
  {DIAGNOSTICKINDID_SOFTWARE_VERSION,           "SOFTWARE_VERSION"},
  {DIAGNOSTICKINDID_MACHINE_UPTIME,             "MACHINE_UPTIME"},
  {DIAGNOSTICKINDID_APP_UPTIME,                 "APP_UPTIME"},
  {DIAGNOSTICKINDID_MEMORY_FOOTPRINT,           "MEMORY_FOOTPRINT"},
  {DIAGNOSTICKINDID_DATASIZE_STORED,            "DATASIZE_STORED"},
  {DIAGNOSTICKINDID_INSTANCES_STORED,           "INSTANCES_STORED"},
  {DIAGNOSTICKINDID_MESSAGES_SENT_RCVD,         "MESSAGES_SENT_RCVD"},
  {DIAGNOSTICKINDID_EWMA_BYTES_SENT,            "EWMA_BYTES_SENT"},
  {DIAGNOSTICKINDID_EWMA_BYTES_RCVD,            "EWMA_BYTES_RCVD"},
  {DIAGNOSTICKINDID_UNDERLAY_HOP,               "UNDERLAY_HOP"},
  {DIAGNOSTICKINDID_BATTERY_STATUS,             "BATTERY_STATUS"},
  {0x00, NULL}
};

static const value_string routemodes[] = {
  {ROUTEMODE_RESERVED,                         "reserved"},
  {ROUTEMODE_DDR,                              "DDR"},
  {ROUTEMODE_RPR,                              "RPR"},
  {0x00, NULL}
};

static const value_string applicationids[] = {
  /* Application IDs */
  {APPLICATIONID_INVALID,                      "INVALID"},
  {APPLICATIONID_SIP_5060,                     "SIP"},
  {APPLICATIONID_SIP_5061,                     "SIP"},
  {APPLICATIONID_RESERVED,                     "Reserved"},
  {0x00, NULL}
};


/*
 * defragmentation
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
  case 3:
    length = ((gint32) (tvb_get_ntohs(tvb, offset) <<8) + (tvb_get_guint8(tvb, offset+2)));
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
dissect_opaque_string_or_data(tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int anchor_index, guint16 offset, guint16 length_size, gint32 max_field_length, gboolean is_string)
{
  proto_tree *opaque_tree;
  proto_item *ti_anchor;
  gint length_index = -1;
  gint32 length = -1;
  int hf = hf_reload_opaque;
  int hf_data = hf_reload_opaque_data;


  if (anchor_index>=0) {
    hf=anchor_index;
  }

  if (is_string) {
    hf_data = hf_reload_opaque_string;
  }

  switch (length_size) {
  case 1:
    length_index = hf_reload_length_uint8;
    length = (gint32)tvb_get_guint8(tvb,offset);
    break;
  case 2:
    length_index = hf_reload_length_uint16;
    length = (gint32)tvb_get_ntohs(tvb, offset);
    break;
  case 3:
    length_index = hf_reload_length_uint24;
    length = ((gint32) (tvb_get_ntohs(tvb, offset) <<8) + (tvb_get_guint8(tvb, offset+2)));
    break;
  case 4:
    length_index = hf_reload_length_uint32;
    length = (gint32)tvb_get_ntohl(tvb, offset);
    break;

  default:
    break;
  }

  if (length_index < 0) return 0;

  ti_anchor = proto_tree_add_item(tree, hf, tvb, offset, length_size + length, FALSE);

  if (max_field_length > 0) {
    if ((length + length_size) > max_field_length) {
      expert_add_info_format(pinfo, ti_anchor, PI_PROTOCOL, PI_ERROR, "Computed length > max_field length");
      length = max_field_length - length_size;
    }
  }

  opaque_tree = proto_item_add_subtree(ti_anchor, ett_reload_opaque);
  proto_tree_add_uint(opaque_tree, length_index, tvb, offset, length_size, (guint)length);
  if (length) {
    proto_tree_add_item(opaque_tree, hf_data, tvb, offset + length_size, length, FALSE);
  }
  if (hf != hf_reload_opaque) {
    proto_item_append_text(ti_anchor, " (opaque<%d>)", length);
  }
  else {
    proto_item_append_text(ti_anchor, "<%d>", length);
  }

  return (length_size + length);
}

static int
dissect_opaque(tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int anchor_index, guint16 offset, guint16 length_size, gint32 max_field_length) {
  return dissect_opaque_string_or_data(tvb, pinfo, tree, anchor_index, offset, length_size, max_field_length, FALSE);
}

static int
dissect_opaque_string(tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, int anchor_index, guint16 offset, guint16 length_size, gint32 max_field_length) {
  return dissect_opaque_string_or_data(tvb, pinfo, tree, anchor_index, offset, length_size, max_field_length, TRUE);
}

static int dissect_length(tvbuff_t *tvb, proto_tree *tree, guint16 offset,  guint16 length_size) {
  switch (length_size) {
  case 1:
    proto_tree_add_item(tree, hf_reload_length_uint8, tvb, offset, 1, ENC_BIG_ENDIAN);
    return 1;

  case 2:
    proto_tree_add_item(tree, hf_reload_length_uint16, tvb, offset, 2, ENC_BIG_ENDIAN);
    return 2;

  case 3:
    proto_tree_add_item(tree, hf_reload_length_uint24, tvb, offset, 3, ENC_BIG_ENDIAN);
    return 3;

  case 4:
    proto_tree_add_item(tree, hf_reload_length_uint32, tvb, offset, 4, ENC_BIG_ENDIAN);
    return 4;

  default:
    break;
  }
  return 0;
}

static int dissect_resourceid(int anchor, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  int hf = hf_reload_resourceid;
  guint8 local_length;

  if (anchor >= 0) {
    hf = anchor;
  }

  local_length = tvb_get_guint8(tvb, offset);

  /* We don't know the node ID. Just assume that all the data is part of it */
  if (length < local_length+1) {
    ti_local = proto_tree_add_item(tree, hf, tvb, offset, length, FALSE);
    expert_add_info_format(pinfo, ti_local, PI_PROTOCOL, PI_ERROR, "Truncated ResourceId");
    return length;
  }

  ti_local = proto_tree_add_item(tree, hf, tvb, offset, 1+local_length, FALSE);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_resourceid);
  proto_tree_add_item(local_tree, hf_reload_length_uint8, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(local_tree, hf_reload_opaque_data, tvb, offset+1, local_length, ENC_NA);

  if (hf != hf_reload_resourceid) {
    proto_item_append_text(ti_local, " (ResourceId<%d>)", local_length);
  }
  else {
    proto_item_append_text(ti_local, "<%d>", local_length);
  }

  return 1+local_length;
}

static int dissect_nodeid(int anchor, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_nodeid;
  int hf = hf_reload_nodeid;

  if (anchor >= 0) {
    hf = anchor;
  }

  /* We don't know the node ID. Just assume that all the data is part of it */
  if (length < reload_nodeid_length) {
    ti_nodeid = proto_tree_add_item(tree, hf, tvb, offset, length, FALSE);
    expert_add_info_format(pinfo, ti_nodeid, PI_PROTOCOL, PI_ERROR, "Truncated NodeId");
    return length;
  }

  ti_nodeid = proto_tree_add_item(tree, hf, tvb, offset, reload_nodeid_length, FALSE);
  {
    gboolean allZeros=TRUE;
    gboolean allOnes=TRUE;
    guint i;

    for (i=0; i<reload_nodeid_length; i++) {
      guint8 byte = tvb_get_guint8(tvb,offset+i);
      if (byte!=0) {
        allZeros = FALSE;
        if (allOnes==FALSE) break;
      }
      if (byte != 0xFF) {
        allOnes = FALSE;
        if (allZeros == FALSE) break;
      }
    }

    if (allZeros) {
      proto_item_append_text(ti_nodeid, "\n  [Invalid]");
    }
    if (allOnes) {
      proto_item_append_text(ti_nodeid, "\n  [Wildcard]");
    }

  }


  return reload_nodeid_length;
}

static int
dissect_destination(int anchor, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  guint8 destination_type;
  proto_tree *destination_tree;
  proto_item *ti_destination;
  guint8 destination_length=0;
  int hf = hf_reload_destination;

  if (anchor >= 0) {
    hf = anchor;
  }

  destination_type = tvb_get_guint8(tvb,offset);

  if (destination_type & 0x80) {
    /* simple compressed case */
    ti_destination = proto_tree_add_item(tree, hf, tvb, offset, 2, FALSE);
    if (hf==anchor) {
      proto_item_append_text(ti_destination, " (Destination)");
    }
    proto_item_append_text(ti_destination, ": uint16");
    destination_tree = proto_item_add_subtree(ti_destination, ett_reload_destination);
    proto_tree_add_item(destination_tree,hf_reload_destination_compressed_id , tvb, offset, 2, ENC_BIG_ENDIAN);
    return 2;
  }
  else {
    /* normal case */

    destination_length = tvb_get_guint8(tvb,offset+1);
    ti_destination = proto_tree_add_item(tree, hf, tvb, offset, 2+destination_length, FALSE);
    if (hf==anchor) {
      proto_item_append_text(ti_destination, " (Destination)");
    }
    destination_tree = proto_item_add_subtree(ti_destination, ett_reload_destination);
    proto_item_append_text(ti_destination, ": %s", val_to_str(destination_type, destinationtypes, "Unknown"));

    proto_tree_add_item(destination_tree, hf_reload_destination_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_uint(destination_tree, hf_reload_length_uint8, tvb, offset+1, 1, destination_length);
    if (2 + destination_length > length) {
      expert_add_info_format(pinfo, ti_destination, PI_PROTOCOL, PI_ERROR, "Truncated Destination");
      return length;
    }
    switch(destination_type) {
    case DESTINATIONTYPE_NODE:
      dissect_nodeid(hf_reload_destination_data_node_id, tvb, pinfo, destination_tree, offset+2, destination_length);
      break;

    case DESTINATIONTYPE_RESOURCE:
      dissect_resourceid(hf_reload_destination_data_resource_id, tvb, pinfo, destination_tree, offset+2, destination_length);
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
dissect_destination_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *list_tree, guint16 offset, guint16 length, int *numDestinations)
{
  gint local_offset = 0;
  gint local_increment;
  *numDestinations=0;
  while (local_offset +2 <= length) {
    local_increment = dissect_destination(-1,tvb, pinfo, list_tree, offset + local_offset, length-local_offset);
    if (local_increment <= 0) break;
    local_offset += local_increment;
    (*numDestinations)++;
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
  proto_tree_add_uint(probe_information_tree, hf_reload_length_uint8, tvb, offset + 1, 1, probe_length);

  {
    proto_item *ti_probe_information_data;
    proto_tree *probe_information_data_tree;

    ti_probe_information_data = proto_tree_add_item(probe_information_tree, hf_reload_probe_information_data, tvb, offset+2, probe_length, ENC_NA);
    probe_information_data_tree = proto_item_add_subtree(ti_probe_information_data, ett_reload_probe_information_data);

    switch(type) {
    case PROBEINFORMATIONTYPE_RESPONSIBLESET:
      if (probe_length < 4) {
        expert_add_info_format(pinfo, ti_probe_information_data, PI_PROTOCOL, PI_ERROR, "Truncated responsible set");
        return 2 + probe_length;
      }
      proto_tree_add_item(probe_information_data_tree, hf_reload_responsible_set, tvb, offset + 2, 4, ENC_BIG_ENDIAN);
      break;
    case PROBEINFORMATIONTYPE_NUMRESOURCES:
      if (probe_length < 4) {
        expert_add_info_format(pinfo, ti_probe_information_data, PI_PROTOCOL, PI_ERROR, "Truncated num resource info");
        return 2 + probe_length;
      }
      proto_tree_add_item(probe_information_data_tree, hf_reload_num_resources, tvb, offset + 2, 4, ENC_BIG_ENDIAN);
      break;
    case PROBEINFORMATIONTYPE_UPTIME:
      if (probe_length < 4) {
        expert_add_info_format(pinfo, ti_probe_information_data, PI_PROTOCOL, PI_ERROR, "Truncated uptime info");
        return 2 + probe_length;
      }
      proto_tree_add_item(probe_information_data_tree, hf_reload_uptime, tvb, offset + 2, 4, ENC_BIG_ENDIAN);
      break;
    default:
      break;
    }
  }
  return probe_length + 2;
}



static int
dissect_ipaddressport(int anchor, tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
  proto_item *ti_ipaddressport;
  proto_tree *ipaddressport_tree;
  guint8 ipaddressport_type;
  guint8 ipaddressport_length;
  int hf = hf_reload_ipaddressport;

  if (anchor>=0) {
    hf = anchor;
  }

  ipaddressport_length = tvb_get_guint8(tvb, offset+1);
  ti_ipaddressport = proto_tree_add_item(tree, hf, tvb, offset, ipaddressport_length+2, FALSE);
  if (hf==anchor) proto_item_append_text(ti_ipaddressport, " (IpAddressPort)");
  ipaddressport_type = tvb_get_guint8(tvb, offset);
  proto_item_append_text(ti_ipaddressport, ": %s", val_to_str(ipaddressport_type, ipaddressporttypes,"Unknown Type"));
  if (ipaddressport_type==IPADDRESSPORTTYPE_IPV4) {
    proto_item_append_text(ti_ipaddressport, " (%s:%d)", tvb_ip_to_str(tvb, offset+2),tvb_get_ntohs(tvb,offset+2+4));
  }
  else if (ipaddressport_type==IPADDRESSPORTTYPE_IPV6) {
    proto_item_append_text(ti_ipaddressport, " (%s:%d)", tvb_ip6_to_str(tvb, offset+2),tvb_get_ntohs(tvb,offset+2+16));
  }
  ipaddressport_tree = proto_item_add_subtree(ti_ipaddressport, ett_reload_ipaddressport);
  proto_tree_add_item(ipaddressport_tree, hf_reload_ipaddressport_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset +=1;
  proto_tree_add_uint(ipaddressport_tree, hf_reload_length_uint8, tvb, offset, 1, ipaddressport_length);
  offset +=1;
  switch (ipaddressport_type) {
  case IPADDRESSPORTTYPE_IPV4:
  {
    proto_item *ti_ipv4;
    proto_tree *ipv4_tree;
    ti_ipv4 = proto_tree_add_item(ipaddressport_tree, hf_reload_ipv4addrport, tvb, offset, 6, ENC_NA);
    proto_item_append_text(ti_ipv4, ": %s:%d", tvb_ip_to_str(tvb, offset),tvb_get_ntohs(tvb,offset+4));
    ipv4_tree = proto_item_add_subtree(ti_ipv4, ett_reload_ipv4addrport);
    proto_tree_add_item(ipv4_tree, hf_reload_ipv4addr, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(ipv4_tree, hf_reload_port, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
  }
  break;

  case IPADDRESSPORTTYPE_IPV6:
  {
    proto_item *ti_ipv6;
    proto_tree *ipv6_tree;
    ti_ipv6 = proto_tree_add_item(ipaddressport_tree, hf_reload_ipv6addrport, tvb, offset, 6, ENC_NA);
    proto_item_append_text(ti_ipv6, ": %s:%d", tvb_ip6_to_str(tvb, offset),tvb_get_ntohs(tvb,offset+16));
    ipv6_tree = proto_item_add_subtree(ti_ipv6, ett_reload_ipv6addrport);
    proto_tree_add_item(ipv6_tree, hf_reload_ipv6addr, tvb, offset, 16, ENC_NA);
    proto_tree_add_item(ipv6_tree, hf_reload_port, tvb, offset + 16, 2, ENC_BIG_ENDIAN);
  }
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
  int nCandidates = 0;

  icecandidates_length = tvb_get_ntohs(tvb, offset);
  /* Precalculate the length of the icecandidate list */
  if (2+icecandidates_length > length) {
    ti_icecandidates = proto_tree_add_item(tree, hf_reload_icecandidates, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_icecandidates, PI_PROTOCOL, PI_ERROR, "Truncated ice candidates");
    return length;
  }

  ti_icecandidates = proto_tree_add_item(tree, hf_reload_icecandidates, tvb, offset, 2+icecandidates_length, ENC_NA);
  proto_item_append_text(ti_icecandidates, " (IceCandidate<%d>)", icecandidates_length);
  icecandidates_tree = proto_item_add_subtree(ti_icecandidates, ett_reload_icecandidates);
  proto_tree_add_uint(icecandidates_tree, hf_reload_length_uint16, tvb, offset+local_offset, 2, icecandidates_length);
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
      expert_add_info_format(pinfo, ti_icecandidates, PI_PROTOCOL, PI_ERROR, "Truncated IceCandidate");
      break;
    }
    ti_icecandidate = proto_tree_add_item(icecandidates_tree, hf_reload_icecandidate, tvb, offset+local_offset+ icecandidates_offset, icecandidate_offset, ENC_NA);
    icecandidate_tree = proto_item_add_subtree(ti_icecandidate, ett_reload_icecandidate);
    /* parse from start */
    icecandidate_offset = 0;
    dissect_ipaddressport(hf_reload_icecandidate_addr_port,tvb, icecandidate_tree, offset+local_offset+icecandidates_offset+icecandidate_offset);
    icecandidate_offset += 2 + ipaddressport_length;

    proto_tree_add_item(icecandidate_tree, hf_reload_overlaylink_type, tvb,
                        offset+local_offset+icecandidates_offset+icecandidate_offset, 1, ENC_BIG_ENDIAN);

    icecandidate_offset += 1;
    icecandidate_offset += dissect_opaque_string(tvb, pinfo,icecandidate_tree,  hf_reload_icecandidate_foundation,offset+local_offset+icecandidates_offset + icecandidate_offset, 1, -1);

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
      case CANDTYPE_PRFLX:
      case CANDTYPE_RELAY:
        item_index = hf_reload_icecandidate_relay_addr;
        break;

      default:
        break;
      }
      if (item_index != -1) {
        dissect_ipaddressport(item_index,tvb, icecandidate_tree,
                              offset+local_offset+icecandidates_offset+icecandidate_offset);
        icecandidate_offset += computed_ipaddressport_length + 2;
      }
    }
    /* Ice extensions */
    {
      guint16 iceextensions_offset = 0;
      proto_item *ti_iceextension, *ti_extensions;
      proto_tree *iceextension_tree,*extensions_tree;
      guint16 iceextension_name_length;
      guint16 iceextension_value_length;
      int nExtensions = 0;
      ti_extensions =
        proto_tree_add_item(icecandidate_tree, hf_reload_iceextensions, tvb,
                            offset+local_offset+icecandidates_offset+icecandidate_offset, 2+iceextensions_length,
                            ENC_NA);
      proto_item_append_text(ti_extensions, " (IceExtensions<%d>)", iceextensions_length);
      extensions_tree = proto_item_add_subtree(ti_extensions, ett_reload_iceextensions);

      proto_tree_add_item(extensions_tree, hf_reload_length_uint16, tvb,
                          offset+local_offset+icecandidates_offset+icecandidate_offset, 2, ENC_BIG_ENDIAN);
      icecandidate_offset += 2;
      while (iceextensions_offset < iceextensions_length) {
        int local_increment;
        iceextension_name_length =
          tvb_get_ntohs(tvb, offset+local_offset+icecandidates_offset+icecandidate_offset+iceextensions_offset);
        iceextension_value_length =
          tvb_get_ntohs(tvb, offset+local_offset+icecandidates_offset+icecandidate_offset+iceextensions_offset+iceextension_name_length + 2);
        if ((iceextensions_offset + 4 + iceextension_name_length + iceextension_value_length) > iceextensions_length) {
          expert_add_info_format(pinfo, ti_extensions, PI_PROTOCOL, PI_ERROR, "Truncated extensions");
          break;
        }
        ti_iceextension =
          proto_tree_add_item(extensions_tree, hf_reload_iceextension, tvb,
                              offset+local_offset + icecandidates_offset + icecandidate_offset + iceextensions_offset, 4 + iceextension_name_length + iceextension_value_length, ENC_NA);
        iceextension_tree = proto_item_add_subtree(ti_iceextension, ett_reload_iceextension);
        dissect_opaque(tvb, pinfo, iceextension_tree, hf_reload_iceextension_name,offset+local_offset+ icecandidates_offset + icecandidate_offset + iceextensions_offset, 2, iceextension_name_length+2);
        dissect_opaque(tvb, pinfo, iceextension_tree, hf_reload_iceextension_value,offset+local_offset + icecandidates_offset + icecandidate_offset + iceextensions_offset +2 + iceextension_name_length, 2, iceextension_value_length+2);
        local_increment = 4 + iceextension_name_length + iceextension_value_length;
        if (local_increment <= 0) break;
        iceextensions_offset += local_increment;
        nExtensions++;
      }
      proto_item_append_text(ti_extensions, ": %d elements", nExtensions);
    }
    icecandidate_offset += iceextensions_length;
    if (icecandidate_offset <= 0) break;
    icecandidates_offset += icecandidate_offset;
    nCandidates++;
  }
  proto_item_append_text(ti_icecandidates, ": %d elements", nCandidates);

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
  local_offset += dissect_opaque_string(tvb, pinfo,attachreqans_tree, hf_reload_ufrag,offset+local_offset, 1, -1);
  local_offset += dissect_opaque_string(tvb, pinfo,attachreqans_tree, hf_reload_password,offset+local_offset, 1, -1);
  local_offset += dissect_opaque_string(tvb, pinfo,attachreqans_tree, hf_reload_role,offset+local_offset, 1, -1);
  local_offset += dissect_icecandidates(tvb, pinfo, attachreqans_tree, offset + local_offset, 2+icecandidates_length);

  proto_tree_add_item(attachreqans_tree, hf_reload_sendupdate, tvb, offset+local_offset, 1, ENC_BIG_ENDIAN);
  local_offset += 1;

  return local_offset;
}


static int
dissect_sipregistration(tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local, *ti_sipregistrationdata;
  proto_tree *local_tree, *sipregistrationdata_tree;
  int local_offset = 0;
  guint16 length_field;
  guint8 type;

  ti_local = proto_tree_add_item(tree, hf_reload_sipregistration, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_sipregistration);

  type = tvb_get_guint8(tvb, offset + local_offset);
  proto_tree_add_item(local_tree, hf_reload_sipregistration_type, tvb,offset+local_offset,1, ENC_BIG_ENDIAN);
  local_offset +=1;
  length_field = tvb_get_ntohs(tvb, offset+local_offset);
  proto_tree_add_item(local_tree, hf_reload_length_uint16, tvb,offset+local_offset,2, ENC_BIG_ENDIAN);
  local_offset +=2;
  if (length_field>0) {
    ti_sipregistrationdata = proto_tree_add_item(local_tree, hf_reload_sipregistration_data, tvb, offset, length_field, ENC_NA);
    sipregistrationdata_tree = proto_item_add_subtree(ti_sipregistrationdata, ett_reload_sipregistration_data);

    switch(type) {
    case SIPREGISTRATIONTYPE_URI:
      dissect_opaque_string(tvb,pinfo, sipregistrationdata_tree, hf_reload_sipregistration_data_uri, offset+local_offset, 2, length_field);
      break;

    case SIPREGISTRATIONTYPE_ROUTE:
    {
      guint16 route_offset = 0;
      guint16 destinations_length;
      int numDestinations=0;
      proto_item * ti_destination_list;
      proto_tree *destination_list_tree;
      route_offset += dissect_opaque_string(tvb,pinfo, sipregistrationdata_tree, hf_reload_sipregistration_data_contact_prefs, offset+local_offset, 2, length_field);
      destinations_length = (guint16) get_opaque_length(tvb, offset+local_offset+route_offset, 2);
      ti_destination_list = proto_tree_add_item(sipregistrationdata_tree, hf_reload_sipregistration_data_destination_list, tvb,offset+local_offset+route_offset, length_field-route_offset, ENC_NA);
      destination_list_tree = proto_item_add_subtree(ti_destination_list, ett_reload_sipregistration_destination_list);
      proto_tree_add_item(destination_list_tree, hf_reload_length_uint16, tvb,offset+local_offset+route_offset, 2, ENC_BIG_ENDIAN);
      route_offset+=2;
      if (destinations_length>0) {
        dissect_destination_list(tvb, pinfo, destination_list_tree, offset+local_offset+route_offset,destinations_length, &numDestinations);
      }
      proto_item_append_text(ti_destination_list, " (Destination<%d>): %d elements", destinations_length,numDestinations);
    }
    break;
    }
  }
  local_offset += length_field;

  return local_offset;
}

static int
dissect_turnserver(tvbuff_t *tvb, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  int local_offset = 0;

  ti_local = proto_tree_add_item(tree, hf_reload_turnserver, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_turnserver);

  proto_tree_add_item(local_tree, hf_reload_turnserver_iteration, tvb,offset,1, ENC_BIG_ENDIAN);
  local_offset +=1;
  local_offset += dissect_ipaddressport(hf_reload_turnserver_server_address,tvb, local_tree, offset+local_offset);

  return local_offset;
}

static int dissect_redirserviceproviderdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  int local_offset = 0;

  ti_local = proto_tree_add_item(tree, hf_reload_redirserviceproviderdata, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_redirserviceproviderdata);

  local_offset += dissect_nodeid(hf_reload_redirserviceproviderdata_serviceprovider, tvb, pinfo, local_tree, offset+local_offset, length);
  local_offset += dissect_opaque_string(tvb, pinfo, local_tree, hf_reload_redirserviceproviderdata_namespace, offset+local_offset, 2, length-local_offset);
  proto_tree_add_item(local_tree, hf_reload_redirserviceproviderdata_level, tvb, offset+local_offset, 2, ENC_BIG_ENDIAN);
  local_offset += 2;
  proto_tree_add_item(local_tree, hf_reload_redirserviceproviderdata_node, tvb, offset+local_offset, 2, ENC_BIG_ENDIAN);

  return length;
}

static int dissect_redirserviceprovider(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  int local_offset = 0;
  guint16 length_field;

  length_field = tvb_get_ntohs(tvb, offset);

  if (2+length_field>length) {
    ti_local = proto_tree_add_item(tree, hf_reload_redirserviceprovider, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_local, PI_PROTOCOL, PI_ERROR, "Truncated RedirServiceProvider");
    return length;
  }

  ti_local = proto_tree_add_item(tree, hf_reload_redirserviceprovider, tvb, offset, length_field+2, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_redirserviceprovider);

  proto_tree_add_item(local_tree,  hf_reload_length_uint16, tvb, offset,2, ENC_BIG_ENDIAN);
  local_offset+=2;

  local_offset += dissect_redirserviceproviderdata(tvb, pinfo, local_tree, offset+local_offset, length_field);

  return (2+length_field);
}

static int dissect_datavalue(int anchor, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length, gboolean meta, kind_t *kind) {
  proto_item *ti_datavalue;
  proto_tree *datavalue_tree;
  if (meta != TRUE) {
    int value_length = get_opaque_length(tvb,offset+1,4);
    int hf = hf_reload_datavalue;

    if (anchor >= 0) {
      hf = anchor;
    }

    if (1+4+value_length > length) {
      ti_datavalue = proto_tree_add_item(tree, hf, tvb, offset, length, FALSE);
      expert_add_info_format(pinfo, ti_datavalue, PI_PROTOCOL, PI_ERROR, "Truncated DataValue");
      return length;
    }

    ti_datavalue = proto_tree_add_item(tree,  hf, tvb, offset,1+4+value_length, FALSE);
    datavalue_tree = proto_item_add_subtree(ti_datavalue,ett_reload_datavalue);
    proto_tree_add_item(datavalue_tree, hf_reload_datavalue_exists, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (kind != NULL) {
      switch(kind->id) {

      case DATAKINDID_TURNSERVICE:
      {
        guint32 length_field = tvb_get_ntohl(tvb, offset+1);
        proto_tree_add_item(datavalue_tree,  hf_reload_length_uint32, tvb, offset+1,4, ENC_BIG_ENDIAN);
        if (length_field>0) {
          dissect_turnserver(tvb, datavalue_tree, offset+1+4, length_field);
        }
      }
      break;

      case DATAKINDID_SIP_REGISTRATION:
      {
        guint32 length_field = tvb_get_ntohl(tvb, offset+1);
        proto_tree_add_item(datavalue_tree,  hf_reload_length_uint32, tvb, offset+1,4, ENC_BIG_ENDIAN);
        if (length_field>0) {
          dissect_sipregistration(tvb, pinfo, datavalue_tree, offset+1+4, length_field);
        }
      }
      break;

      case DATAKINDID_CERTIFICATE_BY_NODE:
      case DATAKINDID_CERTIFICATE_BY_USER:
      {
        guint32 length_field = tvb_get_ntohl(tvb, offset+1);
        proto_tree_add_item(datavalue_tree,  hf_reload_length_uint32, tvb, offset+1,4, ENC_BIG_ENDIAN);
        if (length_field>0) {
          asn1_ctx_t asn1_ctx;

          asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
          dissect_x509af_Certificate(FALSE, tvb, offset + 1 + 4, &asn1_ctx,
                                     datavalue_tree, hf_reload_certificate);
        }
      }
      break;

      case DATAKINDID_REDIR:
      {
        guint32 length_field = tvb_get_ntohl(tvb, offset+1);
        proto_tree_add_item(datavalue_tree,  hf_reload_length_uint32, tvb, offset+1,4, ENC_BIG_ENDIAN);
        if (length_field>0) {
          dissect_redirserviceprovider(tvb, pinfo, datavalue_tree, offset+1+4, length_field);
        }
      }
      break;

      default:
        dissect_opaque(tvb, pinfo, datavalue_tree, hf_reload_datavalue_value, offset +1, 4, length-1);
        break;
      }
    }
    else {
      dissect_opaque(tvb, pinfo, datavalue_tree, hf_reload_datavalue_value, offset +1, 4, length-1);
    }
    if (hf == anchor) {
      proto_item_append_text(ti_datavalue, " (DataValue)");
    }
    return (1+4+value_length);
  }
  else {
    /* meta data */
    int hash_length = get_opaque_length(tvb, offset +1+4+1,1);
    int hf = hf_reload_metadata;

    if (anchor >= 0) {
      hf = anchor;
    }


    if (1+4+1+1+hash_length > length) {
      ti_datavalue = proto_tree_add_item(tree, hf, tvb, offset, length, FALSE);
      expert_add_info_format(pinfo, ti_datavalue, PI_PROTOCOL, PI_ERROR, "Truncated MetaData");
      return length;
    }

    ti_datavalue = proto_tree_add_item(tree,  hf, tvb, offset,1+4+1+1+hash_length, FALSE);
    datavalue_tree = proto_item_add_subtree(ti_datavalue,ett_reload_datavalue);
    proto_tree_add_item(datavalue_tree, hf_reload_datavalue_exists, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(datavalue_tree, hf_reload_metadata_value_length, tvb, offset+1, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(datavalue_tree, hf_reload_hash_algorithm, tvb, offset+1+4, 1, ENC_BIG_ENDIAN);
    dissect_opaque(tvb, pinfo, datavalue_tree, hf_reload_metadata_hash_value, offset +1+4+1, 1, length-1-4-1);

    if (hf == anchor) {
      proto_item_append_text(ti_datavalue, " (MetaData)");
    }

    return (1+4+1+hash_length);
  }
  return 0;
}

static int getDataValueLength(tvbuff_t *tvb, guint16 offset, gboolean meta) {
  if (meta!=TRUE) {
    int value_length = get_opaque_length(tvb,offset+1,4);
    return (1+4+value_length);
  }
  else {
    int hash_length = get_opaque_length(tvb, offset +1+4+1,1);
    return (1+4+1+1+hash_length);
  }
  return 0;
}

static int dissect_arrayentry(int anchor, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length, gboolean meta, kind_t *kind) {
  proto_item *ti_arrayentry, *ti_index;
  proto_tree *arrayentry_tree;
  int data_length = getDataValueLength(tvb, offset+4, meta);
  int hf = hf_reload_arrayentry;

  if (anchor>=0) {
    hf = anchor;
  }

  if (4+data_length > length) {
    ti_arrayentry = proto_tree_add_item(tree, hf, tvb, offset, length, FALSE);
    expert_add_info_format(pinfo, ti_arrayentry, PI_PROTOCOL, PI_ERROR, "Truncated ArrayEntry");
    return length;
  }

  ti_arrayentry = proto_tree_add_item(tree,  hf, tvb, offset,4+data_length, FALSE);
  arrayentry_tree = proto_item_add_subtree(ti_arrayentry,ett_reload_arrayentry);
  ti_index = proto_tree_add_item(arrayentry_tree, hf_reload_arrayentry_index, tvb, offset, 4, ENC_BIG_ENDIAN);
  if (0xffffffff == (guint32) tvb_get_ntohl(tvb, offset)) {
    proto_item_append_text(ti_index, "(append)");
  }
  dissect_datavalue(hf_reload_arrayentry_value,tvb, pinfo, arrayentry_tree, offset+4, length-4, meta, kind);

  if (hf==anchor) {
    proto_item_append_text(ti_arrayentry, " (ArrayEntry)");
  }

  return (4+data_length);
}

static int dissect_dictionaryentry(int anchor, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length, gboolean meta, kind_t *kind) {
  proto_item *ti_dictionaryentry;
  proto_tree *dictionaryentry_tree;
  int local_offset = 0;
  guint16 key_length=0;
  int hf = hf_reload_dictionaryentry;

  if (anchor>=0) {
    hf = anchor;
  }

  if (length < 2) {
    ti_dictionaryentry = proto_tree_add_item(tree, hf, tvb, offset, length, FALSE);
    expert_add_info_format(pinfo, ti_dictionaryentry, PI_PROTOCOL, PI_ERROR, "Truncated ArrayEntry");
    return length;
  }
  key_length = get_opaque_length(tvb,offset,2);


  if (length < (key_length +2)) {
    ti_dictionaryentry = proto_tree_add_item(tree, hf, tvb, offset, length, FALSE);
    expert_add_info_format(pinfo, ti_dictionaryentry, PI_PROTOCOL, PI_ERROR, "Truncated ArrayEntry");
    return length;
  }

  {
    int data_length = getDataValueLength(tvb, offset+2+key_length, meta);
    if (length < (key_length+2+data_length)) {
      ti_dictionaryentry = proto_tree_add_item(tree, hf, tvb, offset, length, FALSE);
    }
    else {
      ti_dictionaryentry = proto_tree_add_item(tree, hf, tvb, offset, 2+key_length+1+4+data_length, FALSE);
    }
  }


  dictionaryentry_tree = proto_item_add_subtree(ti_dictionaryentry,ett_reload_dictionaryentry);

  if (hf==anchor) {
    proto_item_append_text(ti_dictionaryentry, " (DictionaryEntry)");
  }

  if (kind != NULL) {
    switch(kind->id) {
    case DATAKINDID_SIP_REGISTRATION:
    case DATAKINDID_REDIR:
    {
      proto_item *ti_key;
      proto_tree *key_tree;
      ti_key = proto_tree_add_item(dictionaryentry_tree, hf_reload_dictionarykey, tvb, offset, 2+key_length, ENC_NA);
      key_tree = proto_item_add_subtree(ti_key,ett_reload_dictionaryentry_key);
      proto_tree_add_item(key_tree, hf_reload_length_uint16, tvb, offset, 2, ENC_BIG_ENDIAN);
      local_offset+=2;
      local_offset+= dissect_nodeid(-1, tvb, pinfo, key_tree, offset+2, key_length);
    }
    break;

    default:
      local_offset += dissect_opaque(tvb, pinfo, dictionaryentry_tree, hf_reload_dictionarykey, offset, 2, length);
      break;
    }
  }
  else {
    local_offset +=
      dissect_opaque(tvb, pinfo, dictionaryentry_tree, hf_reload_dictionarykey, offset, 2, length);
  }

  local_offset += dissect_datavalue(hf_reload_dictionary_value,tvb, pinfo, dictionaryentry_tree, offset+local_offset, length-local_offset, meta, kind);

  return (local_offset);
}

static int
dissect_signature(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset)
{
  int local_offset = 0;
  proto_item *ti_signature;
  proto_tree *signature_tree;
  guint16 signeridentityvalue_length;
  guint16 signaturevalue_length;


  signeridentityvalue_length = tvb_get_ntohs(tvb, offset +2+1);
  signaturevalue_length = tvb_get_ntohs(tvb, offset + 2 + 1 + 2+ signeridentityvalue_length);
  ti_signature = proto_tree_add_item(tree,
                                     hf_reload_signature, tvb, offset,
                                     2 +/* SignatureAndHashAlgorithm */
                                     1 + 2 + signeridentityvalue_length +/* SignatureIdenty length*/
                                     2 + signaturevalue_length,
                                     ENC_NA);

  signature_tree = proto_item_add_subtree(ti_signature, ett_reload_signature);

  {
    proto_item *ti_signatureandhashalgorithm;
    proto_tree *signatureandhashalgorithm_tree;
    ti_signatureandhashalgorithm = proto_tree_add_item(signature_tree, hf_reload_signatureandhashalgorithm, tvb, offset, 2, ENC_NA);
    signatureandhashalgorithm_tree = proto_item_add_subtree( ti_signatureandhashalgorithm, ett_reload_signatureandhashalgorithm);
    proto_tree_add_item(signatureandhashalgorithm_tree, hf_reload_hash_algorithm, tvb, offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_item(signatureandhashalgorithm_tree, hf_reload_signature_algorithm, tvb, offset + local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
  }
  /* Signeridentity */
  {
    proto_item *ti_signeridentity;
    proto_tree *signeridentity_tree;
    guint8 identity_type;
    ti_signeridentity = proto_tree_add_item(signature_tree,
                                            hf_reload_signeridentity,
                                            tvb, offset+local_offset,
                                            1 + 2 + signeridentityvalue_length,
                                            ENC_NA);
    signeridentity_tree = proto_item_add_subtree(ti_signeridentity, ett_reload_signeridentity);
    identity_type = tvb_get_guint8(tvb, offset + local_offset);
    proto_tree_add_item(signeridentity_tree, hf_reload_signeridentity_type, tvb,
                        offset + local_offset, 1, ENC_BIG_ENDIAN);
    local_offset += 1;
    proto_tree_add_uint(signeridentity_tree, hf_reload_length_uint16, tvb,
                        offset + local_offset, 2, signeridentityvalue_length);
    local_offset += 2;
    {
      proto_item *ti_signeridentity_identity;
      proto_tree * signeridentity_identity_tree;
      ti_signeridentity_identity = proto_tree_add_item(signeridentity_tree,
                                   hf_reload_signeridentity_identity,
                                   tvb, offset+local_offset,
                                   signeridentityvalue_length,
                                   ENC_NA);
      signeridentity_identity_tree = proto_item_add_subtree(ti_signeridentity_identity, ett_reload_signeridentity_identity);
      proto_item_append_text(ti_signeridentity_identity, " (SignerIdentityValue[%d])",signeridentityvalue_length);
      {
        proto_item *ti_signeridentityvalue;
        proto_tree *signeridentityvalue_tree;
        if (identity_type == SIGNERIDENTITYTYPE_CERTHASH || identity_type == SIGNERIDENTITYTYPE_CERTHASHNODEID) {
          guint8 certificate_hash_length;

          certificate_hash_length = tvb_get_guint8(tvb, offset + local_offset + 1);
          if (1 + 1 + certificate_hash_length > signeridentityvalue_length) {
            expert_add_info_format(pinfo, ti_signeridentity, PI_PROTOCOL, PI_ERROR, "Truncated signature identity value");
          }
          else {
            ti_signeridentityvalue= proto_tree_add_item(signeridentity_identity_tree,
                                    hf_reload_signeridentity_value,
                                    tvb, offset + local_offset,
                                    1 + 1 + certificate_hash_length,
                                    ENC_NA);
            signeridentityvalue_tree = proto_item_add_subtree(ti_signeridentityvalue, ett_reload_signeridentity_value);
            proto_tree_add_item(signeridentityvalue_tree, hf_reload_signeridentity_value_hash_alg, tvb,
                                offset + local_offset, 1, ENC_BIG_ENDIAN);
            dissect_opaque(tvb, pinfo, signeridentityvalue_tree,
                           (identity_type == SIGNERIDENTITYTYPE_CERTHASH) ?
                           hf_reload_signeridentity_value_certificate_hash:
                           hf_reload_signeridentity_value_certificate_node_id_hash,
                           offset + local_offset +1, 1, -1);
          }
        }
        else {
          expert_add_info_format(pinfo, signeridentity_identity_tree, PI_PROTOCOL, PI_ERROR, "Unknown identity type");
        }
      }
    }
    local_offset += signeridentityvalue_length;
  }
  local_offset +=dissect_opaque(tvb, pinfo, signature_tree, hf_reload_signature_value, offset + local_offset, 2, -1);

  return local_offset;

}


static int
dissect_storeddata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length, kind_t *kind, gboolean meta)
{
  proto_item *ti_storeddata;
  proto_tree *storeddata_tree;
  guint32 storeddata_length;
  guint32 local_offset = 0;

  int hf =  hf_reload_storeddata;

  if (meta == TRUE) {
    hf = hf_reload_storedmetadata;
  }

  storeddata_length = tvb_get_ntohl(tvb, offset);
  local_offset += 4;

  if (storeddata_length + 4 > length) {
    ti_storeddata = proto_tree_add_item(tree, hf, tvb, offset, length, FALSE);
    expert_add_info_format(pinfo, ti_storeddata, PI_PROTOCOL, PI_ERROR, "Truncated StoredData");
    return length;
  }

  local_offset = 0;
  ti_storeddata = proto_tree_add_item(tree, hf, tvb, offset, 4 + storeddata_length, FALSE);
  storeddata_tree = proto_item_add_subtree(ti_storeddata, ett_reload_storeddata);

  proto_tree_add_uint(storeddata_tree, hf_reload_length_uint32, tvb, offset + local_offset, 4, storeddata_length);
  local_offset += 4;
  {
    guint64 storage_time;
    guint32 remaining_ms;
    time_t storage_time_sec;
    nstime_t l_nsTime;

    storage_time = tvb_get_ntoh64(tvb, offset+local_offset);
    storage_time_sec = (time_t)(storage_time/1000);
    remaining_ms = (guint32) (storage_time % 1000);

    l_nsTime.secs = storage_time_sec;
    l_nsTime.nsecs =  remaining_ms*1000*1000;

    proto_tree_add_time(storeddata_tree, hf_reload_storeddata_storage_time, tvb, offset + local_offset, 8, &l_nsTime);
  }
  local_offset += 8;
  proto_tree_add_item(storeddata_tree, hf_reload_storeddata_lifetime, tvb, offset + local_offset, 4, ENC_BIG_ENDIAN);
  local_offset +=4;
  if ((NULL != kind) && (kind->id != DATAKINDID_INVALID)) {
    switch(kind->data_model) {
    case DATAMODEL_SINGLE:
      local_offset += dissect_datavalue(hf_reload_value,tvb, pinfo, storeddata_tree, offset+local_offset, (storeddata_length-local_offset+4), meta, kind);
      break;
    case DATAMODEL_ARRAY:
      local_offset +=  dissect_arrayentry(hf_reload_value,tvb, pinfo, storeddata_tree, offset+local_offset, (storeddata_length-local_offset+4), meta, kind);
      break;
    case DATAMODEL_DICTIONARY:
      local_offset += dissect_dictionaryentry(hf_reload_value,tvb, pinfo, storeddata_tree, offset+local_offset, (storeddata_length-local_offset+4), meta, kind);
      break;
    default:
      expert_add_info_format(pinfo, ti_storeddata, PI_PROTOCOL, PI_ERROR, "Unknown Data Model");
      return  (storeddata_length + 4);
    }
    if (TRUE != meta) {
      dissect_signature(tvb, pinfo, storeddata_tree, offset +local_offset);
    }
  }
  return (storeddata_length + 4);
}



static int
dissect_kindid(int anchor, tvbuff_t *tvb, proto_tree *tree, guint16 offset, kind_t **kind)
{
  proto_item *ti_kindid;
  guint32 kindid = 0;
  int hf = hf_reload_kindid;

  if (anchor>=0) {
    hf = anchor;
  }

  *kind=NULL;

  kindid = tvb_get_ntohl(tvb, offset);
  *kind = getKindFromId(kindid);
  ti_kindid = proto_tree_add_item(tree, hf, tvb, offset, 4, FALSE);
  if ((NULL != (*kind)) && ((*kind)->name != NULL)) {
    proto_item_append_text(ti_kindid, " (%s)", (*kind)->name);
  }

  return 4;
}

static int
dissect_kinddata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length, gboolean meta)
{
  proto_item *ti_kinddata;
  proto_item *kinddata_tree;
  guint32 values_length;
  guint32 local_offset = 0;
  kind_t *kind;
  int hf = hf_reload_kinddata;
  int nValues = 0;

  if (meta) {
    hf = hf_reload_statkindresponse;
  }

  values_length = tvb_get_ntohl(tvb, offset + 4 + 8);
  if (12 + values_length > length) {
    ti_kinddata = proto_tree_add_item(tree, hf, tvb, offset, length, FALSE);
    expert_add_info_format(pinfo, ti_kinddata, PI_PROTOCOL, PI_ERROR, "Truncated kind data");
    return length;
  }
  ti_kinddata = proto_tree_add_item(tree, hf, tvb, offset, 16+values_length, FALSE);
  kinddata_tree = proto_item_add_subtree(ti_kinddata, ett_reload_kinddata);

  local_offset += dissect_kindid(hf_reload_kinddata_kind,tvb, kinddata_tree, offset+local_offset, &kind);

  proto_tree_add_item(kinddata_tree, hf_reload_generation_counter, tvb, offset+local_offset, 8, ENC_BIG_ENDIAN);
  local_offset += 8;
  {
    guint32 values_offset = 0;
    guint32 values_increment;
    proto_item *ti_values;
    proto_tree *values_tree;

    ti_values = proto_tree_add_item(kinddata_tree, hf_reload_values, tvb, offset+local_offset, 4+values_length, ENC_NA);
    values_tree = proto_item_add_subtree(ti_values, ett_reload_values);
    if (meta) {
      proto_item_append_text(ti_values, " (StoredMetaData<%d>)", values_length);
    } else {
      proto_item_append_text(ti_values, " (StoredData<%d>)", values_length);
    }

    proto_tree_add_uint(values_tree, hf_reload_length_uint32, tvb, offset +local_offset, 4, values_length);
    local_offset += 4;

    while (values_offset < values_length) {
      values_increment = dissect_storeddata(tvb, pinfo, values_tree, offset+local_offset+values_offset, values_length - values_offset, kind, meta);
      if (values_increment == 0) {
        break;
      }
      nValues++;
      values_offset += values_increment;
    }
    proto_item_append_text(ti_values, ": %d elements", nValues);
  }

  local_offset += values_length;
  return local_offset;
}

static int dissect_nodeid_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length, int hf, int length_size)
{
  guint16 list_length;
  guint16 local_offset = 0;
  guint16 list_offset = 0;
  guint16 list_increment = 0;
  int nNodeIds=0;
  proto_item *ti_local;
  proto_tree *local_tree;

  list_length= (guint16) get_opaque_length(tvb, offset, length_size);

  if (list_length+length_size>length) {
    ti_local = proto_tree_add_item(tree, hf, tvb, offset, length, FALSE);
    expert_add_info_format(pinfo, ti_local, PI_PROTOCOL, PI_ERROR, "Truncated NodeId list");
  }
  ti_local = proto_tree_add_item(tree, hf, tvb, offset,  list_length+length_size, FALSE);
  proto_item_append_text(ti_local, " (NodeId<%d>)", list_length);

  local_tree =  proto_item_add_subtree(ti_local, ett_reload_nodeid_list);

  local_offset += dissect_length(tvb, local_tree, offset, length_size);
  while (list_offset < list_length) {
    dissect_nodeid(-1, tvb, pinfo, local_tree, offset+local_offset+list_offset,list_length-list_offset);
    list_increment = reload_nodeid_length;
    if (list_increment <= 0) break;
    list_offset += list_increment;
    nNodeIds++;
  }
  proto_item_append_text(ti_local, ":%d elements", nNodeIds);

  return (list_length+length_size);
}


static int
dissect_storekindresponse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16 local_offset = 0;
  guint16 local_length = 0;
  guint16 replicas_length;
  kind_t *kind;

  replicas_length = tvb_get_ntohs(tvb, offset+4+8);
  local_length = 4+8+2+replicas_length;

  if (length < local_length) {
    ti_local = proto_tree_add_item(tree, hf_reload_storekindresponse, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_local, PI_PROTOCOL, PI_ERROR, "Truncated StoreKindResponse");
    return length;
  }
  ti_local = proto_tree_add_item(tree, hf_reload_storekindresponse, tvb, offset,  4+8+2+replicas_length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_storekindresponse);

  local_offset += dissect_kindid(hf_reload_kinddata_kind,tvb, local_tree, offset+local_offset, &kind);
  proto_tree_add_item(local_tree, hf_reload_generation_counter, tvb, offset+local_offset, 8, ENC_BIG_ENDIAN);
  local_offset += 8;
  local_offset += dissect_nodeid_list(tvb, pinfo, local_tree, offset+local_offset, local_length-local_offset, hf_reload_replicas, 2);

  return local_offset;
}

static int
dissect_storeans(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local, *ti_kind_responses;
  proto_tree *local_tree, *kind_responses_tree;
  guint16 local_offset = 0;
  guint16 kind_responses_length;
  guint16 kind_responses_offset=0;
  int nKindResponses=0;

  ti_local = proto_tree_add_item(tree, hf_reload_storeans, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_storeans);
  kind_responses_length = tvb_get_ntohs(tvb, offset);
  ti_kind_responses = proto_tree_add_item(local_tree, hf_reload_storeans_kind_responses, tvb, offset, 2+kind_responses_length, ENC_NA);
  kind_responses_tree = proto_item_add_subtree(ti_kind_responses, ett_reload_storeans_kind_responses);
  proto_item_append_text(ti_kind_responses, " (StoreKindResponse<%d>)", kind_responses_length);

  proto_tree_add_item(kind_responses_tree, hf_reload_length_uint16, tvb, offset, 2, ENC_BIG_ENDIAN);
  local_offset +=2;
  while (kind_responses_offset < kind_responses_length) {
    int local_increment = dissect_storekindresponse(tvb, pinfo, kind_responses_tree, offset+local_offset+kind_responses_offset, kind_responses_length-kind_responses_offset);
    if (local_increment<=0) break;
    kind_responses_offset += local_increment;
    nKindResponses++;
  }
  local_offset += kind_responses_length;
  proto_item_append_text(ti_kind_responses, ": %d elements", nKindResponses);

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
    expert_add_info_format(pinfo, ti_storereq, PI_PROTOCOL, PI_ERROR, "Truncated StoreReq: resource too long");
    return length;
  }

  local_offset += 1; /* replica_num */
  if (local_offset > length) {
    ti_storereq = proto_tree_add_item(tree, hf_reload_storereq, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_storereq, PI_PROTOCOL, PI_ERROR, "Truncated StoreReq: no room for replica_number");
    return length;
  }

  kind_data_length = tvb_get_ntohl(tvb, offset + local_offset);
  local_offset += 4;
  if (local_offset + kind_data_length > length) {
    ti_storereq = proto_tree_add_item(tree, hf_reload_storereq, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_storereq, PI_PROTOCOL, PI_ERROR, "Truncated StoreReq: kind_data too long");
    return length;
  }
  local_offset += kind_data_length;

  ti_storereq = proto_tree_add_item(tree, hf_reload_storereq, tvb, offset, local_offset, ENC_NA);
  storereq_tree = proto_item_add_subtree(ti_storereq, ett_reload_storereq);

  /* Parse from start */
  local_offset = 0;
  local_offset += dissect_resourceid(hf_reload_resource, tvb, pinfo, storereq_tree, offset+local_offset, length);

  proto_tree_add_item(storereq_tree, hf_reload_store_replica_num, tvb, offset + local_offset, 1, ENC_BIG_ENDIAN);
  local_offset += 1;


  {
    guint32 kind_data_offset = 0;
    guint32 kind_data_increment;
    proto_item *ti_kind_data;
    proto_tree *kind_data_tree;
    int nKindDatas=0;

    ti_kind_data = proto_tree_add_item(storereq_tree, hf_reload_store_kind_data, tvb, offset+local_offset,4+kind_data_length, ENC_NA);
    proto_item_append_text(ti_kind_data, " (StoreKindData<%d>)", kind_data_length);
    kind_data_tree = proto_item_add_subtree(ti_kind_data, ett_reload_store_kind_data);
    proto_tree_add_item(kind_data_tree, hf_reload_length_uint32, tvb, offset + local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;

    while (kind_data_offset < kind_data_length) {
      kind_data_increment = dissect_kinddata(tvb, pinfo, kind_data_tree, offset+local_offset+kind_data_offset, kind_data_length - kind_data_offset, FALSE);
      if (kind_data_increment == 0) {
        break;
      }
      nKindDatas++;
      kind_data_offset += kind_data_increment;
    }

    proto_item_append_text(ti_kind_data, ": %d elements", nKindDatas);
  }
  local_offset += kind_data_length;

  return local_offset;
}

static int dissect_arrayrange(tvbuff_t *tvb, proto_tree *tree, guint16 offset) {
  proto_item *ti;
  gint32 first;
  gint32 last;

  ti = proto_tree_add_item(tree, hf_reload_arrayrange, tvb, offset, (16), ENC_NA);
  first =  tvb_get_ntohl(tvb, offset);
  last  =  tvb_get_ntohl(tvb, offset+4);

  proto_item_append_text(ti, " [%d-", first);
  if ((guint32)last != 0xFFFFFFFF) {
    proto_item_append_text(ti, "%d]", last);
  }
  else {
    proto_item_append_text(ti, "end]");
  }
  return 8;

}
static int
dissect_storeddataspecifier(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  guint16 length_field, local_offset=0;
  proto_item *ti_storeddataspecifier;
  proto_tree *storeddataspecifier_tree;
  kind_t *kind=NULL;

  length_field = tvb_get_ntohs(tvb, offset+4+8);
  if ((length_field + 4 + 8 + 2) > length) {
    ti_storeddataspecifier = proto_tree_add_item(tree, hf_reload_storeddataspecifier, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_storeddataspecifier, PI_PROTOCOL, PI_ERROR, "Truncated StoredDataSpecifier");
    return length;
  }

  ti_storeddataspecifier = proto_tree_add_item(tree, hf_reload_storeddataspecifier, tvb, offset, (length_field + 4 + 8 +2), ENC_NA);
  storeddataspecifier_tree = proto_item_add_subtree(ti_storeddataspecifier, ett_reload_storeddataspecifier);

  local_offset += dissect_kindid(hf_reload_kinddata_kind,tvb,storeddataspecifier_tree, offset, &kind);
  proto_tree_add_item(storeddataspecifier_tree, hf_reload_generation_counter, tvb, offset+local_offset, 8, ENC_BIG_ENDIAN);
  local_offset += 8;
  proto_tree_add_item(storeddataspecifier_tree, hf_reload_length_uint16, tvb, offset+local_offset, 2, ENC_BIG_ENDIAN);
  local_offset += 2;

  if ((kind != NULL) && (kind->id != DATAKINDID_INVALID)) {
    switch(kind->data_model) {
    case DATAMODEL_ARRAY:
    {
      proto_item *ti_indices;
      proto_tree *indices_tree;
      guint16 indices_offset =0;
      guint16 indices_length = tvb_get_ntohs(tvb, offset+local_offset);
      int nIndices=0;
      ti_indices = proto_tree_add_item(storeddataspecifier_tree, hf_reload_storeddataspecifier_indices, tvb, offset+local_offset, 2+indices_length, ENC_NA);
      proto_item_append_text(ti_indices, " (ArrayRange<%d>)", indices_length);
      indices_tree =  proto_item_add_subtree(ti_indices, ett_reload_storeddataspecifier_indices);
      proto_tree_add_item(indices_tree, hf_reload_length_uint16, tvb, offset+local_offset, 2, ENC_BIG_ENDIAN);
      local_offset += 2;
      while (indices_offset < indices_length) {
        indices_offset += dissect_arrayrange(tvb, indices_tree, offset + local_offset + indices_offset);
        nIndices++;
      }
      local_offset += indices_length;
      proto_item_append_text(ti_indices, ": %d elements", nIndices);
    }
    break;

    case DATAMODEL_DICTIONARY:
    {
      proto_item *ti_keys;
      proto_tree *keys_tree;
      guint16 keys_offset =0;
      guint16 keys_length = tvb_get_ntohs(tvb, offset+local_offset);
      int nKeys=0;
      ti_keys = proto_tree_add_item(tree, hf_reload_storeddataspecifier_keys, tvb, offset+local_offset, 2+keys_length, ENC_NA);
      keys_tree =  proto_item_add_subtree(ti_keys, ett_reload_storeddataspecifier_keys);
      local_offset += 2;
      while (keys_offset < keys_length) {
        guint32 local_increment;
        local_increment = dissect_opaque(tvb, pinfo, keys_tree, hf_reload_dictionarykey, offset, 2, keys_length-keys_offset);
        if (local_increment==0) break;
        keys_offset += local_increment;
        nKeys++;
      }
      local_offset += keys_length;
      proto_item_append_text(ti_keys, "(%d keys)", nKeys);

    }
    break;

    default:
      break;
    }
  }
  return (length_field + 4 + 8 +2);
}


static int
dissect_fetchreq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length, gboolean meta)
{
  proto_item *ti_fetchreq;
  proto_item *ti_specifiers;
  proto_tree *fetchreq_tree;
  proto_tree *specifiers_tree;
  guint16 resourceid_length;
  guint16 specifiers_length;
  guint16 specifiers_offset = 0;
  int nSpecifiers = 0;
  guint16 local_offset = 0;
  guint16 local_length =0;
  int hf =  hf_reload_fetchreq;

  if (meta == TRUE) {
    hf = hf_reload_statreq;
  }

  resourceid_length = get_opaque_length(tvb,offset, 1);
  specifiers_length = get_opaque_length(tvb, offset+1+resourceid_length, 2);

  if (1+ resourceid_length+ 2 + specifiers_length > length) {
    ti_fetchreq = proto_tree_add_item(tree, hf, tvb, offset, length, FALSE);
    expert_add_info_format(pinfo, ti_fetchreq, PI_PROTOCOL, PI_ERROR, "Truncated FetchReq");
    return length;
  }
  local_length =  1+ resourceid_length+ 2 + specifiers_length;
  ti_fetchreq = proto_tree_add_item(tree, hf, tvb, offset, local_length, FALSE);
  fetchreq_tree = proto_item_add_subtree(ti_fetchreq, ett_reload_fetchreq);

  local_offset +=
    dissect_resourceid(hf_reload_resource, tvb, pinfo, fetchreq_tree, offset, local_length);

  ti_specifiers = proto_tree_add_item(fetchreq_tree, hf_reload_fetchreq_specifiers, tvb, offset+local_offset, 2+specifiers_length, ENC_NA);
  specifiers_tree = proto_item_add_subtree(ti_specifiers, ett_reload_fetchreq_specifiers);
  proto_item_append_text(ti_specifiers, "(StoredDataSpecifier<%d>)", specifiers_length);
  proto_tree_add_item(specifiers_tree, hf_reload_length_uint16, tvb, offset+local_offset, 2, ENC_BIG_ENDIAN);
  local_offset += 2;

  while (specifiers_offset < specifiers_length) {
    guint32 specifiers_increment;
    specifiers_increment = dissect_storeddataspecifier(tvb, pinfo, specifiers_tree, offset+local_offset+specifiers_offset, specifiers_length-specifiers_offset);
    if (specifiers_increment == 0) {
      break;
    }
    nSpecifiers++;
    specifiers_offset += specifiers_increment;
  }
  local_offset += specifiers_length;
  proto_item_append_text(ti_specifiers, ": %d elements", nSpecifiers);

  return (1+ resourceid_length+ 2 + specifiers_length);
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
    expert_add_info_format(pinfo, ti_fetchans, PI_PROTOCOL, PI_ERROR, "Truncated FetchAns");
    return length;
  }
  ti_fetchans = proto_tree_add_item(tree, hf_reload_fetchans, tvb, offset, 4 + kind_responses_length, ENC_NA);
  fetchans_tree = proto_item_add_subtree(ti_fetchans, ett_reload_fetchans);

  proto_tree_add_uint(fetchans_tree, hf_reload_length_uint16, tvb, offset, 4, FALSE);

  while (kind_responses_offset < kind_responses_length) {
    guint32 kind_responses_increment;
    kind_responses_increment = dissect_kinddata(tvb, pinfo, fetchans_tree, offset + 4 + kind_responses_offset, kind_responses_length - kind_responses_offset, FALSE);
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
  int nResponses=0;

  kind_responses_length = tvb_get_ntohl(tvb, offset);

  if (4 + kind_responses_length > length) {
    ti_statans = proto_tree_add_item(tree, hf_reload_statans, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_statans, PI_PROTOCOL, PI_ERROR, "Truncated StatAns");
    return length;
  }
  ti_statans = proto_tree_add_item(tree, hf_reload_statans, tvb, offset, 4 + kind_responses_length, ENC_NA);
  proto_item_append_text(ti_statans, " (StatKindResponse<%d>)", kind_responses_length);
  statans_tree = proto_item_add_subtree(ti_statans, ett_reload_statans);

  proto_tree_add_uint(statans_tree, hf_reload_length_uint32, tvb, offset, 4, kind_responses_length);


  while (kind_responses_offset < kind_responses_length) {
    guint32 kind_responses_increment;
    kind_responses_increment = dissect_kinddata(tvb, pinfo, statans_tree, offset + 4 + kind_responses_offset, kind_responses_length - kind_responses_offset, TRUE);
    if (kind_responses_increment == 0) {
      break;
    }
    nResponses++;
    kind_responses_offset += kind_responses_increment;
  }

  proto_item_append_text(ti_statans, ": %d elements", nResponses);

  return 4 + kind_responses_length;
}


static int
dissect_chordupdate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_chordupdate;
  proto_tree *chordupdate_tree;
  guint16 local_offset = 0;
  guint8 type;

  ti_chordupdate = proto_tree_add_item(tree, hf_reload_chordupdate, tvb, offset, length, ENC_NA);
  chordupdate_tree = proto_item_add_subtree(ti_chordupdate, ett_reload_chordupdate);

  proto_tree_add_item(chordupdate_tree, hf_reload_uptime, tvb, offset+local_offset, 4, ENC_BIG_ENDIAN);
  local_offset += 4;
  type = tvb_get_guint8(tvb, offset + local_offset);
  proto_tree_add_uint(chordupdate_tree, hf_reload_chordupdate_type, tvb, offset+local_offset, 1, type);
  local_offset += 1;

  switch(type) {
  case CHORDUPDATETYPE_NEIGHBORS:
    local_offset += dissect_nodeid_list(tvb, pinfo, chordupdate_tree, offset+local_offset, length-local_offset, hf_reload_chordupdate_predecessors, 2);
    local_offset += dissect_nodeid_list(tvb, pinfo, chordupdate_tree, offset+local_offset, length-local_offset, hf_reload_chordupdate_successors, 2);
    break;

  case CHORDUPDATETYPE_FULL:
    local_offset += dissect_nodeid_list(tvb, pinfo, chordupdate_tree, offset+local_offset, length-local_offset, hf_reload_chordupdate_predecessors, 2);
    local_offset += dissect_nodeid_list(tvb, pinfo, chordupdate_tree, offset+local_offset, length-local_offset, hf_reload_chordupdate_successors, 2);
    local_offset += dissect_nodeid_list(tvb, pinfo, chordupdate_tree, offset+local_offset, length-local_offset, hf_reload_chordupdate_fingers, 2);
    break;

  default:
    break;
  }
  return local_offset;
}


static int
dissect_chordroutequeryans(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_chordroutequeryans;
  proto_tree *chordroutequeryans_tree;

  ti_chordroutequeryans = proto_tree_add_item(tree, hf_reload_chordroutequeryans, tvb, offset, length, ENC_NA);
  chordroutequeryans_tree = proto_item_add_subtree(ti_chordroutequeryans, ett_reload_chordroutequeryans);
  dissect_nodeid(hf_reload_chordroutequeryans_next_peer, tvb, pinfo, chordroutequeryans_tree, offset, length);

  return length;
}

static int
dissect_chordleavedata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16 local_offset = 0;
  guint8 type;

  ti_local = proto_tree_add_item(tree, hf_reload_chordleave, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_chordleave);

  type = tvb_get_guint8(tvb, offset + local_offset);
  proto_tree_add_uint(local_tree, hf_reload_chordleave_type, tvb, offset+local_offset, 1, type);
  local_offset += 1;

  switch(type) {
  case CHORDLEAVETYPE_FROM_SUCC:
    local_offset += dissect_nodeid_list(tvb, pinfo, local_tree, offset+local_offset, length-local_offset, hf_reload_chordleave_successors, 2);
    break;

  case CHORDLEAVETYPE_FROM_PRED:
    local_offset += dissect_nodeid_list(tvb, pinfo, local_tree, offset+local_offset, length-local_offset, hf_reload_chordleave_predecessors, 2);
    break;

  default:
    break;
  }
  return local_offset;
}

static int dissect_kindid_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length, guint16 length_size)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  int kinds_length=0;
  int kinds_offset=0;
  int nKinds=0;

  kinds_length = get_opaque_length(tvb, offset, length_size);

  if ((guint16)length<kinds_length+length_size) {
    ti_local = proto_tree_add_item(tree, hf_reload_kindid_list, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_local, PI_PROTOCOL, PI_ERROR, "Truncated kinds list");
  }
  ti_local = proto_tree_add_item(tree, hf_reload_kindid_list, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_kindid_list);
  proto_item_append_text(ti_local, "(KindId<%d>)", kinds_length);

  dissect_length(tvb, local_tree, offset, length_size);

  while (kinds_offset < kinds_length) {
    kind_t *kind;
    int local_increment = dissect_kindid(-1,tvb, local_tree,offset+length_size+kinds_offset, &kind);
    if (local_increment <= 0) break;
    kinds_offset += local_increment;
    nKinds++;
  }
  proto_item_append_text(ti_local, ": %d elements", nKinds);

  return (length_size+kinds_length);
}

static int dissect_findreq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length) {
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16 local_offset=0;

  ti_local = proto_tree_add_item(tree, hf_reload_findreq, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_findreq);

  local_offset += dissect_resourceid(hf_reload_resource, tvb, pinfo, local_tree, offset, length);
  dissect_kindid_list(tvb, pinfo, local_tree, offset+local_offset, length-local_offset, 1);

  return length;
}

static int dissect_findans(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length) {
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16 results_length;

  ti_local = proto_tree_add_item(tree, hf_reload_findans, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_findans);
  results_length = tvb_get_ntohs(tvb, offset);
  proto_item_append_text(ti_local, " (FindKindData<%d>)", results_length);
  if (results_length + 2 > length) {
    expert_add_info_format(pinfo, ti_local, PI_PROTOCOL, PI_ERROR, "Truncated FindAns");
  }
  proto_tree_add_uint(local_tree, hf_reload_length_uint16, tvb, offset, 2, results_length);

  {
    guint16 results_offset = 0;
    int nResults=0;
    while (results_offset < results_length) {
      proto_item *ti_findkinddata;
      proto_tree *findkinddata_tree;
      guint16 findkinddata_length;
      kind_t *kind;
      findkinddata_length = 4/*kind id */ + 1 + get_opaque_length(tvb,offset + 2 + results_offset + 4, 1)/* resourceId */;
      if (results_offset + findkinddata_length > results_length) {
        ti_findkinddata = proto_tree_add_item(local_tree, hf_reload_findkinddata, tvb, offset + results_offset, results_length - results_offset, ENC_NA);
        expert_add_info_format(pinfo, ti_findkinddata, PI_PROTOCOL, PI_ERROR, "Truncated FindKindData");
        break;
      }

      ti_findkinddata = proto_tree_add_item(local_tree, hf_reload_findkinddata, tvb, offset + 2 + results_offset, findkinddata_length, ENC_NA);
      findkinddata_tree = proto_item_add_subtree(ti_findkinddata, ett_reload_findkinddata);
      dissect_kindid(hf_reload_kinddata_kind,tvb, findkinddata_tree, offset+2+results_offset,&kind);
      dissect_resourceid(hf_reload_findkinddata_closest, tvb, pinfo, findkinddata_tree, offset+2+results_offset+4,  results_length - 4 - results_offset);
      if (findkinddata_length<=0) break;
      results_offset += findkinddata_length;
      nResults++;
    }
    proto_item_append_text(ti_local, ": %d elements", nResults);
  }

  return length;
}

static int dissect_selftuningdata(tvbuff_t *tvb, proto_tree *tree, guint16 offset)
{
  proto_item *ti_local;
  proto_tree *local_tree;

  ti_local = proto_tree_add_item(tree, hf_reload_self_tuning_data, tvb, offset, 12, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_self_tuning_data);

  proto_tree_add_item(local_tree, hf_reload_self_tuning_data_network_size, tvb, offset, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(local_tree, hf_reload_self_tuning_data_join_rate, tvb, offset+4, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(local_tree, hf_reload_self_tuning_data_leave_rate, tvb, offset+8, 4, ENC_BIG_ENDIAN);

  return 12;
}

static int dissect_extensiveroutingmodeoption(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16 local_offset=0;

  ti_local = proto_tree_add_item(tree, hf_reload_extensiveroutingmodeoption, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_extensiveroutingmodeoption);

  proto_tree_add_item(local_tree, hf_reload_routemode, tvb, offset, 1, ENC_BIG_ENDIAN);
  local_offset += 1;
  proto_tree_add_item(local_tree, hf_reload_extensiveroutingmode_transport, tvb,
                      offset+local_offset, 1, ENC_BIG_ENDIAN);
  local_offset += 1;
  local_offset += dissect_ipaddressport(hf_reload_extensiveroutingmode_ipaddressport, tvb, local_tree, offset+local_offset);
  {
    proto_item *ti_destination;
    proto_tree *destination_tree;
    guint16 destination_length;
    int nDestinations=0;
    destination_length = tvb_get_guint8(tvb, offset+local_offset);
    if (destination_length+1+local_offset>length) {
      expert_add_info_format(pinfo, ti_local, PI_PROTOCOL, PI_ERROR, "Truncated ExtensiveRoutingModeOption");
      destination_length = length -1-local_offset;
    }
    ti_destination = proto_tree_add_item(local_tree, hf_reload_extensiveroutingmode_destination, tvb,offset+local_offset, 1+destination_length, ENC_NA);
    proto_item_append_text(ti_destination, " (Destination<%d>)", destination_length);
    destination_tree = proto_item_add_subtree(ti_destination, ett_reload_extensiveroutingmode_destination);
    proto_tree_add_item(destination_tree, hf_reload_length_uint8, tvb,offset+local_offset, 1, ENC_BIG_ENDIAN);
    local_offset +=1;
    dissect_destination_list(tvb, pinfo, destination_tree, offset+local_offset, destination_length, &nDestinations);
    proto_item_append_text(ti_destination, ": %d elements", nDestinations);

    return  local_offset += destination_length;
  }
  return local_offset;
}

static int dissect_forwardingoption(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_option;
  guint16 local_offset = 0;
  guint8 option_type = tvb_get_guint8(tvb,offset);
  guint8 option_flags = tvb_get_guint8(tvb, offset+ 1);
  guint16 option_length = tvb_get_ntohs(tvb, offset+ 2);
  proto_tree *option_tree;

  ti_option = proto_tree_add_item(tree, hf_reload_forwarding_option, tvb, offset+local_offset, option_length + 4, ENC_NA);
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
    proto_tree_add_bits_item(flags_tree, hf_reload_forwarding_option_flag_ignore_state_keeping, tvb, bit_offset+4, 1, FALSE);
    proto_tree_add_bits_item(flags_tree, hf_reload_forwarding_option_flag_response_copy, tvb, bit_offset+5, 1, FALSE);
    proto_tree_add_bits_item(flags_tree, hf_reload_forwarding_option_flag_destination_critical, tvb, bit_offset+6, 1, FALSE);
    proto_tree_add_bits_item(flags_tree, hf_reload_forwarding_option_flag_forward_critical, tvb, bit_offset+7, 1, FALSE);
  }
  proto_tree_add_uint(option_tree, hf_reload_length_uint16, tvb, offset+local_offset+2, 2, option_length);
  local_offset += 4;
  if (local_offset + option_length > length) {
    expert_add_info_format(pinfo, ti_option, PI_PROTOCOL, PI_ERROR, "Truncated ForwardingOption");
    return length;
  }

  switch (option_type) {
  case OPTIONTYPE_EXTENSIVE_ROUTING_MODE:
    dissect_extensiveroutingmodeoption(tvb, pinfo, option_tree, offset+local_offset, option_length);
    break;

  default:
    proto_tree_add_item(option_tree, hf_reload_opaque_data, tvb, offset+local_offset, option_length, ENC_NA);
    break;
  }
  local_offset += option_length;

  return local_offset;
}

static int dissect_dmflag(tvbuff_t *tvb, proto_tree *tree, guint16 offset) {
  proto_item *ti_local;
  proto_tree *local_tree;
  guint i;
  guint32 bit_offset=offset<<3;

  ti_local = proto_tree_add_item(tree, hf_reload_dmflags, tvb, offset, 64, ENC_BIG_ENDIAN);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_dmflags);

  for (i=0; i<(sizeof(reload_dmflag_items)/sizeof(gint *)); i++) {
    if (reload_dmflag_items[i]!=NULL) {
      proto_tree_add_bits_item(local_tree, *(reload_dmflag_items[i]), tvb, bit_offset+63-i, 1, FALSE);
    }
  }
  return 8;
}

static int dissect_diagnosticextension(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16 local_offset=0;
  guint16 local_length = 0;

  local_length = 2 + 4 + get_opaque_length(tvb, offset+2,4);
  ti_local = proto_tree_add_item(tree, hf_reload_diagnosticextension, tvb, offset, local_length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_diagnosticextension);

  proto_tree_add_item(local_tree, hf_reload_diagnosticextension_type, tvb, offset, 2, ENC_BIG_ENDIAN);
  local_offset +=2;
  local_offset += dissect_opaque(tvb, pinfo, local_tree, hf_reload_diagnosticextension_contents, offset + local_offset, 4, length-2);

  return local_offset;
}

static int dissect_diagnosticrequest(int anchor, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length) {
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16 local_offset=0;
  guint32 local_length=0;
  int hf = hf_reload_diagnosticrequest;

  if (anchor >= 0) {
    hf = anchor;
  }

  ti_local = proto_tree_add_item(tree, hf, tvb, offset, length, FALSE);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_diagnosticrequest);

  proto_tree_add_item(local_tree, hf_reload_diagnostic_expiration, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
  local_offset+=8;
  proto_tree_add_item(local_tree, hf_reload_diagnosticrequest_timestampinitiated, tvb, offset+local_offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
  local_offset+=8;
  local_length = tvb_get_ntohl(tvb, offset+local_offset);
  proto_tree_add_item(local_tree, hf_reload_length_uint32, tvb, offset+local_offset, 4, ENC_BIG_ENDIAN);
  local_offset+=4;

  local_offset+=dissect_dmflag(tvb, local_tree, offset+local_offset);
  if (local_offset+local_length > length) {
    expert_add_info_format(pinfo, ti_local, PI_PROTOCOL, PI_ERROR, "Truncated DiagnosticRequest");
    local_length = length-local_offset;
  }
  if (local_length>0) {
    proto_item *ti_extensions;
    proto_tree *extensions_tree;
    guint16 extensions_offset=0;
    guint32 extensions_length=0;
    int nExtensions = 0;

    ti_extensions = proto_tree_add_item(local_tree, hf_reload_diagnosticrequest_extensions, tvb, offset+local_offset, local_length, ENC_NA);
    extensions_tree = proto_item_add_subtree(ti_extensions, ett_reload_diagnosticrequest_extensions);
    extensions_length = tvb_get_ntohl(tvb, offset+local_offset);
    if (extensions_length+4 > local_length) {
      expert_add_info_format(pinfo, ti_extensions, PI_PROTOCOL, PI_ERROR, "Truncated Diagnostic extensions");
      extensions_length = local_length-4;
    }
    proto_item_append_text(ti_extensions, " (DiagnosticExtension<%d>)",extensions_length);
    proto_tree_add_item(extensions_tree, hf_reload_length_uint32, tvb, offset+local_offset, 4, ENC_BIG_ENDIAN);
    while (extensions_offset<extensions_length) {
      int local_increment = dissect_diagnosticextension(tvb, pinfo, extensions_tree, offset+4+local_offset+extensions_offset, extensions_length-extensions_offset);
      if (local_increment<=0) break;
      extensions_offset += local_increment;
      nExtensions++;
    }
    proto_item_append_text(ti_extensions, " : %d elements", nExtensions);
  }
  local_offset+=local_length;
  return local_offset;
}

static int dissect_pathtrackreq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16 local_offset=0;

  ti_local = proto_tree_add_item(tree, hf_reload_pathtrackreq, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_pathtrackreq);
  local_offset += dissect_destination(hf_reload_pathtrackreq_destination, tvb, pinfo, local_tree, offset+local_offset,length);
  local_offset += dissect_diagnosticrequest(hf_reload_pathtrackreq_request, tvb, pinfo, local_tree, offset+local_offset, length-local_offset);

  return local_offset;
}

static int dissect_diagnosticinfo(tvbuff_t *tvb, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16 local_offset=0;
  guint16 local_length=0;
  guint16 kind;

  local_length = 2 + tvb_get_ntohs(tvb, offset+2);
  ti_local = proto_tree_add_item(tree, hf_reload_diagnosticinfo, tvb, offset, local_length+4, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_diagnosticinfo);

  proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_kind, tvb, offset+local_offset, 2, ENC_BIG_ENDIAN);
  local_offset +=2;
  proto_tree_add_item(local_tree, hf_reload_length_uint16, tvb, offset+local_offset, 2, ENC_BIG_ENDIAN);
  local_offset+=2;

  kind = tvb_get_ntohs(tvb, offset);
  switch(kind) {
  case DIAGNOSTICKINDID_STATUS_INFO:
    proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_congestion_status, tvb, offset+local_offset, 1, ENC_BIG_ENDIAN);
    break;

  case DIAGNOSTICKINDID_ROUTING_TABLE_SIZE:
    proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_number_peers, tvb, offset+local_offset, 4, ENC_BIG_ENDIAN);
    break;

  case DIAGNOSTICKINDID_PROCESS_POWER:
    proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_processing_power, tvb, offset+local_offset, 4, ENC_BIG_ENDIAN);
    break;

  case DIAGNOSTICKINDID_BANDWIDTH:
    proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_bandwidth, tvb, offset+local_offset, 4, ENC_BIG_ENDIAN);
    break;

  case DIAGNOSTICKINDID_SOFTWARE_VERSION:
    proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_software_version, tvb, offset+local_offset, length, ENC_ASCII|ENC_NA);
    break;

  case DIAGNOSTICKINDID_MACHINE_UPTIME:
    proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_machine_uptime, tvb, offset+local_offset, 8, ENC_BIG_ENDIAN);
    break;

  case DIAGNOSTICKINDID_APP_UPTIME:
    proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_app_uptime, tvb, offset+local_offset, 8, ENC_BIG_ENDIAN);
    break;

  case DIAGNOSTICKINDID_MEMORY_FOOTPRINT:
    proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_memory_footprint, tvb, offset+local_offset, 4, ENC_BIG_ENDIAN);
    break;

  case DIAGNOSTICKINDID_DATASIZE_STORED:
    proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_datasize_stored, tvb, offset+local_offset, 8, ENC_BIG_ENDIAN);
    break;

  case DIAGNOSTICKINDID_INSTANCES_STORED:
  {
    proto_item *ti_instances;
    proto_tree *instances_tree;
    guint16 instances_offset = 0;
    int nElements=0;

    ti_instances = proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_instances_stored, tvb, offset+local_offset, length, ENC_NA);
    instances_tree = proto_item_add_subtree(ti_instances, ett_reload_diagnosticinfo_instances_stored);
    proto_item_append_text(ti_instances, "[%d]", length);
    while (instances_offset < length) {
      proto_item *ti_instances_per_kindid;
      proto_tree *instances_per_kindid_tree;
      kind_t *kind;
      guint64 instances;
      ti_instances_per_kindid = proto_tree_add_item(instances_tree, hf_reload_diagnosticinfo_instancesstored_info, tvb, offset+local_offset+instances_offset, 12, ENC_NA);
      instances_per_kindid_tree = proto_item_add_subtree(ti_instances_per_kindid, ett_reload_diagnosticinfo_instancesstored_info);
      dissect_kindid(hf_reload_kinddata_kind, tvb, instances_per_kindid_tree, offset+local_offset+instances_offset, &kind);
      proto_tree_add_item(instances_per_kindid_tree, hf_reload_diagnosticinfo_instancesstored_instances, tvb, offset+local_offset+instances_offset+4, 8, ENC_BIG_ENDIAN);
      instances = tvb_get_ntoh64(tvb, offset+local_offset+instances_offset+4);
      proto_item_append_text(ti_instances_per_kindid, ": %s/%" G_GINT64_MODIFIER "d", kind->name,instances);
      instances_offset +=12;
      nElements++;
    }
    if (nElements>0) {
      proto_item_append_text(ti_instances, ": %d", nElements);
    }
  }
  break;


  case DIAGNOSTICKINDID_MESSAGES_SENT_RCVD:
  {
    proto_item *ti_messages;
    proto_tree *messages_tree;
    guint16 messages_offset = 0;
    int nElements=0;

    ti_messages = proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_messages_sent_rcvd, tvb, offset+local_offset, length, ENC_NA);
    messages_tree = proto_item_add_subtree(ti_messages, ett_reload_diagnosticinfo_messages_sent_rcvd);
    proto_item_append_text(ti_messages, "[%d]", length);

    while (messages_offset < length) {
      proto_item *ti_sent_rcvd;
      proto_tree *sent_rcvd_tree;
      guint16 message_code;

      ti_sent_rcvd = proto_tree_add_item(messages_tree, hf_reload_diagnosticinfo_messages_sent_rcvd_info, tvb, offset+local_offset+messages_offset, 20, ENC_NA);

      sent_rcvd_tree = proto_item_add_subtree(ti_sent_rcvd, ett_reload_diagnosticinfo_messages_sent_rcvd_info);
      message_code = tvb_get_ntohs(tvb, offset+local_offset+messages_offset);
      if (message_code == RELOAD_ERROR) {
        proto_tree_add_uint_format_value(sent_rcvd_tree, hf_reload_diagnosticinfo_message_code, tvb,
                                         offset+local_offset+messages_offset, 2,
                                         message_code,
                                         "error");

      }
      else {
        proto_tree_add_uint_format_value(sent_rcvd_tree, hf_reload_diagnosticinfo_message_code, tvb,
                                         offset+local_offset+messages_offset, 2,
                                         message_code,
                                         "%s_%s",
                                         val_to_str(MSGCODE_TO_METHOD(message_code), methods_short, "Unknown"),
                                         val_to_str(MSGCODE_TO_CLASS(message_code), classes_short, "Unknown"));
      }
      proto_tree_add_item(sent_rcvd_tree, hf_reload_diagnosticinfo_messages_sent, tvb, offset+local_offset+messages_offset+2, 8, ENC_BIG_ENDIAN);
      proto_tree_add_item(sent_rcvd_tree, hf_reload_diagnosticinfo_messages_rcvd, tvb, offset+local_offset+messages_offset+2+8, 8, ENC_BIG_ENDIAN);
      messages_offset +=18;
      nElements++;
    }
    if (nElements>0) {
      proto_item_append_text(ti_messages, ": %d", nElements);
    }
  }
  break;

  case DIAGNOSTICKINDID_EWMA_BYTES_SENT:
    proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_ewma_bytes_sent, tvb, offset+local_offset, 4, ENC_BIG_ENDIAN);
    break;

  case DIAGNOSTICKINDID_EWMA_BYTES_RCVD:
    proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_ewma_bytes_rcvd, tvb, offset+local_offset, 4, ENC_BIG_ENDIAN);
    break;

  case DIAGNOSTICKINDID_UNDERLAY_HOP:
    proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_underlay_hops, tvb, offset+local_offset, 1, ENC_BIG_ENDIAN);
    break;

  case DIAGNOSTICKINDID_BATTERY_STATUS:
    proto_tree_add_item(local_tree, hf_reload_diagnosticinfo_battery_status, tvb, offset+local_offset, 1, ENC_BIG_ENDIAN);
    break;

  default:
    proto_tree_add_item(local_tree, hf_reload_opaque_data, tvb, offset+local_offset, length, ENC_NA);
    break;

  }

  return local_length;
}


static int dissect_diagnosticresponse(int anchor, tvbuff_t *tvb, packet_info *pinfo,proto_tree *tree, guint16 offset, guint16 length) {
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16 local_offset=0;
  int hf = hf_reload_diagnosticresponse;

  if (anchor >= 0) {
    hf = anchor;
  }

  ti_local = proto_tree_add_item(tree, hf, tvb, offset, length, FALSE);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_diagnosticresponse);

  proto_tree_add_item(local_tree, hf_reload_diagnostic_expiration, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
  local_offset+=8;
  proto_tree_add_item(local_tree, hf_reload_diagnosticresponse_timestampreceived, tvb, offset+local_offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
  local_offset+=8;
  proto_tree_add_item(local_tree, hf_reload_diagnosticresponse_hopcounter, tvb, offset+local_offset, 1, ENC_BIG_ENDIAN);


  {
    proto_item *ti_diagnostics;
    proto_tree *diagnostics_tree;
    guint16 diagnostics_offset=0;
    guint32 diagnostics_length=0;
    int nDiagnostics = 0;

    diagnostics_length = tvb_get_ntohl(tvb, offset+local_offset);
    if (diagnostics_length+local_offset+4>length) {
      expert_add_info_format(pinfo, ti_local, PI_PROTOCOL, PI_ERROR, "Truncated Diagnostic Response");
      diagnostics_length = length -4 -local_offset;
    }
    ti_diagnostics = proto_tree_add_item(local_tree, hf_reload_diagnosticresponse_diagnostic_info_list, tvb, offset+local_offset, diagnostics_length, ENC_NA);
    diagnostics_tree = proto_item_add_subtree(ti_local, ett_reload_diagnosticresponse_diagnostic_info_list);
    proto_item_append_text(ti_diagnostics, " (DiagnosticInfo<%d>)",diagnostics_length);
    proto_tree_add_item(diagnostics_tree, hf_reload_length_uint32, tvb, offset+local_offset, 4, ENC_BIG_ENDIAN);
    local_offset += 4;
    while (diagnostics_offset<diagnostics_length) {
      int local_increment = dissect_diagnosticinfo(tvb, diagnostics_tree, offset+local_offset+diagnostics_offset, diagnostics_length-diagnostics_offset);
      if (local_increment<=0) break;
      diagnostics_offset += local_increment;
      nDiagnostics++;
    }
    proto_item_append_text(ti_diagnostics, " : %d elements", nDiagnostics);
    local_offset += diagnostics_length;
  }

  return local_offset;
}

static int dissect_pathtrackans(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16 local_offset=0;

  ti_local = proto_tree_add_item(tree, hf_reload_pathtrackans, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_pathtrackans);
  local_offset += dissect_destination(hf_reload_pathtrackans_next_hop, tvb, pinfo, local_tree, offset+local_offset,length);
  local_offset += dissect_diagnosticresponse(hf_reload_pathtrackans_response, tvb, pinfo, local_tree, offset+local_offset, length-local_offset);

  return local_offset;
}

static int dissect_joinreq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16 local_offset=0;

  ti_local = proto_tree_add_item(tree, hf_reload_joinreq, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_joinreq);

  local_offset += dissect_nodeid(hf_reload_joinreq_joining_peer_id, tvb, pinfo, local_tree, offset, length);
  local_offset += dissect_opaque(tvb, pinfo, local_tree, hf_reload_overlay_specific, offset + local_offset, 2,
                                 length - local_offset);
  return local_offset;
}

static int dissect_joinans(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16 local_offset=0;

  ti_local = proto_tree_add_item(tree, hf_reload_joinans, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_joinans);

  local_offset = dissect_opaque(tvb, pinfo, local_tree, hf_reload_overlay_specific, offset + local_offset, 2,
                                length );
  return local_offset;
}

static int dissect_leavereq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local;
  proto_tree *local_tree;
  guint16 local_offset=0;

  ti_local = proto_tree_add_item(tree, hf_reload_leavereq, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_leavereq);

  local_offset += dissect_nodeid(hf_reload_leavereq_leaving_peer_id, tvb, pinfo, local_tree, offset, length);
  if (0==strcmp(TOPOLOGY_PLUGIN_CHORD_RELOAD, reload_topology_plugin)) {
    proto_item *ti_overlay_specific;
    proto_tree *overlay_specific_tree;
    guint16 overlay_length;
    ti_overlay_specific = proto_tree_add_item(local_tree, hf_reload_overlay_specific, tvb,  offset+local_offset,  length - local_offset, ENC_NA);
    overlay_specific_tree = proto_item_add_subtree(ti_overlay_specific, ett_reload_overlay_specific);
    proto_tree_add_item(overlay_specific_tree, hf_reload_length_uint16, tvb,  offset+local_offset,  2, ENC_BIG_ENDIAN);
    overlay_length = tvb_get_ntohs(tvb, offset+local_offset);
    local_offset+= 2;
    dissect_chordleavedata(tvb, pinfo, overlay_specific_tree, offset+local_offset, overlay_length);
    local_offset += overlay_length;
  }
  else {
    local_offset += dissect_opaque(tvb, pinfo, local_tree, hf_reload_overlay_specific, offset + reload_nodeid_length, 2,
                                   length - local_offset);
  }

  return local_offset;
}

static int dissect_probereq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local, *ti_requested_info;
  proto_tree *local_tree, *requested_info_tree;
  guint8 info_list_length = 0;

  ti_local = proto_tree_add_item(tree, hf_reload_probereq, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_probereq);
  ti_requested_info = proto_tree_add_item(local_tree, hf_reload_probereq_requested_info, tvb, offset, length, ENC_NA);
  requested_info_tree = proto_item_add_subtree(ti_requested_info, ett_reload_probereq_requested_info);
  info_list_length = tvb_get_guint8(tvb, offset);
  proto_item_append_text(ti_requested_info, " (ProbeInformationType<%d>)", info_list_length);
  proto_tree_add_uint(requested_info_tree, hf_reload_length_uint8, tvb, offset, 1, info_list_length);
  if (info_list_length +1> length) {
    expert_add_info_format(pinfo, ti_requested_info, PI_PROTOCOL, PI_ERROR, "Truncated requested_info");
    info_list_length = length - 1;
  }
  {
    int probe_offset = 0;
    int nInfos=0;
    while (probe_offset < info_list_length) {
      proto_tree_add_item(requested_info_tree, hf_reload_probe_information_type, tvb, offset + 1 + probe_offset, 1, ENC_BIG_ENDIAN);
      probe_offset += 1;
      nInfos++;
    }
    proto_item_append_text(ti_requested_info, ": %d elements", nInfos);
  }

  return info_list_length;
}

static int dissect_probeans(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  proto_item *ti_local, *ti_infos;
  proto_tree *local_tree, *infos_tree;
  guint16 info_list_length = 0;

  ti_local = proto_tree_add_item(tree, hf_reload_probeans, tvb, offset, length, ENC_NA);
  local_tree = proto_item_add_subtree(ti_local, ett_reload_probeans);

  info_list_length = tvb_get_ntohs(tvb, offset);
  if (info_list_length+2 >length) {
    expert_add_info_format(pinfo, ti_local, PI_PROTOCOL, PI_ERROR, "Truncated ProbeAns");
    info_list_length = length - 2;
  }
  ti_infos = proto_tree_add_item(local_tree, hf_reload_probeans_probe_info, tvb, offset, info_list_length, ENC_NA);
  proto_item_append_text(ti_infos, " (ProbeInformation<%d>)", info_list_length);
  infos_tree = proto_item_add_subtree(ti_infos, ett_reload_probeans_probe_info);
  {
    int probe_offset = 0;
    int probe_increment;
    int nInfos = 0;
    while (probe_offset < info_list_length) {
      probe_increment = dissect_probe_information(tvb, pinfo, infos_tree, offset + 2 + probe_offset, info_list_length - probe_offset);
      if (probe_increment <= 0) {
        break;
      }
      probe_offset += probe_increment;
      nInfos++;
    }
    proto_item_append_text(ti_infos, ": %d elements", nInfos);
  }
  return length;
}

extern gint dissect_reload_messagecontents(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 offset, guint16 length)
{
  guint32 message_body_length;
  guint32 extensions_length;
  proto_item *ti_message_contents;
  proto_tree *message_contents_tree;
  guint16 message_code;

  message_body_length = tvb_get_ntohl(tvb, offset + 2);
  extensions_length = tvb_get_ntohl(tvb, offset + 2 + 4 + message_body_length);

  if (2 + 4 + message_body_length + 4 + extensions_length > length) {
    ti_message_contents = proto_tree_add_item(tree, hf_reload_message_contents, tvb, offset, length, ENC_NA);
    expert_add_info_format(pinfo, ti_message_contents, PI_PROTOCOL, PI_ERROR, "Truncated MessageContents");
    return length;
  }

  ti_message_contents = proto_tree_add_item(tree, hf_reload_message_contents, tvb, offset, 2 + 4 + message_body_length + 4 + extensions_length, ENC_NA);
  message_contents_tree = proto_item_add_subtree(ti_message_contents, ett_reload_message_contents);

  message_code = tvb_get_ntohs(tvb, offset);

  if (message_code != RELOAD_ERROR) {
    proto_item *ti_message_body;
    proto_tree *message_body_tree;
    gchar *message_type_str = NULL;

    /* message_code was already parsed */
    {
      proto_item *ti_message_code;
      ti_message_code = proto_tree_add_item(message_contents_tree, hf_reload_message_code, tvb,
                                            offset, 2, ENC_BIG_ENDIAN);
      proto_item_append_text(ti_message_code, " (%s_%s)",
                             val_to_str(MSGCODE_TO_METHOD(message_code), methods_short, "Unknown %d"),
                             val_to_str(MSGCODE_TO_CLASS(message_code), classes_short, "Unknown %d"));
    }
    offset += 2;
    /* Message body */
    ti_message_body = proto_tree_add_item(message_contents_tree, hf_reload_message_body, tvb, offset, 4 + message_body_length, ENC_NA);
    message_body_tree = proto_item_add_subtree(ti_message_body, ett_reload_message_body);
    proto_tree_add_uint(message_body_tree, hf_reload_length_uint32, tvb, offset, 4, message_body_length);
    offset +=4;

    if (message_body_length > 0) {
      switch(MSGCODE_TO_METHOD(message_code)) {
      case METHOD_ROUTEQUERY:
      {
        if (IS_REQUEST(message_code)) {
          {
            proto_item * ti_routequeryreq;
            proto_tree * routequeryreq_tree;
            int destination_length;
            message_type_str = "RouteQueryReq";
            ti_routequeryreq = proto_tree_add_item(message_body_tree, hf_reload_routequeryreq, tvb, offset, message_body_length, ENC_NA);
            routequeryreq_tree = proto_item_add_subtree(ti_routequeryreq, ett_reload_routequeryreq);
            proto_tree_add_item(routequeryreq_tree, hf_reload_sendupdate, tvb, offset, 1, ENC_BIG_ENDIAN);
            destination_length = dissect_destination(hf_reload_routequeryreq_destination,tvb, pinfo, routequeryreq_tree, offset + 1, message_body_length - 1 - 2);
            dissect_opaque(tvb, pinfo, routequeryreq_tree, hf_reload_overlay_specific, offset + 1 + destination_length, 2, (message_body_length - 1 - destination_length));
          }
        }
        else {
          message_type_str = "ChordRouteQueryAns";
          /* Answer is entirely Overlay-specific */
          if (0==strcmp(TOPOLOGY_PLUGIN_CHORD_RELOAD, reload_topology_plugin)) {
            dissect_chordroutequeryans(tvb, pinfo, message_body_tree, offset, message_body_length);
          }
        }
      }
      break;

      case METHOD_PROBE:
      {
        if (IS_REQUEST(message_code)) {
          message_type_str = "ProbeReq";
          dissect_probereq(tvb, pinfo, message_body_tree, offset, message_body_length);
        }
        else {
          message_type_str = "ProbeAns";
          dissect_probeans(tvb, pinfo, message_body_tree, offset, message_body_length);
        }
      }
      break;

      case METHOD_ATTACH:
      {
        message_type_str = "AttachReqAns";
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
          int hf =  hf_reload_appattachans;
          message_type_str = "AttachAppAns";
          if (IS_REQUEST(message_code)) {
            hf =  hf_reload_appattachreq;
            message_type_str = "AttachAppReq";
          }
          ti_appattach = proto_tree_add_item(message_body_tree, hf, tvb, offset+local_offset, message_body_length, FALSE);
          appattach_tree  = proto_item_add_subtree(ti_appattach, ett_reload_appattach);
          local_offset += dissect_opaque_string(tvb, pinfo,appattach_tree, hf_reload_ufrag,offset+local_offset, 1, message_body_length-local_offset);
          local_offset += dissect_opaque_string(tvb, pinfo,appattach_tree, hf_reload_password,offset+local_offset, 1, message_body_length-local_offset);
          proto_tree_add_item(appattach_tree, hf_reload_application, tvb, offset+local_offset, 2, ENC_BIG_ENDIAN);
          local_offset += 2;
          local_offset += dissect_opaque_string(tvb, pinfo,appattach_tree, hf_reload_role,offset+local_offset, 1, message_body_length-local_offset);
          dissect_icecandidates(tvb, pinfo, appattach_tree, offset+local_offset, message_body_length-local_offset);
        }
      }
      break;

      case METHOD_PING:
      {
        if (IS_REQUEST(message_code)) {
          proto_item *ti_local;
          proto_tree *local_tree;
          message_type_str = "PingReq";
          ti_local = proto_tree_add_item(message_body_tree, hf_reload_pingreq, tvb, offset, message_body_length, ENC_NA);
          local_tree = proto_item_add_subtree(ti_local, ett_reload_pingreq);

          dissect_opaque(tvb, pinfo, local_tree, hf_reload_padding, offset, 2, message_body_length);
        }
        else {
          message_type_str = "PingAns";
          if (message_body_length < 16) {
            expert_add_info_format(pinfo, ti_message_contents, PI_PROTOCOL, PI_ERROR, "Truncated ping answer");
          }
          else {
            proto_item *ti_local;
            proto_tree *local_tree;

            ti_local = proto_tree_add_item(message_body_tree, hf_reload_pingans, tvb, offset, message_body_length, ENC_NA);
            local_tree = proto_item_add_subtree(ti_local, ett_reload_pingans);
            proto_tree_add_item(local_tree, hf_reload_ping_response_id, tvb, offset, 8, ENC_BIG_ENDIAN);
            {
              guint64 time;
              guint32 remaining_ms;
              time_t time_sec;
              nstime_t l_nsTime;

              time = tvb_get_ntoh64(tvb, offset+8);
              time_sec = (time_t)time/1000;
              remaining_ms = (guint32)(time % 1000);

              l_nsTime.secs = time_sec;
              l_nsTime.nsecs =  remaining_ms*1000*1000;

              proto_tree_add_time(local_tree, hf_reload_ping_time, tvb, offset + 8, 8, &l_nsTime);
            }
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

          message_type_str = "ConfigUpdateReq";
          ti_configupdate = proto_tree_add_item(message_body_tree, hf_reload_configupdatereq, tvb, offset+local_offset, message_body_length, ENC_NA);
          configupdate_tree  = proto_item_add_subtree(ti_configupdate, ett_reload_configupdatereq);
          configupdate_type = tvb_get_guint8(tvb, offset + local_offset);
          proto_tree_add_uint(configupdate_tree, hf_reload_configupdatereq_type, tvb, offset+local_offset, 1, configupdate_type);
          local_offset += 1;
          configupdate_length = tvb_get_ntohl(tvb, offset + local_offset);
          proto_tree_add_uint(configupdate_tree, hf_reload_length_uint32, tvb,  offset + local_offset, 4, configupdate_length);
          if (5 + configupdate_length > message_body_length) {
            expert_add_info_format(pinfo, ti_configupdate, PI_PROTOCOL, PI_ERROR, "Truncated ConfigUpdateReq");
            break;
          }
          local_offset += 4;
          switch(configupdate_type) {
          case CONFIGUPDATETYPE_CONFIG:
          {

            if (xml_handle == NULL) {
              expert_add_info_format(pinfo, ti_configupdate, PI_PROTOCOL, PI_WARN, "Can not find xml dissector");
              dissect_opaque_string(tvb, pinfo, configupdate_tree, hf_reload_configupdatereq_configdata, offset+local_offset, 3, configupdate_length);
            }
            else {
              proto_item *ti_config_data;
              proto_tree *config_data_tree;
              guint32 config_length;
              config_length = tvb_get_ntoh24(tvb,offset+local_offset);
              ti_config_data = proto_tree_add_item(configupdate_tree, hf_reload_configupdatereq_configdata, tvb, offset+local_offset, configupdate_length, ENC_NA);
              config_data_tree = proto_item_add_subtree(ti_config_data, ett_reload_configupdatereq_config_data);
              proto_tree_add_item(config_data_tree, hf_reload_length_uint24, tvb, offset+local_offset, 3, ENC_BIG_ENDIAN);
              call_dissector_only(xml_handle,
                                  tvb_new_subset(tvb, offset+local_offset+3, config_length, length-offset-local_offset-3),
                                  pinfo, config_data_tree);
            }
          }

          break;

          case CONFIGUPDATETYPE_KIND:
          {
            proto_item *ti_kinds;
            proto_tree *kinds_tree;
            guint32 kinds_length;
            guint32 kinds_offset = 0;
            int nKinds=0;
            ti_kinds = proto_tree_add_item(configupdate_tree, hf_reload_configupdatereq_kinds, tvb, offset+local_offset, configupdate_length, ENC_NA);
            kinds_tree = proto_item_add_subtree(ti_kinds, ett_reload_configupdatereq_kinds);
            kinds_length = get_opaque_length(tvb, offset+local_offset, 3);
            proto_item_append_text(ti_kinds, " (KindDescription<%d>)", kinds_length);
            local_offset +=dissect_length(tvb, kinds_tree, offset+local_offset,  3);
            while (kinds_offset < kinds_length) {
              guint16 local_increment = tvb_get_ntohs(tvb,offset+local_offset+kinds_offset);
              if (xml_handle == NULL) {
                expert_add_info_format(pinfo, ti_configupdate, PI_PROTOCOL, PI_WARN, "Can not find xml dissector");
                dissect_opaque_string(tvb, pinfo, configupdate_tree, hf_reload_kinddescription, offset+local_offset+kinds_offset, 2, configupdate_length);
              }
              else {
                proto_item *ti_kinddescription;
                proto_tree *kinddescription_tree;
                ti_kinddescription = proto_tree_add_item(kinds_tree, hf_reload_kinddescription, tvb, offset+local_offset+kinds_offset, 2+local_increment, ENC_NA);
                kinddescription_tree = proto_item_add_subtree(ti_kinddescription, ett_reload_kinddescription);
                proto_tree_add_item(kinddescription_tree, hf_reload_length_uint16, tvb, offset+local_offset+kinds_offset, 2, ENC_BIG_ENDIAN);
                call_dissector(xml_handle,
                               tvb_new_subset(tvb, offset+local_offset+kinds_offset+2, local_increment, length-(offset+local_offset+kinds_offset+2)),
                               pinfo, kinddescription_tree);
              }
              local_increment += 2;
              if (local_increment<=0) break;
              kinds_offset += local_increment;
              nKinds++;
            }
            proto_item_append_text(ti_kinds, ": %d elements", nKinds);
          }
          break;
          }

        }
        else {
          message_type_str = "ConfigUpdateAns";
        }
        break;
      }

      case METHOD_STORE:
      {
        if (IS_REQUEST(message_code)) {
          message_type_str = "StoreReq";
          dissect_storereq(tvb, pinfo, message_body_tree, offset, message_body_length);
        }
        else {
          message_type_str = "StoreAns";
          dissect_storeans(tvb, pinfo, message_body_tree, offset, message_body_length);
        }
      }
      break;

      case METHOD_FETCH:
      {
        if (IS_REQUEST(message_code)) {
          message_type_str = "FetchReq";
          dissect_fetchreq(tvb, pinfo, message_body_tree, offset, message_body_length, FALSE);
        }
        else {
          /* response */
          message_type_str = "FetchAns";
          dissect_fetchans(tvb, pinfo, message_body_tree, offset, message_body_length);
        }
      }
      break;

      case METHOD_STAT:
      {
        if (IS_REQUEST(message_code)) {
          message_type_str = "StatReq";
          dissect_fetchreq(tvb, pinfo, message_body_tree, offset, message_body_length, TRUE);
        }
        else {
          message_type_str = "StatAns";
          dissect_statans(tvb, pinfo, message_body_tree, offset, message_body_length);
        }
      }
      break;

      case METHOD_FIND:
      {
        if (IS_REQUEST(message_code)) {
          message_type_str = "FindReq";
          dissect_findreq(tvb,pinfo, message_body_tree,offset,message_body_length);
        }
        else {
          message_type_str = "FindAns";
          dissect_findans(tvb, pinfo, message_body_tree, offset, message_body_length);
        }
      }
      break;

      case METHOD_LEAVE:
      {
        if (IS_REQUEST(message_code)) {
          message_type_str = "LeaveReq";
          dissect_leavereq(tvb,pinfo, message_body_tree,offset,message_body_length);
        }
        else {
          message_type_str = "LeaveAns";
          dissect_opaque(tvb, pinfo, message_body_tree, hf_reload_overlay_specific, offset, 2, message_body_length);
        }
      }
      break;

      case METHOD_JOIN:
      {
        if (IS_REQUEST(message_code)) {
          message_type_str = "JoinReq";
          dissect_joinreq(tvb, pinfo, message_body_tree, offset, message_body_length);
        }
        else {
          message_type_str = "JoinAns";
          dissect_joinans(tvb, pinfo, message_body_tree, offset, message_body_length);
        }
      }
      break;

      case METHOD_UPDATE:
        if (0==strcmp(TOPOLOGY_PLUGIN_CHORD_RELOAD, reload_topology_plugin)) {
          if (IS_REQUEST(message_code)) {
            message_type_str = "ChordUpdate";
            dissect_chordupdate(tvb, pinfo, message_body_tree, offset, message_body_length);
          }
        }
        break;

      case METHOD_PATH_TRACK:
        if (IS_REQUEST(message_code)) {
          message_type_str = "PathTrackReck";
          dissect_pathtrackreq(tvb, pinfo, message_body_tree, offset, message_body_length);
        }
        else {
          message_type_str = "PathTrackAns";
          dissect_pathtrackans(tvb, pinfo, message_body_tree, offset, message_body_length);
        }
        break;

      default:
        break;
      }
    }
    if (message_type_str!= NULL) {
      proto_item_append_text(ti_message_body, " (%s<%d>)", message_type_str, message_body_length);
    }
    else {
      proto_item_append_text(ti_message_body,
                             " (%s%s<%d>)",
                             val_to_str(MSGCODE_TO_METHOD(message_code),methods,"opaque"),
                             val_to_str(MSGCODE_TO_CLASS(message_code), classes_Short, ""),
                             message_body_length);

    }
  }
  else {
    /* Error Response */
    guint16 error_length, error_code;
    proto_item *ti_message_body;
    proto_tree *message_body_tree;
    proto_item *ti_error;
    proto_tree *error_tree;

    /* message_code was already parsed */
    proto_tree_add_uint_format_value(message_contents_tree, hf_reload_message_code, tvb, offset, 2, message_code, "Error");
    offset += 2;

    /* Message body */
    ti_message_body = proto_tree_add_item(message_contents_tree, hf_reload_message_body, tvb, offset, 4 + message_body_length, ENC_NA);
    message_body_tree = proto_item_add_subtree(ti_message_body, ett_reload_message_body);
    error_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(message_body_tree, hf_reload_length_uint32, tvb, offset, 4, message_body_length);
    offset +=4;

    error_code = tvb_get_ntohs(tvb, offset);
    if (2 + 2 + error_length >length) {
      expert_add_info_format(pinfo, ti_message_body, PI_PROTOCOL, PI_ERROR, "Truncated error message");
      return length;
    }

    ti_error = proto_tree_add_item(message_body_tree, hf_reload_error_response, tvb, offset, 2 + 2 + error_length, ENC_NA);
    error_tree = proto_item_add_subtree(ti_error, ett_reload_error_response);
    proto_tree_add_item(error_tree, hf_reload_error_response_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text(ti_error, ": %s", val_to_str(error_code, errorcodes, "Unknown"));
    switch(error_code) {
    case ERRORCODE_GENERATIONCOUNTERTOOLOW:
    {
      guint16 local_length = tvb_get_ntohs(tvb, offset+2);
      proto_tree_add_item(error_tree, hf_reload_length_uint16, tvb, offset+2, 2, ENC_BIG_ENDIAN);
      dissect_storeans(tvb, pinfo, error_tree, offset+4, local_length);
    }
    break;

    case ERRORCODE_UNKNOWNKIND:
    {
      guint16 local_length = tvb_get_ntohs(tvb, offset+2);
      proto_tree_add_item(error_tree, hf_reload_length_uint16, tvb, offset+2, 2, ENC_BIG_ENDIAN);
      dissect_kindid_list(tvb, pinfo, error_tree, offset+4, local_length,1);
    }
    break;

    case ERRORCODE_UNDERLAY_DESTINATION_UNREACHABLE:
    {
      proto_tree_add_item(error_tree, hf_reload_opaque_string, tvb, offset+2, 32, ENC_ASCII|ENC_NA);
    }
    break;

    default:
      dissect_opaque_string(tvb, pinfo, error_tree, hf_reload_error_response_info, offset+2, 2, -1);
      if (error_code <= 19) {
        guint16 info_length = tvb_get_ntohs(tvb,offset+2);
        if (info_length>0) {
          proto_item_append_text(ti_error, " (%s)", tvb_get_ephemeral_string(tvb, offset+4, info_length));
        }
      }
      break;
    }
  }
  offset += message_body_length;

  {
    proto_tree *extensions_tree;
    proto_item *ti_extensions;
    proto_tree *extension_tree;
    guint16 extension_offset = 0;
    int nExtensions = 0;

    ti_extensions =
      proto_tree_add_item(message_contents_tree, hf_reload_message_extensions, tvb, offset, 4+extensions_length, ENC_NA);
    extensions_tree = proto_item_add_subtree(ti_extensions, ett_reload_message_extensions);
    proto_tree_add_item(extensions_tree, hf_reload_length_uint32, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    while (extension_offset < extensions_length) {
      guint16 type;
      proto_item *ti_extension;
      guint32 extension_content_length = tvb_get_ntohl(tvb, offset + extension_offset + 3);
      if ((extension_offset + 3 + 4 + extension_content_length) > extensions_length) {
        expert_add_info_format(pinfo, ti_extensions, PI_PROTOCOL, PI_ERROR, "Truncated message extensions");
        break;
      }
      ti_extension = proto_tree_add_item(extensions_tree, hf_reload_message_extension, tvb, offset+ extension_offset, 3 + 4 + extension_content_length, ENC_NA);
      extension_tree = proto_item_add_subtree(ti_extension, ett_reload_message_extension);
      type = tvb_get_ntohs(tvb, offset+ extension_offset);
      proto_tree_add_item(extension_tree, hf_reload_message_extension_type, tvb, offset+ extension_offset, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(extension_tree, hf_reload_message_extension_critical, tvb, offset+ extension_offset + 2, 1, ENC_BIG_ENDIAN);
      switch(type) {

      case MESSAGEEXTENSIONTYPE_SELF_TUNING_DATA:
      {
        guint32 extension_length;
        proto_tree_add_item(extension_tree, hf_reload_length_uint32, tvb, offset+extension_offset+3, 4, ENC_BIG_ENDIAN);
        extension_length = tvb_get_ntohl(tvb, offset+extension_offset+3);
        if (extension_length > 0) {
          dissect_selftuningdata(tvb, extension_tree, offset+extension_offset+3+4);
        }
      }
      break;

      case MESSAGEEXTENSIONTYPE_DIAGNOSTIC_PING:
      {
        guint32 extension_length;
        proto_tree_add_item(extension_tree, hf_reload_length_uint32, tvb, offset+extension_offset+3, 4, ENC_BIG_ENDIAN);
        extension_length = tvb_get_ntohl(tvb, offset+extension_offset+3);
        if ((extension_length > 0) && (MSGCODE_TO_METHOD(message_code)==METHOD_PING)) {
          if (IS_REQUEST(message_code)) {
            dissect_diagnosticrequest(-1, tvb, pinfo, extension_tree, offset+extension_offset+3+4, extension_length);
          }
          else {
            dissect_diagnosticresponse(-1, tvb, pinfo, extension_tree, offset+extension_offset+3+4, extension_length);
          }
        }
      }
      break;

      default:
        dissect_opaque(tvb, pinfo, extension_tree, hf_reload_message_extension_content, offset + extension_offset + 3, 4, -1);
        break;
      }
      extension_offset += 3 + 4 + extension_content_length;
      nExtensions ++;
    }
    proto_item_append_text(ti_extensions, " (%d elements)", nExtensions);
  }
  offset += extensions_length;

  return ( 2 + 4 + message_body_length + 4 + extensions_length);
}

static int
dissect_reload_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *reload_tree;
  guint32 relo_token;
  guint effective_length;
  guint msg_length, dgram_msg_length;
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
  guint32 fragment = 0;
  gboolean save_fragmented = FALSE;
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
  dgram_msg_length = msg_length;

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

  ti = proto_tree_add_item(tree, proto_reload, tvb, 0, -1, FALSE);

  reload_tree = proto_item_add_subtree(ti, ett_reload);

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
  {
    proto_item *ti_tmp;
    guint16 tmp;
    tmp = tvb_get_ntohs(tvb,8);
    ti_tmp = proto_tree_add_item(reload_forwarding_tree, hf_reload_configuration_sequence, tvb, 8, 2, ENC_BIG_ENDIAN);
    if (tmp==0) {
      proto_item_append_text(ti_tmp, "\n  [sequence value not verified]");
    }
  }
  proto_tree_add_item(reload_forwarding_tree, hf_reload_version, tvb, 10, 1, ENC_BIG_ENDIAN);

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
  proto_tree_add_uint(reload_forwarding_tree, hf_reload_length_uint32, tvb, 16, 4, msg_length);
  proto_tree_add_item(reload_forwarding_tree, hf_reload_trans_id, tvb, 20, 8, ENC_BIG_ENDIAN);
  {
    proto_item *ti_tmp;
    guint32 tmp;
    tmp =tvb_get_ntohl(tvb,28);
    ti_tmp = proto_tree_add_item(reload_forwarding_tree, hf_reload_max_response_length, tvb, 28, 4, ENC_BIG_ENDIAN);
    if (0==tmp) {
      proto_item_append_text(ti_tmp, "\n  [Response length not restricted]");
    }
  }
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
    int numDestinations=0;
    ti_vialist = proto_tree_add_item(reload_forwarding_tree, hf_reload_via_list, tvb, offset, via_list_length, ENC_NA);
    vialist_tree = proto_item_add_subtree(ti_vialist, ett_reload_via_list);

    dissect_destination_list(tvb, pinfo, vialist_tree, offset, via_list_length, &numDestinations);
    proto_item_append_text(ti_vialist, " (Destination<%d>): %d elements",via_list_length,numDestinations);
  }
  offset += via_list_length;

  if (((guint)offset + destination_list_length) > msg_length) {
    expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_ERROR, "Truncated RELOAD packet");
    return offset;
  }

  if (destination_list_length > 0) {
    proto_item *ti_destination_list;
    proto_tree *destination_list_tree;
    int numDestinations;
    ti_destination_list = proto_tree_add_item(reload_forwarding_tree, hf_reload_destination_list, tvb, offset, destination_list_length, ENC_NA);
    destination_list_tree = proto_item_add_subtree(ti_destination_list, ett_reload_destination_list);

    dissect_destination_list(tvb, pinfo, destination_list_tree, offset, destination_list_length, &numDestinations);
    proto_item_append_text(ti_destination_list, " (Destination<%d>): %d elements",destination_list_length,numDestinations);
  }
  offset += destination_list_length;

  if (((guint)offset + options_length) > msg_length) {
    expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_ERROR, "Truncated RELOAD packet");
    return offset;
  }

  if (options_length > 0) {
    guint16 local_offset = 0;
    proto_item *ti_options;
    proto_tree *options_tree;
    int nOptions=0;

    ti_options = proto_tree_add_item(reload_forwarding_tree, hf_reload_forwarding_options, tvb, offset+local_offset, options_length, ENC_NA);
    options_tree = proto_item_add_subtree(ti_options, ett_reload_forwarding_options);
    while (local_offset < options_length) {
      int local_increment;
      local_increment = dissect_forwardingoption(tvb, pinfo, options_tree, offset+local_offset, options_length-local_offset);
      if (0>=local_increment) break;
      local_offset += local_increment;
      nOptions++;
    }
    proto_item_append_text(ti_options, " (ForwardingOption<%d>): %d elements",options_length,nOptions);
  }
  offset += options_length;

  if ((reload_defragment) && ((fragmented != FALSE) && !((fragment == 0) && (last_fragment)))) {
    tvbuff_t   *next_tvb = NULL;
    reload_fd_head = NULL;

    if (tvb_bytes_exist(tvb, offset, msg_length - offset)) {
      reload_fd_head = fragment_add_check(tvb, offset, pinfo,
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
      col_add_fstr(pinfo->cinfo, COL_INFO, "Fragmented RELOAD protocol (trans id=%x%x off=%u",
                   transaction_id[0],transaction_id[1], fragment);
      if (reload_fd_head && reload_fd_head->reassembled_in != pinfo->fd->num) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " [Reassembled in #%u]",
                        reload_fd_head->reassembled_in);
      }
      save_fragmented = pinfo->fragmented;
      pinfo->fragmented = TRUE;
      call_dissector(data_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree);
      pinfo->fragmented = save_fragmented;
      return effective_length;
    }
    tvb = next_tvb;
    msg_length -= offset; /* need to adjust the length, as the new tvb starts after the forwarding header */
    offset = 0;
  }

  effective_length = tvb_length(tvb);
  if (effective_length < msg_length) {
    /* The effective length is too small for the packet */
    expert_add_info_format(pinfo, NULL, PI_PROTOCOL, PI_ERROR, "Truncated RELOAD packet");
    return 0;
  }

  /*Handle retransmission after reassembly since we use message_contents for it */

  message_code = tvb_get_ntohs(tvb, offset);

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

  if (message_code == RELOAD_ERROR) {
    error_code = tvb_get_ntohs(tvb, forwarding_length + 2+4);
    msg_class_str = "Error Response";
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", msg_class_str, val_to_str(error_code, errorcodes, "Unknown"));
    proto_item_append_text(ti, ": %s %s", msg_class_str, val_to_str(error_code, errorcodes, "Unknown"));
  }
  else {
    msg_class_str = val_to_str(MSGCODE_TO_CLASS(message_code), classes, "Unknown %d");
    msg_method_str = val_to_str(MSGCODE_TO_METHOD(message_code), methods, "Unknown %d");

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                 msg_method_str, msg_class_str);
    proto_item_append_text(ti, ": %s %s", msg_method_str, msg_class_str);
  }


  offset += dissect_reload_messagecontents(tvb, pinfo, reload_tree, offset, (effective_length - offset));

  /* Security Block */
  {
    proto_item *ti_security_block;
    proto_tree *security_block_tree;
    proto_item *ti_certificates;
    proto_tree *certificates_tree;
    guint16 certificates_length;
    guint16 signeridentityvalue_length;
    guint16 signaturevalue_length;
    guint16 security_block_offset = 0;

    certificates_length = tvb_get_ntohs(tvb, offset);
    security_block_offset += 2 + certificates_length;
    security_block_offset += 2; /* SignatureAndHashAlgorithm     algorithm; */
    security_block_offset += 1; /* SignerIdentityType     identity_type; */
    signeridentityvalue_length = tvb_get_ntohs(tvb, offset +security_block_offset);
    security_block_offset += 2;
    security_block_offset += signeridentityvalue_length;
    signaturevalue_length = tvb_get_ntohs(tvb, offset +security_block_offset);
    security_block_offset += 2;
    security_block_offset += signaturevalue_length;

    ti_security_block = proto_tree_add_item(reload_tree, hf_reload_security_block, tvb, offset,
                                            security_block_offset, ENC_NA);
    security_block_tree = proto_item_add_subtree(ti_security_block, ett_reload_security_block);
    /* start parsing from the beginning */
    security_block_offset = 0;
    ti_certificates = proto_tree_add_item(security_block_tree,
                                          hf_reload_certificates, tvb, offset,
                                          2 + certificates_length,
                                          ENC_NA);
    proto_item_append_text(ti_certificates, " (GenericCertificate<%d>)", certificates_length);
    certificates_tree = proto_item_add_subtree(ti_certificates, ett_reload_certificates);
    proto_tree_add_uint(certificates_tree, hf_reload_length_uint16, tvb, offset, 2, certificates_length);
    security_block_offset += 2;
    /* certificates */

    {
      guint16 certificate_offset = 0;
      int nCertificates = 0;
      while (certificate_offset < certificates_length) {
        proto_item *ti_genericcertificate;
        proto_tree *genericcertificate_tree;
        guint16 certificate_length;

        certificate_length = tvb_get_ntohs(tvb, offset + security_block_offset + certificate_offset + 1);
        if (certificate_offset + 1 + 2 + certificate_length > certificates_length) {
          expert_add_info_format(pinfo, ti_security_block, PI_PROTOCOL, PI_ERROR, "Truncated certificate");
          break;
        }
        ti_genericcertificate =
          proto_tree_add_item(certificates_tree,
                              hf_reload_genericcertificate, tvb, offset + security_block_offset + certificate_offset,
                              1 + 2 + certificate_length,
                              ENC_NA);
        genericcertificate_tree = proto_item_add_subtree(ti_genericcertificate, ett_reload_genericcertificate);

        proto_tree_add_item(genericcertificate_tree, hf_reload_certificate_type, tvb,
                            offset + security_block_offset + certificate_offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(genericcertificate_tree, hf_reload_length_uint16, tvb,
                            offset + security_block_offset + certificate_offset+1, 2, ENC_BIG_ENDIAN);

        switch (tvb_get_guint8(tvb, offset + security_block_offset + certificate_offset)) {
        case 0: {
          asn1_ctx_t asn1_ctx;

          asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
          dissect_x509af_Certificate(FALSE, tvb, offset + security_block_offset + certificate_offset + 1 + 2, &asn1_ctx,
                                     genericcertificate_tree, hf_reload_certificate);
        }
        break;

        default:
          dissect_opaque(tvb, pinfo, genericcertificate_tree, hf_reload_certificate, offset + security_block_offset + certificate_offset + 1, 2, -1);
        }
        certificate_offset += 1 + 2 + certificate_length;
        nCertificates++;
      }
      proto_item_append_text(ti_certificates, ": %d elements", nCertificates);
    }

    security_block_offset += certificates_length;

    dissect_signature(tvb, pinfo, security_block_tree, offset + security_block_offset);
    /* Signature */
  }


  return dgram_msg_length;
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
        BASE_NONE, NULL, 0x0, "The response to this RELOAD Request is in this frame", HFILL
      }
    },
    { &hf_reload_response_to,
      { "Request in", "reload.response-to", FT_FRAMENUM,
        BASE_NONE, NULL, 0x0, "This is a response to the RELOAD Request in this frame", HFILL
      }
    },
    { &hf_reload_time,
      { "Time", "reload.time", FT_RELATIVE_TIME,
        BASE_NONE, NULL, 0x0, "The time between the Request and the Response", HFILL
      }
    },
    { &hf_reload_duplicate,
      { "Duplicated original message in", "reload.duplicate", FT_FRAMENUM,
        BASE_NONE, NULL, 0x0, "This is a duplicate of RELOAD message in this frame", HFILL
      }
    },
    { &hf_reload_forwarding,
      { "ForwardingHeader",    "reload.forwarding",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_token,
      { "relo_token (uint32)", "reload.forwarding.token",  FT_UINT32,
        BASE_HEX, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_overlay,
      { "overlay (uint32)",  "reload.forwarding.overlay",  FT_UINT32,
        BASE_HEX, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_configuration_sequence,
      { "configuration_sequence (uint16)", "reload.forwarding.configuration_sequence", FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_version,
      { "version (uint8)",  "reload.forwarding.version",  FT_UINT8,
        BASE_HEX, VALS(versions), 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_ttl,
      { "ttl (uint8)",  "reload.forwarding.ttl",  FT_UINT8,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_fragment_flag,
      { "fragment (uint32)", "reload.forwarding.fragment", FT_UINT32,
        BASE_HEX, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_fragment_fragmented,
      { "Fragmented (always set)", "reload.forwarding.fragment.fragmented", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_fragment_last_fragment,
      { "Last Fragment", "reload.forwarding.fragment.last", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_fragment_reserved,
      { "Reserved (always 0)", "reload.forwarding.fragment.reserved", FT_BOOLEAN, 1, NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_fragment_offset,
      { "Fragment Offset","reload.forwarding.fragment.offset",  FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_trans_id,
      { "transaction_id (uint32)", "reload.forwarding.trans_id", FT_UINT64,
        BASE_HEX, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_max_response_length,
      { "max_response_length (uint32)",  "reload.forwarding.max_response_length",  FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_via_list_length,
      { "via_list_length (uint16)",  "reload.forwarding.via_list.length",  FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_destination_list_length,
      { "destination_list_length (uint16)",  "reload.forwarding.destination_list.length",  FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_options_length,
      { "options_length (uint16)", "reload.forwarding.options.length", FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_via_list,
      { "via_list",   "reload.forwarding.via_list", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_destination,
      { "Destination",    "reload.destination",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_destination_compressed_id,
      { "compressed_id (uint16)", "reload.forwarding.destination.compressed_id",  FT_UINT16,
        BASE_HEX, NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_destination_type,
      { "type (DestinationType)",    "reload.forwarding.destination.type",  FT_UINT8,
        BASE_HEX, VALS(destinationtypes), 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_destination_data_node_id,
      { "node_id (NodeId)",    "reload.destination.data.nodeid", FT_BYTES,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_destination_data_resource_id,
      { "resource_id",    "reload.destination.data.resourceid", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_nodeid,
      { "NodeId",    "reload.nodeid", FT_BYTES,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_resourceid,
      { "ResourceId",    "reload.resource_id", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_destination_data_compressed_id,
      { "compressed_id",    "reload.destination.data.compressed_id",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_destination_list,
      { "destination_list",   "reload.forwarding.destination_list", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_forwarding_options,
      { "options",    "reload.forwarding.option", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_forwarding_option,
      { "ForwardingOption",    "reload.forwarding.option", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_forwarding_option_type,
      { "type (ForwardingOptionType)", "reload.forwarding.option.type",  FT_UINT8,
        BASE_DEC, VALS(forwardingoptiontypes),  0x0,  NULL, HFILL
      }
    },
    { &hf_reload_forwarding_option_flags,
      { "flags (uint8)",  "reload.forwarding.option.flags", FT_UINT8,
        BASE_HEX, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_forwarding_option_flag_ignore_state_keeping,
      { "IGNORE_STATE_KEEPING", "reload.forwarding.option.flag.response_copy", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_forwarding_option_flag_response_copy,
      { "RESPONSE_COPY", "reload.forwarding.option.flag.response_copy", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_forwarding_option_flag_destination_critical,
      { "DESTINATION_CRITICAL", "reload.forwarding.option.flags.destination_critical", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_forwarding_option_flag_forward_critical,
      { "FORWARD_CRITICAL", "reload.forwarding.option.flags.forward_critical", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_attachreqans,
      { "AttachReqAns", "reload.attachreqans",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_ufrag,
      { "ufrag",  "reload.ufrag", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_password,
      { "password", "reload.password",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_role,
      { "role", "reload.role",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_icecandidates,
      { "candidates",   "reload.icecandidates", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_icecandidate,
      { "IceCandidate",    "reload.icecandidate",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_icecandidate_addr_port,
      { "addr_port",    "reload.icecandidate.addr_port",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_icecandidate_relay_addr,
      { "rel_addr_port",    "reload.icecandidate.relay_addr", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_ipaddressport,
      { "IpAddressPort",    "reload.ipaddressport", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_ipaddressport_type,
      { "type (AddressType)", "reload.ipaddressport.type",  FT_UINT8,
        BASE_HEX, VALS(ipaddressporttypes), 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_ipv4addrport,
      { "IPv4AddrPort",    "reload.ipv4addrport", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_ipv4addr,
      { "addr (uint32)", "reload.ipv4addr",  FT_IPv4,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_ipv6addrport,
      { "IPv6AddrPort",    "reload.ipv6addrport", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_ipv6addr,
      { "addr (uint128)", "reload.ipv6addr",  FT_IPv6,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_port,
      { "port (uint16)", "reload.port",  FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_overlaylink_type,
      { "overlay_link (OverlayLinkType)",  "reload.overlaylink.type",  FT_UINT8,
        BASE_DEC, VALS(overlaylinktypes), 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_icecandidate_foundation,
      { "foundation", "reload.icecandidate.foundation", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_icecandidate_priority,
      { "priority (uint32)", "reload.icecandidate.priority", FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_icecandidate_type,
      { "Ice candidate type", "reload.icecandidate.type", FT_UINT8,
        BASE_DEC, VALS(candtypes),  0x0,  NULL, HFILL
      }
    },
    { &hf_reload_iceextensions,
      { "extensions",    "reload.iceextensions",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_iceextension,
      { "IceExtension",    "reload.iceextension",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_iceextension_name,
      { "name", "reload.iceextension.name", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_iceextension_value,
      { "value",  "reload.iceextension.value",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_sendupdate,
      { "send_update (Boolean)", "reload.sendupdate",  FT_BOOLEAN,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_message_contents,
      { "MessageContents",   "reload.message.contents",  FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_message_code,
      { "message_code (uint16)", "reload.message.code",  FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_message_body,
      { "message_body", "reload.message.body",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_message_extensions,
      { "extensions",  "reload.message.extensions", FT_NONE,
        BASE_NONE, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_message_extension,
      { "MessageExtension",    "reload.message_extension", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_message_extension_type,
      { "type (MessageExtensionType)", "reload.message_extension.type",  FT_UINT16,
        BASE_DEC, VALS(messageextensiontypes), 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_message_extension_critical,
      { "critical (Boolean)", "reload.message_extension.critical",  FT_BOOLEAN,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_message_extension_content,
      { "extension_content",  "reload.message_extension.content", FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_error_response,
      { "ErrorResponse", "reload.error_response",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_error_response_code,
      { "error_code (uint16)", "reload.error_response.code", FT_UINT16,
        BASE_DEC, VALS(errorcodes), 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_error_response_info,
      { "error_info", "reload.error_response_info", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_security_block,
      { "SecurityBlock", "reload.security_block",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_certificates,
      { "certificates",  "reload.certificates", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_certificate_type,
      { "type (CertificateType)", "reload.certificate.type",  FT_UINT8,
        BASE_DEC, VALS(tls_certificate_type), 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_genericcertificate,
      { "GenericCertificate", "reload.genericcertificate",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_certificate,
      { "certificate", "reload.certificate",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_signature,
      { "signature (Signature)",  "reload.signature", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_signatureandhashalgorithm,
      { "algorithm (SignatureAndHashAlgorithm)",  "reload.signatureandhashalgorithm", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_hash_algorithm,
      { "hash (HashAlgorithm)", "reload.hash_algorithm",  FT_UINT8,
        BASE_DEC, VALS(tls_hash_algorithm), 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_signeridentity_value_hash_alg,
      { "hash_alg (HashAlgorithm)", "reload.signeridentityvalue.hash_alg",  FT_UINT8,
        BASE_DEC, VALS(tls_hash_algorithm), 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_signature_algorithm,
      { "signature (SignatureAlgorithm)",  "reload.signature_algorithm", FT_UINT8,
        BASE_DEC, VALS(tls_signature_algorithm),  0x0,  NULL, HFILL
      }
    },
    { &hf_reload_signeridentity,
      { "identity (SignerIdentity)", "reload.signature.identity",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_signeridentity_identity,
      { "identity", "reload.signature.identity.identity",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_signeridentity_type,
      { "identity_type (SignerIdentityType)",  "reload.signature.identity.type", FT_UINT8,
        BASE_DEC, VALS(signeridentitytypes), 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_signeridentity_value,
      { "SignatureIdentityValue", "reload.signature.identity.value",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_signeridentity_value_certificate_hash,
      { "certificate_hash",  "reload.signature.identity.value.certificate_hash", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_signeridentity_value_certificate_node_id_hash,
      { "certificate_node_id_hash",  "reload.signature.identity.value.certificate_node_id_hash", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_signature_value,
      { "signature_value",  "reload.signature.value.",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_length_uint8,
      { "length (uint8)", "reload.length.8", FT_UINT8,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_length_uint16,
      { "length (uint16)", "reload.length.16", FT_UINT16,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_length_uint24,
      { "length (uint24)", "reload.length.24", FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_length_uint32,
      { "length (uint32)", "reload.length.32",  FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_opaque,
      { "opaque",  "reload.opaque", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_opaque_data,
      { "data (bytes)", "reload.opaque.data", FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_opaque_string,
      { "data (string)", "reload.opaque.string", FT_STRING,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_routequeryreq,
      { "RouteQueryReq",  "reload.routequeryreq", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_routequeryreq_destination,
      { "destination",  "reload.routequeryreq.destination", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_overlay_specific,
      { "overlay_specific_data",  "reload.overlay_specific_data", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_probereq,
      { "ProbeReq", "reload.probereq",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_probereq_requested_info,
      { "requested_info", "reload.probereq.requested_info",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_probe_information,
      { "ProbeInformation",  "reload.probe_information", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_probe_information_data,
      { "value (ProbeInformationData)",  "reload.probe_information", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_probe_information_type,
      { "type (ProbeInformationType)", "reload.probe_information.type", FT_UINT8,
        BASE_HEX, VALS(probeinformationtypes),  0x0,  NULL, HFILL
      }
    },
    { &hf_reload_responsible_set,
      { "responsible_ppb (uint32)",  "reload.responsible_set", FT_UINT32,
        BASE_HEX, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_num_resources,
      { "num_resources (uint32)",  "reload.num_resources", FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_uptime,
      { "uptime (uint32)", "reload.uptime", FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_probeans,
      { "ProbeAns",  "reload.probeans", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_probeans_probe_info,
      { "probe_info",  "reload.probeans", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_appattachreq,
      { "AppAttachReq", "reload.appattachreq", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_appattachans,
      { "AppAttachAns", "reload.appattachans", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_application,
      { "application (uint16)", "reload.application", FT_UINT16,
        BASE_DEC, VALS(applicationids), 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_ping_response_id,
      { "response_id (uint64)", "reload.ping.response_id",  FT_UINT64,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_ping_time,
      { "time (uint64)", "reload.ping.time", FT_ABSOLUTE_TIME,
        ABSOLUTE_TIME_UTC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_storeddata,
      { "StoredData",  "reload.storeddata", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_storedmetadata,
      { "StoredMetaData",  "reload.storedmetadata", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_storeddata_storage_time,
      { "storage_time (uint64)", "reload.storeddata.storage_time", FT_ABSOLUTE_TIME,
        ABSOLUTE_TIME_UTC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_storeddata_lifetime,
      { "lifetime (uint32)",  "reload.storeddata.lifetime", FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_datavalue,
      { "DataValue",  "reload.datavalue", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_value,
      { "value",  "reload.value", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_metadata,
      { "MetaData",  "reload.metadata", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_datavalue_exists,
      { "exists (Boolean)", "reload.datavalue.exists",  FT_BOOLEAN,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_datavalue_value,
      { "value",    "reload.datavaluevalue", FT_NONE,
        BASE_NONE,  NULL,   0x0,  NULL, HFILL
      }
    },
    { &hf_reload_metadata_value_length,
      { "value_length (uint32)",  "reload.metadata.value_length", FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { & hf_reload_metadata_hash_value,
      { "hash_value",  "reload.metadata.hash_value", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_arrayentry,
      { "ArrayEntry",  "reload.arrayentry", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_arrayentry_index,
      { "index (uint32)",  "reload.arrayentry.index", FT_UINT32,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_arrayentry_value,
      { "value",  "reload.arrayentry.value", FT_NONE,
        BASE_NONE, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_dictionaryentry,
      { "DictionaryEntry",  "reload.dictionaryentry", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_dictionarykey,
      { "key (DictionaryKey)",  "reload.dictionarykey", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_dictionary_value,
      { "value (DataValue)",  "reload.dictionary.value", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_kinddata,
      { "StoreKindData",  "reload.kinddata", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_kinddata_kind,
      { "kind (KindId)",  "reload.kinddata.kind", FT_UINT32,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_statkindresponse,
      { "StatKindResponse",  "reload.statkindresponse", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_kindid,
      { "KindId",  "reload.kindid",  FT_UINT32,
        BASE_DEC, NULL,  0x0,  NULL, HFILL
      }
    },
    { &hf_reload_kindid_list,
      { "kinds",  "reload.kindid_list", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_generation_counter,
      { "generation_counter (uint64)", "reload.generation_counter", FT_UINT64,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_values,
      { "values",  "reload.kinddata.values_length",  FT_NONE,
        BASE_NONE, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_storereq,
      { "StoreReq", "reload.storereq", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_resource,
      { "resource", "reload.resource", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_store_replica_num,
      { "replica_number (uint8)",  "reload.store.replica_number", FT_UINT8,
        BASE_DEC, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_store_kind_data,
      { "kind_data",  "reload.store.kind_data",  FT_NONE,
        BASE_NONE, NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_storeans,
      { "StoreAns", "reload.storeans", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_storeans_kind_responses,
      { "kind_responses", "reload.storeans.kind_responses", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_storekindresponse,
      { "StoreKindResponse", "reload.storekindresponse", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_replicas,
      { "replicas", "reload.storekindresponse.replicas", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_statreq,
      { "StatReq", "reload.statreq", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_fetchans,
      { "FetchAns", "reload.fetchans", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_fetchreq,
      { "FetchReq", "reload.fetchreq", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_fetchreq_specifiers,
      { "specifiers", "reload.fetchreq.specifiers", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_arrayrange,
      { "ArrayRange", "reload.arrayrange", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_storeddataspecifier,
      { "StoredDataSpecifier", "reload.storeddataspecifier", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_storeddataspecifier_indices,
      { "indices", "reload.storeddataspecifier.indices", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_storeddataspecifier_keys,
      { "indices", "reload.storeddataspecifier.keys", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_statans,
      { "StatAns",  "reload.statans", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_findans,
      { "FindAns",  "reload.findans", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_findkinddata_closest,
      { "closest",  "reload.findkindata.closest", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_findkinddata,
      { "FindKindData", "reload.findkinddata", FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_fragment_overlap,
      { "Fragment overlap", "reload.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Fragment overlaps with other fragments", HFILL
      }
    },

    { &hf_reload_fragment_overlap_conflict,
      { "Conflicting data in fragment overlap", "reload.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Overlapping fragments contained conflicting data", HFILL
      }
    },

    { &hf_reload_fragment_multiple_tails,
      { "Multiple tail fragments found",  "reload.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Several tails were found when defragmenting the packet", HFILL
      }
    },

    { &hf_reload_fragment_too_long_fragment,
      { "Fragment too long",  "reload.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Fragment contained data past end of packet", HFILL
      }
    },

    { &hf_reload_fragment_error,
      { "Defragmentation error", "reload.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "Defragmentation error due to illegal fragments", HFILL
      }
    },

    { &hf_reload_fragment_count,
      { "Fragment count", "reload.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL
      }
    },

    { &hf_reload_fragment,
      { "RELOAD fragment", "reload.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },

    { &hf_reload_fragments,
      { "RELOAD fragments", "reload.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL
      }
    },

    { &hf_reload_reassembled_in,
      { "Reassembled RELOAD in frame", "reload.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "This RELOAD packet is reassembled in this frame", HFILL
      }
    },

    { &hf_reload_reassembled_length,
      { "Reassembled RELOAD length", "reload.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
        "The total length of the reassembled payload", HFILL
      }
    },

    { &hf_reload_configupdatereq,
      { "ConfigUpdateReq",  "reload.configupdatereq.",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },

    { &hf_reload_configupdatereq_type,
      { "type (ConfigUpdateType)", "reload.configupdatereq.type", FT_UINT8,
        BASE_DEC, VALS(configupdatetypes),  0x0,  NULL, HFILL
      }
    },

    { &hf_reload_configupdatereq_configdata,
      { "config_data",  "reload.configupdatereq.config_data",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },

    { &hf_reload_configupdatereq_kinds,
      { "kinds",  "reload.configupdatereq.kinds",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_kinddescription,
      { "KindDescription",  "reload.configupdatereq.kinds",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_pingreq,
      { "PingReq",  "reload.padding",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_pingans,
      { "PingAns",  "reload.padding",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_padding,
      { "padding",  "reload.padding",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },

    { &hf_reload_chordupdate,
      { "ChordUpdate",  "reload.chordupdate",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_chordupdate_type,
      { "type (ChordUpdateType)", "reload.chordupdate.type", FT_UINT8,
        BASE_DEC, VALS(chordupdatetypes),  0x0,  NULL, HFILL
      }
    },
    { &hf_reload_chordupdate_predecessors,
      { "predecessors",  "reload.chordupdate.predecessors",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_chordupdate_successors,
      { "successors",  "reload.chordupdate.predecessors",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_chordupdate_fingers,
      { "fingers",  "reload.chordupdate.fingers",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_chordroutequeryans,
      { "ChordRouteQueryAns",  "reload.chordroutequeryans",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_chordroutequeryans_next_peer,
      { "next_peer (NodeId)",  "reload.chordroutequeryans.nodeid",  FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_chordleave,
      { "ChordLeaveData",  "reload.chordleavedata",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_chordleave_type,
      { "type (ChordLeaveType)", "reload.chordleavedata.type", FT_UINT8,
        BASE_DEC, VALS(chordleavetypes),  0x0,  NULL, HFILL
      }
    },
    { &hf_reload_chordleave_predecessors,
      { "predecessors",  "reload.chordleavedata.predecessors",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_chordleave_successors,
      { "successors",  "reload.chordleavedata.predecessors",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_turnserver,
      { "TurnServer",  "reload.turnserver",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_turnserver_iteration,
      { "iteration (uint8)",  "reload.turnserver.iteration",  FT_UINT8,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_turnserver_server_address,
      { "server_address",  "reload.turnserver.server_address",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_sipregistration,
      { "SipRegistration",  "reload.sipregistration",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_sipregistration_type,
      { "type (SipRegistrationType)",  "reload.sipregistration.type",  FT_UINT8,
        BASE_DEC,  VALS(sipregistrationtypes), 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_sipregistration_data,
      { "data (SipRegistrationData)",  "reload.sipregistration.data",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_sipregistration_data_uri,
      { "uri",  "reload.sipregistration.data.uri",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_sipregistration_data_contact_prefs,
      { "contact_prefs",  "reload.sipregistration.data.contact_prefs",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_sipregistration_data_destination_list,
      { "destination_list",  "reload.sipregistration.data.destination_list",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_redirserviceprovider,
      { "RedirServiceProvider",  "reload.redirserviceprovider",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_redirserviceproviderdata,
      { "data (RedirServiceProviderData)",  "reload.redirserviceprovider.data",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_redirserviceproviderdata_serviceprovider,
      { "serviceProvider (NodeId)",  "reload.redirserviceprovider.data.serviceprovider",  FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_redirserviceproviderdata_namespace,
      { "namespace",  "reload.redirserviceprovider.data.namespace",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_redirserviceproviderdata_level,
      { "level (uint16)",  "reload.redirserviceprovider.data.level",  FT_UINT16,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_redirserviceproviderdata_node,
      { "node (uint16)",  "reload.redirserviceprovider.data.node",  FT_UINT16,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_self_tuning_data,
      { "SelfTuningData",  "reload.selftuning_data",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_self_tuning_data_network_size,
      { "network_size (uint32)",  "reload.selftuning_data.network_size",  FT_UINT32,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_self_tuning_data_join_rate,
      { "join_rate (uint32)",  "reload.selftuning_data.join_rate",  FT_UINT32,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_self_tuning_data_leave_rate,
      { "leave_rate (uint32)",  "reload.selftuning_data.leave_rate",  FT_UINT32,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_findreq,
      { "FindReq",  "reload.findreq",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_dmflags,
      { "dMFlags (uint64)",  "reload.dmflags",  FT_UINT64,
        BASE_HEX,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_dmflag_status_info,
      { "STATUS_INFO", "reload.dmflags.status_info", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_dmflag_routing_table_size,
      { "ROUTING_TABLE_SIZE", "reload.dmflags.routing_table_size", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_dmflag_process_power,
      { "PROCESS_POWER", "reload.dmflags.process_power", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_dmflag_bandwidth,
      { "BANDWIDTH", "reload.dmflags.bandwidth", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_dmflag_software_version,
      { "SOFTWARE_VERSION", "reload.dmflags.software_version", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_dmflag_machine_uptime,
      { "MACHINE_UPTIME", "reload.dmflags.machine_uptime", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_dmflag_app_uptime,
      { "APP_UPTIME", "reload.dmflags.app_uptime", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_dmflag_memory_footprint,
      { "MEMORY_FOOTPRINT", "reload.dmflags.memory_footprint", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_dmflag_datasize_stored,
      { "DATASIZE_STORED", "reload.dmflags.datasize_stored", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_dmflag_instances_stored,
      { "INSTANCES_STORED", "reload.dmflags.instances_stored", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_dmflag_messages_sent_rcvd,
      { "MESSAGES_SENT_RCVD", "reload.dmflags.messages_sent_rcvd", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_dmflag_ewma_bytes_sent,
      { "EWMA_BYTES_SENT", "reload.dmflags.ewma_bytes_sent", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_dmflag_ewma_bytes_rcvd,
      { "EWMA_BYTES_RCVD", "reload.dmflags.ewma_bytes_rcvd", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_dmflag_underlay_hop,
      { "UNDERLAY_HOP", "reload.dmflags.underlay_hop", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_dmflag_battery_status,
      { "BATTERY_STATUS", "reload.dmflags.battery_status", FT_BOOLEAN, 1, TFS(&tfs_set_notset), 0x0,
        NULL, HFILL
      }
    },
    { &hf_reload_diagnosticrequest,
      { "DiagnosticRequest",  "reload.diagnosticrequest",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticresponse,
      { "DiagnosticResponse",  "reload.diagnosticresponse",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticextension,
      { "DiagnosticExtension",  "reload.diagnosticextension",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticextension_type,
      { "type (DiagnosticExtensionRequestType)",  "reload.diagnosticextension.type",  FT_UINT16,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticextension_contents,
      { "diagnostic_extension_contents",  "reload.diagnosticextension.contents",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnostic_expiration, {
        "expiration (uint64)", "reload.diagnostic.expiration", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
        NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_reload_diagnosticrequest_timestampinitiated, {
        "timestampInitiated (uint64)", "reload.diagnosticrequest.timestampinitiated",FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
        NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_reload_diagnosticrequest_extensions,
      { "diagnostic_extensions",  "reload.diagnosticrequest.extensions",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_pathtrackreq,
      { "PathTrackReq",  "reload.pathtrackreq",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_pathtrackreq_destination,
      { "destination (Destination)",  "reload.pathtrackreq.destination",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_pathtrackreq_request,
      { "request (DiagnosticRequest)",  "reload.pathtrackreq.request",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo,
      { "DiagnosticInfo",  "reload.diagnostic.info",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_kind,
      { "kind (DiagnosticKindId)",  "reload.diagnostic.kindid",  FT_UINT16,
        BASE_DEC,  VALS(diagnostickindids), 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_congestion_status,
      { "congestion_status (uint8)",  "reload.diagnostic.info.congestion_status",  FT_UINT8,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_number_peers,
      { "number_peers (uint32)",  "reload.diagnostic.info.number_peers",  FT_UINT32,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_processing_power,
      { "processing_power (uint32)",  "reload.diagnostic.info.processing_power",  FT_UINT32,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_bandwidth,
      { "bandwidth (uint32)",  "reload.diagnostic.info.bandwidth",  FT_UINT32,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_software_version,
      { "software_version (opaque string)",  "reload.diagnostic.info.software_version",  FT_STRING,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_machine_uptime,
      { "machine_uptime (uint64)",  "reload.diagnostic.info.machine_uptime",  FT_UINT64,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_app_uptime,
      { "app_uptime (uint64)",  "reload.diagnostic.info.app_uptime",  FT_UINT64,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_memory_footprint,
      { "memory_footprint(uint32)",  "reload.diagnostic.info.memory_footprint",  FT_UINT32,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_datasize_stored,
      { "datasize_stored (uint64)",  "reload.diagnostic.info.datasize_stored",  FT_UINT64,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_instances_stored,
      { "instances_stored",  "reload.diagnostic.info.instances_stored",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_instancesstored_info,
      { "InstancesStoredInfo)",  "reload.diagnostic.info.instancesstored_info",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_instancesstored_instances,
      { "instances (uint64)",  "reload.diagnostic.info.instancesstored_instances",  FT_UINT64,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_messages_sent_rcvd,
      { "messages_sent_rcvd",  "reload.diagnostic.info.messages_sent_rcvd",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_messages_sent_rcvd_info,
      { "MessagesSentRcvdInfo",  "reload.diagnostic.info.messages_sent_rcvd.info",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_message_code,
      { "messages_code (uint16)",  "reload.diagnostic.info.message_code",  FT_UINT16,
        BASE_HEX,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_messages_sent,
      { "sent (uint64)",  "reload.diagnostic.info.messages_sent",  FT_UINT64,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_messages_rcvd,
      { "rcvd (uint64)",  "reload.diagnostic.info.messages_rcvd",  FT_UINT64,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_ewma_bytes_sent,
      { "ewma_bytes_sent (uint32)",  "reload.diagnostic.info.ewma_bytes_sent",  FT_UINT32,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_ewma_bytes_rcvd,
      { "ewma_bytes_rcvd (uint32)",  "reload.diagnostic.info.ewma_bytes_rcvd",  FT_UINT32,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_underlay_hops,
      { "underlay_hops (uint8)",  "reload.diagnostic.info.underlay_hops",  FT_UINT8,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticinfo_battery_status,
      { "battery_status (uint8)",  "reload.diagnostic.info.battery_status",  FT_UINT8,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticresponse_timestampreceived, {
        "timestampReceived (uint64)", "reload.diagnosticresponse.timestampreceived",FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
        NULL, 0x0, NULL, HFILL
      }
    },
    { &hf_reload_diagnosticresponse_hopcounter,
      { "hopCounter (uint8)",  "reload.diagnosticresponse.hopcounter",  FT_UINT8,
        BASE_DEC,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_diagnosticresponse_diagnostic_info_list,
      { "diagnostic_info_list",  "reload.diagnosticresponse.diagnostic_info_list",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_pathtrackans,
      { "PathTrackAns",  "reload.pathtrackans",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_pathtrackans_next_hop,
      { "next_hop",  "reload.pathtrackans.next_hop",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_pathtrackans_response,
      { "response (DiagnosticResponse)",  "reload.pathtrackand.response",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_extensiveroutingmodeoption,
      { "ExtensiveRoutingModeOption",  "reload.extensiveroutingmodeoption",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_routemode,
      { "routemode (RouteMode)", "reload.routemode", FT_UINT8,
        BASE_DEC, VALS(routemodes),  0x0,  NULL, HFILL
      }
    },
    { &hf_reload_extensiveroutingmode_transport,
      { "transport (OverlayLinkType)",  "reload.extensiveroutingmode.transport",  FT_UINT8,
        BASE_DEC, VALS(overlaylinktypes), 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_extensiveroutingmode_ipaddressport,
      { "ipaddressport (IpAddressPort)",  "reload.extensiveroutingmode.ipaddressport",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_extensiveroutingmode_destination,
      { "destination",  "reload.extensiveroutingmode.destination",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_joinreq,
      { "JoinReq",  "reload.joinreq",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_joinans,
      { "JoinAns",  "reload.joinans",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_joinreq_joining_peer_id,
      { "joining_peer_id (NodeId)",  "reload.joinreq.joining_peer_id",  FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_leavereq,
      { "LeaveReq",  "reload.leavereq",  FT_NONE,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
    },
    { &hf_reload_leavereq_leaving_peer_id,
      { "leaving_peer_id (NodeId)",  "reload.leavereq.leaving_peer_id",  FT_BYTES,
        BASE_NONE,  NULL, 0x0,  NULL, HFILL
      }
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
    &ett_reload_resourceid,
    &ett_reload_forwarding_options,
    &ett_reload_forwarding_option,
    &ett_reload_forwarding_option_flags,
    &ett_reload_forwarding_option_directresponseforwarding,
    &ett_reload_attachreqans,
    &ett_reload_icecandidates,
    &ett_reload_icecandidate,
    &ett_reload_icecandidate_computed_address,
    &ett_reload_iceextensions,
    &ett_reload_iceextension,
    &ett_reload_ipaddressport,
    &ett_reload_ipv4addrport,
    &ett_reload_ipv6addrport,
    &ett_reload_message_contents,
    &ett_reload_message_extensions,
    &ett_reload_message_extension,
    &ett_reload_error_response,
    &ett_reload_security_block,
    &ett_reload_certificates,
    &ett_reload_genericcertificate,
    &ett_reload_signature,
    &ett_reload_signatureandhashalgorithm,
    &ett_reload_signeridentity,
    &ett_reload_signeridentity_identity,
    &ett_reload_signeridentity_value,
    &ett_reload_opaque,
    &ett_reload_message_body,
    &ett_reload_routequeryreq,
    &ett_reload_probereq,
    &ett_reload_probereq_requested_info,
    &ett_reload_probe_information,
    &ett_reload_probe_information_data,
    &ett_reload_probeans,
    &ett_reload_probeans_probe_info,
    &ett_reload_appattach,
    &ett_reload_pingreq,
    &ett_reload_pingans,
    &ett_reload_storeddata,
    &ett_reload_kinddata,
    &ett_reload_values,
    &ett_reload_datavalue,
    &ett_reload_arrayentry,
    &ett_reload_dictionaryentry,
    &ett_reload_storereq,
    &ett_reload_store_kind_data,
    &ett_reload_storeans,
    &ett_reload_storeans_kind_responses,
    &ett_reload_storekindresponse,
    &ett_reload_fetchans,
    &ett_reload_fetchreq,
    &ett_reload_fetchreq_specifiers,
    &ett_reload_storeddataspecifier,
    &ett_reload_storeddataspecifier_indices,
    &ett_reload_storeddataspecifier_keys,
    &ett_reload_statans,
    &ett_reload_findans,
    &ett_reload_findkinddata,
    &ett_reload_fragments,
    &ett_reload_fragment,
    &ett_reload_configupdatereq,
    &ett_reload_configupdatereq_config_data,
    &ett_reload_kinddescription,
    &ett_reload_configupdatereq_kinds,
    &ett_reload_storekindresponse_replicas,
    &ett_reload_nodeid_list,
    &ett_reload_chordupdate,
    &ett_reload_chordroutequeryans,
    &ett_reload_chordleave,
    &ett_reload_turnserver,
    &ett_reload_sipregistration,
    &ett_reload_sipregistration_data,
    &ett_reload_sipregistration_destination_list,
    &ett_reload_dictionaryentry_key,
    &ett_reload_overlay_specific,
    &ett_reload_kindid_list,
    &ett_reload_redirserviceproviderdata,
    &ett_reload_redirserviceprovider,
    &ett_reload_findreq,
    &ett_reload_dmflags,
    &ett_reload_diagnosticextension,
    &ett_reload_diagnosticrequest_extensions,
    &ett_reload_pathtrackreq,
    &ett_reload_diagnosticinfo,
    &ett_reload_diagnosticinfo_instances_stored,
    &ett_reload_diagnosticinfo_instancesstored_info,
    &ett_reload_diagnosticinfo_messages_sent_rcvd,
    &ett_reload_diagnosticinfo_messages_sent_rcvd_info,
    &ett_reload_diagnosticresponse,
    &ett_reload_diagnosticresponse_diagnostic_info_list,
    &ett_reload_pathtrackans,
    &ett_reload_extensiveroutingmodeoption,
    &ett_reload_extensiveroutingmode_destination,
    &ett_reload_joinreq,
    &ett_reload_joinans,
    &ett_reload_leavereq,
  };

  static uat_field_t reloadkindidlist_uats_flds[] = {
    UAT_FLD_DEC(kindidlist_uats,id,"Kind-ID Number","Custom Kind-ID Number"),
    UAT_FLD_CSTRING(kindidlist_uats,name,"Kind-ID Name","Custom Kind-ID Name"),
    UAT_FLD_VS(kindidlist_uats,data_model,"Kind-ID data model",datamodels,"Kind ID data model"),
    UAT_END_FIELDS
  };


  /* Register the protocol name and description */
  proto_reload = proto_register_protocol("REsource LOcation And Discovery", "RELOAD", "reload");
  register_dissector("reload", dissect_reload_message_no_return, proto_reload);
  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_reload, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  reload_module = prefs_register_protocol(proto_reload, NULL);

  reloadkindids_uat =
    uat_new("Kind-ID Table",
            sizeof(kind_t),
            "reload_kindids",                     /* filename */
            TRUE,                           /* from_profile */
            (void*) &kindidlist_uats,       /* data_ptr */
            &nreloadkinds,                   /* numitems_ptr */
            UAT_CAT_GENERAL,                   /* category */
            NULL,                           /* Help section (currently a wiki page) */
            uat_kindid_copy_cb,
            NULL,
            uat_kindid_record_free_cb,
            NULL,
            reloadkindidlist_uats_flds);


  prefs_register_uat_preference(reload_module, "kindid.table",
                                "Kind ID list",
                                "A table of Kind ID definitions",
                                reloadkindids_uat);

  prefs_register_bool_preference(reload_module, "defragment",
                                 "Reassemble fragmented reload datagrams",
                                 "Whether fragmented RELOAD datagrams should be reassembled",
                                 &reload_defragment);
  prefs_register_uint_preference(reload_module, "nodeid_length",
                                 "NodeId Length",
                                 "Length of the NodeId as defined in the overlay.",
                                 10,
                                 &reload_nodeid_length);
  prefs_register_string_preference(reload_module, "topology_plugin",
                                   "topology plugin", "topology plugin defined in the overlay", &reload_topology_plugin);

  register_init_routine(reload_defragment_init);
}

void
proto_reg_handoff_reload(void)
{

  data_handle = find_dissector("data");
  xml_handle = find_dissector("xml");

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
