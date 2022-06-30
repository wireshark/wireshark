/* packet-knxip.c
 * Routines for KNXnet/IP dissection
 * By Jan Kessler <kessler@ise.de>
 * Copyright 2004, Jan Kessler <kessler@ise.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * See
 *
 *    https://my.knx.org/en/shop/knx-specifications
 *
 * for the specifications.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto.h>
#include <epan/ipproto.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/tvbuff.h>
#include <epan/strutil.h>

#include "packet-tcp.h"
#include "packet-udp.h"
#include "packet-knxip.h"
#include "packet-knxip_decrypt.h"

#define KIP_DEFAULT_PORT_RANGE "3671" /* IANA-assigned (EIBnet aka KNXnet) */
/* Other ports are commonly used, especially 3672 by KNX IP Gateways, but
 * not registered.
 */

#define ECDH_PUBLIC_VALUE_SIZE  32

#define KIP_HDR_LEN 6

 /* The following service families are defined for the
 version 1.0 KNXnet/IP implementation of the eFCP protocol
 */
#define KIP_SERVICE_CORE  0x02
#define KIP_SERVICE_MANAGEMENT  0x03
#define KIP_SERVICE_TUNNELING  0x04
#define KIP_SERVICE_ROUTING  0x05
#define KIP_SERVICE_REMOTE_LOGGING  0x06
#define KIP_SERVICE_REMOTE_DIAG_AND_CONFIG  0x07
#define KIP_SERVICE_OBJECT_SERVER  0x08
#define KIP_SERVICE_SECURITY  0x09

 /* The service codes for the core services (device discovery,
 self description and connection management) as defined in
 chapter 2 of the KNXnet/IP system specification
 */
#define KIP_SEARCH_REQUEST  0x0201
#define KIP_SEARCH_RESPONSE  0x0202
#define KIP_DESCRIPTION_REQUEST  0x0203
#define KIP_DESCRIPTION_RESPONSE  0x0204
#define KIP_CONNECT_REQUEST  0x0205
#define KIP_CONNECT_RESPONSE  0x0206
#define KIP_CONNECTIONSTATE_REQUEST  0x0207
#define KIP_CONNECTIONSTATE_RESPONSE  0x0208
#define KIP_DISCONNECT_REQUEST  0x0209
#define KIP_DISCONNECT_RESPONSE  0x020A
#define KIP_SEARCH_REQUEST_EXT  0x020B
#define KIP_SEARCH_RESPONSE_EXT  0x020C

 /* The service codes for the device management services
 (tunneling of cEMI local management procedures) as
 defined in chapter 3 of the KNXnet/IP system specification
 */
#define KIP_CONFIGURATION_REQUEST  0x0310
#define KIP_CONFIGURATION_ACK  0x0311

 /* The service codes for the tunneling services
 (transport of cEMI frames from service interface) as
 defined in chapter 4 of the KNXnet/IP system specification
 */
#define KIP_TUNNELING_REQUEST  0x0420
#define KIP_TUNNELING_ACK  0x0421
#define KIP_TUNNELING_FEATURE_GET  0x0422
#define KIP_TUNNELING_FEATURE_RESPONSE  0x0423
#define KIP_TUNNELING_FEATURE_SET  0x0424
#define KIP_TUNNELING_FEATURE_INFO  0x0425

 /* The service codes for the routing services
 (transport of cEMI frames between EIB couplers) as
 defined in chapter 5 of the KNXnet/IP system specification
 */
#define KIP_ROUTING_INDICATION  0x0530
#define KIP_ROUTING_LOST_MESSAGE  0x0531
#define KIP_ROUTING_BUSY  0x0532
#define KIP_ROUTING_SYSTEM_BROADCAST  0x0533

 /* The service codes for RemoteDiagAndConfig
 */
#define KIP_REMOTE_DIAG_REQUEST  0x0740
#define KIP_REMOTE_DIAG_RESPONSE  0x0741
#define KIP_REMOTE_CONFIG_REQUEST  0x0742
#define KIP_REMOTE_RESET_REQUEST  0x0743

 /* The service codes for KNX-IP Secure
 */
#define KIP_SECURE_WRAPPER  0x0950
#define KIP_SESSION_REQUEST  0x0951
#define KIP_SESSION_RESPONSE  0x0952
#define KIP_SESSION_AUTHENTICATE  0x0953
#define KIP_SESSION_STATUS  0x0954
#define KIP_TIMER_NOTIFY  0x0955

 /* KNXnet/IP host protocols */
#define KIP_IPV4_UDP  0x01
#define KIP_IPV4_TCP  0x02

 /* The different types of DIBs (Description Information Blocks)
 for the KNXnet/IP Core Discovery and Description services
 as defined in chapter 1 of the KNXnet/IP system specification
 */
#define KIP_DIB_DEVICE_INFO  0x01
#define KIP_DIB_SUPP_SVC_FAMILIES  0x02
#define KIP_DIB_IP_CONFIG  0x03
#define KIP_DIB_CUR_CONFIG  0x04
#define KIP_DIB_KNX_ADDRESSES  0x05
#define KIP_DIB_SECURED_SERVICE_FAMILIES  0x06
#define KIP_DIB_TUNNELING_INFO  0x07
#define KIP_DIB_EXTENDED_DEVICE_INFO  0x08
#define KIP_DIB_MFR_DATA  0xFE

 /* The different types of SRPs (Search Request Parameter Blocks)
 for the KNXnet/IP Core Discovery and Description services
 */
#define KIP_SRP_BY_PROGMODE  0x01
#define KIP_SRP_BY_MACADDR  0x02
#define KIP_SRP_BY_SERVICE  0x03
#define KIP_SRP_REQUEST_DIBS  0x04

 /* The different KNX medium types for the hardware (device info)
 DIB as defined in AN033 Common EMI Specification
 */
#define KIP_KNXTYPE_TP0  0x01
#define KIP_KNXTYPE_TP1  0x02
#define KIP_KNXTYPE_PL110  0x04
#define KIP_KNXTYPE_PL132  0x08
#define KIP_KNXTYPE_RF  0x10
#define KIP_KNXTYPE_IP  0x20

 /* KNXnet/IP connection types */
#define KIP_DEVICE_MGMT_CONNECTION  0x03
#define KIP_TUNNEL_CONNECTION  0x04
#define KIP_REMLOG_CONNECTION  0x06
#define KIP_REMCONF_CONNECTION  0x07
#define KIP_OBJSVR_CONNECTION  0x08

 /* Tunneling v2 feature ids */
#define KIP_TUNNELING_FEATURE_ID_SUPPORTED_EMI_TYPE  0x01
#define KIP_TUNNELING_FEATURE_ID_HOST_DEVICE_DEVICE_DESCRIPTOR_TYPE_0  0x02
#define KIP_TUNNELING_FEATURE_ID_BUS_CONNECTION_STATUS 0x03
#define KIP_TUNNELING_FEATURE_ID_KNX_MANUFACTURER_CODE 0x04
#define KIP_TUNNELING_FEATURE_ID_ACTIVE_EMI_TYPE 0x05
#define KIP_TUNNELING_FEATURE_ID_INDIVIDUAL_ADDRESS 0x06
#define KIP_TUNNELING_FEATURE_ID_MAX_APDU_LENGTH 0x07
#define KIP_TUNNELING_FEATURE_ID_INFO_SERVICE_ENABLE 0x08

 /* KNXnet/IP tunnel types */
#define TUNNEL_LINKLAYER  0x02
#define TUNNEL_RAW  0x04
#define TUNNEL_BUSMONITOR  0x80

 /* KNXnet/IP error codes */
#define KIP_E_NO_ERROR  0x00
#define KIP_E_CONNECTION_ID  0x21
#define KIP_E_CONNECTION_TYPE  0x22
#define KIP_E_CONNECTION_OPTION  0x23
#define KIP_E_NO_MORE_CONNECTIONS  0x24
#define KIP_E_NO_MORE_UNIQUE_CONNECTIONS  0x25
#define KIP_E_DATA_CONNECTION  0x26
#define KIP_E_KNX_CONNECTION  0x27
#define KIP_E_TUNNELING_LAYER  0x29

/* KNXnet/IP remote selection types */
#define SELECT_PROGMODE  0x01
#define SELECT_MACADDRESS  0x02

/* SESSION_STATUS codes */
#define SESSION_STATUS_AUTHENTICATION_SUCCESS  0x00
#define SESSION_STATUS_AUTHENTICATION_FAILED  0x01
#define SESSION_STATUS_UNAUTHENTICATED  0x02
#define SESSION_STATUS_TIMEOUT  0x03
#define SESSION_STATUS_KEEPALIVE  0x04
#define SESSION_STATUS_CLOSE  0x05

/* Initialize the protocol identifier that is needed for the
 protocol hook and to register the fields in the protocol tree
*/
static gint proto_knxip = -1;

/* Initialize the registered fields identifiers. These fields
 will be registered with the protocol during initialization.
 Protocol fields are like type definitions. The protocol dissector
 later on adds items of these types to the protocol tree.
*/
static gint hf_bytes = -1;
static gint hf_folder = -1;
static gint hf_knxip_header_length = -1;
static gint hf_knxip_protocol_version = -1;
static gint hf_knxip_service_id = -1;
static gint hf_knxip_service_family = -1;
static gint hf_knxip_service_type = -1;
static gint hf_knxip_total_length = -1;
static gint hf_knxip_structure_length = -1;
static gint hf_knxip_host_protocol = -1;
static gint hf_knxip_ip_address = -1;
static gint hf_knxip_port = -1;
static gint hf_knxip_description_type = -1;
static gint hf_knxip_knx_medium = -1;
static gint hf_knxip_device_status = -1;
static gint hf_knxip_program_mode = -1;
static gint hf_knxip_knx_address = -1;
static gint hf_knxip_project_id = -1;
static gint hf_knxip_project_number = -1;
static gint hf_knxip_installation_number = -1;
static gint hf_knxip_serial_number = -1;
static gint hf_knxip_multicast_address = -1;
static gint hf_knxip_mac_address = -1;
static gint hf_knxip_friendly_name = -1;
static gint hf_knxip_service_version = -1;
static gint hf_knxip_security_version = -1;
static gint hf_knxip_manufacturer_code = -1;
static gint hf_knxip_connection_type = -1;
static gint hf_knxip_knx_layer = -1;
static gint hf_knxip_reserved = -1;
static gint hf_knxip_channel = -1;
static gint hf_knxip_status = -1;
static gint hf_knxip_seq_counter = -1;
static gint hf_knxip_ip_subnet = -1;
static gint hf_knxip_ip_gateway = -1;
static gint hf_knxip_ip_assign = -1;
static gint hf_knxip_ip_caps = -1;
static gint hf_knxip_ip_dhcp = -1;
static gint hf_knxip_tunnel_feature = -1;
static gint hf_knxip_routing_loss = -1;
static gint hf_knxip_busy_time = -1;
static gint hf_knxip_busy_control = -1;
static gint hf_knxip_selector = -1;
static gint hf_knxip_max_apdu_length = -1;
static gint hf_knxip_medium_status = -1;
static gint hf_knxip_mask_version = -1;
static gint hf_knxip_srp_mandatory = -1;
static gint hf_knxip_srp_type = -1;
static gint hf_knxip_reset_command = -1;
static gint hf_knxip_session = -1;
static gint hf_knxip_tag = -1;
static gint hf_knxip_user = -1;
static gint hf_knxip_session_status = -1;

/* Initialize the subtree pointers. These pointers are needed to
 display the protocol in a structured tree. Subtrees hook on
 already defined fields or (the topmost) on the protocol itself
*/
static gint ett_kip = -1;
static gint ett_efcp = -1;
static gint ett_service = -1;
static gint ett_hpai = -1;
static gint ett_dib = -1;
static gint ett_medium = -1;
static gint ett_status = -1;
static gint ett_projectid = -1;
static gint ett_service_family = -1;
static gint ett_ip_assignment = -1;
static gint ett_cri = -1;
static gint ett_crd = -1;
static gint ett_cnhdr = -1;
static gint ett_loss = -1;
static gint ett_busy = -1;
static gint ett_selector = -1;
static gint ett_decrypted = -1;
static gint ett_tunnel = -1;

/* Set up the value_string tables for the service families
 and the service types (note that the service types in KNXnet/IP
 version 1.0 are unique even across service families...)
*/
static const value_string knxip_service_family_vals[] = {
  { KIP_SERVICE_CORE, "Core" },
  { KIP_SERVICE_MANAGEMENT, "Device Management" },
  { KIP_SERVICE_TUNNELING, "Tunneling" },
  { KIP_SERVICE_ROUTING, "Routing" },
  { KIP_SERVICE_REMOTE_LOGGING, "Remote Logging" },
  { KIP_SERVICE_REMOTE_DIAG_AND_CONFIG, "Remote Diag And Config" },
  { KIP_SERVICE_OBJECT_SERVER, "Object Server" },
  { KIP_SERVICE_SECURITY, "Security" },
  { 0, NULL}
};
static const value_string knxip_service_type_vals[] = {
  { KIP_SEARCH_REQUEST, "Search Request" },
  { KIP_SEARCH_RESPONSE, "Search Response" },
  { KIP_DESCRIPTION_REQUEST, "Description Request" },
  { KIP_DESCRIPTION_RESPONSE, "Description Response" },
  { KIP_CONNECT_REQUEST, "Connect Request" },
  { KIP_CONNECT_RESPONSE, "Connect Response" },
  { KIP_CONNECTIONSTATE_REQUEST, "Connection State Request" },
  { KIP_CONNECTIONSTATE_RESPONSE, "Connection State Response" },
  { KIP_DISCONNECT_REQUEST, "Disconnect Request" },
  { KIP_DISCONNECT_RESPONSE, "Disconnect Response" },
  { KIP_SEARCH_REQUEST_EXT, "Search Request Extended" },
  { KIP_SEARCH_RESPONSE_EXT, "Search Response Extended" },
  { KIP_CONFIGURATION_REQUEST, "Configuration Request" },
  { KIP_CONFIGURATION_ACK, "Configuration Acknowledgement" },
  { KIP_TUNNELING_REQUEST, "Tunneling Request" },
  { KIP_TUNNELING_ACK, "Tunneling Acknowledgement" },
  { KIP_TUNNELING_FEATURE_GET, "Tunneling Feature Get" },
  { KIP_TUNNELING_FEATURE_RESPONSE, "Tunneling Feature Response" },
  { KIP_TUNNELING_FEATURE_SET, "Tunneling Feature Set" },
  { KIP_TUNNELING_FEATURE_INFO, "Tunneling Feature Info" },
  { KIP_ROUTING_INDICATION, "Routing Indication" },
  { KIP_ROUTING_LOST_MESSAGE, "Routing Loss" },
  { KIP_ROUTING_BUSY, "Routing Busy" },
  { KIP_ROUTING_SYSTEM_BROADCAST, "Routing System Broadcast" },
  { KIP_REMOTE_DIAG_REQUEST, "Remote Diagnostic Request" },
  { KIP_REMOTE_DIAG_RESPONSE, "Remote Diagnostic Response" },
  { KIP_REMOTE_CONFIG_REQUEST, "Remote Configuration Request" },
  { KIP_REMOTE_RESET_REQUEST, "Remote Reset Request" },
  { KIP_SECURE_WRAPPER, "Secure Wrapper" },
  { KIP_SESSION_REQUEST, "Session Request" },
  { KIP_SESSION_RESPONSE, "Session Response" },
  { KIP_SESSION_AUTHENTICATE, "Session Authenticate" },
  { KIP_SESSION_STATUS, "Session Status" },
  { KIP_TIMER_NOTIFY, "Timer Notify" },
  { 0, NULL}
};
static const value_string svc_vals[] = {  /* abbreviated service names */
  { KIP_SEARCH_REQUEST, "SearchReq" },
  { KIP_SEARCH_RESPONSE, "SearchResp" },
  { KIP_DESCRIPTION_REQUEST, "DescrReq" },
  { KIP_DESCRIPTION_RESPONSE, "DescrResp" },
  { KIP_CONNECT_REQUEST, "ConnectReq" },
  { KIP_CONNECT_RESPONSE, "ConnectResp" },
  { KIP_CONNECTIONSTATE_REQUEST, "ConnStateReq" },
  { KIP_CONNECTIONSTATE_RESPONSE, "ConnStateResp" },
  { KIP_DISCONNECT_REQUEST, "DisconnectReq" },
  { KIP_DISCONNECT_RESPONSE, "DisconnectResp" },
  { KIP_SEARCH_REQUEST_EXT, "SearchReqExt" },
  { KIP_SEARCH_RESPONSE_EXT, "SearchRespExt" },
  { KIP_CONFIGURATION_REQUEST, "ConfigReq" },
  { KIP_CONFIGURATION_ACK, "ConfigAck" },
  { KIP_TUNNELING_REQUEST, "TunnelReq" },
  { KIP_TUNNELING_ACK, "TunnelAck" },
  { KIP_TUNNELING_FEATURE_GET, "TunnelFeatureGet" },
  { KIP_TUNNELING_FEATURE_RESPONSE, "TunnelFeatureResp" },
  { KIP_TUNNELING_FEATURE_SET, "TunnelFeatureSet" },
  { KIP_TUNNELING_FEATURE_INFO, "TunnelFeatureInfo" },
  { KIP_ROUTING_INDICATION, "RoutingInd" },
  { KIP_ROUTING_LOST_MESSAGE, "RoutingLoss" },
  { KIP_ROUTING_BUSY, "RoutingBusy" },
  { KIP_ROUTING_SYSTEM_BROADCAST, "RoutingSBC" },
  { KIP_REMOTE_DIAG_REQUEST, "RemoteDiagReq" },
  { KIP_REMOTE_DIAG_RESPONSE, "RemoteDiagResp" },
  { KIP_REMOTE_CONFIG_REQUEST, "RemoteConfigReq" },
  { KIP_REMOTE_RESET_REQUEST, "RemoteResetReq" },
  { KIP_SECURE_WRAPPER, "SecureWrapper" },
  { KIP_SESSION_REQUEST, "SessionReq" },
  { KIP_SESSION_RESPONSE, "SessionResp" },
  { KIP_SESSION_AUTHENTICATE, "SessionAuth" },
  { KIP_SESSION_STATUS, "SessionStatus" },
  { KIP_TIMER_NOTIFY, "TimerNotify" },
  { 0, NULL}
};
static const value_string host_protocol_vals[] = {
  { KIP_IPV4_UDP, "IPv4 UDP" },
  { KIP_IPV4_TCP, "IPv4 TCP" },
  { 0, NULL}
};
static const value_string description_type_vals[] = {
  { KIP_DIB_DEVICE_INFO, "Device Information" },
  { KIP_DIB_SUPP_SVC_FAMILIES, "Supported Service Families" },
  { KIP_DIB_IP_CONFIG, "IP Configuration" },
  { KIP_DIB_CUR_CONFIG, "Current Configuration" },
  { KIP_DIB_KNX_ADDRESSES, "KNX Addresses" },
  { KIP_DIB_SECURED_SERVICE_FAMILIES, "Secured Service Families" },
  { KIP_DIB_TUNNELING_INFO, "Tunneling Information" },
  { KIP_DIB_EXTENDED_DEVICE_INFO, "Extended Device Information" },
  { KIP_DIB_MFR_DATA, "Manufacturer Data" },
  { 0, NULL}
};
static const value_string descr_type_vals[] = {  /* abbreviated DIB names */
  { KIP_DIB_DEVICE_INFO, "DevInfo" },
  { KIP_DIB_SUPP_SVC_FAMILIES, "SuppSvc" },
  { KIP_DIB_IP_CONFIG, "IpConfig" },
  { KIP_DIB_CUR_CONFIG, "CurConfig" },
  { KIP_DIB_KNX_ADDRESSES, "KnxAddr" },
  { KIP_DIB_SECURED_SERVICE_FAMILIES, "SecSvcFam" },
  { KIP_DIB_TUNNELING_INFO, "TunnelInfo" },
  { KIP_DIB_EXTENDED_DEVICE_INFO, "ExtDevInfo" },
  { KIP_DIB_MFR_DATA, "MfrData" },
  { 0, NULL}
};
#if 0
static const value_string search_request_parameter_type_vals[] = {
  { KIP_SRP_BY_PROGMODE, "By programming mode" },
  { KIP_SRP_BY_MACADDR, "By MAC address" },
  { KIP_SRP_BY_SERVICE, "By service" },
  { KIP_SRP_REQUEST_DIBS, "Request DIBs" },
  { 0, NULL }
};
#endif
static const value_string srp_type_vals[] = {  /* abbreviated SRP names */
  { KIP_SRP_BY_PROGMODE, "ProgMode" },
  { KIP_SRP_BY_MACADDR, "MacAddr" },
  { KIP_SRP_BY_SERVICE, "Service" },
  { KIP_SRP_REQUEST_DIBS, "Dibs" },
  { 0, NULL }
};
static const value_string medium_type_vals[] = {
  { KIP_KNXTYPE_TP0, "TP0" },
  { KIP_KNXTYPE_TP1, "TP1" },
  { KIP_KNXTYPE_PL110, "PL110" },
  { KIP_KNXTYPE_PL132, "PL132" },
  { KIP_KNXTYPE_RF, "RF" },
  { KIP_KNXTYPE_IP, "IP" },
  { 0, NULL}
};
static const value_string connection_type_vals[] = {
  { KIP_DEVICE_MGMT_CONNECTION, "Device Management Connection" },
  { KIP_TUNNEL_CONNECTION, "Tunneling Connection" },
  { KIP_REMLOG_CONNECTION, "Remote Logging Connection" },
  { KIP_REMCONF_CONNECTION, "Remote Configuration Connection" },
  { KIP_OBJSVR_CONNECTION, "Object Server Connection" },
  { 0, NULL}
};
static const value_string conn_type_vals[] = {
  { KIP_DEVICE_MGMT_CONNECTION, "Config" },
  { KIP_TUNNEL_CONNECTION, "Tunnel" },
  { KIP_REMLOG_CONNECTION, "RemoteLogging" },
  { KIP_REMCONF_CONNECTION, "RemoteConfig" },
  { KIP_OBJSVR_CONNECTION, "ObjectServer" },
  { 0, NULL }
};
static const value_string tunneling_feature_id_vals[] = {
  { KIP_TUNNELING_FEATURE_ID_SUPPORTED_EMI_TYPE, "SupportedEmiType" },
  { KIP_TUNNELING_FEATURE_ID_HOST_DEVICE_DEVICE_DESCRIPTOR_TYPE_0, "MaskVersion" },
  { KIP_TUNNELING_FEATURE_ID_BUS_CONNECTION_STATUS, "BusStatus" },
  { KIP_TUNNELING_FEATURE_ID_KNX_MANUFACTURER_CODE, "Manufacturer" },
  { KIP_TUNNELING_FEATURE_ID_ACTIVE_EMI_TYPE, "ActiveEmiType" },
  { KIP_TUNNELING_FEATURE_ID_INDIVIDUAL_ADDRESS, "IndividualAddress" },
  { KIP_TUNNELING_FEATURE_ID_MAX_APDU_LENGTH, "MaxApduLength" },
  { KIP_TUNNELING_FEATURE_ID_INFO_SERVICE_ENABLE, "InfoServiceEnable" },
  { 0, NULL }
};
static const value_string knx_layer_vals[] = {
  { TUNNEL_LINKLAYER, "LinkLayer" },
  { TUNNEL_RAW, "Raw" },
  { TUNNEL_BUSMONITOR, "Busmonitor" },
  { 0, NULL}
};
static const value_string error_vals[] = {
  { KIP_E_NO_ERROR, "OK" },
  { KIP_E_CONNECTION_ID, "E_CONNECTION_ID" },
  { KIP_E_CONNECTION_TYPE, "E_CONNECTION_TYPE" },
  { KIP_E_CONNECTION_OPTION, "E_CONNECTION_OPTION" },
  { KIP_E_NO_MORE_CONNECTIONS, "E_NO_MORE_CONNECTIONS" },
  { KIP_E_NO_MORE_UNIQUE_CONNECTIONS, "E_NO_MORE_UNIQUE_CONNECTIONS" },
  { KIP_E_DATA_CONNECTION, "E_DATA_CONNECTION" },
  { KIP_E_KNX_CONNECTION, "E_KNX_CONNECTION" },
  { KIP_E_TUNNELING_LAYER, "E_TUNNELING_LAYER" },
  { 0, NULL}
};
static const value_string session_status_vals[] = {
  { SESSION_STATUS_AUTHENTICATION_SUCCESS, "STATUS_AUTHENTICATION_SUCCESS" },
  { SESSION_STATUS_AUTHENTICATION_FAILED, "STATUS_AUTHENTICATION_FAILED" },
  { SESSION_STATUS_UNAUTHENTICATED, "STATUS_UNAUTHENTICATED" },
  { SESSION_STATUS_TIMEOUT, "STATUS_TIMEOUT" },
  { SESSION_STATUS_KEEPALIVE, "STATUS_KEEPALIVE" },
  { SESSION_STATUS_CLOSE, "STATUS_CLOSE" },
  { 0, NULL }
};

guint8 knxip_error;
guint8 knxip_host_protocol;

expert_field ei_knxip_error = EI_INIT;
expert_field ei_knxip_warning = EI_INIT;

static gboolean pref_desegment = TRUE;
static const gchar* pref_key_texts[ MAX_KNX_DECRYPTION_KEYS ];
//static const gchar* authentication_code_text;
//static const gchar* password_hash_text;
static const gchar* pref_key_file_name;
static const gchar* pref_key_file_pwd;
static const gchar* pref_key_info_file_name;

/* KNX decryption keys
*/
guint8 knx_decryption_keys[ MAX_KNX_DECRYPTION_KEYS ][ KNX_KEY_LENGTH ];
guint8 knx_decryption_key_count;

/* Forward declarations
*/
static gint dissect_knxip( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_ );
void proto_reg_handoff_knxip( void );
void proto_register_knxip( void );

/* Add raw data to list view, tree view, and parent folder
*/
static proto_item* knxip_tree_add_data( proto_tree* tree, tvbuff_t* tvb, gint offset, gint length, column_info* cinfo, proto_item* item,
  const gchar* name, const gchar* text1, const gchar* text2 )
{
  proto_item* new_item = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, length, NULL, "%s: $", name );
  if( text1 ) col_append_str( cinfo, COL_INFO, text1 );
  if( text2 ) proto_item_append_text( item, "%s", text2 );

  while( length > 0 )
  {
    guint8 value = tvb_get_guint8( tvb, offset );
    if( text1 ) col_append_fstr( cinfo, COL_INFO, "%02X", value );
    if( text2 ) proto_item_append_text( item, "%02X", value );
    proto_item_append_text( new_item, " %02X", value );
    offset++;
    length--;
  }

  return new_item;
}

/* Show unknown or unexpected data
*/
static proto_item* knxip_tree_add_unknown_data( proto_tree* tree, tvbuff_t* tvb, gint offset, gint length )
{
  return proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, length, NULL, "? Unknown data (%d bytes)", length );
}

static guint8 hex_to_knx_key( const gchar* text, guint8 key[ KNX_KEY_LENGTH ] )
{
  size_t n_bytes = 0;
  guint8* bytes = convert_string_to_hex( text, &n_bytes );
  if( bytes == NULL )
  {
    n_bytes = 0;
  }
  else
  {
    if( n_bytes )
    {
      if( n_bytes > KNX_KEY_LENGTH ) n_bytes = KNX_KEY_LENGTH;
      if( n_bytes ) memcpy( key, bytes, n_bytes );
      while( n_bytes < KNX_KEY_LENGTH ) key[ n_bytes++ ] = 0;
    }
    g_free( bytes );
  }
  return n_bytes != 0;
}

static proto_item* knxip_tree_add_status( proto_tree* tree, tvbuff_t* tvb, gint offset )
{
  return proto_tree_add_item( tree, hf_knxip_status, tvb, offset, 1, ENC_BIG_ENDIAN );
}

static proto_item* knxip_tree_add_reserved( proto_tree* tree, tvbuff_t* tvb, gint offset, packet_info* pinfo, guint8* p_ok )
{
  proto_item* new_item = proto_tree_add_item( tree, hf_knxip_reserved, tvb, offset, 1, ENC_BIG_ENDIAN );
  if( tvb_get_guint8( tvb, offset ) )
  {
    proto_item_prepend_text( new_item, "? " );
    expert_add_info_format( pinfo, new_item, KIP_ERROR, "Expected: 0x00" );
    if( p_ok ) *p_ok = 0;
  }
  return new_item;
}

static proto_item* knxip_tree_add_missing_reserved( proto_tree* tree, tvbuff_t* tvb, gint offset, packet_info* pinfo )
{
  proto_item* new_item = proto_tree_add_expert_format( tree, pinfo, KIP_ERROR, tvb, offset, 0, "? Reserved: expected 1 byte" );
  return new_item;
}

static proto_item* knxip_tree_add_length( proto_tree* tree, tvbuff_t* tvb, gint offset, gint value )
{
  return proto_tree_add_uint_format_value( tree, hf_knxip_structure_length, tvb, offset, 1, value, "%u bytes", value );
}

static void knxip_item_illegal_length( proto_item* length_item, packet_info* pinfo, const gchar* info )
{
  proto_item_prepend_text( length_item, "? " );
  expert_add_info_format( pinfo, length_item, KIP_ERROR, "%s", info );
}

static proto_item* knxip_tree_add_ip_address( proto_tree* tree, tvbuff_t* tvb, gint offset, gchar* output, gint output_max )
{
  if( output )
  {
    const guint8* ipa = tvb_get_ptr( tvb, offset, 4 );
    snprintf( output, output_max, "%u.%u.%u.%u", ipa[ 0 ], ipa[ 1 ], ipa[ 2 ], ipa[ 3 ] );
  }
  return proto_tree_add_item( tree, hf_knxip_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN );
}

static proto_item* knxip_tree_add_knx_address( proto_tree* tree, gint hfindex, tvbuff_t* tvb, gint offset, gchar* output, gint output_max )
{
  guint16 value = tvb_get_ntohs( tvb, offset );
  gchar text[ 32 ];
  snprintf( text, sizeof text, "%u.%u.%u", (value >> 12) & 0xF, (value >> 8) & 0xF, value & 0xFF );
  if( output ) snprintf( output, output_max, "%s", text );
  proto_item* new_item = proto_tree_add_item( tree, hfindex, tvb, offset, 2, ENC_BIG_ENDIAN );
  proto_item_append_text( new_item, " = %s", text );
  return new_item;
}

static proto_item* knxip_tree_add_bit( proto_tree* tree, tvbuff_t* tvb, gint offset, gint bitpos, const gchar* name, gchar* output, gint output_max )
{
  gchar format[ 32 ] = ".... .... = %s: %d";
  guint8 value = (tvb_get_guint8( tvb, offset ) >> bitpos) & 1;
  format[ 7 - bitpos + (bitpos < 4) ] = '0' + value;

  if( value && output )
  {
    if( *output )
    {
      do { ++output; --output_max; } while( *output );
      snprintf( output, output_max, " | " );
      while( *output ) { ++output; --output_max; }
    }

    snprintf( output, output_max, "%s", name );
  }

  return proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, 1, NULL, format, name, value );
}

static proto_item* knxip_tree_add_ip_assignment( proto_tree* tree, gint hfindex, tvbuff_t* tvb, gint offset, guint8 manual )
{
  proto_item* node = proto_tree_add_item( tree, hfindex, tvb, offset, 1, ENC_BIG_ENDIAN );
  proto_tree* list = proto_item_add_subtree( node, ett_ip_assignment );
  gchar output[ 128 ];
  *output = '\0';
  knxip_tree_add_bit( list, tvb, offset, 2 + manual, "AutoIP", output, sizeof output );
  knxip_tree_add_bit( list, tvb, offset, 1 + manual, "DHCP", output, sizeof output );
  knxip_tree_add_bit( list, tvb, offset, 0 + manual, "BootP", output, sizeof output );
  if( manual ) knxip_tree_add_bit( list, tvb, offset, 0, "manual", output, sizeof output );
  if( *output ) proto_item_append_text( node, " = %s", output );
  return node;
}

/* Dissect HPAI field
*/
static guint8 dissect_hpai( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset, guint8* p_ok, gchar* name, guint8 check_protocol )
{
  guint8 ok = 1;
  gint offset = *p_offset;
  gint remaining_len = tvb_captured_length_remaining( tvb, offset );
  guint8 struct_len = (remaining_len <= 0) ? 0 : tvb_get_guint8( tvb, offset );
  gint eff_struct_len = (struct_len <= remaining_len) ? struct_len : remaining_len;

  proto_item* hpai_item = proto_tree_add_none_format( tree, hf_folder, tvb, offset, eff_struct_len, "HPAI %s Endpoint", name );

  gchar info[ 80 ];
  gchar* output = info;
  gint output_max = sizeof info;
  snprintf( info, sizeof info, "???" );

  if( struct_len <= 0 )
  {
    proto_item_prepend_text( hpai_item, "Missing " );
    expert_add_info_format( pinfo, hpai_item, KIP_ERROR, "Expected: 8 bytes" );
    ok = 0;
  }
  else
  {
    /* 1 byte Structure Length */
    proto_tree* hpai_tree = proto_item_add_subtree( hpai_item, ett_hpai );
    proto_item* length_item = knxip_tree_add_length( hpai_tree, tvb, offset, struct_len );
    proto_item* node;

    gint end_pos = offset + eff_struct_len;
    offset++;

    if( struct_len != 8 )
    {
      knxip_item_illegal_length( length_item, pinfo, "Expected: 8 bytes" );
      ok = 0;
    }

    if( struct_len > remaining_len )
    {
      expert_add_info_format( pinfo, length_item, KIP_ERROR, "Available: %u bytes", remaining_len );
      struct_len = (guint8) remaining_len;

      if( ok )
      {
        proto_item_prepend_text( length_item, "? " );
        ok = 0;
      }
    }
    else if( struct_len < 2 )
    {
      expert_add_info_format( pinfo, hpai_item, KIP_ERROR, "Missing 1 byte Host Protocol" );
      ok = 0;
    }
    else
    {
      /* 1 byte Host Protocol */
      guint8 host_protocol = tvb_get_guint8( tvb, offset );
      const gchar* host_protocol_name = "???";
      guint8 protocol_error = 0;

      node = proto_tree_add_item( hpai_tree, hf_knxip_host_protocol, tvb, offset, 1, ENC_BIG_ENDIAN );

      if( host_protocol == KIP_IPV4_UDP )
      {
        host_protocol_name = "UDP";
        if( check_protocol )
        {
          if( knxip_host_protocol != IP_PROTO_UDP && knxip_host_protocol != IP_PROTO_UDPLITE )
          {
            protocol_error = 1;
          }
        }
      }
      else if( host_protocol == KIP_IPV4_TCP )
      {
        host_protocol_name = "TCP";
        if( check_protocol )
        {
          if( knxip_host_protocol != IP_PROTO_TCP )
          {
            protocol_error = 1;
          }
        }
      }
      else
      {
        protocol_error = 2;
      }

      if( protocol_error )
      {
        proto_item_prepend_text( node, "? " );
        expert_add_info_format( pinfo, node, KIP_ERROR, (protocol_error == 1) ? "Wrong Host Protocol" : "Expected: 0x01 or 0x02" );
        ok = 0;
      }

      offset++;

      if( struct_len < 6 )
      {
        expert_add_info_format( pinfo, hpai_item, KIP_ERROR, "Missing 4 bytes IP Address" );
        ok = 0;
      }
      else
      {
        /* 4 bytes IP Address */
        node = knxip_tree_add_ip_address( hpai_tree, tvb, offset, output, output_max );

        if( host_protocol == KIP_IPV4_TCP && strcmp( output, "0.0.0.0" ) != 0 )
        {
          proto_item_prepend_text( node, "? " );
          expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 0.0.0.0" );
          ok = 0;
        }

        offset += 4;

        while( *output ) { ++output; --output_max; }
        if( output_max > 1 ) { *output++ = ':'; --output_max; }
        snprintf( output, output_max, "???" );

        if( struct_len < 8 )
        {
          expert_add_info_format( pinfo, hpai_item, KIP_ERROR, "Missing 2 bytes Port Number" );
          ok = 0;
        }
        else
        {
          /* 2 bytes Port Number */
          guint16 port = tvb_get_ntohs( tvb, offset );

          snprintf( output, output_max, "%u", port );
          while( *output ) { ++output; --output_max; }

          node = proto_tree_add_item( hpai_tree, hf_knxip_port, tvb, offset, 2, ENC_BIG_ENDIAN );

          if( host_protocol == KIP_IPV4_TCP && port != 0 )
          {
            proto_item_prepend_text( node, "? " );
            expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 0" );
            ok = 0;
          }

          offset += 2;
        }
      }

      if( offset < end_pos )
      {
        knxip_tree_add_unknown_data( hpai_tree, tvb, offset, end_pos - offset );
        ok = 0;
      }

      proto_item_append_text( hpai_item, ": %s %s", info, host_protocol_name );
    }
  }

  col_append_fstr( pinfo->cinfo, COL_INFO, " @%s", info );
  proto_item_append_text( item, ", %s @ %s", name, info );

  if( !ok )
  {
    proto_item_prepend_text( hpai_item, "? " );
    if( p_ok ) *p_ok = 0;
  }

  *p_offset += struct_len;
  return struct_len;
}

/* Dissect CRI (= Connection Request Information)
*/
static guint8 dissect_cri( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset, guint8* p_ok )
{
  gint offset = *p_offset;
  gint remaining_len = tvb_captured_length_remaining( tvb, offset );
  guint8 struct_len = (remaining_len <= 0) ? 0 : tvb_get_guint8( tvb, offset );
  gint eff_struct_len = (struct_len <= remaining_len) ? struct_len : remaining_len;

  proto_item* cri_item = proto_tree_add_none_format( tree, hf_folder, tvb, offset, eff_struct_len, "CRI" );

  guint8 conn_type = 0;
  const gchar* conn_type_name = NULL;
  guint8 ok = 0;
  gchar extra_text[ 32 ];
  *extra_text = '\0';

  if( struct_len <= 0 )
  {
    proto_item_prepend_text( cri_item, "Missing " );
    expert_add_info_format( pinfo, cri_item, KIP_ERROR, "Expected: min 2 bytes" );
    //ok = 0;
  }
  else
  {
    proto_tree* cri_tree = proto_item_add_subtree( cri_item, ett_cri );
    proto_item* length_item = knxip_tree_add_length( cri_tree, tvb, offset, struct_len );
    proto_item* type_item = NULL;
    guint8 length_ok = 1;

    if( struct_len > remaining_len )
    {
      expert_add_info_format( pinfo, length_item, KIP_ERROR, "Available: %u bytes", remaining_len );
      struct_len = (guint8) remaining_len;
      //ok = 0;
      length_ok = 0;
    }

    if( struct_len < 2 )
    {
      expert_add_info_format( pinfo, cri_item, KIP_ERROR, "Missing 1 byte Connection Type" );
      //ok = 0;
    }
    else
    {
      conn_type = tvb_get_guint8( tvb, offset + 1 );
      type_item = proto_tree_add_item( cri_tree, hf_knxip_connection_type, tvb, offset + 1, 1, ENC_BIG_ENDIAN );
      conn_type_name = try_val_to_str( conn_type, connection_type_vals );
      if( !conn_type_name )
      {
        proto_item_prepend_text( type_item, "? " );
        expert_add_info_format( pinfo, type_item, KIP_ERROR, "Unknown" );
        //ok = 0;

        if( struct_len > 2 )
        {
          knxip_tree_add_unknown_data( cri_tree, tvb, offset + 2, struct_len - 2 );
        }
      }
      else
      {
        proto_item_append_text( cri_item, " %s", conn_type_name );
        ok = 1;

        switch( conn_type )
        {
        case KIP_DEVICE_MGMT_CONNECTION:
        case KIP_REMLOG_CONNECTION:
        case KIP_REMCONF_CONNECTION:
        case KIP_OBJSVR_CONNECTION:
          if( struct_len > 2 )
          {
            expert_add_info_format( pinfo, length_item, KIP_ERROR, "Expected: 2 bytes" );
            length_ok = 0;

            knxip_tree_add_unknown_data( cri_tree, tvb, offset + 2, struct_len - 2 );
            ok = 0;
          }
          break;

        case KIP_TUNNEL_CONNECTION:
          if( (struct_len != 4) && (struct_len != 6) )
          {
            expert_add_info_format( pinfo, length_item, KIP_ERROR, "Expected: 4 or 6 bytes" );
            length_ok = 0;
            ok = 0;
          }
          if( struct_len >= 3 )
          {
            guint8 knx_layer = tvb_get_guint8( tvb, offset + 2 );
            const gchar* knx_layer_name = try_val_to_str( knx_layer, knx_layer_vals );
            proto_item* layer_item = proto_tree_add_item( cri_tree, hf_knxip_knx_layer, tvb, offset + 2, 1, ENC_BIG_ENDIAN );
            proto_item_append_text( cri_item, ", Layer: %s", knx_layer_name ? knx_layer_name : "Unknown" );
            if( !knx_layer_name )
            {
              proto_item_prepend_text( layer_item, "? " );
              expert_add_info_format( pinfo, layer_item, KIP_ERROR, "Expected: 0x02" );
              ok = 0;
            }

            if( struct_len < 4 )
            {
              expert_add_info_format( pinfo, cri_item, KIP_ERROR, "Missing Reserved byte" );
              ok = 0;
            }
            else
            {
              knxip_tree_add_reserved( cri_tree, tvb, offset + 3, pinfo, &ok );
            }
            if( struct_len >= 6 )
            {
              knxip_tree_add_knx_address( cri_tree, hf_knxip_knx_address, tvb, offset + 4, extra_text, sizeof extra_text );
            }
            if( struct_len > 6 )
            {
              knxip_tree_add_unknown_data( cri_tree, tvb, offset + 6, struct_len - 6 );
              ok = 0;
            }
          }
          break;
        }
      }
    }

    if( !length_ok )
    {
      proto_item_prepend_text( length_item, "? " );
    }
  }

  conn_type_name = try_val_to_str( conn_type, conn_type_vals );
  if( !conn_type_name )
  {
    ok = 0;
  }
  else
  {
    if( pinfo )
    {
      column_info* cinfo = pinfo->cinfo;
      col_prepend_fstr( cinfo, COL_INFO, "%s ", conn_type_name );
      if( *extra_text )
      {
        col_append_fstr( cinfo, COL_INFO, ", %s", extra_text );
      }
    }

    proto_item_append_text( item, ", %s", conn_type_name );
    if( *extra_text )
    {
      proto_item_append_text( item, ", %s", extra_text );
    }
  }

  if( !ok )
  {
    proto_item_prepend_text( cri_item, "? " );
    if( p_ok ) *p_ok = 0;
  }

  *p_offset += struct_len;
  return struct_len;
}

/* Dissect CRD (= Connection Response Data)
*/
static guint8 dissect_crd( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset, guint8* p_ok )
{
  gint offset = *p_offset;
  gint remaining_len = tvb_captured_length_remaining( tvb, offset );
  guint8 struct_len = (remaining_len <= 0) ? 0 : tvb_get_guint8( tvb, offset );
  gint eff_struct_len = (struct_len <= remaining_len) ? struct_len : remaining_len;

  proto_item* crd_item = proto_tree_add_none_format( tree, hf_folder, tvb, offset, eff_struct_len, "CRD" );

  guint8 conn_type = 0;
  const gchar* conn_type_name = NULL;
  guint8 ok = 0;

  if( struct_len <= 0 )
  {
    proto_item_prepend_text( crd_item, "Missing " );
    expert_add_info_format( pinfo, crd_item, KIP_ERROR, "Expected: min 2 bytes" );
    //ok = 0;
  }
  else
  {
    proto_tree* crd_tree = proto_item_add_subtree( crd_item, ett_crd );
    proto_item* length_item = knxip_tree_add_length( crd_tree, tvb, offset, struct_len );
    proto_item* type_item = NULL;
    guint8 length_ok = 1;

    if( struct_len > remaining_len )
    {
      expert_add_info_format( pinfo, length_item, KIP_ERROR, "Available: %u bytes", remaining_len );
      struct_len = (guint8) remaining_len;
      //ok = 0;
      length_ok = 0;
    }

    if( struct_len < 2 )
    {
      expert_add_info_format( pinfo, crd_item, KIP_ERROR, "Missing 1 byte Connection Type" );
      //ok = 0;
    }
    else
    {
      conn_type = tvb_get_guint8( tvb, offset + 1 );
      type_item = proto_tree_add_item( crd_tree, hf_knxip_connection_type, tvb, offset + 1, 1, ENC_BIG_ENDIAN );
      conn_type_name = try_val_to_str( conn_type, connection_type_vals );
      if( !conn_type_name )
      {
        proto_item_prepend_text( type_item, "? " );
        expert_add_info_format( pinfo, type_item, KIP_ERROR, "Unknown" );
        //ok = 0;

        if( struct_len > 2 )
        {
          knxip_tree_add_unknown_data( crd_tree, tvb, offset + 2, struct_len - 2 );
        }
      }
      else
      {
        proto_item_append_text( crd_item, " %s", conn_type_name );
        ok = 1;

        switch( conn_type )
        {
        case KIP_DEVICE_MGMT_CONNECTION:
        case KIP_REMLOG_CONNECTION:
        case KIP_REMCONF_CONNECTION:
        case KIP_OBJSVR_CONNECTION:
          if( struct_len > 2 )
          {
            expert_add_info_format( pinfo, length_item, KIP_ERROR, "Expected: 2 bytes" );
            knxip_tree_add_unknown_data( crd_tree, tvb, offset + 2, struct_len - 2 );
            ok = 0;
            length_ok = 0;
          }
          break;

        case KIP_TUNNEL_CONNECTION:
          if( struct_len != 4 )
          {
            expert_add_info_format( pinfo, length_item, KIP_ERROR, "Expected: 4 bytes" );
            ok = 0;
            length_ok = 0;
          }

          if( struct_len < 4 )
          {
            expert_add_info_format( pinfo, crd_item, KIP_ERROR, "Missing 2 bytes KNX Address" );
            //ok = 0;
            if( struct_len > 2 )
            {
              knxip_tree_add_unknown_data( crd_tree, tvb, offset + 2, struct_len - 2 );
            }
          }
          else
          {
            gchar output[ 40 ];
            knxip_tree_add_knx_address( crd_tree, hf_knxip_knx_address, tvb, offset + 2, output, sizeof output );
            proto_item_append_text( crd_item, ", KNX Address: %s", output );
            if( pinfo )
            {
              col_append_fstr( pinfo->cinfo, COL_INFO, ", %s", output );
            }
            if( item )
            {
              proto_item_append_text( item, ", %s", output );
            }
            if( struct_len > 4 )
            {
              knxip_tree_add_unknown_data( crd_tree, tvb, offset + 4, struct_len - 4 );
              //ok = 0;
            }
          }
          break;
        }
      }
    }

    if( !length_ok )
    {
      proto_item_prepend_text( length_item, "? " );
    }
  }

  conn_type_name = try_val_to_str( conn_type, conn_type_vals );
  if( pinfo && conn_type_name ) col_prepend_fstr( pinfo->cinfo, COL_INFO, "%s ", conn_type_name );
  proto_item_append_text( item, ", %s", conn_type_name ? conn_type_name : "???" );

  if( !ok )
  {
    proto_item_prepend_text( crd_item, "? " );
    if( p_ok ) *p_ok = 0;
  }

  *p_offset += struct_len;
  return struct_len;
}

/* Dissect Connection Header
*/
static guint8 dissect_cnhdr( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset, guint8* p_ok, guint8 response )
{
  gint offset = *p_offset;
  gint remaining_len = tvb_captured_length_remaining( tvb, offset );
  guint8 struct_len = (remaining_len <= 0) ? 0 : tvb_get_guint8( tvb, offset );
  gint eff_struct_len = (struct_len <= remaining_len) ? struct_len : remaining_len;

  proto_item* cnhdr_item = proto_tree_add_none_format( tree, hf_folder, tvb, offset, eff_struct_len, "Connection Header" );

  guint8 ok = 0;
  gchar info[ 100 ];
  gint output_max = sizeof info;
  gchar* output = info;

  *output++ = '#';
  output_max--;
  snprintf( output, output_max, "???" );

  if( struct_len <= 0 )
  {
    proto_item_prepend_text( cnhdr_item, "Missing " );
    expert_add_info_format( pinfo, cnhdr_item, KIP_ERROR, "Expected: 4 bytes" );
  }
  else
  {
    proto_tree* cnhdr_tree = proto_item_add_subtree( cnhdr_item, ett_cnhdr );
    proto_item* length_item = knxip_tree_add_length( cnhdr_tree, tvb, offset, struct_len );

    gint end_pos = offset + eff_struct_len;
    offset++;

    if( struct_len == 4 )
    {
      ok = 1;
    }
    else
    {
      knxip_item_illegal_length( length_item, pinfo, "Expected: 4 bytes" );
    }

    if( struct_len > remaining_len )
    {
      expert_add_info_format( pinfo, length_item, KIP_ERROR, "Available: %u bytes", remaining_len );
      struct_len = (guint8) remaining_len;

      if( ok )
      {
        proto_item_prepend_text( length_item, "? " );
        ok = 0;
      }
    }

    if( struct_len < 2 )
    {
      expert_add_info_format( pinfo, cnhdr_item, KIP_ERROR, "Missing 1 byte Channel" );
      //ok = 0;
    }
    else
    {
      snprintf( output, output_max, "%02X:", tvb_get_guint8( tvb, offset ) );
      while( *output ) { ++output; --output_max; }
      snprintf( output, output_max, "???" );

      proto_tree_add_item( cnhdr_tree, hf_knxip_channel, tvb, offset, 1, ENC_BIG_ENDIAN );
      offset++;

      if( struct_len < 3 )
      {
        expert_add_info_format( pinfo, cnhdr_item, KIP_ERROR, "Missing 1 byte Sequence Counter" );
        //ok = 0;
      }
      else
      {
        snprintf( output, output_max, "%u", tvb_get_guint8( tvb, offset ) );
        while( *output ) { ++output; --output_max; }

        proto_tree_add_item( cnhdr_tree, hf_knxip_seq_counter, tvb, offset, 1, ENC_BIG_ENDIAN );
        offset++;

        if( response )
        {
          if( output_max > 1 )
          {
            *output++ = ' ';
            output_max--;
            snprintf( output, output_max, "???" );
          }
        }

        if( struct_len < 4 )
        {
          expert_add_info_format( pinfo, cnhdr_item, KIP_ERROR, "Missing 1 byte %s", response ? "Status" : "Reserved" );
          //ok = 0;
        }
        else
        {
          if( response )
          {
            snprintf( output, output_max, "%s", val_to_str( tvb_get_guint8( tvb, offset ), error_vals, "Error 0x%02x" ) );
            knxip_tree_add_status( cnhdr_tree, tvb, offset );
          }
          else
          {
            knxip_tree_add_reserved( cnhdr_tree, tvb, offset, pinfo, &ok );
          }

          offset++;
        }
      }

      if( offset < end_pos )
      {
        knxip_tree_add_unknown_data( cnhdr_tree, tvb, offset, end_pos - offset );
        //ok = 0;
      }

      proto_item_append_text( cnhdr_item, ": %s", info );
    }
  }

  if( pinfo ) col_append_fstr( pinfo->cinfo, COL_INFO, " %s", info );
  proto_item_append_text( item, ", %s", info );

  if( !ok )
  {
    proto_item_prepend_text( cnhdr_item, "? " );
    if( p_ok ) *p_ok = 0;
  }

  *p_offset += struct_len;
  return struct_len;
}

/* Dissect tunneling feature frames.
*/
static void dissect_tunneling_feature( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset, guint8* p_ok, guint16 service )
{
  column_info* cinfo = pinfo->cinfo;
  gint offset = *p_offset;
  gint remaining_len;
  proto_item* node;
  guint8 c;
  const gchar* name;
  guint8 ok = 1;
  guint8 isResponse = (service == KIP_TUNNELING_FEATURE_RESPONSE);
  guint8 status = 0;

  /* Connection Header */
  dissect_cnhdr( tvb, pinfo, item, tree, &offset, &ok, FALSE );

  remaining_len = tvb_captured_length_remaining( tvb, offset );

  /* 1 byte Feature Identifier */
  if( remaining_len <= 0 )
  {
    proto_tree_add_expert_format( tree, pinfo, KIP_ERROR, tvb, offset, 0, "? Feature Identifier: expected 1 byte" );
    ok = 0;
  }
  else
  {
    c = tvb_get_guint8( tvb, offset );
    name = try_val_to_str( c, tunneling_feature_id_vals );
    if( !name ) name = "Unknown";
    node = proto_tree_add_item( tree, hf_knxip_tunnel_feature, tvb, offset, 1, ENC_BIG_ENDIAN );
    proto_item_append_text( node, " = %s", name );
    proto_item_append_text( item, " %s", name );
    col_append_fstr( cinfo, COL_INFO, " %s", name );

    ++offset;
    --remaining_len;
  }

  /* 1 byte Return Code / Reserved */
  name = isResponse ? "Status" : "Reserved";
  if( remaining_len <= 0 )
  {
    proto_tree_add_expert_format( tree, pinfo, KIP_ERROR, tvb, offset, 0, "? %s: expected 1 byte", name );
    ok = 0;
  }
  else
  {
    status = tvb_get_guint8( tvb, offset );
    proto_tree_add_item( tree, isResponse ? hf_knxip_status : hf_knxip_reserved, tvb, offset, 1, ENC_BIG_ENDIAN );

    if( isResponse && (status != 0 || remaining_len == 1) )
    {
      proto_item_append_text( item, " E=$%02X", status );
      col_append_fstr( cinfo, COL_INFO, " E=$%02X", status );
    }

    ++offset;
    --remaining_len;
  }

  /* Feature Value */
  if( remaining_len <= 0 )
  {
    if( service != KIP_TUNNELING_FEATURE_GET && status == 0 )
    {
      proto_tree_add_expert_format( tree, pinfo, KIP_ERROR, tvb, offset, 0, "? Feature Value: missing" );
      ok = 0;
    }
  }
  else
  {
    node = knxip_tree_add_data( tree, tvb, offset, remaining_len, cinfo, item, "Feature Value", " $", " $" );
    if( service == KIP_TUNNELING_FEATURE_GET )
    {
      expert_add_info_format( pinfo, node, KIP_ERROR, "Unexpected" );
      ok = 0;
    }
    offset += remaining_len;
  }

  *p_offset = offset;

  if( p_ok && !ok ) *p_ok = 0;
}

/* Dissect cEMI
*/
static void dissect_cemi( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* p_offset )
{
  gint offset = *p_offset;
  gint remaining_len = tvb_captured_length_remaining( tvb, offset );

  /* Call the cEMI data dissector for the remaining bytes
  */
  tvb = tvb_new_subset_remaining( tvb, offset );

  dissector_handle_t cemi_handle = find_dissector( "cemi" );
  if( cemi_handle )
  {
    call_dissector( cemi_handle, tvb, pinfo, tree );
  }


  *p_offset = offset + remaining_len;
}

/* Dissect ROUTING_LOSS
*/
static guint8 dissect_routing_loss( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset )
{
  gint offset = *p_offset;
  gint remaining_len = tvb_captured_length_remaining( tvb, offset );
  guint8 struct_len = (remaining_len <= 0) ? 0 : tvb_get_guint8( tvb, offset );
  gint eff_struct_len = (struct_len <= remaining_len) ? struct_len : remaining_len;
  guint8 ok = 0;

  proto_item* info_item = proto_tree_add_none_format( tree, hf_folder, tvb, offset, struct_len, "Loss Info" );

  gchar info[ 16 ];
  snprintf( info, sizeof info, "???" );

  if( struct_len <= 0 )
  {
    proto_item_prepend_text( info_item, "Missing " );
    expert_add_info_format( pinfo, info_item, KIP_ERROR, "Expected: 4 bytes" );
  }
  else
  {
    proto_tree* info_tree = proto_item_add_subtree( info_item, ett_loss );
    proto_item* length_item = knxip_tree_add_length( info_tree, tvb, offset, struct_len );

    gint end_pos = offset + eff_struct_len;
    offset++;

    if( struct_len == 4 )
    {
      ok = 1;
    }
    else
    {
      expert_add_info_format( pinfo, length_item, KIP_ERROR, "Expected: 4 bytes" );
    }

    if( struct_len > remaining_len )
    {
      expert_add_info_format( pinfo, length_item, KIP_ERROR, "Available: %u bytes", remaining_len );
      struct_len = (guint8) remaining_len;
      ok = 0;
    }

    if( !ok )
    {
      proto_item_prepend_text( length_item, "? " );
    }

    if( struct_len >= 2 )
    {
      knxip_tree_add_status( info_tree, tvb, offset );
      offset++;

      /* 2 bytes Lost Messages */
      if( struct_len >= 4 )
      {
        guint16 loss = tvb_get_ntohs( tvb, offset );
        snprintf( info, sizeof info, "%u", loss );
        proto_tree_add_item( info_tree, hf_knxip_routing_loss, tvb, offset, 2, ENC_BIG_ENDIAN );
        offset += 2;
      }

      if( offset < end_pos )
      {
        knxip_tree_add_unknown_data( info_tree, tvb, offset, end_pos - offset );
      }

      proto_item_append_text( info_item, ": %s", info );
    }
  }

  if( pinfo ) col_append_fstr( pinfo->cinfo, COL_INFO, ": %s", info );
  proto_item_append_text( item, ": %s", info );

  if( !ok )
  {
    proto_item_prepend_text( info_item, "? " );
  }

  *p_offset += struct_len;
  return ok;
}

/* Dissect ROUTING_BUSY
*/
static guint8 dissect_routing_busy( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset )
{
  gint offset = *p_offset;
  gint remaining_len = tvb_captured_length_remaining( tvb, offset );
  guint8 struct_len = (remaining_len <= 0) ? 0 : tvb_get_guint8( tvb, offset );
  gint eff_struct_len = (struct_len <= remaining_len) ? struct_len : remaining_len;
  guint8 ok = 0;

  proto_item* info_item = proto_tree_add_none_format( tree, hf_folder, tvb, offset, eff_struct_len, "Busy Info" );

  gchar info[ 16 ];
  snprintf( info, sizeof info, "???" );

  if( struct_len <= 0 )
  {
    proto_item_prepend_text( info_item, "Missing " );
    expert_add_info_format( pinfo, info_item, KIP_ERROR, "Expected: 6 bytes" );
  }
  else
  {
    proto_tree* info_tree = proto_item_add_subtree( info_item, ett_loss );
    proto_item* length_item = knxip_tree_add_length( info_tree, tvb, offset, struct_len );

    gint end_pos = offset + eff_struct_len;
    offset++;

    if( struct_len == 6 )
    {
      ok = 1;
    }
    else
    {
      expert_add_info_format( pinfo, length_item, KIP_ERROR, "Expected: 6 bytes" );
    }

    if( struct_len > remaining_len )
    {
      expert_add_info_format( pinfo, length_item, KIP_ERROR, "Available: %u bytes", remaining_len );
      struct_len = (guint8) remaining_len;
      ok = 0;
    }

    if( !ok )
    {
      proto_item_prepend_text( length_item, "? " );
    }

    if( struct_len >= 2 )
    {
      knxip_tree_add_status( info_tree, tvb, offset );
      offset++;

      if( struct_len >= 4 )
      {
        /* 2 bytes Wait Time (ms) */
        proto_item* new_item = proto_tree_add_item( info_tree, hf_knxip_busy_time, tvb, offset, 2, ENC_BIG_ENDIAN );
        proto_item_append_text( new_item, " ms" );
        snprintf( info, sizeof info, "%u ms", tvb_get_ntohs( tvb, offset ) );
        offset += 2;

        if( struct_len >= 6 )
        {
          /* 2 bytes Control */
          proto_tree_add_item( info_tree, hf_knxip_busy_control, tvb, offset, 2, ENC_BIG_ENDIAN );
          offset += 2;
        }
      }

      if( offset < end_pos )
      {
        knxip_tree_add_unknown_data( info_tree, tvb, offset, end_pos - offset );
      }

      proto_item_append_text( info_item, ": %s", info );
    }
  }

  if( pinfo ) col_append_fstr( pinfo->cinfo, COL_INFO, ": %s", info );
  proto_item_append_text( item, ": %s", info );

  if( !ok )
  {
    proto_item_prepend_text( info_item, "? " );
  }

  *p_offset += struct_len;
  return ok;
}

/* Dissect SELECTOR field
*/
static guint8 dissect_selector( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset, guint8* p_ok )
{
  gint offset = *p_offset;
  gint remaining_len = tvb_captured_length_remaining( tvb, offset );
  guint8 struct_len = (remaining_len <= 0) ? 0 : tvb_get_guint8( tvb, offset );
  gint eff_struct_len = (struct_len <= remaining_len) ? struct_len : remaining_len;
  guint8 ok = 0;

  proto_item* info_item = proto_tree_add_none_format( tree, hf_folder, tvb, offset, eff_struct_len, "Selector" );

  gchar info[ 40 ];
  snprintf( info, sizeof info, "???" );

  if( struct_len <= 0 )
  {
    proto_item_prepend_text( info_item, "Missing " );
    expert_add_info_format( pinfo, info_item, KIP_ERROR, "Expected: min 2 bytes" );
    //ok = 0;
  }
  else
  {
    proto_tree* info_tree = proto_item_add_subtree( info_item, ett_loss );
    proto_item* length_item = knxip_tree_add_length( info_tree, tvb, offset, struct_len );
    guint8 length_ok = 1;

    gint end_pos = offset + eff_struct_len;
    offset++;

    if( struct_len > remaining_len )
    {
      expert_add_info_format( pinfo, length_item, KIP_ERROR, "Available: %u bytes", remaining_len );
      //ok = 0;
      length_ok = 0;
      struct_len = (guint8) remaining_len;
    }

    if( struct_len < 2 )
    {
      expert_add_info_format( pinfo, length_item, KIP_ERROR, "Expected: min 2 bytes" );
      //ok = 0;
      length_ok = 0;
    }
    else
    {
      /* 1 byte Selection Type */
      guint8 sel = tvb_get_guint8( tvb, offset );
      proto_item* type_item = proto_tree_add_item( info_tree, hf_knxip_selector, tvb, offset, 1, ENC_BIG_ENDIAN );
      proto_item_append_text( type_item, " = %s", (sel == SELECT_PROGMODE) ? "ProgMode" : (sel == SELECT_MACADDRESS) ? "MAC" : "Unknown" );
      offset++;
      ok = 1;

      if( sel == SELECT_PROGMODE )
      {
        snprintf( info, sizeof info, "ProgMode" );

        if( struct_len != 2 )
        {
          expert_add_info_format( pinfo, length_item, KIP_ERROR, "Expected: 2 bytes" );
          ok = 0;
          length_ok = 0;
        }
      }
      else if( sel == SELECT_MACADDRESS )
      {
        gchar* output = info;
        gint output_max = sizeof info;
        snprintf( output, output_max, "MAC=" );
        while( *output ) { ++output; --output_max; }
        snprintf( output, output_max, "???" );

        if( struct_len != 8 )
        {
          expert_add_info_format( pinfo, length_item, KIP_ERROR, "Expected: 8 bytes" );
          ok = 0;
          length_ok = 0;
        }

        if( struct_len >= 8 )
        {
          /* 6 bytes MAC Address */
          guint8 mac[ 6 ];
          tvb_memcpy( tvb, mac, offset, 6 );
          snprintf( output, output_max, "%02x:%02x:%02x:%02x:%02x:%02x", mac[ 0 ], mac[ 1 ], mac[ 2 ], mac[ 3 ], mac[ 4 ], mac[ 5 ] );
          proto_tree_add_item( info_tree, hf_knxip_mac_address, tvb, offset, 6, ENC_NA );
          offset += 6;
        }
      }
      else
      {
        proto_item_prepend_text( type_item, "? " );
        expert_add_info_format( pinfo, type_item, KIP_ERROR, "Unknown" );
        ok = 0;
      }

      if( offset < end_pos )
      {
        knxip_tree_add_unknown_data( info_tree, tvb, offset, end_pos - offset );
        ok = 0;
      }

      proto_item_append_text( info_item, ": %s", info );
    }

    if( !length_ok )
    {
      proto_item_prepend_text( length_item, "? " );
    }
  }

  if( pinfo ) col_append_fstr( pinfo->cinfo, COL_INFO, " %s", info );
  proto_item_append_text( item, ", %s", info );

  if( !ok )
  {
    proto_item_prepend_text( info_item, "? " );
    if( p_ok ) *p_ok = 0;
  }

  *p_offset += struct_len;
  if( p_ok && !ok ) *p_ok = 0;
  return struct_len;
}

/* Dissect DevInfo DIB
*/
static guint8 dissect_dib_devinfo( tvbuff_t* tvb, packet_info* pinfo,
  proto_item* dib_item, proto_tree* dib_tree, proto_item* length_item, guint8 length_ok,
  gint* p_offset, guint8 struct_len, wmem_strbuf_t* output )
{
  gint offset = *p_offset;
  wmem_strbuf_t* info = wmem_strbuf_new(wmem_packet_scope(), "");
  guint8 prog_mode = 0;
  guint8 ok = 1;

  if( struct_len != 54 )
  {
    if( length_ok ) knxip_item_illegal_length( length_item, pinfo, "Expected: 54 bytes" );
    ok = 0;
  }

  if( struct_len >= 3 )
  {
    /* 1 byte KNX Medium */
    guint8 knx_medium = tvb_get_guint8( tvb, offset );
    proto_item* item = proto_tree_add_item( dib_tree, hf_knxip_knx_medium, tvb, offset, 1, ENC_BIG_ENDIAN );
    proto_tree* tree = proto_item_add_subtree( item, ett_medium );
    knxip_tree_add_bit( tree, tvb, offset, 5, "IP", NULL, 0 );
    knxip_tree_add_bit( tree, tvb, offset, 4, "RF", NULL, 0 );
    knxip_tree_add_bit( tree, tvb, offset, 3, "PL132", NULL, 0 );
    knxip_tree_add_bit( tree, tvb, offset, 2, "PL110", NULL, 0 );
    knxip_tree_add_bit( tree, tvb, offset, 1, "TP1", NULL, 0 );
    knxip_tree_add_bit( tree, tvb, offset, 0, "TP0", NULL, 0 );

    /* Check for missing or multiple medium */
    {
      guint8 data = knx_medium;
      guint8 media = 0;
      while( data )
      {
        if( data & 1 )
        {
          media++;
        }
        data >>= 1;;
      }

      if( media != 1 )
      {
        expert_add_info_format( pinfo, item, KIP_WARNING, media ? "Multiple" : "Missing" );
      }
    }

    offset++;

    if( struct_len >= 4 )
    {
      /* 1 byte Device Status */
      guint8 status = tvb_get_guint8( tvb, offset );
      item = proto_tree_add_item( dib_tree, hf_knxip_device_status, tvb, offset, 1, ENC_BIG_ENDIAN );
      tree = proto_item_add_subtree( item, ett_status );
      proto_tree_add_item( tree, hf_knxip_program_mode, tvb, offset, 1, ENC_BIG_ENDIAN );

      if( status & 0x01 )
      {
        proto_item_append_text( item, " (ProgMode)" );
        prog_mode = 1;
      }

      offset++;

      if( struct_len >= 6 )
      {
        /* 2 bytes KNX Address */
        gchar addr[ 32 ];
        knxip_tree_add_knx_address( dib_tree, hf_knxip_knx_address, tvb, offset, addr, sizeof addr );
        wmem_strbuf_append( info, addr );

        offset += 2;

        if( struct_len >= 8 )
        {
          /* 2 bytes Project Installation Identifier */
          guint16 project_id = tvb_get_ntohs( tvb, offset );
          item = proto_tree_add_item( dib_tree, hf_knxip_project_id, tvb, offset, 2, ENC_BIG_ENDIAN );
          tree = proto_item_add_subtree( item, ett_projectid );
          proto_tree_add_item( tree, hf_knxip_project_number, tvb, offset, 2, ENC_BIG_ENDIAN );
          proto_tree_add_item( tree, hf_knxip_installation_number, tvb, offset, 2, ENC_BIG_ENDIAN );
          proto_item_append_text( item, " (%u:%u)", project_id / 16, project_id % 16 );

          offset += 2;

          if( struct_len >= 14 )
          {
            /* 6 bytes KNX Serial Number */
            proto_tree_add_item( dib_tree, hf_knxip_serial_number, tvb, offset, 6, ENC_BIG_ENDIAN );
            offset += 6;
          }

          if( struct_len >= 18 )
          {
            /* 4 bytes Routing Multicast Address */
            proto_tree_add_item( dib_tree, hf_knxip_multicast_address, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset += 4;

            if( struct_len >= 24 )
            {
              /* 6 bytes MAC Address */
              proto_tree_add_item( dib_tree, hf_knxip_mac_address, tvb, offset, 6, ENC_NA );
              offset += 6;

              if( struct_len >= 54 )
              {
                /* 30 bytes Friendly Name - ISO 8859-1 */
                char *friendly_name;

                proto_tree_add_item_ret_display_string( dib_tree, hf_knxip_friendly_name, tvb, offset, 30, ENC_ISO_8859_1 | ENC_NA, wmem_packet_scope(), &friendly_name );

                wmem_strbuf_append_printf( info, " \"%s\"", friendly_name );

                offset += 30;
              }
            }
          }
        }
      }
    }
  }

  if( wmem_strbuf_get_len( info ) == 0 )
  {
    wmem_strbuf_append( info, "???" );
  }
  if( prog_mode )
  {
    wmem_strbuf_append( info, " PROGMODE" );
  }
  if( output )
  {
    wmem_strbuf_append( output, wmem_strbuf_get_str( info ) );
  }
  proto_item_append_text( dib_item, ": %s", wmem_strbuf_get_str( info ) );

  *p_offset = offset;
  return ok;
}

/* Dissect SuppSvc DIB
*/
static guint8 dissect_dib_suppsvc( tvbuff_t* tvb, packet_info* pinfo,
  proto_item* dib_item, proto_tree* dib_tree, proto_item* length_item, guint8 length_ok,
  gint* p_offset, guint8 struct_len )
{
  gint offset = *p_offset;
  gint end_pos = offset - 2 + struct_len;
  guint8 ok = 1;
  gchar separator = ':';
  guint8 sf_count[ 8 ] = { 0 };

  if( struct_len & 1 )
  {
    if( length_ok ) knxip_item_illegal_length( length_item, pinfo, "Expected: even number" );
    ok = 0;
  }

  while( offset + 2 <= end_pos )
  {
    guint8 service_family = tvb_get_guint8( tvb, offset );
    guint8 version = tvb_get_guint8( tvb, offset + 1 );
    const gchar* service_family_name = try_val_to_str( service_family, knxip_service_family_vals );
    proto_item* item = proto_tree_add_none_format( dib_tree, hf_folder, tvb, offset, 2, "KNXnet/IP %s v%u",
      service_family_name ? service_family_name : "Unknown Service Family", version );
    proto_tree* tree = proto_item_add_subtree( item, ett_service_family );

    /* 1 byte Service Family ID */
    proto_tree_add_item( tree, hf_knxip_service_family, tvb, offset, 1, ENC_BIG_ENDIAN );

    /* 1 byte Service Family Version */
    proto_tree_add_item( tree, hf_knxip_service_version, tvb, offset + 1, 1, ENC_BIG_ENDIAN );

    if( service_family >= KIP_SERVICE_TUNNELING && service_family_name )
    {
      proto_item_append_text( dib_item, "%c %s", separator, service_family_name );
      separator = ',';
    }

    if( service_family < 8 )
    {
      ++sf_count[ service_family ];
    }

    offset += 2;
  }

  if( !sf_count[ KIP_SERVICE_CORE ] )
  {
    expert_add_info_format( pinfo, dib_item, KIP_WARNING, "Missing: Core (0x02)" );
  }
  if( !sf_count[ KIP_SERVICE_MANAGEMENT ] )
  {
    expert_add_info_format( pinfo, dib_item, KIP_WARNING, "Missing: Device Management (0x03)" );
  }

  *p_offset = offset;
  return ok;
}

/* Dissect IpConfig DIB
*/
static guint8 dissect_dib_ipconfig( tvbuff_t* tvb, packet_info* pinfo,
  proto_item* dib_item, proto_tree* dib_tree, proto_item* length_item, guint8 length_ok,
  gint* p_offset, guint8 struct_len )
{
  gint offset = *p_offset;
  guint8 ok = 1;
  gchar text[ 32 ];

  if( struct_len != 16 )
  {
    if( length_ok ) knxip_item_illegal_length( length_item, pinfo, "Expected: 16 bytes" );
    ok = 0;
  }

  if( struct_len < 6 )
  {
    snprintf( text, sizeof text, "???" );
  }
  else
  {
    /* 4 bytes IP Address */
    knxip_tree_add_ip_address( dib_tree, tvb, offset, text, sizeof text );
    offset += 4;

    if( struct_len >= 10 )
    {
      /* 4 bytes Subnet Mask */
      proto_tree_add_item( dib_tree, hf_knxip_ip_subnet, tvb, offset, 4, ENC_BIG_ENDIAN );
      offset += 4;

      if( struct_len >= 14 )
      {
        /* 4 bytes Default Gateway */
        proto_tree_add_item( dib_tree, hf_knxip_ip_gateway, tvb, offset, 4, ENC_BIG_ENDIAN );
        offset += 4;

        if( struct_len >= 15 )
        {
          /* 1 byte IP Capabilities */
          knxip_tree_add_ip_assignment( dib_tree, hf_knxip_ip_caps, tvb, offset, 0 );
          offset++;

          if( struct_len >= 16 )
          {
            /* 1 byte IP Assignment Method */
            knxip_tree_add_ip_assignment( dib_tree, hf_knxip_ip_assign, tvb, offset, 1 );
            offset++;
          }
        }
      }
    }
  }

  proto_item_append_text( dib_item, ": %s", text );

  *p_offset = offset;
  return ok;
}

/* Dissect CurConfig DIB
*/
static guint8 dissect_dib_curconfig( tvbuff_t* tvb, packet_info* pinfo,
  proto_item* dib_item, proto_tree* dib_tree, proto_item* length_item, guint8 length_ok,
  gint* p_offset, guint8 struct_len )
{
  gint offset = *p_offset;
  guint8 ok = 1;
  gchar text[ 32 ];

  if( struct_len != 20 )
  {
    if( length_ok ) knxip_item_illegal_length( length_item, pinfo, "Expected: 20 bytes" );
    ok = 0;
  }

  if( struct_len < 6 )
  {
    snprintf( text, sizeof text, "???" );
  }
  else
  {
    /* 4 bytes IP Address */
    knxip_tree_add_ip_address( dib_tree, tvb, offset, text, sizeof text );
    offset += 4;

    if( struct_len >= 10 )
    {
      /* 4 bytes Subnet Mask */
      proto_tree_add_item( dib_tree, hf_knxip_ip_subnet, tvb, offset, 4, ENC_BIG_ENDIAN );
      offset += 4;

      if( struct_len >= 14 )
      {
        /* 4 bytes Default Gateway */
        proto_tree_add_item( dib_tree, hf_knxip_ip_gateway, tvb, offset, 4, ENC_BIG_ENDIAN );
        offset += 4;

        if( struct_len >= 18 )
        {
          /* 4 bytes DHCP Server */
          proto_tree_add_item( dib_tree, hf_knxip_ip_dhcp, tvb, offset, 4, ENC_BIG_ENDIAN );
          offset += 4;

          if( struct_len >= 19 )
          {
            /* IP Assignment Method */
            knxip_tree_add_ip_assignment( dib_tree, hf_knxip_ip_assign, tvb, offset, 1 );
            offset++;

            if( struct_len >= 20 )
            {
              /* Reserved Byte */
              knxip_tree_add_reserved( dib_tree, tvb, offset, pinfo, &ok );
              offset++;
            }
          }
        }
      }
    }
  }

  proto_item_append_text( dib_item, ": %s", text );

  *p_offset = offset;
  return ok;
}

/* Dissect KnxAddr DIB
*/
static guint8 dissect_dib_knxaddr( tvbuff_t* tvb, packet_info* pinfo,
  proto_item* dib_item, proto_tree* dib_tree, proto_item* length_item, guint8 length_ok,
  gint* p_offset, guint8 struct_len )
{
  gint offset = *p_offset;
  guint8 ok = 1;
  gchar text1[ 32 ];
  gchar text2[ 32 ];

  if( struct_len < 4 )
  {
    if( length_ok ) knxip_item_illegal_length( length_item, pinfo, "Expected: >= 4 bytes" );
    snprintf( text1, sizeof text1, "???" );
    ok = 0;
  }
  else
  {
    gint end_pos = offset - 2 + struct_len;

    if( struct_len & 1 )
    {
      if( length_ok ) knxip_item_illegal_length( length_item, pinfo, "Expected: even number" );
      ok = 0;
    }

    /* 2 bytes KNX Address */
    knxip_tree_add_knx_address( dib_tree, hf_knxip_knx_address, tvb, offset, text1, sizeof text1 );
    proto_item_append_text( dib_item, ": %s", text1 );
    offset += 2;

    while( offset + 2 <= end_pos )
    {
      /* 2 bytes Additional KNX Address */
      knxip_tree_add_knx_address( dib_tree, hf_knxip_knx_address, tvb, offset, text2, sizeof text2 );
      proto_item_append_text( dib_item, ", %s", text2 );
      offset += 2;
    }
  }

  *p_offset = offset;
  return ok;
}

/* Dissect SecuredServices DIB
*/
static guint8 dissect_dib_secured_service_families( tvbuff_t* tvb, packet_info* pinfo,
  proto_item* dib_item, proto_tree* dib_tree, proto_item* length_item, guint8 length_ok,
  gint* p_offset, guint8 struct_len )
{
  gint offset = *p_offset;
  gint end_pos = offset - 2 + struct_len;
  guint8 ok = 1;
  gchar separator = ':';

  if( struct_len & 1 )
  {
    if( length_ok ) knxip_item_illegal_length( length_item, pinfo, "Expected: even number" );
    ok = 0;
  }

  while( offset + 2 <= end_pos )
  {
    guint8 service_family = tvb_get_guint8( tvb, offset );
    guint8 version = tvb_get_guint8( tvb, offset + 1 );
    const gchar* service_family_name = try_val_to_str( service_family, knxip_service_family_vals );
    proto_item* item = proto_tree_add_none_format( dib_tree, hf_folder, tvb, offset, 2, "KNXnet/IP %s v%u",
      service_family_name ? service_family_name : "Unknown Service Family", version );
    proto_tree* tree = proto_item_add_subtree( item, ett_service_family );

    /* 1 byte Service Family ID */
    proto_tree_add_item( tree, hf_knxip_service_family, tvb, offset, 1, ENC_BIG_ENDIAN );

    /* 1 byte Security Version */
    proto_tree_add_item( tree, hf_knxip_security_version, tvb, offset + 1, 1, ENC_BIG_ENDIAN );

    if( service_family_name )
    {
      proto_item_append_text( dib_item, "%c %s", separator, service_family_name );
      separator = ',';
    }

    offset += 2;
  }

  *p_offset = offset;
  return ok;
}

/* Dissect TunnelingInfo DIB
*/
static guint8 dissect_dib_tunneling_info( tvbuff_t* tvb, packet_info* pinfo,
  proto_item* dib_item, proto_tree* dib_tree, proto_item* length_item, guint8 length_ok,
  gint* p_offset, guint8 struct_len )
{
  gint offset = *p_offset;
  guint8 ok = 1;

  if( struct_len < 4 )
  {
    if( length_ok )
    {
      knxip_item_illegal_length( length_item, pinfo, "Expected: >= 4 bytes" );
      ok = 0;
    }
  }
  else
  {
    gint end_pos = offset - 2 + struct_len;
    gchar separator = ':';

    /* 2 bytes Max APDU Length */
    proto_tree_add_item( dib_tree, hf_knxip_max_apdu_length, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;

    if( struct_len & 3 )
    {
      if( length_ok )
      {
        knxip_item_illegal_length( length_item, pinfo, "Expected: 4 + n * 4 bytes" );
        ok = 0;
      }
    }

    while( offset + 4 <= end_pos )
    {
      guint8 flags = tvb_get_guint8( tvb, offset + 3 );
      guint8 is_free = flags & 1;
      gchar text[ 32 ];
      proto_item* node;
      proto_tree* list;

      node = proto_tree_add_none_format( dib_tree, hf_folder, tvb, offset, 4, "Tunneling Slot" );
      list = proto_item_add_subtree( node, ett_tunnel );

      /* 2 bytes KNX Address, 1 byte reserved */
      knxip_tree_add_knx_address( list, hf_knxip_knx_address, tvb, offset, text, sizeof text );
      proto_item_append_text( node, ": %s Free=%u", text, is_free );
      offset += 3;

      /* 1 byte flags */
      knxip_tree_add_bit( list, tvb, offset, 2, "Usable", NULL, 0 );
      knxip_tree_add_bit( list, tvb, offset, 1, "Authorized", NULL, 0 );
      knxip_tree_add_bit( list, tvb, offset, 0, "Free", NULL, 0 );
      offset++;

      if( !is_free )
      {
        proto_item_append_text( dib_item, "%c %s", separator, text );
        separator = ',';
      }
    }
  }

  *p_offset = offset;
  return ok;
}

/* Dissect ExtDevInfo DIB
*/
static guint8 dissect_dib_extdevinfo( tvbuff_t* tvb, packet_info* pinfo,
  proto_item* dib_item, proto_tree* dib_tree, proto_item* length_item, guint8 length_ok,
  gint* p_offset, guint8 struct_len )
{
  gint offset = *p_offset;
  guint8 status = 0;
  guint8 ok = 1;

  if( struct_len != 8 )
  {
    if( length_ok ) knxip_item_illegal_length( length_item, pinfo, "Expected: 8 bytes" );
    ok = 0;
  }

  if( struct_len >= 3 )
  {
    /* 1 byte Medium Status */
    status = tvb_get_guint8( tvb, offset );
    proto_tree_add_item( dib_tree, hf_knxip_medium_status, tvb, offset, 1, ENC_BIG_ENDIAN );
    if( status )
    {
      proto_item_append_text( dib_item, ": MediumStatus=$%02X", status );
    }

    offset++;

    if( struct_len >= 4 )
    {
      /* 1 byte reserved */
      knxip_tree_add_reserved( dib_tree, tvb, offset, pinfo, &ok );
      offset++;

      if( struct_len >= 6 )
      {
        /* 2 bytes Max APDU Length */
        proto_tree_add_item( dib_tree, hf_knxip_max_apdu_length, tvb, offset, 2, ENC_BIG_ENDIAN );
        offset += 2;

        if( struct_len >= 8 )
        {
          /* 2 bytes Mask Version */
          proto_tree_add_item( dib_tree, hf_knxip_mask_version, tvb, offset, 2, ENC_BIG_ENDIAN );
          offset += 2;
        }
      }
    }
  }

  *p_offset = offset;
  return ok;
}

/* Dissect MfrData DIB
*/
static guint8 dissect_dib_mfrdata( tvbuff_t* tvb, packet_info* pinfo,
  proto_item* dib_item, proto_tree* dib_tree, proto_item* length_item, guint8 length_ok,
  gint* p_offset, guint8 struct_len )
{
  gint offset = *p_offset;
  guint8 ok = 1;
  gchar text[ 32 ];

  if( struct_len < 4 )
  {
    if( length_ok ) knxip_item_illegal_length( length_item, pinfo, "Expected: >= 4 bytes" );
    snprintf( text, sizeof text, "???" );
    ok = 0;
  }
  else
  {
    proto_tree_add_item( dib_tree, hf_knxip_manufacturer_code, tvb, offset, 2, ENC_BIG_ENDIAN );
    snprintf( text, sizeof text, "0x%04x", tvb_get_ntohs( tvb, offset ) );
    offset += 2;
  }

  proto_item_append_text( dib_item, ": %s", text );

  *p_offset = offset;
  return ok;
}

/* Dissect DIB
*/
static guint8 dissect_dib( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree,
  gint* p_offset, wmem_strbuf_t* output, gchar separator, guint8* p_count, guint8* p_ok )
{
  gint offset = *p_offset;
  gint remaining_len = tvb_captured_length_remaining( tvb, offset );
  guint8 struct_len = (remaining_len <= 0) ? 0 : tvb_get_guint8( tvb, offset );
  if( struct_len > 0 )
  {
    gint eff_struct_len = (struct_len <= remaining_len) ? struct_len : remaining_len;
    gint end_pos = offset + eff_struct_len;
    const gchar* dib_name = NULL;
    guint8 dib_type = 0;
    guint8 ok = 1;
    guint8 length_ok = 1;

    proto_item* dib_item = proto_tree_add_none_format( tree, hf_folder, tvb, offset, eff_struct_len, "DIB" );
    proto_tree* dib_tree = proto_item_add_subtree( dib_item, ett_dib );
    proto_item* length_item = knxip_tree_add_length( dib_tree, tvb, offset, struct_len );

    offset++;

    if( struct_len > remaining_len )
    {
      proto_item_prepend_text( length_item, "? " );
      expert_add_info_format( pinfo, length_item, KIP_ERROR, "Available: %u bytes", remaining_len );
      struct_len = (guint8) remaining_len;
      ok = 0;
      length_ok = 0;
    }

    if( eff_struct_len < 2 )
    {
      expert_add_info_format( pinfo, dib_item, KIP_ERROR, "Missing 1 byte Description Type" );
      ok = 0;
    }
    else
    {
      proto_item* type_item = proto_tree_add_item( dib_tree, hf_knxip_description_type, tvb, offset, 1, ENC_BIG_ENDIAN );

      dib_type = tvb_get_guint8( tvb, offset );
      dib_name = try_val_to_str( dib_type, descr_type_vals );
      offset++;

      if( !dib_name )
      {
        proto_item_append_text( dib_item, " ???" );
        proto_item_append_text( type_item, " (Unknown)" );
      }
      else
      {
        proto_item_append_text( dib_item, " %s", dib_name );
      }

      if( p_count )
      {
        ++p_count[ dib_type ];
      }

      switch( dib_type )
      {
      case KIP_DIB_DEVICE_INFO:
        ok &= dissect_dib_devinfo( tvb, pinfo, dib_item, dib_tree, length_item, length_ok, &offset, struct_len, output );
        break;

      case KIP_DIB_SUPP_SVC_FAMILIES:
        ok &= dissect_dib_suppsvc( tvb, pinfo, dib_item, dib_tree, length_item, length_ok, &offset, struct_len );
        break;

      case KIP_DIB_IP_CONFIG:
        ok &= dissect_dib_ipconfig( tvb, pinfo, dib_item, dib_tree, length_item, length_ok, &offset, struct_len );
        break;

      case KIP_DIB_CUR_CONFIG:
        ok &= dissect_dib_curconfig( tvb, pinfo, dib_item, dib_tree, length_item, length_ok, &offset, struct_len );
        break;

      case KIP_DIB_KNX_ADDRESSES:
        ok &= dissect_dib_knxaddr( tvb, pinfo, dib_item, dib_tree, length_item, length_ok, &offset, struct_len );
        break;

      case KIP_DIB_SECURED_SERVICE_FAMILIES:
        ok &= dissect_dib_secured_service_families( tvb, pinfo, dib_item, dib_tree, length_item, length_ok, &offset, struct_len );
        break;

      case KIP_DIB_TUNNELING_INFO:
        ok &= dissect_dib_tunneling_info( tvb, pinfo, dib_item, dib_tree, length_item, length_ok, &offset, struct_len );
        break;

      case KIP_DIB_EXTENDED_DEVICE_INFO:
        ok &= dissect_dib_extdevinfo( tvb, pinfo, dib_item, dib_tree, length_item, length_ok, &offset, struct_len );
        break;

      case KIP_DIB_MFR_DATA:
        ok &= dissect_dib_mfrdata( tvb, pinfo, dib_item, dib_tree, length_item, length_ok, &offset, struct_len );
        break;

      default:
        expert_add_info_format( pinfo, type_item, KIP_WARNING, "Unknown DIB Type" );
        break;
      }

      if( offset < end_pos )
      {
        knxip_tree_add_unknown_data( dib_tree, tvb, offset, end_pos - offset );
        offset =  end_pos;
      }
    }

    if( !output )
    {
      if( pinfo )
      {
        column_info* cinfo = pinfo->cinfo;
        col_append_fstr( cinfo, COL_INFO, "%c ", separator );

        if( !dib_name )
        {
          col_append_str( cinfo, COL_INFO, "???" );
        }
        else
        {
          if( !ok ) col_append_str( cinfo, COL_INFO, "? " );
          col_append_str( cinfo, COL_INFO, dib_name );
        }
      }

      if( item )
      {
        proto_item_append_text( item, "%c ", separator );

        if( !dib_name )
        {
          proto_item_append_text( item, "???" );
        }
        else
        {
          if( !ok ) proto_item_append_text( item, "? " );
          proto_item_append_text( item, "%s", dib_name );
        }
      }
    }

    if( !ok )
    {
      proto_item_prepend_text( dib_item, "? " );
      if( p_ok ) *p_ok = 0;
    }

    *p_offset = offset;
  }

  return struct_len;
}

/* Dissect sequence of DIBs
*/
static gchar dissect_dibs( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset, wmem_strbuf_t* output, gchar separator, guint8* p_count, guint8* p_ok )
{
  while( dissect_dib( tvb, pinfo, item, tree, p_offset, output, separator, p_count, p_ok ) )
  {
    separator = ',';
  }

  return separator;
}

/* Dissect SRP
*/
static guint8 dissect_srp( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset, guint8* p_ok )
{
  gint offset = *p_offset;
  gint remaining_len = tvb_captured_length_remaining( tvb, offset );
  guint8 struct_len = (remaining_len <= 0) ? 0 : tvb_get_guint8( tvb, offset );
  if( struct_len > 0 )
  {
    gint eff_struct_len = (struct_len <= remaining_len) ? struct_len : remaining_len;
    gint end_pos = offset + eff_struct_len;
    column_info* cinfo = pinfo ? pinfo->cinfo : NULL;
    proto_item* srp_item = proto_tree_add_none_format( tree, hf_folder, tvb, offset, eff_struct_len, "SRP" );
    proto_tree* srp_tree = proto_item_add_subtree( srp_item, ett_dib );
    proto_item* length_item = knxip_tree_add_length( srp_tree, tvb, offset, struct_len );
    guint8 ok = 1;
    guint8 length_ok = 1;

    offset++;

    if( struct_len > remaining_len )
    {
      expert_add_info_format( pinfo, length_item, KIP_ERROR, "Available: %u bytes", remaining_len );
      ok = 0;
      length_ok = 0;
    }

    if( eff_struct_len < 2 )
    {
      expert_add_info_format( pinfo, srp_item, KIP_ERROR, "Missing 1 byte SRP Type" );
      ok = 0;
    }
    else
    {
      /* 1 bit Mandatory */
      proto_tree_add_item( srp_tree, hf_knxip_srp_mandatory, tvb, offset, 1, ENC_BIG_ENDIAN );

      /* 7 bits SRP Type */
      guint8 srp_type = tvb_get_guint8( tvb, offset ) & 0x7F;
      const gchar* srp_name = try_val_to_str( srp_type, srp_type_vals );
      proto_item* type_item = proto_tree_add_item( srp_tree, hf_knxip_srp_type, tvb, offset, 1, ENC_BIG_ENDIAN );
      guint8 expected_len = 0;
      guint8 unknown = !srp_name;
      if( unknown )
      {
        expert_add_info_format( pinfo, type_item, KIP_WARNING, "Unknown SRP Type" );
        srp_name = "???";
      }

      proto_item_append_text( srp_item, " %s", srp_name ? srp_name : "???" );
      proto_item_append_text( type_item, " = %s", srp_name ? srp_name : "???" );

      if( !unknown )
      {
        col_append_fstr( cinfo, COL_INFO, " %s", srp_name );
        proto_item_append_text( item, ", %s", srp_name );
      }

      switch( srp_type )
      {
      case 1:
        expected_len = 2;
        break;
      case 2:
        expected_len = 8;
        break;
      case 3:
        expected_len = 4;
        break;
      }

      if( expected_len )
      {
        if( struct_len != expected_len )
        {
          expert_add_info_format( pinfo, length_item, KIP_ERROR, "Expected: %u bytes", expected_len );
          ok = 0;
          length_ok = 0;
        }
      }
      offset++;

      if( offset < end_pos )
      {
        knxip_tree_add_data( srp_tree, tvb, offset, end_pos - offset, srp_name ? cinfo : NULL, item, "Data", "=$", " = $" );

        proto_item_append_text( srp_item, ": $" );
        while( offset < end_pos )
        {
          proto_item_append_text( srp_item, " %02X", tvb_get_guint8( tvb, offset ) );
          ++offset;
        }

        //offset = end_pos;
      }
    }

    if( !ok )
    {
      proto_item_prepend_text( srp_item, "? " );
      if( p_ok ) *p_ok = 0;
    }

    if( !length_ok )
    {
      proto_item_prepend_text( length_item, "? " );
    }

    *p_offset += struct_len;
  }

  return struct_len;
}

/* Dissect sequence of SRPs
*/
static void dissect_srps( tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, gint *p_offset, guint8* p_ok )
{
  while( dissect_srp( tvb, pinfo, item, tree, p_offset, p_ok ) );
}

/* Dissect RESET command
*/
static guint8 dissect_resetter( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset )
{
  guint8 ok = 0;
  gint offset = *p_offset;
  gint remaining_len = tvb_captured_length_remaining( tvb, offset );
  guint8 struct_len = ((guint) remaining_len < 2) ? (guint8) remaining_len : 2;
  guint8 mode = (struct_len <= 0) ? 0 : tvb_get_guint8( tvb, offset );
  const gchar* mode_name = (mode == 0x01) ? "Restart" : (mode == 0x02) ? "Master Reset" : NULL;
  const gchar* mode_info = mode_name ? mode_name : "???";
  proto_item* node;

  if( struct_len <= 0 )
  {
    proto_tree_add_expert_format( tree, pinfo, KIP_ERROR, tvb, offset, 0, "? Command, Reserved: expected 2 bytes" );
  }
  else
  {
    /* 1 byte Reset Command */
    node = proto_tree_add_item( tree, hf_knxip_reset_command, tvb, offset, 1, ENC_BIG_ENDIAN );
    proto_item_append_text( node, " = %s", mode_info );

    if( !mode_name )
    {
      expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 0x01 or 0x02" );
    }
    else
    {
      ok = 1;
    }

    if( struct_len != 2 )
    {
      proto_tree_add_expert_format( tree, pinfo, KIP_ERROR, tvb, offset, 0, "? Reserved: expected 1 byte" );
      ok = 0;
    }
    else
    {
      /* 1 byte Reserved */
      knxip_tree_add_reserved( tree, tvb, offset + 1, pinfo, &ok );
    }
  }

  if( pinfo ) col_append_fstr( pinfo->cinfo, COL_INFO, ", %s", mode_info );
  proto_item_append_text( item, ", %s", mode_info );

  *p_offset += struct_len;
  return ok;
}

/* Decrypt SECURE_WRAPPER. Returns decrypted part if MAC matches
*/
static guint8* decrypt_secure_wrapper( const guint8* key, const guint8* data, gint h_length, gint p_length )
{
  guint8 header_length = *data;
  gint a_length = header_length + 2;
  if( a_length > h_length )
  {
    a_length = h_length;
  }

  if( h_length >= header_length + 16 && p_length >= 16 )
  {
    const guint8* nonce = data + a_length;
    guint8* decrypted = knxip_ccm_decrypt( NULL, key, data + h_length, p_length, nonce, 14 );

    if( decrypted )
    {
      /* Calculate MAC */
      guint8 mac[ KNX_KEY_LENGTH ];
      p_length -= 16;

      knxip_ccm_calc_cbc_mac( mac, key, data, a_length, decrypted, p_length, nonce, 14 );

      /* Check MAC */
      if( memcmp( decrypted + p_length, mac, 16 ) != 0 )
      {
        wmem_free( wmem_packet_scope(), decrypted );
        decrypted = NULL;
      }
    }

    return decrypted;
  }

  return NULL;
}

static void make_key_info( gchar* text, gint text_max, const guint8* key, const gchar* context )
{
  guint8 count;

  if( !key )
  {
    snprintf( text, text_max, "without key" );
  }
  else
  {
    if( context  )
    {
      snprintf( text, text_max, "with %s key", context );
    }
    else
    {
      snprintf( text, text_max, "with key" );
    }

    for( count = 16; count; --count )
    {
      while( *text ) { ++text; --text_max; }
      snprintf( text, text_max, " %02X", *key++ );
    }
  }
}

/* Dissect SECURE_WRAPPER
*/
static guint8 dissect_secure_wrapper( guint8 header_length, tvbuff_t* tvb, packet_info* pinfo, proto_tree* root, proto_item* item, proto_tree* tree, gint* p_offset )
{
  guint8 ok = 1;
  gint offset = *p_offset;
  gint size = tvb_captured_length_remaining( tvb, offset );
  column_info* cinfo = pinfo->cinfo;
  const guint8* dest_addr = (pinfo->dst.type == AT_IPv4) ? (const guint8*) pinfo->dst.data : NULL;
  proto_item* node;

  /* 2 bytes Session ID */
  if( size < 2 )
  {
    node = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, size, NULL, "? Session" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 2 bytes" );
    ok = 0;
  }
  else
  {
    guint16 session = tvb_get_ntohs( tvb, offset );
    proto_tree_add_item( tree, hf_knxip_session, tvb, offset, 2, ENC_BIG_ENDIAN );

    if( session )
    {
      col_append_fstr( cinfo, COL_INFO, " #%04X", session );
      proto_item_append_text( item, ", Session: $%04X", session );
    }

    offset += 2;
    size -= 2;

    /* 6 bytes Sequence Nr */
    if( size < 6 )
    {
      node = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, size, NULL, "? Sequence Number" );
      expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 6 bytes" );
      ok = 0;
    }
    else
    {
      knxip_tree_add_data( tree, tvb, offset, 6, cinfo, item, "Sequence Number", " $", ", Seq Nr: $" );
      offset += 6;
      size -= 6;

      /* 6 bytes Serial Nr */
      if( size < 6 )
      {
        node = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, size, NULL, "? Serial Number" );
        expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 6 bytes" );
        ok = 0;
      }
      else
      {
        knxip_tree_add_data( tree, tvb, offset, 6, cinfo, item, "Serial Number", ".", ", Ser Nr: $" );
        offset += 6;
        size -= 6;

        /* 2 bytes Tag */
        if( size < 2 )
        {
          node = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, size, NULL, "? Tag" );
          expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 2 bytes" );
          ok = 0;
        }
        else
        {
          guint16 tag = tvb_get_ntohs( tvb, offset );
          proto_tree_add_item( tree, hf_knxip_tag, tvb, offset, 2, ENC_BIG_ENDIAN );
          col_append_fstr( cinfo, COL_INFO, ".%04X", tag );
          proto_item_append_text( item, ", Tag: $%04X", tag );
          offset += 2;
          size -= 2;

          /* Encrypted part */
          if( size < 16 )
          {
            node = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, size, NULL, "? Encrypted" );
            expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: min 16 bytes" );
            ok = 0;
          }
          else
          {
            const guint8* encrypted = tvb_get_ptr( tvb, offset, size - offset );
            const gint a_length = header_length + 16;  // length of leading non-encrypted data
            const guint8* a_data = encrypted - a_length;  // ptr to KIP header
            guint8* decrypted = NULL;
            const guint8* key = NULL;
            gchar decrypt_info[ 128 ];
            struct knx_keyring_mca_keys* mca_key;
            guint8 key_index;

            node = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, size, encrypted, "Encrypted (%d bytes)", size );

            *decrypt_info = '\0';

            if( dest_addr )
            {
              // Try keys associateD with IP MCA in keyring.XML
              for( mca_key = knx_keyring_mca_keys; mca_key; mca_key = mca_key->next )
              {
                if( memcmp( mca_key->mca, dest_addr, 4 ) == 0 )
                {
                  key = mca_key->key;
                  decrypted = decrypt_secure_wrapper( key, a_data, a_length, size );
                  if( decrypted )
                  {
                    make_key_info( decrypt_info, sizeof decrypt_info, key, "MCA" );
                    break;
                  }
                }
              }
            }

            if( !decrypted )
            {
              // Try explicitly specified keys
              for( key_index = 0; key_index < knx_decryption_key_count; ++key_index )
              {
                key = knx_decryption_keys[ key_index ];
                decrypted = decrypt_secure_wrapper( key, a_data, a_length, size );
                if( decrypted )
                {
                  make_key_info( decrypt_info, sizeof decrypt_info, key, NULL );
                  break;
                }
              }
            }

            if( !decrypted )
            {
              const gchar* text = knx_decryption_key_count ? " (decryption failed)" : knx_keyring_mca_keys ? " (no key found)" : " (no key available)";
              proto_item_append_text( node, "%s", text );
            }
            else
            {
              tvbuff_t* tvb2 = tvb_new_child_real_data( tvb, decrypted, size, size );
              gint size2 = size - 16;
              proto_item_append_text( item, ", MAC OK" );
              //tvb_set_free_cb( tvb2, wmem_free );
              add_new_data_source( pinfo, tvb2, "Decrypted" );

              item = proto_tree_add_none_format( root, hf_folder, tvb2, 0, size, "Decrypted" );
              tree = proto_item_add_subtree( item, ett_decrypted );

              if( *decrypt_info )
              {
                proto_item_append_text( item, " (%s)", decrypt_info );
              }

              /* Embedded KIP packet */
              knxip_tree_add_data( tree, tvb2, 0, size2, NULL, NULL, "Embedded KNXnet/IP packet", NULL, NULL );

              /* MAC */
              knxip_tree_add_data( tree, tvb2, size2, 16, NULL, NULL, "Message Authentication Code", NULL, NULL );

              /* Dissect embedded KIP packet */
              {
                tvbuff_t* tvb3 = tvb_new_subset_length( tvb2, 0, size2 );
                dissect_knxip( tvb3, pinfo, root, NULL );
              }
            }
          }
        }
      }
    }
  }

  *p_offset = offset + size;
  return ok;
}

/* Check encrypted MAC in TIMER_NOTIFY
*/
static guint8 check_timer_sync_mac( const guint8* key, const guint8* data, gint header_length )
{
  // Calculate and encrypt MAC
  const guint8* nonce = data + header_length;
  guint8 mac[ KNX_KEY_LENGTH ];
  knxip_ccm_calc_cbc_mac( mac, key, data, header_length, NULL, 0, nonce, 14 );
  knxip_ccm_encrypt( mac, key, NULL, 0, mac, nonce, 14 );

  // Check MAC
  return (memcmp( nonce + 14, mac, 16 ) == 0);
}

/* Dissect TIMER_NOTIFY
*/
static guint8 dissect_timer_notify( guint8 header_length, tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset )
{
  guint8 ok = 1;
  gint offset = *p_offset;
  gint size = tvb_captured_length_remaining( tvb, offset );
  column_info* cinfo = pinfo->cinfo;
  const guint8* dest_addr = (pinfo->dst.type == AT_IPv4) ? (const guint8*) pinfo->dst.data : NULL;
  proto_item* node;

  /* 6 bytes Timestamp */
  if( size < 6 )
  {
    node = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, size, NULL, "? Timestamp" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 6 bytes" );
    ok = 0;
  }
  else
  {
    knxip_tree_add_data( tree, tvb, offset, 6, cinfo, item, "Timestamp", " $", ", Timestamp: $" );
    offset += 6;
    size -= 6;

    /* 6 bytes Serial Nr */
    if( size < 6 )
    {
      node = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, size, NULL, "? Serial Number" );
      expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 6 bytes" );
      ok = 0;
    }
    else
    {
      knxip_tree_add_data( tree, tvb, offset, 6, cinfo, item, "Serial Number", ".", ", Ser Nr: $" );
      offset += 6;
      size -= 6;

      /* 2 bytes Tag */
      if( size < 2 )
      {
        node = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, size, NULL, "? Tag" );
        expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 2 bytes" );
        ok = 0;
      }
      else
      {
        guint16 tag = tvb_get_ntohs( tvb, offset );
        proto_tree_add_item( tree, hf_knxip_tag, tvb, offset, 2, ENC_BIG_ENDIAN );
        col_append_fstr( cinfo, COL_INFO, ".%04X", tag );
        proto_item_append_text( item, ", Tag: $%04X", tag );
        offset += 2;
        size -= 2;

        /* 16 bytes MAC */
        if( size < 16 )
        {
          node = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, size, NULL, "? Message Authentication Code" );
          expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 16 bytes" );
          ok = 0;
        }
        else
        {
          const gint a_length = header_length + 14;  // length of leading non-encrypted data
          const guint8* a_data = tvb_get_ptr( tvb, offset - a_length, a_length + 16 );
          const guint8* key = NULL;
          guint8 mac_ok = 0;
          guint8 mac_error = 0;
          gchar mac_info[ 128 ];
          struct knx_keyring_mca_keys* mca_key;
          guint8 key_index;

          knxip_tree_add_data( tree, tvb, offset, 16, NULL, NULL, "Message Authentication Code", NULL, NULL );

          *mac_info = '\0';

          if( dest_addr )
          {
            // Try keys associated with IP MCA in keyring.XML
            for( mca_key = knx_keyring_mca_keys; mca_key; mca_key = mca_key->next )
            {
              if( memcmp( mca_key->mca, dest_addr, 4 ) == 0 )
              {
                key = mca_key->key;
                if( check_timer_sync_mac( key, a_data, header_length ) )
                {
                  mac_ok = 1;
                  make_key_info( mac_info, sizeof mac_info, key, "MCA" );
                  break;
                }
              }
            }
          }

          if( !mac_ok )
          {
            // Try explicitly specified keys
            for( key_index = 0; key_index < knx_decryption_key_count; ++key_index )
            {
              key = knx_decryption_keys[ key_index ];
              if( check_timer_sync_mac( key, a_data, header_length ) )
              {
                mac_ok = 1;
                make_key_info( mac_info, sizeof mac_info, key, NULL );
                break;
              }
            }
          }

          if( mac_ok )
          {
            node = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, size, NULL, "MAC OK" );
            col_append_str( cinfo, COL_INFO, " OK" );
            proto_item_append_text( item, ", MAC OK" );

            if( *mac_info )
            {
              proto_item_append_text( node, " (%s)", mac_info );
            }

	    /* TODO: mac_error is never being set... */
            if( mac_error )
            {
              expert_add_info_format( pinfo, node, KIP_WARNING, "OK with wrong key" );
              col_append_str( cinfo, COL_INFO, " (!)" );
              proto_item_append_text( item, " (!)" );
            }
          }

          offset += 16;
          size = 0;
        }
      }
    }
  }

  *p_offset = offset + size;
  return ok;
}

/* Dissect SESSION_REQUEST
*/
static guint8 dissect_session_request( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset )
{
  guint8 ok = 1;
  gint offset = *p_offset;

  /* Control Endpoint HPAI */
  if( dissect_hpai( tvb, pinfo, item, tree, &offset, &ok, "Control", 1 ) )
  {
    gint size = tvb_captured_length_remaining( tvb, offset );
    proto_item* node;

    /* DH Client Public Value */
    if( size <= 0 )
    {
      proto_tree_add_expert_format( tree, pinfo, KIP_ERROR, tvb, offset, 0, "? DH Client Public Value: missing" );
      ok = 0;
    }
    else
    {
      node = knxip_tree_add_data( tree, tvb, offset, size, NULL, NULL, "DH Client Public Value", NULL, NULL );

#if ECDH_PUBLIC_VALUE_SIZE > 0
      if( size != ECDH_PUBLIC_VALUE_SIZE )
      {
        proto_item_prepend_text( node, "? " );
        expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: %u bytes", ECDH_PUBLIC_VALUE_SIZE );
        ok = 0;
      }
#endif

      offset += size;
    }
  }

  *p_offset = offset;
  return ok;
}

/* Dissect SESSION_RESPONSE
*/
static guint8 dissect_session_response( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset )
{
  guint8 ok = 1;
  gint offset = *p_offset;
  column_info* cinfo = pinfo->cinfo;
  gint size = tvb_captured_length_remaining( tvb, offset );
  proto_item *node;

  /* 2 bytes Session ID */
  if( size < 2 )
  {
    node = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, size, NULL, "? Session" );
    expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 2 bytes" );
    offset += size;
    ok = 0;
  }
  else
  {
    guint16 session = tvb_get_ntohs( tvb, offset );
    col_append_fstr( cinfo, COL_INFO, " #%04X", session );
    proto_item_append_text( item, " #%04X", session );
    proto_tree_add_item( tree, hf_knxip_session, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;
    size -= 2;

    /* DH Server Public Value */
    {
      gint size2 = size - 16;
      if( size2 < 0 )
      {
        size2 = 0;
      }

      node = knxip_tree_add_data( tree, tvb, offset, size2, NULL, NULL, "DH Server Public Value", NULL, NULL );

      if( size2 != ECDH_PUBLIC_VALUE_SIZE )
      {
        proto_item_prepend_text( node, "? " );
        expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: %u bytes", ECDH_PUBLIC_VALUE_SIZE );
        ok = 0;
      }

      offset += size2;
      size -= size2;
    }

    /* 16 bytes MAC */
    if( size < 16 )
    {
      node = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, size, NULL, "? Message Authentication Code" );
      expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 16 bytes" );
      offset += size;
      ok = 0;
    }
    else
    {
      knxip_tree_add_data( tree, tvb, offset, 16, NULL, NULL, "Message Authentication Code", NULL, NULL );
      offset += 16;
    }
  }

  *p_offset = offset;
  return ok;
}

/* Dissect SESSION_AUTHENTICATE
*/
static guint8 dissect_session_auth( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset )
{
  guint8 ok = 1;
  gint offset = *p_offset;
  column_info* cinfo = pinfo->cinfo;
  gint size = tvb_captured_length_remaining( tvb, offset );
  proto_item* node;

  /* 1 byte Reserved */
  if( size <= 0 )
  {
    proto_tree_add_expert_format( tree, pinfo, KIP_ERROR, tvb, offset, 0, "? Reserved: expected 1 byte" );
    ok = 0;
  }
  else
  {
    knxip_tree_add_reserved( tree, tvb, offset, pinfo, &ok );
    ++offset;
    --size;

    /* 1 byte User ID */
    if( size <= 0 )
    {
      proto_tree_add_expert_format( tree, pinfo, KIP_ERROR, tvb, offset, 0, "? User: expected 1 byte" );
      ok = 0;
    }
    else
    {
      guint8 user_id = tvb_get_guint8( tvb, offset );
      col_append_fstr( cinfo, COL_INFO, " User=%u", user_id );
      proto_item_append_text( item, ", User = %u", user_id );
      proto_tree_add_item( tree, hf_knxip_user, tvb, offset, 1, ENC_BIG_ENDIAN );
      ++offset;
      --size;

      /* 16 bytes MAC */
      if( size < 16 )
      {
        node = proto_tree_add_bytes_format( tree, hf_bytes, tvb, offset, size, NULL, "? Message Authentication Code" );
        expert_add_info_format( pinfo, node, KIP_ERROR, "Expected: 16 bytes" );
        offset += size;
        ok = 0;
      }
      else
      {
        knxip_tree_add_data( tree, tvb, offset, 16, NULL, NULL, "Message Authentication Code", NULL, NULL );
        offset += 16;
      }
    }
  }

  *p_offset = offset;
  return ok;
}

/* Dissect SESSION_STATUS
*/
static guint8 dissect_session_status( tvbuff_t* tvb, packet_info* pinfo, proto_item* item, proto_tree* tree, gint* p_offset )
{
  guint8 ok = 1;
  gint offset = *p_offset;
  column_info* cinfo = pinfo->cinfo;
  gint size = tvb_captured_length_remaining( tvb, offset );

  /* 1 byte Status */
  if( size <= 0 )
  {
    proto_tree_add_expert_format( tree, pinfo, KIP_ERROR, tvb, offset, 0, "? Status: expected 1 byte" );
    ok = 0;
  }
  else
  {
    guint8 status = tvb_get_guint8( tvb, offset );
    col_append_fstr( cinfo, COL_INFO, " %u", status );
    proto_item_append_text( item, ": %u", status );
    proto_tree_add_item( tree, hf_knxip_session_status, tvb, offset, 1, ENC_BIG_ENDIAN );
    ++offset;
    --size;

    /* 1 byte Reserved */
    if( size <= 0 )
    {
      proto_tree_add_expert_format( tree, pinfo, KIP_ERROR, tvb, offset, 0, "? Reserved: expected 1 byte" );
      ok = 0;
    }
    else
    {
      knxip_tree_add_reserved( tree, tvb, offset, pinfo, &ok );
      ++offset;
      --size;
    }
  }

  *p_offset = offset;
  return ok;
}

/* Dissect KNX-IP data after KNX-IP header
*/
static void dissect_knxip_data( guint8 header_length, guint8 protocol_version _U_, guint16 service, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_item* kip_item, proto_tree* kip_tree )
{
  guint8 ok = 1;
  guint8 service_family = (service >> 8);
  const gchar* service_family_name = try_val_to_str( service_family, knxip_service_family_vals );
  const gchar* service_name = try_val_to_str( service, knxip_service_type_vals );
  const gchar* svc_name = try_val_to_str( service, svc_vals );
  gint offset = header_length;
  gint remaining_len = tvb_captured_length_remaining( tvb, offset );
  column_info* cinfo = pinfo->cinfo;

  /* Make sure that we cope with a well known service family
  */
  if( service_family_name == NULL )
  {
    col_add_str( cinfo, COL_INFO, "Unknown Service Family" );
    proto_item_append_text( kip_item, " Unknown Service Family" );
    ok = 0;
  }
  else
  {
    /* Make sure that we cope with a well known service type
    */
    if( service_name == NULL )
    {
      col_append_fstr( cinfo, COL_INFO, "%s: ? Unknown Service Type", service_family_name );
      proto_item_append_text( kip_item, " Unknown Service Type" );
      ok = 0;
    }
    else
    {
      col_append_str( cinfo, COL_INFO, svc_name ? svc_name : service_name );
      proto_item_append_text( kip_item, " %s", service_name );

      /* Dissect according to Service Type
      */
      switch( service )
      {

        /* CORE */

      case KIP_SEARCH_REQUEST:
        {
          /* Discovery Endpoint HPAI */
          dissect_hpai( tvb, pinfo, kip_item, kip_tree, &offset, &ok, "Discovery", 1 );
        }
        break;

      case KIP_SEARCH_REQUEST_EXT:
        {
          /* Discovery Endpoint HPAI */
          if( dissect_hpai( tvb, pinfo, kip_item, kip_tree, &offset, &ok, "Discovery", 0 ) )
          {
            /* Search Request Parameters */
            dissect_srps( tvb, pinfo, kip_item, kip_tree, &offset, &ok );
          }
        }
        break;

      case KIP_SEARCH_RESPONSE:
      case KIP_SEARCH_RESPONSE_EXT:
        {
          /* Control Endpoint HPAI */
          if( dissect_hpai( tvb, pinfo, kip_item, kip_tree, &offset, &ok, "Control", 0 ) )
          {
            /* DIBs */
            guint8 dib_count[ 256 ] = { 0 };
            wmem_strbuf_t* output;
            char *info;

            output = wmem_strbuf_new(wmem_packet_scope(), "");
            dissect_dibs( tvb, pinfo, kip_item, kip_tree, &offset, output, '\0', dib_count, &ok );
            info = wmem_strbuf_finalize(output);
            if( *info )
            {
              col_append_fstr( cinfo, COL_INFO, ", %s", info );
              proto_item_append_text( kip_item, ", %s", info );
            }

            if( service == KIP_SEARCH_RESPONSE )
            {
              if( !dib_count[ KIP_DIB_DEVICE_INFO ] )
              {
                expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing DIB DevInfo" );
                ok = 0;
              }
              if( !dib_count[ KIP_DIB_SUPP_SVC_FAMILIES ] )
              {
                expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing DIB SuppSvc" );
                ok = 0;
              }
            }
          }
        }
        break;

      case KIP_DESCRIPTION_REQUEST:
        {
          /* Control Endpoint HPAI */
          dissect_hpai( tvb, pinfo, kip_item, kip_tree, &offset, &ok, "Control", 1 );
        }
        break;

      case KIP_DESCRIPTION_RESPONSE:
        {
          /* DIBs */
          guint8 dib_count[ 256 ] = { 0 };
          dissect_dibs( tvb, pinfo, kip_item, kip_tree, &offset, NULL, ':', dib_count, &ok );
          if( !dib_count[ KIP_DIB_DEVICE_INFO ] )
          {
            expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing DIB DevInfo" );
            ok = 0;
          }
          if( !dib_count[ KIP_DIB_SUPP_SVC_FAMILIES ] )
          {
            expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing DIB SuppSvc" );
            ok = 0;
          }
        }
        break;

      case KIP_CONNECT_REQUEST:
        {
          /* Control Endpoint HPAI */
          if( dissect_hpai( tvb, pinfo, kip_item, kip_tree, &offset, &ok, "Control", 1 ) )
          {
            /* Data Endpoint HPAI */
            if( dissect_hpai( tvb, pinfo, kip_item, kip_tree, &offset, &ok, "Data", 1 ) )
            {
              /* CRI */
              dissect_cri( tvb, pinfo, kip_item, kip_tree, &offset, &ok );
            }
          }
        }
        break;

      case KIP_CONNECT_RESPONSE:
        {
          /* 1 byte Channel ID */
          if( remaining_len < 1 )
          {
            col_append_fstr( cinfo, COL_INFO, " ???" );
            proto_item_append_text( kip_item, ", ???" );
            expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing 1 byte Channel" );
            ok = 0;
          }
          else
          {
            guint8 channel = tvb_get_guint8( tvb, offset );
            proto_tree_add_item( kip_tree, hf_knxip_channel, tvb, offset, 1, ENC_BIG_ENDIAN );
            offset++;

            /* 1 byte Status */
            if( remaining_len < 2 )
            {
              col_append_fstr( cinfo, COL_INFO, " ???" );
              proto_item_append_text( kip_item, ", ???" );
              expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing 1 byte Status" );
              ok = 0;
            }
            else
            {
              guint8 status = tvb_get_guint8( tvb, offset );
              knxip_tree_add_status( kip_tree, tvb, offset );
              offset++;

              if( status == KIP_E_NO_ERROR )
              {
                col_append_fstr( cinfo, COL_INFO, " #%02X", channel );
                proto_item_append_text( kip_item, ", Conn #%02X", channel );

                /* Data Endpoint HPAI */
                if( dissect_hpai( tvb, pinfo, kip_item, kip_tree, &offset, &ok, "Data", 1 ) )
                {
                  /* CRD */
                  dissect_crd( tvb, pinfo, kip_item, kip_tree, &offset, &ok );
                }
              }
              else
              {
                const gchar* status_info = val_to_str( status, error_vals, "Error 0x%02x" );
                col_append_fstr( cinfo, COL_INFO, " %s", status_info );
                proto_item_append_text( kip_item, ": %s", status_info );
              }
            }
          }
        }
        break;

      case KIP_CONNECTIONSTATE_REQUEST:
        {
          /* 1 byte Channel ID */
          col_append_fstr( cinfo, COL_INFO, " #" );
          proto_item_append_text( kip_item, ", Conn #" );

          if( remaining_len < 1 )
          {
            col_append_fstr( cinfo, COL_INFO, "???" );
            proto_item_append_text( kip_item, "???" );
            expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing 1 byte Channel" );
            ok = 0;
          }
          else
          {
            guint8 channel = tvb_get_guint8( tvb, offset );
            col_append_fstr( cinfo, COL_INFO, "%02X", channel );
            proto_item_append_text( kip_item, "%02X", channel );
            proto_tree_add_item( kip_tree, hf_knxip_channel, tvb, offset, 1, ENC_BIG_ENDIAN );
            offset++;

            /* Reserved Byte */
            if( remaining_len < 2 )
            {
              knxip_tree_add_missing_reserved( kip_tree, tvb, offset, pinfo );
              ok = 0;
            }
            else
            {
              knxip_tree_add_reserved( kip_tree, tvb, offset, pinfo, &ok );
              offset++;

              /* Control Endpoint HPAI */
              dissect_hpai( tvb, pinfo, kip_item, kip_tree, &offset, &ok, "Control", 1 );
            }
          }
        }
        break;

      case KIP_CONNECTIONSTATE_RESPONSE:
        {
          /* 1 byte Channel ID */
          col_append_fstr( cinfo, COL_INFO, " #" );
          proto_item_append_text( kip_item, ", Conn #" );

          if( remaining_len < 1 )
          {
            col_append_fstr( cinfo, COL_INFO, "???" );
            proto_item_append_text( kip_item, "???" );
            expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing 1 byte Channel" );
            ok = 0;
          }
          else
          {
            guint8 channel = tvb_get_guint8( tvb, offset );
            col_append_fstr( cinfo, COL_INFO, "%02X ", channel );
            proto_item_append_text( kip_item, "%02X: ", channel );
            proto_tree_add_item( kip_tree, hf_knxip_channel, tvb, offset, 1, ENC_BIG_ENDIAN );
            offset++;

            /* 1 byte Status */
            if( remaining_len < 2 )
            {
              col_append_fstr( cinfo, COL_INFO, "???" );
              proto_item_append_text( kip_item, "???" );
              expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing 1 byte Status" );
              ok = 0;
            }
            else
            {
              guint8 status = tvb_get_guint8( tvb, offset );
              const gchar* status_info = val_to_str( status, error_vals, "Error 0x%02x" );
              col_append_fstr( cinfo, COL_INFO, "%s", status_info );
              proto_item_append_text( kip_item, "%s", status_info );
              knxip_tree_add_status( kip_tree, tvb, offset );
              offset++;
            }
          }
        }
        break;

      case KIP_DISCONNECT_REQUEST:
        {
          /* 1 byte Channel ID */
          col_append_fstr( cinfo, COL_INFO, " #" );
          proto_item_append_text( kip_item, ", Conn #" );

          if( remaining_len < 1 )
          {
            col_append_fstr( cinfo, COL_INFO, "???" );
            proto_item_append_text( kip_item, "???" );
            expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing 1 byte Channel" );
            ok = 0;
          }
          else
          {
            guint8 channel = tvb_get_guint8( tvb, offset );
            col_append_fstr( cinfo, COL_INFO, "%02X", channel );
            proto_item_append_text( kip_item, "%02X", channel );
            proto_tree_add_item( kip_tree, hf_knxip_channel, tvb, offset, 1, ENC_BIG_ENDIAN );
            offset++;

            /* Reserved Byte */
            if( remaining_len < 2 )
            {
              knxip_tree_add_missing_reserved( kip_tree, tvb, offset, pinfo );
              ok = 0;
            }
            else
            {
              knxip_tree_add_reserved( kip_tree, tvb, offset, pinfo, &ok );
              offset++;

              /* Control Endpoint HPAI */
              dissect_hpai( tvb, pinfo, kip_item, kip_tree, &offset, &ok, "Control", 1 );
            }
          }
        }
        break;

      case KIP_DISCONNECT_RESPONSE:
        {
          /* 1 byte Channel ID */
          col_append_fstr( cinfo, COL_INFO, " #" );
          proto_item_append_text( kip_item, ", Conn #" );

          if( remaining_len < 1 )
          {
            col_append_fstr( cinfo, COL_INFO, "???" );
            proto_item_append_text( kip_item, "???" );
            expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing 1 byte Channel" );
            ok = 0;
          }
          else
          {
            guint8 channel = tvb_get_guint8( tvb, offset );
            col_append_fstr( cinfo, COL_INFO, "%02X ", channel );
            proto_item_append_text( kip_item, "%02X: ", channel );
            proto_tree_add_item( kip_tree, hf_knxip_channel, tvb, offset, 1, ENC_BIG_ENDIAN );
            offset++;

            /* 1 byte Status */
            if( remaining_len < 2 )
            {
              col_append_fstr( cinfo, COL_INFO, "???" );
              proto_item_append_text( kip_item, "???" );
              expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing 1 byte Status" );
              ok = 0;
            }
            else
            {
              guint8 status = tvb_get_guint8( tvb, offset );
              const gchar* status_info = val_to_str( status, error_vals, "Error 0x%02x" );
              col_append_fstr( cinfo, COL_INFO, "%s", status_info );
              proto_item_append_text( kip_item, "%s", status_info );
              knxip_tree_add_status( kip_tree, tvb, offset );
              offset++;
            }
          }
        }
        break;

        /* MANAGEMENT */

      case KIP_CONFIGURATION_REQUEST:
        {
          /* Connection Header */
          if( dissect_cnhdr( tvb, pinfo, kip_item, kip_tree, &offset, &ok, FALSE ) )
          {
            /* cEMI */
            dissect_cemi( tvb, pinfo, tree, &offset );
          }
        }
        break;

      case KIP_CONFIGURATION_ACK:
        {
          /* Connection Header */
          dissect_cnhdr( tvb, pinfo, kip_item, kip_tree, &offset, &ok, TRUE );
        }
        break;

        /* TUNNELING */

      case KIP_TUNNELING_REQUEST:
        {
          /* Connection Header */
          if( dissect_cnhdr( tvb, pinfo, kip_item, kip_tree, &offset, &ok, FALSE ) )
          {
            /* cEMI */
            dissect_cemi( tvb, pinfo, tree, &offset );
          }
        }
        break;

      case KIP_TUNNELING_ACK:
        {
          /* Connection Header */
          dissect_cnhdr( tvb, pinfo, kip_item, kip_tree, &offset, &ok, TRUE );
        }
        break;

      case KIP_TUNNELING_FEATURE_GET:
      case KIP_TUNNELING_FEATURE_RESPONSE:
      case KIP_TUNNELING_FEATURE_SET:
      case KIP_TUNNELING_FEATURE_INFO:
        {
          /* Connection Header, 1 byte Feature ID, 1 byte Return Code, Feature Value */
          dissect_tunneling_feature( tvb, pinfo, kip_item, kip_tree, &offset, &ok, service );
        }
        break;

        /* ROUTING */

      case KIP_ROUTING_INDICATION:
        {
          /* cEMI */
          dissect_cemi( tvb, pinfo, tree, &offset );
        }
        break;

      case KIP_ROUTING_LOST_MESSAGE:
        {
          /* Routing Loss */
          ok &= dissect_routing_loss( tvb, pinfo, kip_item, kip_tree, &offset );
        }
        break;

      case KIP_ROUTING_BUSY:
        {
          /* Routing Busy */
          ok &= dissect_routing_busy( tvb, pinfo, kip_item, kip_tree, &offset );
        }
        break;

      case KIP_ROUTING_SYSTEM_BROADCAST:
        {
          /* cEMI */
          dissect_cemi( tvb, pinfo, tree, &offset );
        }
        break;

        /* REMOTE_DIAG_AND_CONFIG */

      case KIP_REMOTE_DIAG_REQUEST:
        {
          /* Discovery Endpoint HPAI */
          if( dissect_hpai( tvb, pinfo, kip_item, kip_tree, &offset, &ok, "Discovery", 0 ) )
          {
            /* Selector */
            dissect_selector( tvb, pinfo, kip_item, kip_tree, &offset, &ok );
          }
        }
        break;

      case KIP_REMOTE_DIAG_RESPONSE:
        {
          /* Selector */
          if( dissect_selector( tvb, pinfo, kip_item, kip_tree, &offset, &ok ) )
          {
            /* DIBs */
            guint8 dib_count[ 256 ] = { 0 };
            dissect_dibs( tvb, pinfo, kip_item, kip_tree, &offset, NULL, ',', dib_count, &ok );
            if( !dib_count[ KIP_DIB_IP_CONFIG ] )
            {
              expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing DIB IpConfig" );
              ok = 0;
            }
            if( !dib_count[ KIP_DIB_CUR_CONFIG ] )
            {
              expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing DIB CurConfig" );
              ok = 0;
            }
            if( !dib_count[ KIP_DIB_KNX_ADDRESSES ] )
            {
              expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Missing DIB KnxAddr" );
              ok = 0;
            }
          }
        }
        break;

      case KIP_REMOTE_CONFIG_REQUEST:
        {
          /* Discovery Endpoint HPAI */
          if( dissect_hpai( tvb, pinfo, kip_item, kip_tree, &offset, &ok, "Discovery", 0 ) )
          {
            /* Selector */
            if( dissect_selector( tvb, pinfo, kip_item, kip_tree, &offset, &ok ) )
            {
              /* DIBs */
              gint old_offset = offset;
              dissect_dibs( tvb, pinfo, kip_item, kip_tree, &offset, NULL, ',', NULL, &ok );
              if( offset <= old_offset )
              {
                expert_add_info_format( pinfo, kip_item, KIP_WARNING, "Missing DIB" );
              }
            }
          }
        }
        break;

      case KIP_REMOTE_RESET_REQUEST:
        {
          /* Selector */
          if( dissect_selector( tvb, pinfo, kip_item, kip_tree, &offset, &ok ) )
          {
            /* Reset Mode */
            ok &= dissect_resetter( tvb, pinfo, kip_item, kip_tree, &offset );
          }
        }
        break;

      case KIP_SECURE_WRAPPER:
        ok &= dissect_secure_wrapper( header_length, tvb, pinfo, tree, kip_item, kip_tree, &offset );
        break;

      case KIP_TIMER_NOTIFY:
        ok &= dissect_timer_notify( header_length, tvb, pinfo, kip_item, kip_tree, &offset );
        break;

      case KIP_SESSION_REQUEST:
        ok &= dissect_session_request( tvb, pinfo, kip_item, kip_tree, &offset );
        break;

      case KIP_SESSION_RESPONSE:
        ok &= dissect_session_response( tvb, pinfo, kip_item, kip_tree, &offset );
        break;

      case KIP_SESSION_AUTHENTICATE:
        ok &= dissect_session_auth( tvb, pinfo, kip_item, kip_tree, &offset );
        break;

      case KIP_SESSION_STATUS:
        ok &= dissect_session_status( tvb, pinfo, kip_item, kip_tree, &offset );
        break;
      }
    }
  }

  if( offset >= 0 )
  {
    remaining_len = tvb_captured_length_remaining( tvb, offset );
    if( remaining_len > 0 )
    {
      if( tree )
      {
        proto_item* unknown_item = knxip_tree_add_unknown_data( kip_tree, tvb, offset, remaining_len );
        expert_add_info_format( pinfo, unknown_item, KIP_ERROR, "Unexpected trailing data" );
      }

      ok = 0;
    }
  }

  if( !ok )
  {
    /* If not already done */
    if( !knxip_error )
    {
      knxip_error = 1;
      col_prepend_fstr( cinfo, COL_INFO, "? " );
    }

    proto_item_prepend_text( kip_item, "? " );
  }
}

static guint
get_knxip_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  return tvb_get_ntohs( tvb, offset+4 );
}

static gint dissect_knxip( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_ )
{
  gint offset = 0;
  guint remaining_len = tvb_captured_length( tvb );
  guint8 header_len = 0;
  guint8 protocol_version = 0;
  guint16 service_id = 0;
  guint16 total_len = 0;
  guint8 error = 0;

  column_info* cinfo = pinfo->cinfo;

  proto_item* kip_item = NULL;
  proto_tree* kip_tree = NULL;
  proto_item* header_item = NULL;
  proto_tree* header_tree = NULL;
  proto_item* header_len_item = NULL;
  proto_item* version_item = NULL;
  proto_item* service_item = NULL;
  proto_tree* service_tree = NULL;
  proto_item* total_length_item = NULL;

  gchar version_info[ 16 ];

  unsigned level = p_get_proto_depth(pinfo, proto_knxip);
  if( level == 0 )
  {
    knxip_error = 0;
    col_set_str( cinfo, COL_PROTOCOL, "KNXnet/IP" );
    col_clear( cinfo, COL_INFO );
  }
  else
  {
    col_append_str( cinfo, COL_INFO, " " );
  }
  p_set_proto_depth(pinfo, proto_knxip, level+1);

  kip_item = proto_tree_add_item( tree, proto_knxip, tvb, offset, (remaining_len <= 0) ? 0 : -1, ENC_BIG_ENDIAN );
  kip_tree = proto_item_add_subtree( kip_item, ett_kip );

  if( remaining_len <= 0 )
  {
    /* This may happen if we are embedded in another KNXnet/IP frame (level != 0)
    */
    proto_item_prepend_text( kip_item, "? " );
    expert_add_info_format( pinfo, kip_item, KIP_ERROR, "Expected: min 6 bytes" );
    col_append_str( cinfo, COL_INFO, "? empty" );

    /* If not already done */
    if( !knxip_error )
    {
      knxip_error = 1;
      col_prepend_fstr( cinfo, COL_INFO, "? " );
    }
  }
  else
  {
    /* 1 byte Header Length */
    header_len = tvb_get_guint8( tvb, 0 );

    if( tree )
    {
      header_item = proto_tree_add_none_format( kip_tree, hf_folder, tvb, 0,
        (header_len <= remaining_len) ? header_len : remaining_len, "KNX/IP Header" );
      header_tree = proto_item_add_subtree( header_item, ett_efcp );
      header_len_item = proto_tree_add_uint_format( header_tree, hf_knxip_header_length,
        tvb, 0, 1, header_len, "Header Length: %u bytes", header_len );
    }

    if( header_len > remaining_len )
    {
      proto_item_prepend_text( header_len_item, "? " );
      expert_add_info_format( pinfo, header_len_item, KIP_ERROR, "Available: %u bytes", remaining_len );
      error = 1;
      header_len = (guint8) remaining_len;
    }
    else if( header_len != KIP_HDR_LEN )
    {
      proto_item_prepend_text( header_len_item, "? " );
      expert_add_info_format( pinfo, header_len_item, KIP_ERROR, "Expected: 6 bytes" );
      error = 1;
    }

    offset++;

    if( header_len >= 2 )
    {
      /* 1 byte Protocol Version */
      protocol_version = tvb_get_guint8( tvb, 1 );
      snprintf( version_info, sizeof version_info, "%u.%u", hi_nibble( protocol_version ), lo_nibble( protocol_version ) );

      if( tree )
      {
        version_item = proto_tree_add_uint_format( header_tree, hf_knxip_protocol_version,
          tvb, 1, 1, protocol_version, "Protocol Version: %s", version_info );
      }

      if( protocol_version != 0x10 )
      {
        proto_item_prepend_text( version_item, "? " );
        expert_add_info_format( pinfo, version_item, KIP_ERROR, "Expected: Protocol Version 1.0" );
        error = 1;
      }

      offset++;

      if( header_len >= 4 )
      {
        /* 2 bytes Service ID */
        service_id = tvb_get_ntohs( tvb, 2 );

        if( tree )
        {
          const gchar* name = try_val_to_str( service_id, knxip_service_type_vals );
          proto_item_append_text( header_item, ": " );
          if( name )
            proto_item_append_text( header_item, "%s", name );
          else
            proto_item_append_text( header_item, "Service = 0x%04x", service_id );
          service_item = proto_tree_add_item( header_tree, hf_knxip_service_id, tvb, 2, 2, ENC_BIG_ENDIAN );
          service_tree = proto_item_add_subtree( service_item, ett_service );
          proto_tree_add_item( service_tree, hf_knxip_service_family, tvb, 2, 1, ENC_BIG_ENDIAN );
          proto_tree_add_item( service_tree, hf_knxip_service_type, tvb, 2, 2, ENC_BIG_ENDIAN );
        }

        offset += 2;

        if( header_len >= KIP_HDR_LEN )
        {
          /* 2 bytes Total Length */
          total_len = tvb_get_ntohs( tvb, 4 );

          if( tree )
          {
            total_length_item = proto_tree_add_uint_format( header_tree, hf_knxip_total_length,
              tvb, 4, 2, total_len, "Total Length: %u bytes", total_len );
          }

          if( total_len < header_len )
          {
            proto_item_prepend_text( total_length_item, "? " );
            expert_add_info_format( pinfo, total_length_item, KIP_ERROR, "Expected: >= Header Length" );
            error = 1;
          }
          else if( total_len > remaining_len )
          {
            proto_item_prepend_text( total_length_item, "? " );
            expert_add_info_format( pinfo, total_length_item, KIP_ERROR, "Available: %u bytes", remaining_len );
            error = 1;
          }
          else if( total_len < remaining_len )
          {
            proto_item_prepend_text( total_length_item, "? " );
            expert_add_info_format( pinfo, total_length_item, KIP_ERROR, "Available: %u bytes", remaining_len );
            error = 1;
          }

          offset += 2;
        }
      }
    }

    if( offset < header_len )
    {
      knxip_tree_add_unknown_data( header_tree, tvb, offset, header_len - offset );
    }

    if( error )
    {
      proto_item_prepend_text( header_item, "? " );

      if( level == 0 )
      {
        col_prepend_fstr( cinfo, COL_PROTOCOL, "? " );
      }
      else
      {
        /* If not already done */
        if( !knxip_error )
        {
          knxip_error = 1;
          col_prepend_fstr( cinfo, COL_INFO, "? " );
        }
      }
    }

    dissect_knxip_data( header_len, protocol_version, service_id, tvb, pinfo, tree, kip_item, kip_tree );
  }
  return tvb_captured_length( tvb );
}

static gint dissect_tcp_knxip( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* udata )
{
  knxip_host_protocol = IP_PROTO_TCP;
  tcp_dissect_pdus(tvb, pinfo, tree, pref_desegment, KIP_HDR_LEN, get_knxip_pdu_len, dissect_knxip, udata);

  return tvb_captured_length( tvb );
}

static gint dissect_udp_knxip( tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* udata )
{
  knxip_host_protocol = IP_PROTO_UDP;
  udp_dissect_pdus( tvb, pinfo, tree, KIP_HDR_LEN, NULL, get_knxip_pdu_len, dissect_knxip, udata );
  return tvb_captured_length( tvb );
}

void proto_register_knxip( void )
{
  /* Header fields */
  static hf_register_info hf[] =
  {
    { &hf_bytes, { "Data", "knxip.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_folder, { "Folder", "knxip.folder", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_knxip_header_length, { "Header Length", "knxip.headerlength", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_knxip_protocol_version, { "Protocol Version", "knxip.version", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_service_id, { "Service Identifier", "knxip.service", FT_UINT16, BASE_HEX, VALS( knxip_service_type_vals ), 0, NULL, HFILL } },
    { &hf_knxip_service_family, { "Service Family", "knxip.service.family", FT_UINT8, BASE_HEX, VALS( knxip_service_family_vals ), 0, NULL, HFILL } },
    { &hf_knxip_service_type, { "Service Type", "knxip.service.type", FT_UINT16, BASE_HEX, VALS( knxip_service_type_vals ), 0, NULL, HFILL } },
    { &hf_knxip_total_length, { "Total Length", "knxip.totallength", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_knxip_structure_length, { "Structure Length", "knxip.struct.length", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_knxip_host_protocol, { "Host Protocol", "knxip.hostprotocol", FT_UINT8, BASE_HEX, VALS( host_protocol_vals ), 0, NULL, HFILL } },
    { &hf_knxip_ip_address, { "IP Address", "knxip.ipaddr", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_knxip_port, { "Port Number", "knxip.port", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_knxip_description_type, { "Description Type", "knxip.dibtype", FT_UINT8, BASE_HEX, VALS( description_type_vals ), 0, NULL, HFILL } },
    { &hf_knxip_knx_medium, { "KNX Medium", "knxip.medium", FT_UINT8, BASE_HEX, VALS( medium_type_vals ), 0, NULL, HFILL } },
    { &hf_knxip_device_status, { "Device Status", "knxip.device.status", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_program_mode, { "Programming Mode", "knxip.progmode", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_knxip_knx_address, { "KNX Individual Address", "knxip.knxaddr", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_project_id, { "Project Installation Identifier", "knxip.project", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_project_number, { "Project Number", "knxip.project.nr", FT_UINT16, BASE_DEC, NULL, 0xFFF0, NULL, HFILL } },
    { &hf_knxip_installation_number, { "Installation Number", "knxip.project.installation", FT_UINT16, BASE_DEC, NULL, 0x000F, NULL, HFILL } },
    { &hf_knxip_serial_number, { "KNX Serial Number", "knxip.sernr", FT_UINT48, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_multicast_address, { "Multicast Address", "knxip.mcaddr", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_knxip_mac_address, { "MAC Address", "knxip.macaddr", FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_knxip_friendly_name, { "Friendly Name", "knxip.device.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_knxip_service_version, { "Service Version", "knxip.service.version", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_security_version, { "Security Version", "knxip.security.version", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_manufacturer_code, { "KNX Manufacturer Code", "knxip.manufacturer", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_connection_type, { "Connection Type", "knxip.conn.type", FT_UINT8, BASE_HEX, VALS( connection_type_vals ), 0, NULL, HFILL } },
    { &hf_knxip_knx_layer, { "KNX Layer", "knxip.tunnel.layer", FT_UINT8, BASE_HEX, VALS( knx_layer_vals ), 0, NULL, HFILL } },
    { &hf_knxip_channel, { "Channel", "knxip.channel", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_status, { "Status", "knxip.status", FT_UINT8, BASE_HEX, VALS( error_vals ), 0, NULL, HFILL } },
    { &hf_knxip_reserved, { "Reserved", "knxip.reserved", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_seq_counter, { "Sequence Counter", "knxip.seqctr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_knxip_ip_subnet, { "Subnet Mask", "knxip.subnet", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_knxip_ip_gateway, { "Default Gateway", "knxip.gateway", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_knxip_ip_assign, { "IP Assignment", "knxip.ipassign", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_ip_caps, { "IP Capabilities", "knxip.ipcaps", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_ip_dhcp, { "DHCP Server", "knxip.dhcp", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_knxip_tunnel_feature, { "Tunneling Feature Identifier", "knxip.tunnel.feature", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_routing_loss, { "Lost Messages", "knxip.loss", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_knxip_busy_time, { "Wait Time", "knxip.busy.time", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_knxip_busy_control, { "Control", "knxip.busy.control", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_selector, { "Selector", "knxip.selector", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_max_apdu_length, { "Max APDU Length", "knxip.maxapdulength", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_knxip_medium_status, { "Medium Status", "knxip.medium.status", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_mask_version, { "Mask Version", "knxip.mask.version", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_srp_mandatory, { "Mandatory", "knxip.srp.mandatory", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL } },
    { &hf_knxip_srp_type, { "SRP Type", "knxip.srp.type", FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL } },
    { &hf_knxip_reset_command, { "Command", "knxip.reset.command", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_session, { "Session", "knxip.session", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_tag, { "Tag", "knxip.tag", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_knxip_user, { "User", "knxip.user", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_knxip_session_status, { "Status", "knxip.session.status", FT_UINT8, BASE_HEX, VALS( session_status_vals ), 0, NULL, HFILL } },
  };

  /* Subtrees */
  static gint *ett[] =
  {
    &ett_kip,
    &ett_efcp,
    &ett_service,
    &ett_hpai,
    &ett_dib,
    &ett_medium,
    &ett_status,
    &ett_projectid,
    &ett_service_family,
    &ett_ip_assignment,
    &ett_cri,
    &ett_crd,
    &ett_cnhdr,
    &ett_loss,
    &ett_busy,
    &ett_selector,
    &ett_decrypted,
    &ett_tunnel,
  };

  static ei_register_info ei[] =
  {
    { &ei_knxip_error, { "knxip.error", PI_MALFORMED, PI_ERROR, "KNX/IP error", EXPFILL }},
    { &ei_knxip_warning, { "knxip.warning", PI_PROTOCOL, PI_WARN, "KNX/IP warning", EXPFILL }},
  };

  expert_module_t* expert_knxip;
  module_t* knxip_module;
  guint8 x;

  proto_knxip = proto_register_protocol( "KNX/IP", "KNX/IP", "kip" );

  proto_register_field_array( proto_knxip, hf, array_length( hf ) );
  proto_register_subtree_array( ett, array_length( ett ) );

  register_dissector( "udp.knxip", dissect_udp_knxip, proto_knxip );
  register_dissector( "tcp.knxip", dissect_tcp_knxip, proto_knxip );

  //register_dissector_table( "knxip.version", "KNXnet/IP Protocol Version", proto_knxip, FT_UINT8, BASE_HEX );

  expert_knxip = expert_register_protocol( proto_knxip );
  expert_register_field_array( expert_knxip, ei, array_length( ei ) );

  knxip_module = prefs_register_protocol( proto_knxip, proto_reg_handoff_knxip );

  prefs_register_filename_preference( knxip_module, "key_file", "Key file", "Keyring.XML file (exported from ETS)",
    &pref_key_file_name, FALSE );
  prefs_register_string_preference( knxip_module, "key_file_pwd", "Key file password", "Keyring password",
    &pref_key_file_pwd );
  prefs_register_filename_preference( knxip_module, "key_info_file", "Key info output file", "Output file (- for stdout) for keys extracted from key file",
    &pref_key_info_file_name, FALSE );

  prefs_register_static_text_preference( knxip_module, "", "", NULL );

  prefs_register_static_text_preference( knxip_module, "keys_0",
    "KNX decryption keys",
    NULL );
  prefs_register_static_text_preference( knxip_module, "keys_1",
    "(KNX/IP multicast/group keys, KNX/IP unicast session keys, KNX data-security tool keys and link-table keys)",
    NULL );
  prefs_register_static_text_preference( knxip_module, "keys_2",
    "(format: 16 bytes as hex; example: A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF)",
    NULL );

  for( x = 1; x <= MAX_KNX_DECRYPTION_KEYS; ++x )
  {
    gchar* name = wmem_strdup_printf( wmem_epan_scope(), "key_%u", x );
    gchar* title = wmem_strdup_printf( wmem_epan_scope(), "%u. key", x );
    prefs_register_string_preference( knxip_module, name, title,
      "KNX decryption key (format: 16 bytes as hex; example: A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF)",
      &pref_key_texts[ x - 1 ] );
  }

  prefs_register_bool_preference(knxip_module, "desegment", "Reassemble KNX/IP messages spanning multiple TCP segments.", "Whether the KNX/IP dissector should reassemble messages spanning multiple TCP segments.  To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.", &pref_desegment);
}

void proto_reg_handoff_knxip( void )
{
  dissector_handle_t knxip_handle;
  guint8 x;
  const gchar* text;

  knxip_handle = find_dissector( "udp.knxip" );
  dissector_add_uint_range_with_preference("udp.port", KIP_DEFAULT_PORT_RANGE, knxip_handle);

  knxip_handle = find_dissector( "tcp.knxip" );
  dissector_add_uint_range_with_preference("tcp.port", KIP_DEFAULT_PORT_RANGE, knxip_handle);

  /* Evaluate preferences
  */
  if( pref_key_file_name )
  {
    /* Read Keyring.XML file (containing decryption keys, exported from ETS) */
    read_knx_keyring_xml_file( pref_key_file_name, pref_key_file_pwd, pref_key_info_file_name );
  }

  knx_decryption_key_count = 0;
  for( x = 0; x < MAX_KNX_DECRYPTION_KEYS && knx_decryption_key_count < MAX_KNX_DECRYPTION_KEYS; ++x )
  {
    text = pref_key_texts[ x ];
    if( text )
    {
      if( hex_to_knx_key( text, knx_decryption_keys[ knx_decryption_key_count ] ) )
      {
        ++knx_decryption_key_count;
      }
    }
  }
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
