/* XXX fixme   can not reassemple multiple isns PDU fragments into one
  isns PDU
*/

/* packet-isns.c
 * Routines for iSNS dissection
 * Copyright 2003, Elipsan, Gareth Bushell <gbushell@elipsan.com>
 * (c) 2004 Ronnie Sahlberg   updates
 * (c) 2004 Ming Zhang   updates
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include "packet-tcp.h"
#include <epan/prefs.h>


#define ISNS_PROTO_VER 0x1
#define ISNS_HEADER_SIZE 12

#define ISNS_TCP_PORT 3205
#define ISNS_UDP_PORT 3205

#define ISNS_OTHER_PORT 0
#define ISNS_ESI_PORT 1
#define ISNS_SCN_PORT 2


dissector_handle_t isns_tcp_handle;
dissector_handle_t isns_udp_handle;

static gint ett_isns_flags = -1;
static gint ett_isns_payload = -1;
static gint ett_isns_attribute = -1;
static gint ett_isns_port = -1;
static gint ett_isns_isnt = -1;

static guint AddAttribute(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree,
                          guint offset, guint16 function_id);

/* Initialize the protocol and registered fields */
static int proto_isns = -1;


/* Header Stuff */
static int hf_isns_version = -1;
static int hf_isns_function_id = -1;
static int hf_isns_pdu_length = -1;
static int hf_isns_flags = -1;
static int hf_isns_transaction_id = -1;
static int hf_isns_sequence_id = -1;
static int hf_isns_payload = -1;
static int hf_isns_first_pdu = -1;
static int hf_isns_last_pdu = -1;
static int hf_isns_replace = -1;
static int hf_isns_auth = -1;
static int hf_isns_server = -1;
static int hf_isns_client = -1;

/* Payload stuff */
static int hf_isns_scn_bitmap                                      = -1;
static int hf_isns_scn_bitmap_initiator_and_self_information_only  = -1;
static int hf_isns_scn_bitmap_target_and_self_information_only     = -1;
static int hf_isns_scn_bitmap_management_registration_scn          = -1;
static int hf_isns_scn_bitmap_object_removed                       = -1;
static int hf_isns_scn_bitmap_object_added                         = -1;
static int hf_isns_scn_bitmap_object_updated                       = -1;
static int hf_isns_scn_bitmap_dd_dds_member_removed                = -1;
static int hf_isns_scn_bitmap_dd_dds_member_added                  = -1;
static int hf_isns_isnt_control = -1;
static int hf_isns_isnt_initiator = -1;
static int hf_isns_isnt_target = -1;

static int hf_isns_psb = -1;
static int hf_isns_psb_tunnel_mode = -1;
static int hf_isns_psb_transport_mode = -1;
static int hf_isns_psb_pfs = -1;
static int hf_isns_psb_aggressive_mode = -1;
static int hf_isns_psb_main_mode = -1;
static int hf_isns_psb_ike_ipsec = -1;
static int hf_isns_psb_bitmap = -1;

static int hf_isns_dd_member_portal_port = -1;
static int hf_isns_portal_port = -1;
static int hf_isns_esi_port = -1;
static int hf_isns_scn_port = -1;
static int hf_isns_port_type = -1;

static int hf_isns_entity_protocol = -1;
static int hf_isns_iscsi_node_type = -1;
static int hf_isns_resp_errorcode = -1;
static int hf_isns_attr_tag = -1;
static int hf_isns_attr_len = -1;
static int hf_isns_heartbeat_ipv6_addr = -1;
static int hf_isns_heartbeat_udp_port = -1;
static int hf_isns_heartbeat_tcp_port = -1;
static int hf_isns_heartbeat_interval = -1;
static int hf_isns_heartbeat_counter = -1;

static int hf_isns_mgmt_ip_addr = -1;
static int hf_isns_node_ip_addr = -1;
static int hf_isns_port_ip_addr = -1;
static int hf_isns_portal_ip_addr = -1;
static int hf_isns_dd_member_portal_ip_addr = -1;
static int hf_isns_iscsi_name = -1;
static int hf_isns_switch_name = -1;
static int hf_isns_dd_member_iscsi_name = -1;
static int hf_isns_virtual_fabric_id = -1;
static int hf_isns_proxy_iscsi_name = -1;
static int hf_isns_fc4_descriptor = -1;
static int hf_isns_iscsi_auth_method = -1;
static int hf_isns_iscsi_alias = -1;
static int hf_isns_portal_symbolic_name = -1;
static int hf_isns_dd_set_symbolic_name = -1;
static int hf_isns_dd_symbolic_name = -1;
static int hf_isns_symbolic_port_name = -1;
static int hf_isns_symbolic_node_name = -1;
static int hf_isns_entity_identifier = -1;
static int hf_isns_dd_id_next_id = -1;
static int hf_isns_member_iscsi_index = -1;
static int hf_isns_member_portal_index = -1;
static int hf_isns_member_fc_port_name = -1;
static int hf_isns_vendor_oui = -1;
static int hf_isns_preferred_id = -1;
static int hf_isns_assigned_id = -1;
static int hf_isns_dd_id = -1;
static int hf_isns_dd_set_id = -1;
static int hf_isns_dd_set_next_id = -1;
static int hf_isns_node_index = -1;
static int hf_isns_node_next_index = -1;
static int hf_isns_entity_index = -1;
static int hf_isns_portal_index = -1;
static int hf_isns_portal_next_index = -1;
static int hf_isns_entity_next_index = -1;
static int hf_isns_timestamp = -1;
static int hf_isns_esi_interval = -1;
static int hf_isns_registration_period = -1;
static int hf_isns_port_id = -1;
static int hf_isns_hard_address = -1;
static int hf_isns_wwnn_token = -1;
static int hf_isns_node_ipa = -1;
static int hf_isns_fc_port_name_wwpn = -1;
static int hf_isns_fc_node_name_wwnn = -1;
static int hf_isns_fabric_port_name = -1;
static int hf_isns_permanent_port_name = -1;
static int hf_isns_delimiter = -1;
static int hf_isns_not_decoded_yet = -1;
static int hf_isns_portal_group_tag = -1;
static int hf_isns_pg_iscsi_name = -1;
static int hf_isns_pg_portal_ip_addr = -1;
static int hf_isns_pg_portal_port = -1;
static int hf_isns_pg_index = -1;
static int hf_isns_pg_next_index = -1;



/* Desegment iSNS over TCP messages */
static gboolean isns_desegment = TRUE;

/* Function Id's */
#define ISNS_FUNC_DEVATTRREG     0x0001
#define ISNS_FUNC_DEVATTRQRY     0x0002
#define ISNS_FUNC_DEVGETNEXT     0x0003
#define ISNS_FUNC_DEREGDEV       0x0004
#define ISNS_FUNC_SCNREG         0x0005
#define ISNS_FUNC_SCNDEREG       0x0006
#define ISNS_FUNC_SCNEVENT       0x0007
#define ISNS_FUNC_SCN            0x0008
#define ISNS_FUNC_DDREG          0x0009
#define ISNS_FUNC_DDDEREG        0x000a
#define ISNS_FUNC_DDSREG         0x000b
#define ISNS_FUNC_DDSDEREG       0x000c
#define ISNS_FUNC_ESI            0x000d
#define ISNS_FUNC_HEARTBEAT      0x000e
#define ISNS_FUNC_RQSTDOMID      0x0011
#define ISNS_FUNC_RLSEDOMID      0x0012
#define ISNS_FUNC_GETDOMID       0x0013

#define ISNS_FUNC_RSP_DEVATTRREG 0x8001
#define ISNS_FUNC_RSP_DEVATTRQRY 0x8002
#define ISNS_FUNC_RSP_DEVGETNEXT 0x8003
#define ISNS_FUNC_RSP_DEREGDEV   0x8004
#define ISNS_FUNC_RSP_SCNREG     0x8005
#define ISNS_FUNC_RSP_SCNDEREG   0x8006
#define ISNS_FUNC_RSP_SCNEVENT   0x8007
#define ISNS_FUNC_RSP_SCN        0x8008
#define ISNS_FUNC_RSP_DDREG      0x8009
#define ISNS_FUNC_RSP_DDDEREG    0x800a
#define ISNS_FUNC_RSP_DDSREG     0x800b
#define ISNS_FUNC_RSP_DDSDEREG   0x800c
#define ISNS_FUNC_RSP_ESI        0x800d
#define ISNS_FUNC_RSP_RQSTDOMID  0x8011
#define ISNS_FUNC_RSP_RLSEDOMID  0x8012
#define ISNS_FUNC_RSP_GETDOMID   0x8013

static const value_string isns_function_ids[] = {
/* Requests*/
    {ISNS_FUNC_DEVATTRREG,     "DevAttrReg"},
    {ISNS_FUNC_DEVATTRQRY,     "DevAttrQry"},
    {ISNS_FUNC_DEVGETNEXT,     "DevGetNext"},
    {ISNS_FUNC_DEREGDEV,       "DeregDev"},
    {ISNS_FUNC_SCNREG,         "SCNReg"},
    {ISNS_FUNC_SCNDEREG,       "SCNDereg"},
    {ISNS_FUNC_SCNEVENT,       "SCNEvent"},
    {ISNS_FUNC_SCN,            "SCN"},
    {ISNS_FUNC_DDREG,          "DDReg"},
    {ISNS_FUNC_DDDEREG,        "DDDereg"},
    {ISNS_FUNC_DDSREG,         "DDSReg"},
    {ISNS_FUNC_DDSDEREG,       "DDSDereg"},
    {ISNS_FUNC_ESI,            "ESI"},
    {ISNS_FUNC_HEARTBEAT,      "Heartbeat"},
    {ISNS_FUNC_RQSTDOMID,      "RqstDomId"},
    {ISNS_FUNC_RLSEDOMID,      "RlseDomId"},
    {ISNS_FUNC_GETDOMID,       "GetDomId"},

/* Responses */
    {ISNS_FUNC_RSP_DEVATTRREG, "DevAttrRegRsp"},
    {ISNS_FUNC_RSP_DEVATTRQRY, "DevAttrQryRsp"},
    {ISNS_FUNC_RSP_DEVGETNEXT, "DevGetNextRsp"},
    {ISNS_FUNC_RSP_DEREGDEV,   "DeregDevRsp"},
    {ISNS_FUNC_RSP_SCNREG,     "SCNRegRsp"},
    {ISNS_FUNC_RSP_SCNDEREG,   "SCNDeregRsp"},
    {ISNS_FUNC_RSP_SCNEVENT,   "SCNEventRsp"},
    {ISNS_FUNC_RSP_SCN,        "SCNRsp"},
    {ISNS_FUNC_RSP_DDREG,      "DDRegRsp"},
    {ISNS_FUNC_RSP_DDDEREG,    "DDDeregRsp"},
    {ISNS_FUNC_RSP_DDSREG,     "DDSRegRsp"},
    {ISNS_FUNC_RSP_DDSDEREG,   "DDSDeregRsp"},
    {ISNS_FUNC_RSP_ESI,        "ESIRsp"},
    {ISNS_FUNC_RSP_RQSTDOMID,  "RqstDomIdRsp"},
    {ISNS_FUNC_RSP_RLSEDOMID,  "RlseDomIdRsp"},
    {ISNS_FUNC_RSP_GETDOMID,   "GetDomIdRsp"},

    {0x0,NULL},
};

#define ISNS_ENTITY_PROTOCOL_NO_PROTOCOL 1
#define ISNS_ENTITY_PROTOCOL_ISCSI       2
#define ISNS_ENTITY_PROTOCOL_IFCP        3


static const value_string isns_entity_protocol[] = {
    {ISNS_ENTITY_PROTOCOL_NO_PROTOCOL, "No Protocol"},
    {ISNS_ENTITY_PROTOCOL_ISCSI,       "iSCSI"},
    {ISNS_ENTITY_PROTOCOL_IFCP,        "iFCP"}, 

    {0x0,NULL},
};

static const value_string isns_errorcode[] = {
    { 0,"No Error"},
    { 1,"Unknown Error"},
    { 2,"Message Format Error"},
    { 3,"Invalid Registration"},
    { 4,"RESERVED"},
    { 5,"Invalid Query"},
    { 6,"Source Unknown"},
    { 7,"Source Absent"},
    { 8,"Source Unauthorized"},
    { 9,"No such Entry"},
    {10,"Version Not Supported"},
    {11,"Internal Error"},
    {12,"Busy"},
    {13,"Option Not Understood"},
    {14,"Invalid Update"},
    {15,"Message (FUNCTION_ID) Not supported"},
    {16,"SCN Event Rejected"},
    {17,"SCN Registration Rejected"},
    {18,"Attribute Not Implemented"},
    {19,"FC_DOMAIN_ID Not available"},
    {20,"FC_DOMAIN_ID not allocated"},
    {21,"ESI Not Available"},
    {22,"Invalid Deregistration"},
    {23,"Registration Feature Not Supported"},
	
    {0x0,NULL}
};


#define ISNS_ATTR_TAG_DELIMITER                     0
#define ISNS_ATTR_TAG_ENTITY_IDENTIFIER             1
#define ISNS_ATTR_TAG_ENTITY_PROTOCOL               2
#define ISNS_ATTR_TAG_MGMT_IP_ADDRESS               3
#define ISNS_ATTR_TAG_TIMESTAMP                     4
#define ISNS_ATTR_TAG_PROTOCOL_VERSION_RANGE        5
#define ISNS_ATTR_TAG_REGISTRATION_PERIOD           6
#define ISNS_ATTR_TAG_ENTITY_INDEX                  7
#define ISNS_ATTR_TAG_ENTITY_NEXT_INDEX             8
#define ISNS_ATTR_TAG_ENTITY_ISAKMP_PHASE_1         11
#define ISNS_ATTR_TAG_ENTITY_CERTIFICATE            12
#define ISNS_ATTR_TAG_PORTAL_IP_ADDRESS             16
#define ISNS_ATTR_TAG_PORTAL_PORT                   17
#define ISNS_ATTR_TAG_PORTAL_SYMBOLIC_NAME          18
#define ISNS_ATTR_TAG_ESI_INTERVAL                  19
#define ISNS_ATTR_TAG_ESI_PORT                      20
#define ISNS_ATTR_TAG_PORTAL_INDEX                  22
#define ISNS_ATTR_TAG_SCN_PORT                      23
#define ISNS_ATTR_TAG_PORTAL_NEXT_INDEX             24
#define ISNS_ATTR_TAG_PORTAL_SECURITY_BITMAP        27
#define ISNS_ATTR_TAG_PORTAL_ISAKMP_PHASE_1         28
#define ISNS_ATTR_TAG_PORTAL_ISAKMP_PHASE_2         29
#define ISNS_ATTR_TAG_PORTAL_CERTIFICATE            31
#define ISNS_ATTR_TAG_ISCSI_NAME                    32
#define ISNS_ATTR_TAG_ISCSI_NODE_TYPE               33
#define ISNS_ATTR_TAG_ISCSI_ALIAS                   34
#define ISNS_ATTR_TAG_ISCSI_SCN_BITMAP              35
#define ISNS_ATTR_TAG_ISCSI_NODE_INDEX              36
#define ISNS_ATTR_TAG_WWNN_TOKEN                    37
#define ISNS_ATTR_TAG_ISCSI_NODE_NEXT_INDEX         38
#define ISNS_ATTR_TAG_ISCSI_AUTH_METHOD             42
#define ISNS_ATTR_TAG_PG_ISCSI_NAME                 48
#define ISNS_ATTR_TAG_PG_PORTAL_IP_ADDR             49
#define ISNS_ATTR_TAG_PG_PORTAL_PORT                50
#define ISNS_ATTR_TAG_PORTAL_GROUP_TAG              51
#define ISNS_ATTR_TAG_PORTAL_GROUP_INDEX            52
#define ISNS_ATTR_TAG_PORTAL_GROUP_NEXT_INDEX       53
#define ISNS_ATTR_TAG_FC_PORT_NAME_WWPN             64
#define ISNS_ATTR_TAG_PORT_ID                       65
#define ISNS_ATTR_TAG_FC_PORT_TYPE                  66
#define ISNS_ATTR_TAG_SYMBOLIC_PORT_NAME            67
#define ISNS_ATTR_TAG_FABRIC_PORT_NAME              68
#define ISNS_ATTR_TAG_HARD_ADDRESS                  69
#define ISNS_ATTR_TAG_PORT_IP_ADDRESS               70
#define ISNS_ATTR_TAG_CLASS_OF_SERVICE              71
#define ISNS_ATTR_TAG_FC4_TYPES                     72
#define ISNS_ATTR_TAG_FC4_DESCRIPTOR                73
#define ISNS_ATTR_TAG_FC4_FEATURES                  74
#define ISNS_ATTR_TAG_IFCP_SCN_BITMAP               75
#define ISNS_ATTR_TAG_PORT_ROLE                     76
#define ISNS_ATTR_TAG_PERMANENT_PORT_NAME           77
#define ISNS_ATTR_TAG_FC4_TYPE_CODE                 95
#define ISNS_ATTR_TAG_FC_NODE_NAME_WWNN             96
#define ISNS_ATTR_TAG_SYMBOLIC_NODE_NAME            97
#define ISNS_ATTR_TAG_NODE_IP_ADDRESS               98
#define ISNS_ATTR_TAG_NODE_IPA                      99
#define ISNS_ATTR_TAG_PROXY_ISCSI_NAME              101
#define ISNS_ATTR_TAG_SWITCH_NAME                   128
#define ISNS_ATTR_TAG_PREFERRED_ID                  129
#define ISNS_ATTR_TAG_ASSIGNED_ID                   130
#define ISNS_ATTR_TAG_VIRTUAL_FABRIC_ID             131
#define ISNS_ATTR_TAG_VENDOR_OUI                    256
#define ISNS_ATTR_TAG_DD_SET_ID                     2049
#define ISNS_ATTR_TAG_DD_SET_SYMBOLIC_NAME          2050
#define ISNS_ATTR_TAG_DD_SET_STATUS                 2051
#define ISNS_ATTR_TAG_DD_SET_NEXT_ID                2052
#define ISNS_ATTR_TAG_DD_ID                         2065
#define ISNS_ATTR_TAG_DD_SYMBOLIC_NAME              2066
#define ISNS_ATTR_TAG_DD_MEMBER_ISCSI_INDEX         2067
#define ISNS_ATTR_TAG_DD_MEMBER_ISCSI_NAME          2068
#define ISNS_ATTR_TAG_DD_MEMBER_FC_PORT_NAME        2069
#define ISNS_ATTR_TAG_DD_MEMBER_PORTAL_INDEX        2070
#define ISNS_ATTR_TAG_DD_MEMBER_PORTAL_IP_ADDRESS   2071
#define ISNS_ATTR_TAG_DD_MEMBER_PORTAL_PORT         2072
#define ISNS_ATTR_TAG_DD_FEATURES                   2078
#define ISNS_ATTR_TAG_DD_ID_NEXT_ID                 2079


static const value_string isns_attribute_tags[] = {
    {ISNS_ATTR_TAG_DELIMITER,                   "Delimiter"},
    {ISNS_ATTR_TAG_ENTITY_IDENTIFIER,           "Entity Identifier (EID)"},
    {ISNS_ATTR_TAG_ENTITY_PROTOCOL,             "Entity Protocol"},
    {ISNS_ATTR_TAG_MGMT_IP_ADDRESS,             "Management IP Address"},
    {ISNS_ATTR_TAG_TIMESTAMP,                   "Timestamp"},
    {ISNS_ATTR_TAG_PROTOCOL_VERSION_RANGE,      "Protocol Version Range"},
    {ISNS_ATTR_TAG_REGISTRATION_PERIOD,         "Registration Period"},
    {ISNS_ATTR_TAG_ENTITY_INDEX,                "Entity Index"},
    {ISNS_ATTR_TAG_ENTITY_NEXT_INDEX,           "Entity Next Index"},
    {ISNS_ATTR_TAG_ENTITY_ISAKMP_PHASE_1,       "Entity ISAKMP Phase-1"},
    {ISNS_ATTR_TAG_ENTITY_CERTIFICATE,          "Entity Certificate"},
    {ISNS_ATTR_TAG_PORTAL_IP_ADDRESS,           "Portal IP Address"},
    {ISNS_ATTR_TAG_PORTAL_PORT,                 "Portal TCP/UDP Port"},
    {ISNS_ATTR_TAG_PORTAL_SYMBOLIC_NAME,        "Portal Symbolic Name"},
    {ISNS_ATTR_TAG_ESI_INTERVAL,                "ESI Interval"},
    {ISNS_ATTR_TAG_ESI_PORT,                    "ESI Port"},
    {ISNS_ATTR_TAG_PORTAL_INDEX,                "Portal Index"},
    {ISNS_ATTR_TAG_SCN_PORT,                    "SCN Port"},
    {ISNS_ATTR_TAG_PORTAL_NEXT_INDEX,           "Portal Next Index"},
    {ISNS_ATTR_TAG_PORTAL_SECURITY_BITMAP,      "Portal Security Bitmap"},
    {ISNS_ATTR_TAG_PORTAL_ISAKMP_PHASE_1,       "Portal ISAKMP Phase-1"},
    {ISNS_ATTR_TAG_PORTAL_ISAKMP_PHASE_2,       "Portal ISAKMP Phase-2"},
    {ISNS_ATTR_TAG_PORTAL_CERTIFICATE,          "Portal Certificate"},
    {ISNS_ATTR_TAG_ISCSI_NAME,                  "iSCSI Name"},
    {ISNS_ATTR_TAG_ISCSI_NODE_TYPE,             "iSCSI Node Type"},
    {ISNS_ATTR_TAG_ISCSI_ALIAS,                 "iSCSI Alias"},
    {ISNS_ATTR_TAG_ISCSI_SCN_BITMAP,            "iSCSI SCN Bitmap"},
    {ISNS_ATTR_TAG_ISCSI_NODE_INDEX,            "iSCSI Node Index"},
    {ISNS_ATTR_TAG_WWNN_TOKEN,                  "WWNN Token"},
    {ISNS_ATTR_TAG_ISCSI_NODE_NEXT_INDEX,       "iSCSI Node Next Index"},
    {ISNS_ATTR_TAG_ISCSI_AUTH_METHOD,           "iSCSI AuthMethod"},
    {ISNS_ATTR_TAG_PG_ISCSI_NAME,               "PG iSCSI Name"},
    {ISNS_ATTR_TAG_PG_PORTAL_IP_ADDR,           "PG Portal IP Addr"},
    {ISNS_ATTR_TAG_PG_PORTAL_PORT,              "PG Portal Port"},
    {ISNS_ATTR_TAG_PORTAL_GROUP_TAG,            "Portal Group Tag"},
    {ISNS_ATTR_TAG_PORTAL_GROUP_INDEX,          "PG Index"},
    {ISNS_ATTR_TAG_PORTAL_GROUP_NEXT_INDEX,     "PG Next Index"},
    {ISNS_ATTR_TAG_FC_PORT_NAME_WWPN,           "FC Port Name WWPN"},
    {ISNS_ATTR_TAG_PORT_ID,                     "Port ID"},
    {ISNS_ATTR_TAG_FC_PORT_TYPE,                "FC Port Type"},
    {ISNS_ATTR_TAG_SYMBOLIC_PORT_NAME,          "Symbolic Port Name"},
    {ISNS_ATTR_TAG_FABRIC_PORT_NAME,            "Fabric Port Name"},
    {ISNS_ATTR_TAG_HARD_ADDRESS,                "Hard Address"},
    {ISNS_ATTR_TAG_PORT_IP_ADDRESS,             "Port IP-Address"},
    {ISNS_ATTR_TAG_CLASS_OF_SERVICE,            "Class of Service"},
    {ISNS_ATTR_TAG_FC4_TYPES,                   "FC-4 Types"},
    {ISNS_ATTR_TAG_FC4_DESCRIPTOR,              "FC-4 Descriptor"},
    {ISNS_ATTR_TAG_FC4_FEATURES,                "FC-4 Features"},
    {ISNS_ATTR_TAG_IFCP_SCN_BITMAP,             "iFCP SCN bitmap"},
    {ISNS_ATTR_TAG_PORT_ROLE,                   "Port Role"},
    {ISNS_ATTR_TAG_PERMANENT_PORT_NAME,         "Permanent Port Name"},
    {ISNS_ATTR_TAG_FC4_TYPE_CODE,               "FC-4 Type Code"},
    {ISNS_ATTR_TAG_FC_NODE_NAME_WWNN,           "FC Node Name WWNN"},
    {ISNS_ATTR_TAG_SYMBOLIC_NODE_NAME,          "Symbolic Node Name"},
    {ISNS_ATTR_TAG_NODE_IP_ADDRESS,             "Node IP-Address"},
    {ISNS_ATTR_TAG_NODE_IPA,                    "Node IPA"},
    {ISNS_ATTR_TAG_PROXY_ISCSI_NAME,            "Proxy iSCSI Name"},
    {ISNS_ATTR_TAG_SWITCH_NAME,                 "Switch Name"},
    {ISNS_ATTR_TAG_PREFERRED_ID,                "Preferred ID"},
    {ISNS_ATTR_TAG_ASSIGNED_ID,                 "Assigned ID"},
    {ISNS_ATTR_TAG_VIRTUAL_FABRIC_ID,           "Virtual_Fabric_ID"},
    {ISNS_ATTR_TAG_VENDOR_OUI,                  "iSNS Server Vendor OUI"},
    {ISNS_ATTR_TAG_DD_SET_ID,                   "DD_Set ID"},
    {ISNS_ATTR_TAG_DD_SET_SYMBOLIC_NAME,        "DD_Set Sym Name"},
    {ISNS_ATTR_TAG_DD_SET_STATUS,               "DD_Set Status"},
    {ISNS_ATTR_TAG_DD_SET_NEXT_ID,              "DD_Set_Next_ID"},
    {ISNS_ATTR_TAG_DD_ID,                       "DD_ID"},
    {ISNS_ATTR_TAG_DD_SYMBOLIC_NAME,            "DD_Symbolic Name"},
    {ISNS_ATTR_TAG_DD_MEMBER_ISCSI_INDEX,       "DD_Member iSCSI Index"},
    {ISNS_ATTR_TAG_DD_MEMBER_ISCSI_NAME,        "DD_Member iSCSI Name"},
    {ISNS_ATTR_TAG_DD_MEMBER_FC_PORT_NAME,      "DD_Member FC Port Name"},
    {ISNS_ATTR_TAG_DD_MEMBER_PORTAL_INDEX,      "DD Member Portal Index"},
    {ISNS_ATTR_TAG_DD_MEMBER_PORTAL_IP_ADDRESS, "DD_Member Portal IP Addr"},
    {ISNS_ATTR_TAG_DD_MEMBER_PORTAL_PORT,       "DD Member Portal TCP/UDP"},
    {ISNS_ATTR_TAG_DD_FEATURES,                 "DD_Features"},
    {ISNS_ATTR_TAG_DD_ID_NEXT_ID,               "DD_ID Next ID"},

    {0,NULL}
};


/* iSNS flags */
#define ISNS_FLAGS_CLIENT	0x8000
#define ISNS_FLAGS_SERVER	0x4000
#define ISNS_FLAGS_AUTH		0x2000
#define ISNS_FLAGS_REPLACE	0x1000
#define ISNS_FLAGS_LAST_PDU	0x0800
#define ISNS_FLAGS_FIRST_PDU	0x0400


static const true_false_string isns_scn_bitmap_initiator_and_self_information_only = {
    "True",
    "False"
};
static const true_false_string isns_scn_bitmap_target_and_self_information_only    = {
    "True",
    "False"
};
static const true_false_string isns_scn_bitmap_management_registration_scn         = {
    "True",
    "False"
};
static const true_false_string isns_scn_bitmap_object_removed                      = {
    "True",
    "False"
};
static const true_false_string isns_scn_bitmap_object_added                        = {
    "True",
    "False"
};
static const true_false_string isns_scn_bitmap_object_updated                      = {
    "True",
    "False"
};
static const true_false_string isns_scn_bitmap_dd_dds_member_removed               = {
    "True",
    "False"
};
static const true_false_string isns_scn_bitmap_dd_dds_member_added                 = {
    "True",
    "False"
};

static const true_false_string isns_psb_tunnel_mode = {
    "Preferred",
    "No Preference"
};
static const true_false_string isns_psb_transport_mode = {
    "Preferred",
    "No Preference"
};
static const true_false_string isns_psb_pfs = {
    "Enabled",
    "Disabled"
};
static const true_false_string isns_psb_aggressive_mode = {
    "Enabled",
    "Disabled"
};
static const true_false_string isns_psb_main_mode = {
    "Enabled",
    "Disabled"
};
static const true_false_string isns_psb_ike_ipsec = {
    "Enabled",
    "Disabled"
};
static const true_false_string isns_psb_bitmap = {
    "VALID",
    "INVALID"
};

static const true_false_string isns_isnt_control = {
    "Yes",
    "No"
};
static const true_false_string isns_isnt_initiator = {
    "Yes",
    "No"
};
static const true_false_string isns_isnt_target = {
    "Yes",
    "No"
};

static const true_false_string isns_port_type = {
    "UDP",
    "TCP"
};

static const true_false_string isns_flag_first_pdu = {
    "First PDU of iSNS Message",
    "Not the first PDU of iSNS Message"
};

static const true_false_string isns_flag_last_pdu = {
    "Last PDU of iSNS Message",
    "Not the Last PDU of iSNS Message"
};

static const true_false_string isns_flag_replace = {
    "Replace",
    "Don't replace"
};

static const true_false_string isns_flag_auth = {
    "Authentication Block is PRESENT",
    "No authentication block"
};

static const true_false_string isns_flag_server = {
    "Sender is iSNS server",
    "Sender is not iSNS server"
};

static const true_false_string isns_flag_client = {
    "Sender is iSNS client",
    "Sender is not iSNS client"
};


/* Initialize the subtree pointers */
static gint ett_isns = -1;


/* Code to actually dissect the packets */
static void
dissect_isns_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint offset = 0;
    guint16 function_id;
    guint16 isns_protocol_version;
    guint32 packet_len = tvb_length_remaining(tvb, offset);
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti = NULL;
    proto_tree *isns_tree = NULL;
    
    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "iSNS");
    if (check_col(pinfo->cinfo, COL_INFO)) 
	col_clear(pinfo->cinfo, COL_INFO);

    /* Get the protocol version - only version one at the moment*/ 
    isns_protocol_version = tvb_get_ntohs(tvb, offset + 0);
    
    /* Get the function id from the packet */
    function_id =  tvb_get_ntohs(tvb, offset + 2);
    
    /* Add the function name in the info col */
    if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_str(pinfo->cinfo, COL_INFO,
	            val_to_str(function_id, isns_function_ids,
	                       "Unknown function ID 0x%04x"));
    
    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items. 
     */
    if (tree) {
	guint16 b;	
	guint16 flags;	
	proto_tree *tt;
	proto_item *tflags;
	proto_item *tpayload;

	/* NOTE: The offset and length values in the call to
	 * "proto_tree_add_item()" define what data bytes to highlight in the hex
	 * display window when the line in the protocol tree display
	 * corresponding to that item is selected.
	 *  tvb_length(tvb) is a handy way to highlight all data from the offset to
	 *  the end of the packet. 
	 */

	/* create display subtree for the protocol */
	ti = proto_tree_add_item(tree, proto_isns, tvb, 0, -1, FALSE);
	isns_tree = proto_item_add_subtree(ti, ett_isns);

	/* OK... Sort out the header */
	b = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(isns_tree, hf_isns_version, tvb, offset, 2, b);

	b = tvb_get_ntohs(tvb, offset + 2);
	proto_tree_add_uint(isns_tree, hf_isns_function_id, tvb, offset+2, 2, b);

	b = tvb_get_ntohs(tvb, offset + 4);
	proto_tree_add_uint(isns_tree, hf_isns_pdu_length, tvb, offset+4, 2, b);

	/*FLAGS*/
	flags = tvb_get_ntohs(tvb, offset + 6);
	tflags = proto_tree_add_uint(isns_tree, hf_isns_flags, tvb, offset+6, 2, flags);
	tt = proto_item_add_subtree(tflags, ett_isns_flags);

	proto_tree_add_boolean(tt, hf_isns_client, tvb, offset+6, 2, flags);
	proto_tree_add_boolean(tt, hf_isns_server, tvb, offset+6, 2, flags);
	proto_tree_add_boolean(tt, hf_isns_auth, tvb, offset+6, 2, flags);
	proto_tree_add_boolean(tt, hf_isns_replace, tvb, offset+6, 2, flags);
	proto_tree_add_boolean(tt, hf_isns_last_pdu, tvb, offset+6, 2, flags);
	proto_tree_add_boolean(tt, hf_isns_first_pdu, tvb, offset+6, 2, flags);

	b = tvb_get_ntohs(tvb, offset + 8);
	proto_tree_add_uint(isns_tree, hf_isns_transaction_id, tvb, offset+8, 2, b);

	b = tvb_get_ntohs(tvb, offset + 10);
	proto_tree_add_uint(isns_tree, hf_isns_sequence_id, tvb, offset+10, 2, b);

	tpayload = proto_tree_add_item(isns_tree, hf_isns_payload, tvb, offset+12, packet_len - 12 , FALSE);
	tt = proto_item_add_subtree(tpayload, ett_isns_payload);

	/* Now set the offset to the start of the payload */
	offset += ISNS_HEADER_SIZE;

	/* Decode those attributes baby - Yeah!*/
	switch (function_id)
	{
	case ISNS_FUNC_HEARTBEAT:
	{
	    guint8 hb_ipv6[16];
	    guint16 port;
	    guint32 c;
	    tvb_memcpy(tvb,hb_ipv6,offset,16);
	    proto_tree_add_ipv6(tt,hf_isns_heartbeat_ipv6_addr, tvb, offset, 16, hb_ipv6);
	    offset += 16;

	    port = tvb_get_ntohs(tvb, offset);
	    proto_tree_add_uint(tt,hf_isns_heartbeat_tcp_port, tvb, offset, 2, port);
	    offset += 2;

	    port = tvb_get_ntohs(tvb, offset);
	    proto_tree_add_uint(tt,hf_isns_heartbeat_udp_port, tvb, offset, 2, port);
	    offset += 2;

	    c = tvb_get_ntohl(tvb, offset);
	    proto_tree_add_uint(tt,hf_isns_heartbeat_interval, tvb, offset, 4, c);
	    offset += 4;

	    c = tvb_get_ntohl(tvb, offset);
	    proto_tree_add_uint(tt,hf_isns_heartbeat_counter, tvb, offset, 4, c);
	    offset += 4;
	    break;
	}
	/* Responses */
	case ISNS_FUNC_RSP_DEVATTRREG:
	case ISNS_FUNC_RSP_DEVATTRQRY:
	case ISNS_FUNC_RSP_DEVGETNEXT:
	case ISNS_FUNC_RSP_DEREGDEV:
	case ISNS_FUNC_RSP_SCNREG:
	case ISNS_FUNC_RSP_SCNDEREG:
	case ISNS_FUNC_RSP_SCNEVENT:
	case ISNS_FUNC_RSP_SCN:
	case ISNS_FUNC_RSP_DDREG:
	case ISNS_FUNC_RSP_DDDEREG:
	case ISNS_FUNC_RSP_DDSREG:
	case ISNS_FUNC_RSP_DDSDEREG:
	case ISNS_FUNC_RSP_ESI:
	case ISNS_FUNC_RSP_RQSTDOMID:
	case ISNS_FUNC_RSP_RLSEDOMID:
	case ISNS_FUNC_RSP_GETDOMID:
	{
	    /* Get the Error message of the response */
	    guint32 errorcode =  tvb_get_ntohl(tvb, offset);
	    proto_tree_add_uint(tt,hf_isns_resp_errorcode, tvb, offset, 4, errorcode);
	    offset += 4;
	    /* Messages */
	}
	case ISNS_FUNC_DEVATTRREG:
	case ISNS_FUNC_DEVATTRQRY:
	case ISNS_FUNC_DEVGETNEXT: 
	case ISNS_FUNC_DEREGDEV:
	case ISNS_FUNC_SCNREG:
	case ISNS_FUNC_SCNDEREG:
	case ISNS_FUNC_SCNEVENT:
	case ISNS_FUNC_SCN:
	case ISNS_FUNC_DDREG:
	case ISNS_FUNC_DDDEREG:
	case ISNS_FUNC_DDSREG:
	case ISNS_FUNC_DDSDEREG:
	case ISNS_FUNC_ESI:
	case ISNS_FUNC_RQSTDOMID:
	case ISNS_FUNC_RLSEDOMID:
	case ISNS_FUNC_GETDOMID:
	default:
	    /* we can only look at the attributes for the first PDU */
	    if(!(flags&ISNS_FLAGS_FIRST_PDU)){
		proto_tree_add_text(tt, tvb, offset, packet_len-offset, "This is not the first PDU. The attributes are not decoded");
		return;
	    }

	    while( offset < packet_len )
	    {
		offset = AddAttribute(pinfo, tvb, tt, offset, function_id);
	    }
	}
    }

    return;
}

static guint
get_isns_pdu_len(tvbuff_t *tvb, int offset)
{
    guint16 isns_len;

    isns_len = tvb_get_ntohs(tvb, offset+4);
    return (isns_len+ISNS_HEADER_SIZE);
}

static int
dissect_isns_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{	
	gint length = tvb_length_remaining(tvb, 0);
	guint16 isns_protocol_version;
	guint16 function_id;

	if (length < ISNS_HEADER_SIZE) {
		/*
		 * Not enough room to see if this is valid iSNS.
		 */
		return 0;
	}

	/* Get the protocol version - only version one at the moment*/ 
	isns_protocol_version = tvb_get_ntohs(tvb, 0);
	if (isns_protocol_version != ISNS_PROTO_VER)
		return 0;

	/* Get the function id from the packet */
	function_id =  tvb_get_ntohs(tvb, 2);
	if (match_strval(function_id, isns_function_ids) == NULL) {
		/* Unknown function ID */
		return 0;
	}

	tcp_dissect_pdus(tvb, pinfo, tree, isns_desegment, 12, get_isns_pdu_len,
		dissect_isns_pdu);
	return length;
}

static int
dissect_isns_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{	
	gint length = tvb_length_remaining(tvb, 0);
	guint16 isns_protocol_version;
	guint16 function_id;

	if (length < ISNS_HEADER_SIZE) {
		/*
		 * Not enough room to see if this is valid iSNS.
		 */
		return 0;
	}

	/* Get the protocol version - only version one at the moment*/ 
	isns_protocol_version = tvb_get_ntohs(tvb, 0);
	if (isns_protocol_version != ISNS_PROTO_VER)
		return 0;

	/* Get the function id from the packet */
	function_id =  tvb_get_ntohs(tvb, 2);
	if (match_strval(function_id, isns_function_ids) == NULL) {
		/* Unknown function ID */
		return 0;
	}

	dissect_isns_pdu(tvb, pinfo, tree);
	return length;
}


static guint
dissect_isns_attr_ip_address(tvbuff_t *tvb, guint offset, proto_tree *parent_tree, int hf_index, guint32 tag, guint32 len)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, hf_index, tvb, offset + 8, len, FALSE);
		tree = proto_item_add_subtree(item, ett_isns_attribute);
	}

	proto_tree_add_uint(tree, hf_isns_attr_tag, tvb, offset, 4, tag);
	proto_tree_add_uint(tree, hf_isns_attr_len, tvb, offset+4, 4, len);

	return offset+8+len;
}

static guint
dissect_isns_attr_string(tvbuff_t *tvb, guint offset, proto_tree *parent_tree, int hf_index, guint32 tag, guint32 len)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, hf_index, tvb, offset + 8, len, FALSE);
		tree = proto_item_add_subtree(item, ett_isns_attribute);
	}

	proto_tree_add_uint(tree, hf_isns_attr_tag, tvb, offset, 4, tag);
	proto_tree_add_uint(tree, hf_isns_attr_len, tvb, offset+4, 4, len);

	return offset+8+len;
}

static guint
dissect_isns_attr_integer(tvbuff_t *tvb, guint offset, proto_tree *parent_tree, int hf_index, guint32 tag, guint32 len, guint16 function_id)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	/*
	 * 5.6.5.1
	 * in a DevAttrReg , the PGT (tag 51) may be sent as 0 length
	 * which then means that we wish to register the portal group tag
	 * as NULL.
	 * (At least) some servers will respond with PGT as a 0 length 
	 * value in these instances in the DevAttrRegRsp (eventhough I can
	 * not find this mentioned in the standard) so allow it for the 
	 * response as well.
	 */
	if(len){
		if(parent_tree){
			item=proto_tree_add_item(parent_tree, hf_index, tvb, offset + 8, len, FALSE);
			tree = proto_item_add_subtree(item, ett_isns_attribute);
		}
	} else if((tag==ISNS_ATTR_TAG_PORTAL_GROUP_TAG)&&((function_id==ISNS_FUNC_DEVATTRREG)||(function_id==ISNS_FUNC_RSP_DEVATTRREG))){
		/* 5.6.5.1 */
		if(parent_tree){
			item=proto_tree_add_uint_format(parent_tree, hf_isns_portal_group_tag, tvb, offset, 8, 0, "PG Tag: <NULL>");
			tree = proto_item_add_subtree(item, ett_isns_attribute);
		}
	} else {
		if(parent_tree){
			item=proto_tree_add_text(parent_tree, tvb, offset, 8, "Oops, you surprised me here. a 0 byte integer.");
			tree = proto_item_add_subtree(item, ett_isns_attribute);
		}
	}

	proto_tree_add_uint(tree, hf_isns_attr_tag, tvb, offset, 4, tag);
	proto_tree_add_uint(tree, hf_isns_attr_len, tvb, offset+4, 4, len);

	return offset+8+len;
}

static guint
dissect_isns_attr_port(tvbuff_t *tvb, guint offset, proto_tree *parent_tree, int hf_index, guint32 tag, guint32 len,
                       guint16 port_type, packet_info *pinfo)
{
	proto_item *tree=NULL;
	proto_item *item=NULL;
	guint16 port = tvb_get_ntohs(tvb, offset + 10);
	guint16 isudp = tvb_get_ntohs(tvb, offset + 8)&0x01;
        conversation_t *conversation;

	if(parent_tree){
            item = proto_tree_add_uint(parent_tree, hf_index, tvb, offset+8, 4, port);
            tree = proto_item_add_subtree(item, ett_isns_port);
	}

	proto_tree_add_boolean(tree, hf_isns_port_type, tvb, offset+8, 2, isudp);

	proto_tree_add_uint(tree, hf_isns_attr_tag, tvb, offset, 4, tag);
	proto_tree_add_uint(tree, hf_isns_attr_len, tvb, offset+4, 4, len);

        if ((port_type == ISNS_ESI_PORT) || (port_type == ISNS_SCN_PORT)) {
            if (isudp) {
                conversation = find_conversation (pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
                                                  port, 0, NO_PORT_B);
                if (conversation == NULL) {
                    conversation = conversation_new (pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                                     PT_UDP, port, 0, NO_PORT2_FORCE);
                    conversation_set_dissector (conversation, isns_udp_handle);
                }
            }
            else {
                conversation = find_conversation (pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_TCP,
                                                  port, 0, NO_PORT_B);
                if (conversation == NULL) {
                    conversation = conversation_new (pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                                     PT_TCP, port, 0, NO_PORT2_FORCE);
                    conversation_set_dissector (conversation, isns_tcp_handle);
                }
            }
        }

	return offset+8+len;
}

static guint
dissect_isns_attr_none(tvbuff_t *tvb, guint offset, proto_tree *parent_tree, int hf_index, guint32 tag, guint32 len)
{
	proto_item *tree=NULL;
	proto_item *item=NULL;

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, hf_index, tvb, offset, 8, FALSE);
		tree = proto_item_add_subtree(item, ett_isns_port);
	}

	proto_tree_add_uint(tree, hf_isns_attr_tag, tvb, offset, 4, tag);
	proto_tree_add_uint(tree, hf_isns_attr_len, tvb, offset+4, 4, len);

	return offset+8+len;
}

static guint
dissect_isns_attr_not_decoded_yet(tvbuff_t *tvb, guint offset, proto_tree *parent_tree, int hf_index, guint32 tag, guint32 len)
{
	proto_item *tree=NULL;
	proto_item *item=NULL;

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, hf_index, tvb, offset + 8, len, FALSE);
		tree = proto_item_add_subtree(item, ett_isns_port);
	}

	proto_tree_add_uint(tree, hf_isns_attr_tag, tvb, offset, 4, tag);
	proto_tree_add_uint(tree, hf_isns_attr_len, tvb, offset+4, 4, len);

	return offset+8+len;
}

static guint
dissect_isns_attr_iscsi_node_type(tvbuff_t *tvb, guint offset, proto_tree *parent_tree, int hf_index, guint32 tag, guint32 len)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint32 node_type=tvb_get_ntohl(tvb, offset + 8);

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, hf_index, tvb, offset + 8, len, FALSE);
		tree = proto_item_add_subtree(item, ett_isns_attribute);
	}

	proto_tree_add_boolean(tree, hf_isns_isnt_control,   tvb, offset+8, 4, node_type);
	if(node_type&0x00000004){
		proto_item_append_text(item, " Control");
	}
	proto_tree_add_boolean(tree, hf_isns_isnt_initiator, tvb, offset+8, 4, node_type);
	if(node_type&0x00000002){
		proto_item_append_text(item, " Initiator");
	}
	proto_tree_add_boolean(tree, hf_isns_isnt_target,    tvb, offset+8, 4, node_type);
	if(node_type&0x00000001){
		proto_item_append_text(item, " Target");
	}

	proto_tree_add_uint(tree, hf_isns_attr_tag, tvb, offset, 4, tag);
	proto_tree_add_uint(tree, hf_isns_attr_len, tvb, offset+4, 4, len);

	return offset+8+len;
}



static guint
dissect_isns_attr_portal_security_bitmap(tvbuff_t *tvb, guint offset, proto_tree *parent_tree, int hf_index, guint32 tag, guint32 len)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint32 psb=tvb_get_ntohl(tvb, offset + 8);

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, hf_index, tvb, offset + 8, len, FALSE);
		tree = proto_item_add_subtree(item, ett_isns_attribute);
	}

	proto_tree_add_boolean(tree, hf_isns_psb_tunnel_mode,     tvb, offset+8, 4, psb);
	proto_tree_add_boolean(tree, hf_isns_psb_transport_mode,  tvb, offset+8, 4, psb);
	proto_tree_add_boolean(tree, hf_isns_psb_pfs,             tvb, offset+8, 4, psb);
	proto_tree_add_boolean(tree, hf_isns_psb_aggressive_mode, tvb, offset+8, 4, psb);
	proto_tree_add_boolean(tree, hf_isns_psb_main_mode,       tvb, offset+8, 4, psb);
	proto_tree_add_boolean(tree, hf_isns_psb_ike_ipsec,       tvb, offset+8, 4, psb);
	proto_tree_add_boolean(tree, hf_isns_psb_bitmap,          tvb, offset+8, 4, psb);

	proto_tree_add_uint(tree, hf_isns_attr_tag, tvb, offset, 4, tag);
	proto_tree_add_uint(tree, hf_isns_attr_len, tvb, offset+4, 4, len);

	return offset+8+len;
}



static guint
dissect_isns_attr_scn_bitmap(tvbuff_t *tvb, guint offset, proto_tree *parent_tree, int hf_index, guint32 tag, guint32 len)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint32 scn_bitmap=tvb_get_ntohl(tvb, offset + 8);

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, hf_index, tvb, offset + 8, len, FALSE);
		tree = proto_item_add_subtree(item, ett_isns_attribute);
	}


	/*
	 24              INITIATOR AND SELF INFORMATION ONLY 
	 25              TARGET AND SELF INFORMATION ONLY  
	 26              MANAGEMENT REGISTRATION/SCN 
	 27              OBJECT REMOVED 
	 28              OBJECT ADDED 
	 29              OBJECT UPDATED 
	 30              DD/DDS MEMBER REMOVED (Mgmt Reg/SCN only) 
	 31 (Lsb)        DD/DDS MEMBER ADDED (Mgmt Reg/SCN only) 
	*/
	proto_tree_add_boolean(tree, hf_isns_scn_bitmap_initiator_and_self_information_only, tvb, offset+8, 4, scn_bitmap);
	proto_tree_add_boolean(tree, hf_isns_scn_bitmap_target_and_self_information_only,    tvb, offset+8, 4, scn_bitmap);
	proto_tree_add_boolean(tree, hf_isns_scn_bitmap_management_registration_scn,         tvb, offset+8, 4, scn_bitmap);
	proto_tree_add_boolean(tree, hf_isns_scn_bitmap_object_removed,                      tvb, offset+8, 4, scn_bitmap);
	proto_tree_add_boolean(tree, hf_isns_scn_bitmap_object_added,                        tvb, offset+8, 4, scn_bitmap);
	proto_tree_add_boolean(tree, hf_isns_scn_bitmap_object_updated,                      tvb, offset+8, 4, scn_bitmap);
	proto_tree_add_boolean(tree, hf_isns_scn_bitmap_dd_dds_member_removed,               tvb, offset+8, 4, scn_bitmap);
	proto_tree_add_boolean(tree, hf_isns_scn_bitmap_dd_dds_member_added,                 tvb, offset+8, 4, scn_bitmap);

	proto_tree_add_uint(tree, hf_isns_attr_tag, tvb, offset, 4, tag);
	proto_tree_add_uint(tree, hf_isns_attr_len, tvb, offset+4, 4, len);

	return offset+8+len;
}




static guint
AddAttribute(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree, guint offset,
             guint16 function_id)
{
    guint32 tag,len;


    /* Get the Tag */
    tag = tvb_get_ntohl(tvb, offset);

    /* Now the Length */
    len = tvb_get_ntohl(tvb, offset + 4);

    if (!len) {
        if (tree) {
            proto_tree_add_uint(tree, hf_isns_attr_tag, tvb, offset, 4, tag);
            proto_tree_add_uint(tree, hf_isns_attr_len, tvb, offset+4, 4, len);
        }
        return (offset+8);
    }
    
    tvb_ensure_bytes_exist(tvb, offset, len);

    switch( tag )
    {
    case ISNS_ATTR_TAG_DELIMITER:
	offset = dissect_isns_attr_none(tvb, offset, tree, hf_isns_delimiter, tag, len);
	break;
    case ISNS_ATTR_TAG_ENTITY_IDENTIFIER:
	offset = dissect_isns_attr_string(tvb, offset, tree, hf_isns_entity_identifier, tag, len);
	break;
    case ISNS_ATTR_TAG_ENTITY_PROTOCOL:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_entity_protocol, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_MGMT_IP_ADDRESS:
    if(len != 16) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_ip_address(tvb, offset, tree, hf_isns_mgmt_ip_addr, tag, len);
	break;
    case ISNS_ATTR_TAG_TIMESTAMP:
    if(len != 8) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_timestamp, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_PROTOCOL_VERSION_RANGE:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
    case ISNS_ATTR_TAG_REGISTRATION_PERIOD:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_registration_period, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_ENTITY_INDEX:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_entity_index, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_ENTITY_NEXT_INDEX:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_entity_next_index, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_ENTITY_ISAKMP_PHASE_1:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
    case ISNS_ATTR_TAG_ENTITY_CERTIFICATE:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
    case ISNS_ATTR_TAG_PORTAL_IP_ADDRESS:
    if(len != 16) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_ip_address(tvb, offset, tree, hf_isns_portal_ip_addr, tag, len);
	break;
    case ISNS_ATTR_TAG_PORTAL_PORT:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_port(tvb, offset, tree, hf_isns_portal_port, tag, len, ISNS_OTHER_PORT, pinfo);
	break;
    case ISNS_ATTR_TAG_PORTAL_SYMBOLIC_NAME:
	offset = dissect_isns_attr_string(tvb, offset, tree, hf_isns_portal_symbolic_name, tag, len);
	break;
    case ISNS_ATTR_TAG_ESI_INTERVAL:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_esi_interval, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_ESI_PORT:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_port(tvb, offset, tree, hf_isns_esi_port, tag, len, ISNS_ESI_PORT, pinfo);
	break;
    case ISNS_ATTR_TAG_PORTAL_INDEX:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_portal_index, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_SCN_PORT:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_port(tvb, offset, tree, hf_isns_scn_port, tag, len, ISNS_SCN_PORT, pinfo);
	break;
    case ISNS_ATTR_TAG_PORTAL_NEXT_INDEX:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_portal_next_index, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_PORTAL_SECURITY_BITMAP:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_portal_security_bitmap(tvb, offset, tree, hf_isns_psb, tag, len);
	break;
    case ISNS_ATTR_TAG_PORTAL_ISAKMP_PHASE_1:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
    case ISNS_ATTR_TAG_PORTAL_ISAKMP_PHASE_2:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
    case ISNS_ATTR_TAG_PORTAL_CERTIFICATE:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
    case ISNS_ATTR_TAG_ISCSI_NAME:
	offset = dissect_isns_attr_string(tvb, offset, tree, hf_isns_iscsi_name, tag, len);
	break;
    case ISNS_ATTR_TAG_ISCSI_NODE_TYPE:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_iscsi_node_type(tvb, offset, tree, hf_isns_iscsi_node_type, tag, len);
	break;
    case ISNS_ATTR_TAG_ISCSI_ALIAS:
	offset = dissect_isns_attr_string(tvb, offset, tree, hf_isns_iscsi_alias, tag, len);
	break;
    case ISNS_ATTR_TAG_ISCSI_SCN_BITMAP:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_scn_bitmap(tvb, offset, tree, hf_isns_scn_bitmap, tag, len);
	break;
    case ISNS_ATTR_TAG_ISCSI_NODE_INDEX:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_node_index, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_WWNN_TOKEN:
    if(len != 8) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_wwnn_token, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_ISCSI_NODE_NEXT_INDEX:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_node_next_index, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_ISCSI_AUTH_METHOD:
	offset = dissect_isns_attr_string(tvb, offset, tree, hf_isns_iscsi_auth_method, tag, len);
	break;
    case ISNS_ATTR_TAG_PG_ISCSI_NAME:
	offset = dissect_isns_attr_string(tvb, offset, tree, hf_isns_pg_iscsi_name, tag, len);
	break;
    case ISNS_ATTR_TAG_PG_PORTAL_IP_ADDR:
    if(len != 16) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_ip_address(tvb, offset, tree, hf_isns_pg_portal_ip_addr, tag, len);
	break;
    case ISNS_ATTR_TAG_PG_PORTAL_PORT:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_port(tvb, offset, tree, hf_isns_pg_portal_port, tag, len, ISNS_OTHER_PORT, pinfo);
	break;
    case ISNS_ATTR_TAG_PORTAL_GROUP_TAG:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_portal_group_tag, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_PORTAL_GROUP_INDEX:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_pg_index, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_PORTAL_GROUP_NEXT_INDEX:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_pg_next_index, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_FC_PORT_NAME_WWPN:
    if(len != 8) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_fc_port_name_wwpn, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_PORT_ID:
    if(len != 3) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_port_id, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_FC_PORT_TYPE:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
	/*
	  0x0000           Unidentified/Null Entry 
	  0x0001           Fibre Channel N_Port 
	  0x0002           Fibre Channel NL_Port 
	  0x0003           Fibre Channel F/NL_Port 
	  0x0081           Fibre Channel F_Port 
	  0x0082           Fibre Channel FL_Port 
	  0x0084           Fibre Channel E_Port 
	  0xFF12           iFCP Port 
	*/
    case ISNS_ATTR_TAG_SYMBOLIC_PORT_NAME:
	offset = dissect_isns_attr_string(tvb, offset, tree, hf_isns_symbolic_port_name, tag, len);
	break;
    case ISNS_ATTR_TAG_FABRIC_PORT_NAME:
    if(len != 8) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_fabric_port_name, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_HARD_ADDRESS:
    if(len != 3) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_hard_address, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_PORT_IP_ADDRESS:
    if(len != 16) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_ip_address(tvb, offset, tree, hf_isns_port_ip_addr, tag, len);
	break;
    case ISNS_ATTR_TAG_CLASS_OF_SERVICE:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
	/*
	  bit 29             Fibre Channel Class 2 Supported
	  bit 28             Fibre Channel Class 3 Supported
	*/
    case ISNS_ATTR_TAG_FC4_TYPES:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
    case ISNS_ATTR_TAG_FC4_DESCRIPTOR:
	offset = dissect_isns_attr_string(tvb, offset, tree, hf_isns_fc4_descriptor, tag, len);
	break;
    case ISNS_ATTR_TAG_FC4_FEATURES:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
    case ISNS_ATTR_TAG_IFCP_SCN_BITMAP:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
	/*
	  bit 24              INITIATOR AND SELF INFORMATION ONLY
	  bit 25              TARGET AND SELF INFORMATION ONLY
	  bit 26              MANAGEMENT REGISTRATION/SCN
	  bit 27              OBJECT REMOVED
	  bit 28              OBJECT ADDED
	  bit 29              OBJECT UPDATED
	  bit 30              DD/DDS MEMBER REMOVED (Mgmt Reg/SCN only)
	  bit 31 (Lsb)        DD/DDS MEMBER ADDED (Mgmt Reg/SCN only)
	*/
    case ISNS_ATTR_TAG_PORT_ROLE:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
	/*
	  bit 29              Control 
	  bit 30              FCP Initiator 
	  bit 31 (Lsb)        FCP Target 
	*/
    case ISNS_ATTR_TAG_PERMANENT_PORT_NAME:
    if(len != 8) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_permanent_port_name, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_FC4_TYPE_CODE:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
	/* 8bit type code in byte0 */
    case ISNS_ATTR_TAG_FC_NODE_NAME_WWNN:
    if(len != 8) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_fc_node_name_wwnn, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_SYMBOLIC_NODE_NAME:
	offset = dissect_isns_attr_string(tvb, offset, tree, hf_isns_symbolic_node_name, tag, len);
	break;
    case ISNS_ATTR_TAG_NODE_IP_ADDRESS:
    if(len != 16) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_ip_address(tvb, offset, tree, hf_isns_node_ip_addr, tag, len);
	break;
    case ISNS_ATTR_TAG_NODE_IPA:
    if(len != 8) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_node_ipa, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_PROXY_ISCSI_NAME:
	offset = dissect_isns_attr_string(tvb, offset, tree, hf_isns_proxy_iscsi_name, tag, len);
	break;
    case ISNS_ATTR_TAG_SWITCH_NAME:
    if(len != 8) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_switch_name, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_PREFERRED_ID:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_preferred_id, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_ASSIGNED_ID:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_assigned_id, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_VIRTUAL_FABRIC_ID:
	offset = dissect_isns_attr_string(tvb, offset, tree, hf_isns_virtual_fabric_id, tag, len);
	break;
    case ISNS_ATTR_TAG_VENDOR_OUI:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_vendor_oui, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_DD_SET_ID:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_dd_set_id, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_DD_SET_SYMBOLIC_NAME:
	offset = dissect_isns_attr_string(tvb, offset, tree, hf_isns_dd_set_symbolic_name, tag, len);
	break;
    case ISNS_ATTR_TAG_DD_SET_STATUS:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
    case ISNS_ATTR_TAG_DD_SET_NEXT_ID:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_dd_set_next_id, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_DD_ID:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_dd_id, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_DD_SYMBOLIC_NAME:
	offset = dissect_isns_attr_string(tvb, offset, tree, hf_isns_dd_symbolic_name, tag, len);
	break;
    case ISNS_ATTR_TAG_DD_MEMBER_ISCSI_INDEX:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_member_iscsi_index, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_DD_MEMBER_ISCSI_NAME:
	offset = dissect_isns_attr_string(tvb, offset, tree, hf_isns_dd_member_iscsi_name, tag, len);
	break;
    case ISNS_ATTR_TAG_DD_MEMBER_FC_PORT_NAME:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_member_fc_port_name, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_DD_MEMBER_PORTAL_INDEX:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_member_portal_index, tag, len, function_id);
	break;
    case ISNS_ATTR_TAG_DD_MEMBER_PORTAL_IP_ADDRESS:
    if(len != 16) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_ip_address(tvb, offset, tree, hf_isns_dd_member_portal_ip_addr, tag, len);
	break;
    case ISNS_ATTR_TAG_DD_MEMBER_PORTAL_PORT:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_port(tvb, offset, tree, hf_isns_dd_member_portal_port,
                                        tag, len, ISNS_OTHER_PORT, pinfo);
	break;
    case ISNS_ATTR_TAG_DD_FEATURES:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
	break;
    case ISNS_ATTR_TAG_DD_ID_NEXT_ID:
    if(len != 4) THROW(ReportedBoundsError);
	offset = dissect_isns_attr_integer(tvb, offset, tree, hf_isns_dd_id_next_id, tag, len, function_id);
	break;
    default:
	offset = dissect_isns_attr_not_decoded_yet(tvb, offset, tree, hf_isns_not_decoded_yet, tag, len);
    }

    
    /* move on the offset to next attribute */

    return offset;    
}



/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void proto_register_isns(void)
{
    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
	/* The Header Stuff */
	{ &hf_isns_version,
	  { "iSNSP Version","isns.PVer",
	    FT_UINT16, BASE_DEC, NULL, 0,          
	    "iSNS Protocol Version" ,HFILL}
	},
	{ &hf_isns_function_id,
	  { "Function ID","isns.functionid",	    
	    FT_UINT16, BASE_DEC,VALS(&isns_function_ids),0,          
	    "iSNS Function ID" ,HFILL}
	},
	{ &hf_isns_pdu_length,
	  { "PDU Length","isns.pdulength",
	    FT_UINT16, BASE_DEC,NULL,0,
	    "iSNS PDU Length" ,HFILL}
	},

	{ &hf_isns_flags,
	  { "Flags","isns.flags",
	    FT_UINT16, BASE_HEX,NULL,0,
	    "iSNS Flags" ,HFILL}
	},
	{ &hf_isns_client,
	  { "Client    ","isns.flags.client",
	    FT_BOOLEAN, 16, TFS(&isns_flag_client), ISNS_FLAGS_CLIENT,
	    "iSNS Client" ,HFILL}
	},
	{ &hf_isns_server,
	  { "Server    ","isns.flags.server",
	    FT_BOOLEAN, 16, TFS(&isns_flag_server), ISNS_FLAGS_SERVER,
	    "iSNS Server" ,HFILL}
	},
	{ &hf_isns_auth,
	  { "Auth      ","isns.flags.authentication_block",
	    FT_BOOLEAN, 16, TFS(&isns_flag_auth), ISNS_FLAGS_AUTH,
	    "is iSNS Authentication Block present?" ,HFILL}
	},
	{ &hf_isns_replace,
	  { "Replace   ","isns.flags.replace",
	    FT_BOOLEAN, 16, TFS(&isns_flag_replace), ISNS_FLAGS_REPLACE,
	    "iSNS Replace" ,HFILL}
	},
	{ &hf_isns_last_pdu,
	  { "Last PDU  ","isns.flags.lastpdu",
	    FT_BOOLEAN, 16, TFS(&isns_flag_last_pdu), ISNS_FLAGS_LAST_PDU,
	    "iSNS Last PDU" ,HFILL}
	},
	{ &hf_isns_first_pdu,
	  { "First PDU ","isns.flags.firstpdu",
	    FT_BOOLEAN, 16, TFS(&isns_flag_first_pdu), ISNS_FLAGS_FIRST_PDU,
	    "iSNS First PDU",HFILL }
	},


	{ &hf_isns_transaction_id,
	  { "Transaction ID","isns.transactionid",
	    FT_UINT16, BASE_DEC,NULL,0,
	    "iSNS transaction ID" ,HFILL}
	},
	{ &hf_isns_sequence_id,
	  { "Sequence ID","isns.sequenceid",
	    FT_UINT16, BASE_DEC,NULL,0,
	    "iSNS sequence ID" ,HFILL}
	},

	{ &hf_isns_entity_protocol,
	  { "Entity Protocol","isns.entity_protocol",
	    FT_UINT32, BASE_DEC,VALS(isns_entity_protocol),0,
	    "iSNS Entity Protocol" ,HFILL}
	},
	/* The Payload stuff */

	{ &hf_isns_dd_member_portal_port,
	  { "DD Member Portal Port","isns.dd_member_portal_port",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    "TCP/UDP DD Member Portal Port", HFILL }
	},

	{ &hf_isns_iscsi_node_type,
	  { "iSCSI Node Type","isns.iscsi.node_type",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "iSCSI Node Type", HFILL }
	},

	{ &hf_isns_esi_port,
	  { "ESI Port","isns.esi_port",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    "TCP/UDP ESI Port", HFILL }
	},

	{ &hf_isns_scn_port,
	  { "SCN Port","isns.scn_port",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    "TCP/UDP SCN Port", HFILL }
	},

	{ &hf_isns_portal_port,
	  { "Portal Port","isns.portal_port",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    "TCP/UDP Portal Port", HFILL }
	},

	{ &hf_isns_pg_portal_port,
	  { "PG Portal Port","isns.pg.portal_port",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    "PG Portal TCP/UDP Port", HFILL }
	},

	{ &hf_isns_port_type,
	  { "Port Type","isns.port.port_type",
	    FT_BOOLEAN, 16, TFS(&isns_port_type), 0x01, /* bit 15 (or bit 1 of a 16bit word) */
	    "Port Type",HFILL }
	},

	{ &hf_isns_psb,
	  { "Portal Security Bitmap","isns.psb",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Portal Security Bitmap", HFILL }
	},
	{ &hf_isns_psb_tunnel_mode,
	  { "Tunnel Mode     ","isns.psb.tunnel",
	    FT_BOOLEAN, 32, TFS(&isns_psb_tunnel_mode),     0x0040, /* bit 25 */
	    "Tunnel Mode Preferred",HFILL }
	},
	{ &hf_isns_psb_transport_mode,
	  { "Transport Mode  ","isns.psb.transport",
	    FT_BOOLEAN, 32, TFS(&isns_psb_transport_mode),  0x0020, /* bit 26 */
	    "Transport Mode",HFILL }
	},
	{ &hf_isns_psb_pfs,
	  { "PFS             ","isns.psb.pfs",
	    FT_BOOLEAN, 32, TFS(&isns_psb_pfs),        0x0010, /* bit 27 */
	    "PFS",HFILL }
	},
	{ &hf_isns_psb_aggressive_mode,
	  { "Aggressive Mode ","isns.psb.aggressive_mode",
	    FT_BOOLEAN, 32, TFS(&isns_psb_aggressive_mode), 0x0008, /* bit 28 */
	    "Aggressive Mode",HFILL }
	},
	{ &hf_isns_psb_main_mode,
	  { "Main Mode       ","isns.psb.main_mode",
	    FT_BOOLEAN, 32, TFS(&isns_psb_main_mode),  0x0004, /* bit 29 */
	    "Main Mode",HFILL }
	},
	{ &hf_isns_psb_ike_ipsec,
	  { "IKE/IPSec       ","isns.psb.ike_ipsec",
	    FT_BOOLEAN, 32, TFS(&isns_psb_ike_ipsec),  0x0002, /* bit 30 */
	    "IKE/IPSec",HFILL }
	},
	{ &hf_isns_psb_bitmap,
	  { "Bitmap          ","isns.psb.bitmap",
	    FT_BOOLEAN, 32, TFS(&isns_psb_bitmap),     0x0001, /* bit 31 */
	    "Bitmap",HFILL }
	},



	{ &hf_isns_scn_bitmap,
	  { "iSCSI SCN Bitmap","isns.scn_bitmap",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "iSCSI SCN Bitmap", HFILL }
	},
	{ &hf_isns_scn_bitmap_initiator_and_self_information_only,
	  { "Initiator And Self Information Only","isns.scn_bitmap.initiator_and_self_information_only",
	    FT_BOOLEAN, 32, TFS(&isns_scn_bitmap_initiator_and_self_information_only),     0x0080, /* bit 24 */
	    "Initiator And Self Information Only",HFILL }
	},
	{ &hf_isns_scn_bitmap_target_and_self_information_only,
	  { "Target And Self Information Only","isns.scn_bitmap.target_and_self_information_only",
	    FT_BOOLEAN, 32, TFS(&isns_scn_bitmap_target_and_self_information_only),     0x0040, /* bit 25 */
	    "Target And Self Information Only",HFILL }
	},
	{ &hf_isns_scn_bitmap_management_registration_scn,
	  { "Management Registration/SCN","isns.scn_bitmap.management_registration_scn",
	    FT_BOOLEAN, 32, TFS(&isns_scn_bitmap_management_registration_scn),     0x0020, /* bit 26 */
	    "Management Registration/SCN",HFILL }
	},
	{ &hf_isns_scn_bitmap_object_removed,
	  { "Object Removed","isns.scn_bitmap.object_removed",
	    FT_BOOLEAN, 32, TFS(&isns_scn_bitmap_object_removed),     0x0010, /* bit 27 */
	    "Object Removed",HFILL }
	},
	{ &hf_isns_scn_bitmap_object_added,
	  { "Object Added","isns.scn_bitmap.object_added",
	    FT_BOOLEAN, 32, TFS(&isns_scn_bitmap_object_added),     0x0008, /* bit 28 */
	    "Object Added",HFILL }
	},
	{ &hf_isns_scn_bitmap_object_updated,
	  { "Object Updated","isns.scn_bitmap.object_updated",
	    FT_BOOLEAN, 32, TFS(&isns_scn_bitmap_object_updated),     0x0004, /* bit 29 */
	    "Object Updated",HFILL }
	},
	{ &hf_isns_scn_bitmap_dd_dds_member_removed,
	  { "DD/DDS Member Removed (Mgmt Reg/SCN only)","isns.scn_bitmap.dd_dds_member_removed",
	    FT_BOOLEAN, 32, TFS(&isns_scn_bitmap_dd_dds_member_removed),     0x0002, /* bit 30 */
	    "DD/DDS Member Removed (Mgmt Reg/SCN only)",HFILL }
	},
	{ &hf_isns_scn_bitmap_dd_dds_member_added,
	  { "DD/DDS Member Added (Mgmt Reg/SCN only)","isns.scn_bitmap.dd_dds_member_added",
	    FT_BOOLEAN, 32, TFS(&isns_scn_bitmap_dd_dds_member_added),     0x0001, /* bit 31 */
	    "DD/DDS Member Added (Mgmt Reg/SCN only)",HFILL }
	},


	{ &hf_isns_isnt_control,
	  { "Control   ","isns.isnt.control",
	    FT_BOOLEAN, 32, TFS(&isns_isnt_control),  0x0004, /* bit 29 */
	    "Control",HFILL }
	},
	{ &hf_isns_isnt_initiator,
	  { "Initiator ","isns.isnt.initiator",
	    FT_BOOLEAN, 32, TFS(&isns_isnt_initiator),  0x0002, /* bit 30 */
	    "Initiator",HFILL }
	},
	{ &hf_isns_isnt_target,
	  { "Target    ","isns.isnt.target",
	    FT_BOOLEAN, 32, TFS(&isns_isnt_target),     0x0001, /* bit 31 */
	    "Target",HFILL }
	},


	{ &hf_isns_resp_errorcode,
	  { "ErrorCode","isns.errorcode",
	    FT_UINT32, BASE_DEC,TFS(isns_errorcode),0,
	    "iSNS Response Error Code" ,HFILL}
	},

	{ &hf_isns_attr_tag,
	  { "Attribute Tag","isns.attr.tag",
	    FT_UINT32, BASE_DEC,TFS(isns_attribute_tags),0,
	    "iSNS Attribute Tag" ,HFILL}
	},

	{ &hf_isns_attr_len,
	  { "Attribute Length","isns.attr.len",
	    FT_UINT32, BASE_DEC,NULL,0,
	    "iSNS Attribute Length" ,HFILL}
	},

	{ &hf_isns_delimiter,
	  { "Delimiter","isns.delimiter",
	    FT_NONE, BASE_NONE, NULL,0,
	    "iSNS Delimiter" ,HFILL}
	},

	{ &hf_isns_not_decoded_yet,
	  { "Not Decoded Yet","isns.not_decoded_yet",
	    FT_NONE, BASE_NONE, NULL,0,
	    "This tag is not yet decoded by wireshark" ,HFILL}
	},

	{ &hf_isns_heartbeat_ipv6_addr,
	  { "Heartbeat Address (ipv6)","isns.heartbeat.address",
	    FT_IPv6, BASE_NONE, NULL, 0x0,
	    "Server IPv6 Address", HFILL }},

	{ &hf_isns_heartbeat_tcp_port,
	  { "Heartbeat TCP Port","isns.heartbeat.tcpport",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Server TCP Port", HFILL }},

	{ &hf_isns_heartbeat_udp_port,
	  { "Heartbeat UDP Port","isns.heartbeat.udpport",
	    FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Server UDP Port", HFILL }},


	{ &hf_isns_heartbeat_interval,
	  { "Heartbeat Interval (secs)","isns.heartbeat.interval",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Server Heartbeat interval", HFILL }},

	{ &hf_isns_heartbeat_counter,
	  { "Heartbeat counter","isns.heartbeat.counter",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Server Heartbeat Counter", HFILL }},

	{ &hf_isns_iscsi_name,
	  { "iSCSI Name","isns.iscsi_name",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "iSCSI Name of device", HFILL }},

	{ &hf_isns_dd_member_iscsi_name,
	  { "DD Member iSCSI Name","isns.dd_member.iscsi_name",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "DD Member iSCSI Name of device", HFILL }},

	{ &hf_isns_virtual_fabric_id,
	  { "Virtual Fabric ID","isns.virtual_fabric_id",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "Virtual fabric ID", HFILL }},

	{ &hf_isns_proxy_iscsi_name,
	  { "Proxy iSCSI Name","isns.proxy_iscsi_name",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "Proxy iSCSI Name", HFILL }},

	{ &hf_isns_fc4_descriptor,
	  { "FC4 Descriptor","isns.fc4_descriptor",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "FC4 Descriptor of this device", HFILL }},

	{ &hf_isns_iscsi_auth_method,
	  { "iSCSI Auth Method","isns.iscsi_auth_method",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "Authentication Method required by this device", HFILL }},

	{ &hf_isns_iscsi_alias,
	  { "iSCSI Alias","isns.iscsi_alias",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "iSCSI Alias of device", HFILL }},

	{ &hf_isns_portal_symbolic_name,
	  { "Portal Symbolic Name","isns.portal.symbolic_name",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "Symbolic name of this portal", HFILL }},

	{ &hf_isns_dd_set_symbolic_name,
	  { "DD Set Symbolic Name","isns.dd_set.symbolic_name",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "Symbolic name of this DD Set", HFILL }},

	{ &hf_isns_dd_symbolic_name,
	  { "DD Symbolic Name","isns.dd.symbolic_name",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "Symbolic name of this DD", HFILL }},

	{ &hf_isns_symbolic_port_name,
	  { "Symbolic Port Name","isns.port.symbolic_name",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "Symbolic name of this port", HFILL }},

	{ &hf_isns_symbolic_node_name,
	  { "Symbolic Node Name","isns.node.symbolic_name",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "Symbolic name of this node", HFILL }},

	{ &hf_isns_entity_identifier,
	  { "Entity Identifier","isns.entity_identifier",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "Entity Identifier of this object", HFILL }},

	{ &hf_isns_mgmt_ip_addr,
	  { "Management IP Address","isns.mgmt.ip_address",
	    FT_IPv6, BASE_NONE, NULL, 0x0,
	    "Management IPv4/IPv6 Address", HFILL }},

	{ &hf_isns_node_ip_addr,
	  { "Node IP Address","isns.node.ip_address",
	    FT_IPv6, BASE_NONE, NULL, 0x0,
	    "Node IPv4/IPv6 Address", HFILL }},

	{ &hf_isns_port_ip_addr,
	  { "Port IP Address","isns.port.ip_address",
	    FT_IPv6, BASE_NONE, NULL, 0x0,
	    "Port IPv4/IPv6 Address", HFILL }},

	{ &hf_isns_portal_ip_addr,
	  { "Portal IP Address","isns.portal.ip_address",
	    FT_IPv6, BASE_NONE, NULL, 0x0,
	    "Portal IPv4/IPv6 Address", HFILL }},

	{ &hf_isns_dd_member_portal_ip_addr,
	  { "DD Member Portal IP Address","isns.dd.member_portal.ip_address",
	    FT_IPv6, BASE_NONE, NULL, 0x0,
	    "DD Member Portal IPv4/IPv6 Address", HFILL }},

	{ &hf_isns_pg_iscsi_name,
	  { "PG iSCSI Name","isns.pg_iscsi_name",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "PG iSCSI Name", HFILL }},

	{ &hf_isns_pg_portal_ip_addr,
	  { "PG Portal IP Address","isns.pg_portal.ip_address",
	    FT_IPv6, BASE_NONE, NULL, 0x0,
	    "PG Portal IPv4/IPv6 Address", HFILL }},

	{ &hf_isns_pg_index,
	  { "PG Index","isns.pg_index",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "PG Index", HFILL }},

	{ &hf_isns_pg_next_index,
	  { "PG Next Index","isns.pg_next_index",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "PG Next Index", HFILL }},

	{ &hf_isns_dd_id_next_id,
	  { "DD ID Next ID","isns.index",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "DD ID Next ID", HFILL }},

	{ &hf_isns_member_iscsi_index,
	  { "Member iSCSI Index","isns.member_iscsi_index",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Member iSCSI Index", HFILL }},

	{ &hf_isns_member_portal_index,
	  { "Member Portal Index","isns.member_portal_index",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Member Portal Index", HFILL }},

	{ &hf_isns_member_fc_port_name,
	  { "Member FC Port Name","isns.member_fc_port_name",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Member FC Port Name", HFILL }},

	{ &hf_isns_vendor_oui,
	  { "Vendor OUI","isns.index",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Vendor OUI", HFILL }},

	{ &hf_isns_preferred_id,
	  { "Preferred ID","isns.preferred_id",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Preferred ID", HFILL }},

	{ &hf_isns_dd_set_id,
	  { "DD Set ID","isns.dd_set_id",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "DD Set ID", HFILL }},

	{ &hf_isns_dd_id,
	  { "DD ID","isns.dd_id",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "DD ID", HFILL }},

	{ &hf_isns_port_id,
	  { "Port ID","isns.port_id",
	    FT_UINT24, BASE_HEX, NULL, 0x0,
	    "Port ID", HFILL }},

	{ &hf_isns_hard_address,
	  { "Hard Address","isns.hard_address",
	    FT_UINT24, BASE_HEX, NULL, 0x0,
	    "Hard Address", HFILL }},

	{ &hf_isns_wwnn_token,
	  { "WWNN Token","isns.wwnn_token",
	    FT_UINT64, BASE_HEX, NULL, 0x0,
	    "WWNN Token", HFILL }},

	{ &hf_isns_fc_port_name_wwpn,
	  { "FC Port Name WWPN","isns.fc_port_name_wwpn",
	    FT_UINT64, BASE_HEX, NULL, 0x0,
	    "FC Port Name WWPN", HFILL }},

	{ &hf_isns_fc_node_name_wwnn,
	  { "FC Node Name WWNN","isns.fc_node_name_wwnn",
	    FT_UINT64, BASE_HEX, NULL, 0x0,
	    "FC Node Name WWNN", HFILL }},

	{ &hf_isns_node_ipa,
	  { "Node IPA","isns.node_ipa",
	    FT_UINT64, BASE_HEX, NULL, 0x0,
	    "Node IPA", HFILL }},

	{ &hf_isns_fabric_port_name,
	  { "Fabric Port Name","isns.fabric_port_name",
	    FT_UINT64, BASE_HEX, NULL, 0x0,
	    "Fabric Port Name", HFILL }},

	{ &hf_isns_permanent_port_name,
	  { "Permanent Port Name","isns.permanent_port_name",
	    FT_UINT64, BASE_HEX, NULL, 0x0,
	    "Permanent Port Name", HFILL }},

	{ &hf_isns_switch_name,
	  { "Switch Name","isns.switch_name",
	    FT_UINT64, BASE_HEX, NULL, 0x0,
	    "Switch Name", HFILL }},

	{ &hf_isns_dd_set_next_id,
	  { "DD Set Next ID","isns.dd_set_next_id",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "DD Set Next ID", HFILL }},

	{ &hf_isns_assigned_id,
	  { "Assigned ID","isns.assigned_id",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Assigned ID", HFILL }},

	{ &hf_isns_node_index,
	  { "Node Index","isns.node.index",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Node Index", HFILL }},

	{ &hf_isns_node_next_index,
	  { "Node Next Index","isns.node.next_index",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Node INext ndex", HFILL }},

	{ &hf_isns_portal_index,
	  { "Portal Index","isns.portal.index",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Portal Index", HFILL }},

	{ &hf_isns_portal_next_index,
	  { "Portal Next Index","isns.portal.next_index",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Portal Next Index", HFILL }},

	{ &hf_isns_entity_index,
	  { "Entity Index","isns.entity.index",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Entity Index", HFILL }},

	{ &hf_isns_entity_next_index,
	  { "Entity Next Index","isns.entity.next_index",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Next Entity Index", HFILL }},

	{ &hf_isns_timestamp,
	  { "Timestamp","isns.timestamp",
	    FT_UINT64, BASE_DEC, NULL, 0x0,
	    "Timestamp in Seconds", HFILL }},

	{ &hf_isns_esi_interval,
	  { "ESI Interval","isns.esi_interval",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "ESI Interval in Seconds", HFILL }},

	{ &hf_isns_registration_period,
	  { "Registration Period","isns.registration_period",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Registration Period in Seconds", HFILL }},

	{ &hf_isns_portal_group_tag,
	  { "PG Tag","isns.portal_group_tag",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Portal Group Tag", HFILL }},

	{ &hf_isns_payload,
          { "Payload", "isns.payload",
            FT_BYTES, BASE_HEX, NULL, 0,
            "Payload" ,HFILL}
	}
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_isns,
	&ett_isns_flags,
	&ett_isns_payload,
	&ett_isns_attribute,
	&ett_isns_port,
	&ett_isns_isnt
    };
    module_t *isns_module;

/* Register the protocol name and description */
    proto_isns = proto_register_protocol("iSNS",
					 "iSNS", "isns");
    proto_register_field_array(proto_isns, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    isns_module = prefs_register_protocol(proto_isns, NULL);
    prefs_register_bool_preference(isns_module, "desegment",
	"Reassemble iSNS messages spanning multiple TCP segments",
	"Whether the iSNS dissector should reassemble messages spanning multiple TCP segments."
	" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &isns_desegment);
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/

void
proto_reg_handoff_isns(void)
{
    isns_tcp_handle = new_create_dissector_handle(dissect_isns_tcp,proto_isns);
    isns_udp_handle = new_create_dissector_handle(dissect_isns_udp,proto_isns);

    dissector_add("tcp.port",ISNS_TCP_PORT,isns_tcp_handle);
    dissector_add("udp.port",ISNS_UDP_PORT,isns_udp_handle);
}
