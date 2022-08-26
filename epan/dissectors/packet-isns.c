/* XXX fixme   can not reassemble multiple isns PDU fragments into one
  isns PDU
*/

/* packet-isns.c
 * Routines for iSNS dissection
 * Copyright 2003, Elipsan, Gareth Bushell <gbushell@elipsan.com>
 * (c) 2004 Ronnie Sahlberg   updates
 * (c) 2004 Ming Zhang   updates
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>

#include "packet-tcp.h"

void proto_register_isns(void);
void proto_reg_handoff_isns(void);

#define ISNS_PROTO_VER 0x1
#define ISNS_HEADER_SIZE 12

#define ISNS_TCP_PORT 3205
#define ISNS_UDP_PORT 3205

#define ISNS_OTHER_PORT 0
#define ISNS_ESI_PORT 1
#define ISNS_SCN_PORT 2


static dissector_handle_t isns_tcp_handle;
static dissector_handle_t isns_udp_handle;

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
static int hf_isns_not_decoded_yet = -1;
static int hf_isns_portal_group_tag = -1;
static int hf_isns_pg_iscsi_name = -1;
static int hf_isns_pg_portal_ip_addr = -1;
static int hf_isns_pg_portal_port = -1;
static int hf_isns_pg_index = -1;
static int hf_isns_pg_next_index = -1;

static expert_field ei_isns_not_first_pdu = EI_INIT;
static expert_field ei_isns_invalid_attr_len = EI_INIT;

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
static value_string_ext isns_function_ids_ext = VALUE_STRING_EXT_INIT(isns_function_ids);

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
static value_string_ext isns_errorcode_ext = VALUE_STRING_EXT_INIT(isns_errorcode);


#define ISNS_ATTR_TAG_DELIMITER                      0
#define ISNS_ATTR_TAG_ENTITY_IDENTIFIER              1
#define ISNS_ATTR_TAG_ENTITY_PROTOCOL                2
#define ISNS_ATTR_TAG_MGMT_IP_ADDRESS                3
#define ISNS_ATTR_TAG_TIMESTAMP                      4
#define ISNS_ATTR_TAG_PROTOCOL_VERSION_RANGE         5
#define ISNS_ATTR_TAG_REGISTRATION_PERIOD            6
#define ISNS_ATTR_TAG_ENTITY_INDEX                   7
#define ISNS_ATTR_TAG_ENTITY_NEXT_INDEX              8
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
static value_string_ext isns_attribute_tags_ext = VALUE_STRING_EXT_INIT(isns_attribute_tags);

#define ISNS_REQUIRE_ATTR_LEN(x) \
{ \
    if(len != x) { \
        expert_add_info_format(pinfo, len_item, &ei_isns_invalid_attr_len, \
                "Invalid attribute length (should be %d)", x); \
        break; \
    } \
}

/* iSNS flags */
#define ISNS_FLAGS_CLIENT    0x8000
#define ISNS_FLAGS_SERVER    0x4000
#define ISNS_FLAGS_AUTH      0x2000
#define ISNS_FLAGS_REPLACE   0x1000
#define ISNS_FLAGS_LAST_PDU  0x0800
#define ISNS_FLAGS_FIRST_PDU 0x0400


#define tfs_isns_scn_bitmap_initiator_and_self_information_only tfs_true_false
#define tfs_isns_scn_bitmap_target_and_self_information_only    tfs_true_false
#define tfs_isns_scn_bitmap_management_registration_scn         tfs_true_false
#define tfs_isns_scn_bitmap_object_removed                      tfs_true_false
#define tfs_isns_scn_bitmap_object_added                        tfs_true_false
#define tfs_isns_scn_bitmap_object_updated                      tfs_true_false
#define tfs_isns_scn_bitmap_dd_dds_member_removed               tfs_true_false
#define tfs_isns_scn_bitmap_dd_dds_member_added                 tfs_true_false


#define tfs_isns_psb_tunnel_mode    tfs_preferred_no_preference
#define tfs_isns_psb_transport_mode tfs_preferred_no_preference

#define tfs_isns_psb_pfs             tfs_enabled_disabled
#define tfs_isns_psb_aggressive_mode tfs_enabled_disabled
#define tfs_isns_psb_main_mode       tfs_enabled_disabled
#define tfs_isns_psb_ike_ipsec       tfs_enabled_disabled


#define tfs_isns_isnt_control   tfs_yes_no
#define tfs_isns_isnt_initiator tfs_yes_no
#define tfs_isns_isnt_target    tfs_yes_no

static const true_false_string tfs_isns_port_type = {
    "UDP",
    "TCP"
};

static const true_false_string tfs_isns_flag_first_pdu = {
    "First PDU of iSNS Message",
    "Not the first PDU of iSNS Message"
};

static const true_false_string tfs_isns_flag_last_pdu = {
    "Last PDU of iSNS Message",
    "Not the Last PDU of iSNS Message"
};

static const true_false_string tfs_isns_flag_replace = {
    "Replace",
    "Don't replace"
};

static const true_false_string tfs_isns_flag_auth = {
    "Authentication Block is PRESENT",
    "No authentication block"
};

static const true_false_string tfs_isns_flag_server = {
    "Sender is iSNS server",
    "Sender is not iSNS server"
};

static const true_false_string tfs_isns_flag_client = {
    "Sender is iSNS client",
    "Sender is not iSNS client"
};


/* Initialize the subtree pointers */
static gint ett_isns = -1;


/* Code to actually dissect the packets */
static int
dissect_isns_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint offset = 0;
    guint16 function_id;
    guint packet_len;
    proto_item *ti;
    proto_tree *isns_tree;
    guint16     flags;
    proto_tree *tt = NULL;
    proto_item *tpayload;
    static int * const isns_flags[] = {
        &hf_isns_client,
        &hf_isns_server,
        &hf_isns_auth,
        &hf_isns_replace,
        &hf_isns_last_pdu,
        &hf_isns_first_pdu,
        NULL
    };

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "iSNS");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Get the function id from the packet */
    function_id =  tvb_get_ntohs(tvb, offset + 2);

    /* Add the function name in the info col */
    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str_ext(function_id, &isns_function_ids_ext,
                               "Unknown function ID 0x%04x"));

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_isns, tvb, 0, -1, ENC_NA);
    isns_tree = proto_item_add_subtree(ti, ett_isns);

    /* OK... Sort out the header */
    proto_tree_add_item(isns_tree, hf_isns_version,     tvb, offset,   2, ENC_BIG_ENDIAN);
    proto_tree_add_item(isns_tree, hf_isns_function_id, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(isns_tree, hf_isns_pdu_length,  tvb, offset+4, 2, ENC_BIG_ENDIAN);

    flags  = tvb_get_ntohs(tvb, offset + 6);
    proto_tree_add_bitmask(isns_tree, tvb, offset+6, hf_isns_flags, ett_isns_flags, isns_flags, ENC_BIG_ENDIAN);
    proto_tree_add_item(isns_tree, hf_isns_transaction_id, tvb, offset+8,  2, ENC_BIG_ENDIAN);
    proto_tree_add_item(isns_tree, hf_isns_sequence_id,    tvb, offset+10, 2, ENC_BIG_ENDIAN);

    tpayload = proto_tree_add_item(isns_tree, hf_isns_payload, tvb, offset+12, -1, ENC_NA);
    tt = proto_item_add_subtree(tpayload, ett_isns_payload);

    /* Now set the offset to the start of the payload */
    offset += ISNS_HEADER_SIZE;

    /* Decode those attributes baby - Yeah!*/
    switch (function_id)
    {
    case ISNS_FUNC_HEARTBEAT:
        proto_tree_add_item(tt,hf_isns_heartbeat_ipv6_addr, tvb, offset, 16, ENC_NA);
        offset += 16;

        proto_tree_add_item(tt,hf_isns_heartbeat_tcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tt,hf_isns_heartbeat_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tt,hf_isns_heartbeat_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(tt,hf_isns_heartbeat_counter, tvb, offset, 4, ENC_BIG_ENDIAN);
        /*offset += 4;*/
        break;

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

        /* Get the Error message of the response */
        /*  The Error field exists only at the beginning of a message (i.e., in the first PDU */
        if(flags&ISNS_FLAGS_FIRST_PDU){
            proto_tree_add_item(tt,hf_isns_resp_errorcode, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }

        /* Fall Thru if there are attributes */
        if (tvb_reported_length_remaining(tvb, offset) == 0)
            return tvb_captured_length(tvb);
    /* FALL THROUGH */
    /* Messages */
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
            proto_tree_add_expert(tt, pinfo, &ei_isns_not_first_pdu, tvb, offset, -1);
            return tvb_captured_length(tvb);
        }

        packet_len = tvb_reported_length(tvb);
        while( offset < packet_len )
        {
            offset = AddAttribute(pinfo, tvb, tt, offset, function_id);
        }
    }

    return tvb_captured_length(tvb);
}

static guint
get_isns_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint16 isns_len;

    isns_len = tvb_get_ntohs(tvb, offset+4);
    return (isns_len+ISNS_HEADER_SIZE);
}

static int
dissect_isns_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gint length = tvb_captured_length(tvb);
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
    if (try_val_to_str_ext(function_id, &isns_function_ids_ext) == NULL) {
        /* Unknown function ID */
        return 0;
    }

    tcp_dissect_pdus(tvb, pinfo, tree, isns_desegment, ISNS_HEADER_SIZE, get_isns_pdu_len,
                     dissect_isns_pdu, data);
    return length;
}

static int
dissect_isns_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gint length = tvb_captured_length(tvb);
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
    if (try_val_to_str_ext(function_id, &isns_function_ids_ext) == NULL) {
        /* Unknown function ID */
        return 0;
    }

    dissect_isns_pdu(tvb, pinfo, tree, data);
    return length;
}


static void
dissect_isns_attr_port(tvbuff_t *tvb, guint offset, proto_tree *tree, int hf_index,
                       guint16 isns_port_type, packet_info *pinfo)
{
    guint16             port  = tvb_get_ntohs(tvb, offset+2);
    gboolean            is_udp = ((tvb_get_ntohs(tvb, offset) & 0x01) == 0x01);
    conversation_t     *conversation;
    conversation_type ckt;
    dissector_handle_t  handle;

    proto_tree_add_uint(tree, hf_index, tvb, offset, 4, port);
    proto_tree_add_boolean(tree, hf_isns_port_type, tvb, offset, 2, is_udp);

    if ((isns_port_type == ISNS_ESI_PORT) || (isns_port_type == ISNS_SCN_PORT)) {
        if (is_udp) {
            ckt = CONVERSATION_UDP;
            handle = isns_udp_handle;
        }
        else {
            ckt = CONVERSATION_TCP;
            handle = isns_tcp_handle;
        }

        conversation = find_conversation(pinfo->num,
                &pinfo->src, &pinfo->dst, ckt, port, 0, NO_PORT_B);
        if (conversation == NULL) {
            conversation = conversation_new(pinfo->num,
                    &pinfo->src, &pinfo->dst, ckt, port, 0, NO_PORT2_FORCE);
            conversation_set_dissector(conversation, handle);
        }
    }
}


static void
dissect_isns_attr_iscsi_node_type(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    static int * const flags[] = {
        &hf_isns_isnt_control,
        &hf_isns_isnt_initiator,
        &hf_isns_isnt_target,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset,
            hf_isns_iscsi_node_type, ett_isns_attribute, flags, ENC_BIG_ENDIAN);
}



static void
dissect_isns_attr_portal_security_bitmap(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    static int * const flags[] = {
        &hf_isns_psb_tunnel_mode,
        &hf_isns_psb_transport_mode,
        &hf_isns_psb_pfs,
        &hf_isns_psb_aggressive_mode,
        &hf_isns_psb_main_mode,
        &hf_isns_psb_ike_ipsec,
        &hf_isns_psb_bitmap,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_isns_psb, ett_isns_attribute, flags, ENC_BIG_ENDIAN);
}



static void
dissect_isns_attr_scn_bitmap(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
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
    static int * const flags[] = {
        &hf_isns_scn_bitmap_initiator_and_self_information_only,
        &hf_isns_scn_bitmap_target_and_self_information_only,
        &hf_isns_scn_bitmap_management_registration_scn,
        &hf_isns_scn_bitmap_object_removed,
        &hf_isns_scn_bitmap_object_added,
        &hf_isns_scn_bitmap_object_updated,
        &hf_isns_scn_bitmap_dd_dds_member_removed,
        &hf_isns_scn_bitmap_dd_dds_member_added,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_isns_scn_bitmap, ett_isns_attribute, flags, ENC_BIG_ENDIAN);
}


static guint
AddAttribute(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree, guint offset,
             guint16 function_id)
{
    proto_tree *attr_tree;
    proto_item *attr_item;
    guint32 tag,len;
    proto_item *len_item;

    attr_tree = proto_tree_add_subtree(tree, tvb, offset, -1,
            ett_isns_attribute, &attr_item, "Attribute");

    tag = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(attr_tree, hf_isns_attr_tag,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;

    len = tvb_get_ntohl(tvb, offset);
    len_item = proto_tree_add_item(attr_tree, hf_isns_attr_len,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;

    proto_item_append_text(attr_item, ": %s", val_to_str_ext_const(tag, &isns_attribute_tags_ext, "Unknown"));

    /* it seems that an empty attribute is always valid, the original code had a similar statement */
    if (len==0) {
        if ((tag==ISNS_ATTR_TAG_PORTAL_GROUP_TAG) &&
                ((function_id==ISNS_FUNC_DEVATTRREG) || (function_id==ISNS_FUNC_RSP_DEVATTRREG))) {
            /* 5.6.5.1 */
            proto_tree_add_uint_format_value(tree, hf_isns_portal_group_tag, tvb, offset, 8, 0, "<NULL>");
        }
        proto_item_set_len(attr_item, 8+len);
        return offset;
    }

    switch( tag )
    {
        case ISNS_ATTR_TAG_DELIMITER:
            /* delimiter has no data */
            break;
        case ISNS_ATTR_TAG_ENTITY_IDENTIFIER:
            proto_tree_add_item(attr_tree, hf_isns_entity_identifier, tvb, offset, len, ENC_ASCII);
            break;
        case ISNS_ATTR_TAG_ENTITY_PROTOCOL:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_entity_protocol, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_MGMT_IP_ADDRESS:
            ISNS_REQUIRE_ATTR_LEN(16);
            proto_tree_add_item(attr_tree, hf_isns_mgmt_ip_addr, tvb, offset, len, ENC_NA);
            break;
        case ISNS_ATTR_TAG_TIMESTAMP:
            ISNS_REQUIRE_ATTR_LEN(8);
            proto_tree_add_item(attr_tree, hf_isns_timestamp, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_REGISTRATION_PERIOD:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_registration_period, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_ENTITY_INDEX:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_entity_index, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_ENTITY_NEXT_INDEX:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_entity_next_index, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_PORTAL_IP_ADDRESS:
            proto_tree_add_item(attr_tree, hf_isns_portal_ip_addr, tvb, offset, len, ENC_NA);
            break;
        case ISNS_ATTR_TAG_PORTAL_PORT:
            dissect_isns_attr_port(tvb, offset, attr_tree, hf_isns_portal_port, ISNS_OTHER_PORT, pinfo);
            break;
        case ISNS_ATTR_TAG_PORTAL_SYMBOLIC_NAME:
            proto_tree_add_item(attr_tree, hf_isns_portal_symbolic_name, tvb, offset, len, ENC_ASCII);
            break;
        case ISNS_ATTR_TAG_ESI_INTERVAL:
            proto_tree_add_item(attr_tree, hf_isns_esi_interval, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_ESI_PORT:
            dissect_isns_attr_port(tvb, offset, attr_tree, hf_isns_esi_port, ISNS_ESI_PORT, pinfo);
            break;
        case ISNS_ATTR_TAG_PORTAL_INDEX:
            proto_tree_add_item(attr_tree, hf_isns_portal_index, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_SCN_PORT:
            dissect_isns_attr_port(tvb, offset, attr_tree, hf_isns_scn_port, ISNS_SCN_PORT, pinfo);
            break;
        case ISNS_ATTR_TAG_PORTAL_NEXT_INDEX:
            proto_tree_add_item(attr_tree, hf_isns_portal_next_index, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_PORTAL_SECURITY_BITMAP:
            dissect_isns_attr_portal_security_bitmap(tvb, offset, attr_tree);
            break;
        case ISNS_ATTR_TAG_ISCSI_NAME:
            proto_tree_add_item(attr_tree, hf_isns_iscsi_name, tvb, offset, len, ENC_ASCII);
            break;
        case ISNS_ATTR_TAG_ISCSI_NODE_TYPE:
            ISNS_REQUIRE_ATTR_LEN(4);
            dissect_isns_attr_iscsi_node_type(tvb, offset, attr_tree);
            break;
        case ISNS_ATTR_TAG_ISCSI_ALIAS:
            proto_tree_add_item(attr_tree, hf_isns_iscsi_alias, tvb, offset, len, ENC_ASCII);
            break;
        case ISNS_ATTR_TAG_ISCSI_SCN_BITMAP:
            ISNS_REQUIRE_ATTR_LEN(4);
            dissect_isns_attr_scn_bitmap(tvb, offset, attr_tree);
            break;
        case ISNS_ATTR_TAG_ISCSI_NODE_INDEX:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_node_index, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_WWNN_TOKEN:
            ISNS_REQUIRE_ATTR_LEN(8);
            proto_tree_add_item(attr_tree, hf_isns_wwnn_token, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_ISCSI_NODE_NEXT_INDEX:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_node_next_index, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_ISCSI_AUTH_METHOD:
            proto_tree_add_item(attr_tree, hf_isns_iscsi_auth_method, tvb, offset, len, ENC_ASCII);
            break;
        case ISNS_ATTR_TAG_PG_ISCSI_NAME:
            proto_tree_add_item(attr_tree, hf_isns_pg_iscsi_name, tvb, offset, len, ENC_ASCII);
            break;
        case ISNS_ATTR_TAG_PG_PORTAL_IP_ADDR:
            proto_tree_add_item(attr_tree, hf_isns_pg_portal_ip_addr, tvb, offset, len, ENC_NA);
            break;
        case ISNS_ATTR_TAG_PG_PORTAL_PORT:
            ISNS_REQUIRE_ATTR_LEN(4);
            dissect_isns_attr_port(tvb, offset, attr_tree, hf_isns_pg_portal_port, ISNS_OTHER_PORT, pinfo);
            break;
        case ISNS_ATTR_TAG_PORTAL_GROUP_TAG:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_portal_group_tag, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_PORTAL_GROUP_INDEX:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_pg_index, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_PORTAL_GROUP_NEXT_INDEX:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_pg_next_index, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_FC_PORT_NAME_WWPN:
            ISNS_REQUIRE_ATTR_LEN(8);
            proto_tree_add_item(attr_tree, hf_isns_fc_port_name_wwpn, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_PORT_ID:
            ISNS_REQUIRE_ATTR_LEN(3);
            proto_tree_add_item(attr_tree, hf_isns_port_id, tvb, offset, len, ENC_BIG_ENDIAN);
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
            proto_tree_add_item(attr_tree, hf_isns_symbolic_port_name, tvb, offset, len, ENC_ASCII);
            break;
        case ISNS_ATTR_TAG_FABRIC_PORT_NAME:
            ISNS_REQUIRE_ATTR_LEN(8);
            proto_tree_add_item(attr_tree, hf_isns_fabric_port_name, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_HARD_ADDRESS:
            ISNS_REQUIRE_ATTR_LEN(3);
            proto_tree_add_item(attr_tree, hf_isns_hard_address, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_PORT_IP_ADDRESS:
            ISNS_REQUIRE_ATTR_LEN(16);
            proto_tree_add_item(attr_tree, hf_isns_port_ip_addr, tvb, offset, len, ENC_NA);
            break;
            /*
               bit 29             Fibre Channel Class 2 Supported
               bit 28             Fibre Channel Class 3 Supported
             */
        case ISNS_ATTR_TAG_FC4_DESCRIPTOR:
            proto_tree_add_item(attr_tree, hf_isns_fc4_descriptor, tvb, offset, len, ENC_ASCII);
            break;
            /*
               bit 29              Control
               bit 30              FCP Initiator
               bit 31 (Lsb)        FCP Target
             */
        case ISNS_ATTR_TAG_PERMANENT_PORT_NAME:
            ISNS_REQUIRE_ATTR_LEN(8);
            proto_tree_add_item(attr_tree, hf_isns_permanent_port_name, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
            /* 8bit type code in byte0 */
        case ISNS_ATTR_TAG_FC_NODE_NAME_WWNN:
            ISNS_REQUIRE_ATTR_LEN(8);
            proto_tree_add_item(attr_tree, hf_isns_fc_node_name_wwnn, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_SYMBOLIC_NODE_NAME:
            proto_tree_add_item(attr_tree, hf_isns_symbolic_node_name, tvb, offset, len, ENC_ASCII);
            break;
        case ISNS_ATTR_TAG_NODE_IP_ADDRESS:
            ISNS_REQUIRE_ATTR_LEN(16);
            proto_tree_add_item(attr_tree, hf_isns_node_ip_addr, tvb, offset, len, ENC_NA);
            break;
        case ISNS_ATTR_TAG_NODE_IPA:
            ISNS_REQUIRE_ATTR_LEN(8);
            proto_tree_add_item(attr_tree, hf_isns_node_ipa, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_PROXY_ISCSI_NAME:
            proto_tree_add_item(attr_tree, hf_isns_proxy_iscsi_name, tvb, offset, len, ENC_ASCII);
            break;
        case ISNS_ATTR_TAG_SWITCH_NAME:
            ISNS_REQUIRE_ATTR_LEN(8);
            proto_tree_add_item(attr_tree, hf_isns_switch_name, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_PREFERRED_ID:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_preferred_id, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_ASSIGNED_ID:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_assigned_id, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_VIRTUAL_FABRIC_ID:
            proto_tree_add_item(attr_tree, hf_isns_virtual_fabric_id, tvb, offset, len, ENC_ASCII);
            break;
        case ISNS_ATTR_TAG_VENDOR_OUI:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_vendor_oui, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_DD_SET_ID:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_dd_set_id, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_DD_SET_SYMBOLIC_NAME:
            proto_tree_add_item(attr_tree, hf_isns_dd_set_symbolic_name, tvb, offset, len, ENC_ASCII);
            break;
        case ISNS_ATTR_TAG_DD_SET_NEXT_ID:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_dd_set_next_id, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_DD_ID:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_dd_id, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_DD_SYMBOLIC_NAME:
            proto_tree_add_item(attr_tree, hf_isns_dd_symbolic_name, tvb, offset, len, ENC_ASCII);
            break;
        case ISNS_ATTR_TAG_DD_MEMBER_ISCSI_INDEX:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_member_iscsi_index, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_DD_MEMBER_ISCSI_NAME:
            proto_tree_add_item(attr_tree, hf_isns_dd_member_iscsi_name, tvb, offset, len, ENC_ASCII);
            break;
        case ISNS_ATTR_TAG_DD_MEMBER_FC_PORT_NAME:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_member_fc_port_name, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_DD_MEMBER_PORTAL_INDEX:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_member_portal_index, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        case ISNS_ATTR_TAG_DD_MEMBER_PORTAL_IP_ADDRESS:
            ISNS_REQUIRE_ATTR_LEN(16);
            proto_tree_add_item(attr_tree, hf_isns_dd_member_portal_ip_addr, tvb, offset, len, ENC_NA);
            break;
        case ISNS_ATTR_TAG_DD_MEMBER_PORTAL_PORT:
            ISNS_REQUIRE_ATTR_LEN(4);
            dissect_isns_attr_port(tvb, offset, attr_tree, hf_isns_dd_member_portal_port, ISNS_OTHER_PORT, pinfo);
            break;
        case ISNS_ATTR_TAG_DD_ID_NEXT_ID:
            ISNS_REQUIRE_ATTR_LEN(4);
            proto_tree_add_item(attr_tree, hf_isns_dd_id_next_id, tvb, offset, len, ENC_BIG_ENDIAN);
            break;
        default:
            proto_tree_add_item(attr_tree, hf_isns_not_decoded_yet, tvb, offset, len, ENC_NA);
    }

    /* Make sure the data is all there - and that the length won't overflow */
    tvb_ensure_bytes_exist(tvb, offset, len);
    /* Set the length of the item to cover only the actual item length */
    proto_item_set_len(attr_item, 8+len);

    offset += len;
    return offset;
}



void proto_register_isns(void)
{
    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
    /* The Header Stuff */
    { &hf_isns_version,
      { "iSNSP Version", "isns.PVer",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL}
    },
    { &hf_isns_function_id,
      { "Function ID", "isns.functionid",
        FT_UINT16, BASE_DEC|BASE_EXT_STRING, &isns_function_ids_ext, 0,
        NULL, HFILL}
    },
    { &hf_isns_pdu_length,
      { "PDU Length", "isns.pdulength",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL}
    },

    { &hf_isns_flags,
      { "Flags", "isns.flags",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL}
    },
    { &hf_isns_client,
      { "Client", "isns.flags.client",
        FT_BOOLEAN, 16, TFS(&tfs_isns_flag_client), ISNS_FLAGS_CLIENT,
        NULL, HFILL}
    },
    { &hf_isns_server,
      { "Server", "isns.flags.server",
        FT_BOOLEAN, 16, TFS(&tfs_isns_flag_server), ISNS_FLAGS_SERVER,
        NULL, HFILL}
    },
    { &hf_isns_auth,
      { "Auth", "isns.flags.authentication_block",
        FT_BOOLEAN, 16, TFS(&tfs_isns_flag_auth), ISNS_FLAGS_AUTH,
        "is iSNS Authentication Block present?", HFILL}
    },
    { &hf_isns_replace,
      { "Replace", "isns.flags.replace",
        FT_BOOLEAN, 16, TFS(&tfs_isns_flag_replace), ISNS_FLAGS_REPLACE,
        NULL, HFILL}
    },
    { &hf_isns_last_pdu,
      { "Last PDU", "isns.flags.lastpdu",
        FT_BOOLEAN, 16, TFS(&tfs_isns_flag_last_pdu), ISNS_FLAGS_LAST_PDU,
        NULL, HFILL}
    },
    { &hf_isns_first_pdu,
      { "First PDU", "isns.flags.firstpdu",
        FT_BOOLEAN, 16, TFS(&tfs_isns_flag_first_pdu), ISNS_FLAGS_FIRST_PDU,
        NULL, HFILL }
    },


    { &hf_isns_transaction_id,
      { "Transaction ID", "isns.transactionid",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL}
    },
    { &hf_isns_sequence_id,
      { "Sequence ID", "isns.sequenceid",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL}
    },

    { &hf_isns_entity_protocol,
      { "Entity Protocol", "isns.entity_protocol",
        FT_UINT32, BASE_DEC, VALS(isns_entity_protocol), 0,
        NULL, HFILL}
    },
    /* The Payload stuff */

    { &hf_isns_dd_member_portal_port,
      { "DD Member Portal Port", "isns.dd_member_portal_port",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TCP/UDP DD Member Portal Port", HFILL }
    },

    { &hf_isns_iscsi_node_type,
      { "iSCSI Node Type", "isns.iscsi.node_type",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_isns_esi_port,
      { "ESI Port", "isns.esi_port",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TCP/UDP ESI Port", HFILL }
    },

    { &hf_isns_scn_port,
      { "SCN Port", "isns.scn_port",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TCP/UDP SCN Port", HFILL }
    },

    { &hf_isns_portal_port,
      { "Portal Port", "isns.portal_port",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TCP/UDP Portal Port", HFILL }
    },

    { &hf_isns_pg_portal_port,
      { "PG Portal Port", "isns.pg.portal_port",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PG Portal TCP/UDP Port", HFILL }
    },

    { &hf_isns_port_type,
      { "Port Type", "isns.port.port_type",
        FT_BOOLEAN, 16, TFS(&tfs_isns_port_type), 0x01, /* bit 15 (or bit 1 of a 16bit word) */
        NULL, HFILL }
    },

    { &hf_isns_psb,
      { "Portal Security Bitmap", "isns.psb",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_isns_psb_tunnel_mode,
      { "Tunnel Mode", "isns.psb.tunnel",
        FT_BOOLEAN, 32, TFS(&tfs_isns_psb_tunnel_mode),     0x0040, /* bit 25 */
        "Tunnel Mode Preferred", HFILL }
    },
    { &hf_isns_psb_transport_mode,
      { "Transport Mode", "isns.psb.transport",
        FT_BOOLEAN, 32, TFS(&tfs_isns_psb_transport_mode),  0x0020, /* bit 26 */
        NULL, HFILL }
    },
    { &hf_isns_psb_pfs,
      { "PFS", "isns.psb.pfs",
        FT_BOOLEAN, 32, TFS(&tfs_isns_psb_pfs),        0x0010, /* bit 27 */
        NULL, HFILL }
    },
    { &hf_isns_psb_aggressive_mode,
      { "Aggressive Mode", "isns.psb.aggressive_mode",
        FT_BOOLEAN, 32, TFS(&tfs_isns_psb_aggressive_mode), 0x0008, /* bit 28 */
        NULL, HFILL }
    },
    { &hf_isns_psb_main_mode,
      { "Main Mode", "isns.psb.main_mode",
        FT_BOOLEAN, 32, TFS(&tfs_isns_psb_main_mode),  0x0004, /* bit 29 */
        NULL, HFILL }
    },
    { &hf_isns_psb_ike_ipsec,
      { "IKE/IPSec", "isns.psb.ike_ipsec",
        FT_BOOLEAN, 32, TFS(&tfs_isns_psb_ike_ipsec),  0x0002, /* bit 30 */
        NULL, HFILL }
    },
    { &hf_isns_psb_bitmap,
      { "Bitmap", "isns.psb.bitmap",
        FT_BOOLEAN, 32, TFS(&tfs_valid_invalid),     0x0001, /* bit 31 */
        NULL, HFILL }
    },



    { &hf_isns_scn_bitmap,
      { "iSCSI SCN Bitmap", "isns.scn_bitmap",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_isns_scn_bitmap_initiator_and_self_information_only,
      { "Initiator And Self Information Only", "isns.scn_bitmap.initiator_and_self_information_only",
        FT_BOOLEAN, 32, TFS(&tfs_isns_scn_bitmap_initiator_and_self_information_only),     0x0080, /* bit 24 */
        NULL, HFILL }
    },
    { &hf_isns_scn_bitmap_target_and_self_information_only,
      { "Target And Self Information Only", "isns.scn_bitmap.target_and_self_information_only",
        FT_BOOLEAN, 32, TFS(&tfs_isns_scn_bitmap_target_and_self_information_only),     0x0040, /* bit 25 */
        NULL, HFILL }
    },
    { &hf_isns_scn_bitmap_management_registration_scn,
      { "Management Registration/SCN", "isns.scn_bitmap.management_registration_scn",
        FT_BOOLEAN, 32, TFS(&tfs_isns_scn_bitmap_management_registration_scn),     0x0020, /* bit 26 */
        NULL, HFILL }
    },
    { &hf_isns_scn_bitmap_object_removed,
      { "Object Removed", "isns.scn_bitmap.object_removed",
        FT_BOOLEAN, 32, TFS(&tfs_isns_scn_bitmap_object_removed),     0x0010, /* bit 27 */
        NULL, HFILL }
    },
    { &hf_isns_scn_bitmap_object_added,
      { "Object Added", "isns.scn_bitmap.object_added",
        FT_BOOLEAN, 32, TFS(&tfs_isns_scn_bitmap_object_added),     0x0008, /* bit 28 */
        NULL, HFILL }
    },
    { &hf_isns_scn_bitmap_object_updated,
      { "Object Updated", "isns.scn_bitmap.object_updated",
        FT_BOOLEAN, 32, TFS(&tfs_isns_scn_bitmap_object_updated),     0x0004, /* bit 29 */
        NULL, HFILL }
    },
    { &hf_isns_scn_bitmap_dd_dds_member_removed,
      { "DD/DDS Member Removed (Mgmt Reg/SCN only)", "isns.scn_bitmap.dd_dds_member_removed",
        FT_BOOLEAN, 32, TFS(&tfs_isns_scn_bitmap_dd_dds_member_removed),     0x0002, /* bit 30 */
        NULL, HFILL }
    },
    { &hf_isns_scn_bitmap_dd_dds_member_added,
      { "DD/DDS Member Added (Mgmt Reg/SCN only)", "isns.scn_bitmap.dd_dds_member_added",
        FT_BOOLEAN, 32, TFS(&tfs_isns_scn_bitmap_dd_dds_member_added),     0x0001, /* bit 31 */
        NULL, HFILL }
    },


    { &hf_isns_isnt_control,
      { "Control", "isns.isnt.control",
        FT_BOOLEAN, 32, TFS(&tfs_isns_isnt_control),  0x0004, /* bit 29 */
        NULL, HFILL }
    },
    { &hf_isns_isnt_initiator,
      { "Initiator", "isns.isnt.initiator",
        FT_BOOLEAN, 32, TFS(&tfs_isns_isnt_initiator),  0x0002, /* bit 30 */
        NULL, HFILL }
    },
    { &hf_isns_isnt_target,
      { "Target", "isns.isnt.target",
        FT_BOOLEAN, 32, TFS(&tfs_isns_isnt_target),     0x0001, /* bit 31 */
        NULL, HFILL }
    },


    { &hf_isns_resp_errorcode,
      { "ErrorCode", "isns.errorcode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &isns_errorcode_ext, 0,
        "iSNS Response Error Code", HFILL}
    },

    { &hf_isns_attr_tag,
      { "Attribute Tag", "isns.attr.tag",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &isns_attribute_tags_ext, 0,
        NULL, HFILL}
    },

    { &hf_isns_attr_len,
      { "Attribute Length", "isns.attr.len",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL}
    },

    { &hf_isns_not_decoded_yet,
      { "Not Decoded Yet", "isns.not_decoded_yet",
        FT_NONE, BASE_NONE, NULL, 0,
        "This tag is not yet decoded by Wireshark", HFILL}
    },

    { &hf_isns_heartbeat_ipv6_addr,
      { "Heartbeat Address (ipv6)", "isns.heartbeat.address",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "Server IPv6 Address", HFILL }},

    { &hf_isns_heartbeat_tcp_port,
      { "Heartbeat TCP Port", "isns.heartbeat.tcpport",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Server TCP Port", HFILL }},

    { &hf_isns_heartbeat_udp_port,
      { "Heartbeat UDP Port", "isns.heartbeat.udpport",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Server UDP Port", HFILL }},


    { &hf_isns_heartbeat_interval,
      { "Heartbeat Interval (secs)", "isns.heartbeat.interval",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Server Heartbeat interval", HFILL }},

    { &hf_isns_heartbeat_counter,
      { "Heartbeat counter", "isns.heartbeat.counter",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Server Heartbeat Counter", HFILL }},

    { &hf_isns_iscsi_name,
      { "iSCSI Name", "isns.iscsi_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "iSCSI Name of device", HFILL }},

    { &hf_isns_dd_member_iscsi_name,
      { "DD Member iSCSI Name", "isns.dd_member.iscsi_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "DD Member iSCSI Name of device", HFILL }},

    { &hf_isns_virtual_fabric_id,
      { "Virtual Fabric ID", "isns.virtual_fabric_id",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_proxy_iscsi_name,
      { "Proxy iSCSI Name", "isns.proxy_iscsi_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_fc4_descriptor,
      { "FC4 Descriptor", "isns.fc4_descriptor",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "FC4 Descriptor of this device", HFILL }},

    { &hf_isns_iscsi_auth_method,
      { "iSCSI Auth Method", "isns.iscsi_auth_method",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Authentication Method required by this device", HFILL }},

    { &hf_isns_iscsi_alias,
      { "iSCSI Alias", "isns.iscsi_alias",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "iSCSI Alias of device", HFILL }},

    { &hf_isns_portal_symbolic_name,
      { "Portal Symbolic Name", "isns.portal.symbolic_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Symbolic name of this portal", HFILL }},

    { &hf_isns_dd_set_symbolic_name,
      { "DD Set Symbolic Name", "isns.dd_set.symbolic_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Symbolic name of this DD Set", HFILL }},

    { &hf_isns_dd_symbolic_name,
      { "DD Symbolic Name", "isns.dd.symbolic_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Symbolic name of this DD", HFILL }},

    { &hf_isns_symbolic_port_name,
      { "Symbolic Port Name", "isns.port.symbolic_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Symbolic name of this port", HFILL }},

    { &hf_isns_symbolic_node_name,
      { "Symbolic Node Name", "isns.node.symbolic_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Symbolic name of this node", HFILL }},

    { &hf_isns_entity_identifier,
      { "Entity Identifier", "isns.entity_identifier",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Entity Identifier of this object", HFILL }},

    { &hf_isns_mgmt_ip_addr,
      { "Management IP Address", "isns.mgmt.ip_address",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "Management IPv4/IPv6 Address", HFILL }},

    { &hf_isns_node_ip_addr,
      { "Node IP Address", "isns.node.ip_address",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "Node IPv4/IPv6 Address", HFILL }},

    { &hf_isns_port_ip_addr,
      { "Port IP Address", "isns.port.ip_address",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "Port IPv4/IPv6 Address", HFILL }},

    { &hf_isns_portal_ip_addr,
      { "Portal IP Address", "isns.portal.ip_address",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "Portal IPv4/IPv6 Address", HFILL }},

    { &hf_isns_dd_member_portal_ip_addr,
      { "DD Member Portal IP Address", "isns.dd.member_portal.ip_address",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "DD Member Portal IPv4/IPv6 Address", HFILL }},

    { &hf_isns_pg_iscsi_name,
      { "PG iSCSI Name", "isns.pg_iscsi_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_pg_portal_ip_addr,
      { "PG Portal IP Address", "isns.pg_portal.ip_address",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "PG Portal IPv4/IPv6 Address", HFILL }},

    { &hf_isns_pg_index,
      { "PG Index", "isns.pg_index",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_pg_next_index,
      { "PG Next Index", "isns.pg_next_index",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_dd_id_next_id,
      { "DD ID Next ID", "isns.dd_id_next_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_member_iscsi_index,
      { "Member iSCSI Index", "isns.member_iscsi_index",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_member_portal_index,
      { "Member Portal Index", "isns.member_portal_index",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_member_fc_port_name,
      { "Member FC Port Name", "isns.member_fc_port_name",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_vendor_oui,
      { "Vendor OUI", "isns.vendor_oui",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_preferred_id,
      { "Preferred ID", "isns.preferred_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_dd_set_id,
      { "DD Set ID", "isns.dd_set_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_dd_id,
      { "DD ID", "isns.dd_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_port_id,
      { "Port ID", "isns.port_id",
        FT_UINT24, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_hard_address,
      { "Hard Address", "isns.hard_address",
        FT_UINT24, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_wwnn_token,
      { "WWNN Token", "isns.wwnn_token",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_fc_port_name_wwpn,
      { "FC Port Name WWPN", "isns.fc_port_name_wwpn",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_fc_node_name_wwnn,
      { "FC Node Name WWNN", "isns.fc_node_name_wwnn",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_node_ipa,
      { "Node IPA", "isns.node_ipa",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_fabric_port_name,
      { "Fabric Port Name", "isns.fabric_port_name",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_permanent_port_name,
      { "Permanent Port Name", "isns.permanent_port_name",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_switch_name,
      { "Switch Name", "isns.switch_name",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_dd_set_next_id,
      { "DD Set Next ID", "isns.dd_set_next_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_assigned_id,
      { "Assigned ID", "isns.assigned_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_node_index,
      { "Node Index", "isns.node.index",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_node_next_index,
      { "Node Next Index", "isns.node.next_index",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Node INext index", HFILL }},

    { &hf_isns_portal_index,
      { "Portal Index", "isns.portal.index",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_portal_next_index,
      { "Portal Next Index", "isns.portal.next_index",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_entity_index,
      { "Entity Index", "isns.entity.index",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isns_entity_next_index,
      { "Entity Next Index", "isns.entity.next_index",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Next Entity Index", HFILL }},

    { &hf_isns_timestamp,
      { "Timestamp", "isns.timestamp",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "Timestamp in Seconds", HFILL }},

    { &hf_isns_esi_interval,
      { "ESI Interval", "isns.esi_interval",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "ESI Interval in Seconds", HFILL }},

    { &hf_isns_registration_period,
      { "Registration Period", "isns.registration_period",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Registration Period in Seconds", HFILL }},

    { &hf_isns_portal_group_tag,
      { "PG Tag", "isns.portal_group_tag",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Portal Group Tag", HFILL }},

    { &hf_isns_payload,
          { "Payload", "isns.payload",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
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

    static ei_register_info ei[] = {
        { &ei_isns_not_first_pdu,
          { "isns.not_first_pdu", PI_PROTOCOL, PI_WARN,
            "This is not the first PDU. The attributes are not decoded", EXPFILL }},
        { &ei_isns_invalid_attr_len,
          { "isns.invalid_attribute_length", PI_PROTOCOL, PI_WARN,
            "Invalid attribute length", EXPFILL }}
   };

    module_t *isns_module;
    expert_module_t* expert_isns;

    /* Register the protocol name and description */
    proto_isns = proto_register_protocol("iSNS", "iSNS", "isns");
    proto_register_field_array(proto_isns, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_isns = expert_register_protocol(proto_isns);
    expert_register_field_array(expert_isns, ei, array_length(ei));

    /* Register preferences */
    isns_module = prefs_register_protocol(proto_isns, NULL);
    prefs_register_bool_preference(
        isns_module, "desegment",
        "Reassemble iSNS messages spanning multiple TCP segments",
        "Whether the iSNS dissector should reassemble messages spanning multiple TCP segments."
        " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
        &isns_desegment);
}

void
proto_reg_handoff_isns(void)
{
    isns_tcp_handle = create_dissector_handle(dissect_isns_tcp,proto_isns);
    isns_udp_handle = create_dissector_handle(dissect_isns_udp,proto_isns);

    dissector_add_uint_with_preference("tcp.port",ISNS_TCP_PORT,isns_tcp_handle);
    dissector_add_uint_with_preference("udp.port",ISNS_UDP_PORT,isns_udp_handle);
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
