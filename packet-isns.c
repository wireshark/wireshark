/* packet-isns.c
 * Routines for iSNS dissection
 * Copyright 2003, Elipsan, Gareth Bushell <gbushell@elipsan.com>
 *
 * $Id: packet-isns.c,v 1.2 2003/10/02 22:44:19 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>

#define ISNS_PROTO_VER 0x1
#define ISNS_HEADER_SIZE 12

#define ISNS_TCP_PORT 3205
#define ISNS_UDP_PORT 3205

static gint ett_isns_flags = -1;
static gint ett_isns_payload = -1;
static gint ett_isns_port = -1;
static gint ett_isns_psb = -1;
static gint ett_isns_isnt = -1;
static gint ett_scn_bitmap = -1;

static guint AddAttribute(tvbuff_t *tvb, proto_tree *tree,guint offset );

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
static int hf_isns_isnt = -1;
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

static int hf_isns_port = -1;
static int hf_isns_port_port = -1;
static int hf_isns_port_type = -1;

static int hf_isns_entity_protocol = -1;
static int hf_isns_resp_errorcode = -1;
static int hf_isns_attr_tag = -1;
static int hf_isns_attr_len = -1;
static int hf_isns_attr_payload = -1;
static int hf_isns_heartbeat_ipv6_addr = -1;
static int hf_isns_heartbeat_udp_port = -1;
static int hf_isns_heartbeat_tcp_port = -1;
static int hf_isns_heartbeat_interval = -1;
static int hf_isns_heartbeat_counter = -1;

static int hf_isns_attr_string = -1;
static int hf_isns_attr_ipaddr = -1;
static int hf_isns_attr_index = -1;
static int hf_isns_attr_seconds = -1;

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
    { 4,"Requested ESI Period Too short"},
    { 5,"Invalid Query"},
    { 6,"Authentication Unknown"},
    { 7,"Authentication Absent"},
    { 8,"Authentication Failed"},
    { 9,"No such Entry"},
    {10,"Version Not Supported"},
    {11,"Internal Bus Error"},
    {12,"Busy Now"},
    {13,"Option Not Understood"},
    {14,"Invalid Update"},
    {15,"Message Not supported"},
    {16,"SCN Event Rejected"},
    {17,"SCN Registration Rejected"},
    {18,"Attribute Not Implemented"},
    {19,"SWITCH_ID Not available"},
    {20,"SWITCH_ID not allocated"},
    {21,"ESI Not Available"},

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
#define ISNS_ATTR_TAG_PORTAL_GROUP                  21
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
#define ISNS_ATTR_TAG_ISCSI_NODE_CERTIFICATE        43
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
#define ISNS_ATTR_TAG_PORT_CERTIFICATE              83
#define ISNS_ATTR_TAG_FC4_TYPE_CODE                 95
#define ISNS_ATTR_TAG_FC_NODE_NAME_WWNN             96
#define ISNS_ATTR_TAG_SYMBOLIC_NODE_NAME            97
#define ISNS_ATTR_TAG_NODE_IP_ADDRESS               98
#define ISNS_ATTR_TAG_NODE_IPA                      99
#define ISNS_ATTR_TAG_NODE_CERTIFICATE              100
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
#define ISNS_ATTR_TAG_DD_MEMBER_IFCP_NODE           2069
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
    {ISNS_ATTR_TAG_PORTAL_GROUP,                "Portal Group Tag"},
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
    {ISNS_ATTR_TAG_ISCSI_NODE_CERTIFICATE,      "iSCSI Node Certificate"},
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
    {ISNS_ATTR_TAG_PORT_CERTIFICATE,            "Port Certificate"},
    {ISNS_ATTR_TAG_FC4_TYPE_CODE,               "FC-4 Type Code"},
    {ISNS_ATTR_TAG_FC_NODE_NAME_WWNN,           "FC Node Name WWNN"},
    {ISNS_ATTR_TAG_SYMBOLIC_NODE_NAME,          "Symbolic Node Name"},
    {ISNS_ATTR_TAG_NODE_IP_ADDRESS,             "Node IP-Address"},
    {ISNS_ATTR_TAG_NODE_IPA,                    "Node IPA"},
    {ISNS_ATTR_TAG_NODE_CERTIFICATE,            "Node Certificate"},
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
    {ISNS_ATTR_TAG_DD_MEMBER_IFCP_NODE,         "DD_Member iFCP Node"},
    {ISNS_ATTR_TAG_DD_MEMBER_PORTAL_INDEX,      "DD Member Portal Index"},
    {ISNS_ATTR_TAG_DD_MEMBER_PORTAL_IP_ADDRESS, "DD_Member Portal IP Addr"},
    {ISNS_ATTR_TAG_DD_MEMBER_PORTAL_PORT,       "DD Member Portal TCP/UDP"},
    {ISNS_ATTR_TAG_DD_FEATURES,                 "DD_Features"},
    {ISNS_ATTR_TAG_DD_ID_NEXT_ID,               "DD_ID Next ID"},

    {0,NULL}
};




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
static int
dissect_isns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint offset = 0;
    guint16 function_id;
    guint16 isns_protocol_version;
    guint32 packet_len = tvb_length_remaining(tvb, offset);
    char * function_id_str;
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti = NULL;
    proto_tree *isns_tree = NULL;
    
    if( packet_len < 12 )
	return 0;

    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "isns");
    if (check_col(pinfo->cinfo, COL_INFO)) 
	col_clear(pinfo->cinfo, COL_INFO);

    /* Get the function id from the packet */
    function_id =  tvb_get_ntohs(tvb, offset + 2);
    function_id_str = match_strval(function_id, isns_function_ids);
    
    /* Get the protocol version - only version one at the moment*/ 
    isns_protocol_version = tvb_get_ntohs(tvb, offset + 0);
    if( (function_id_str == NULL) || (isns_protocol_version != ISNS_PROTO_VER) )
	return 0;
    
    /* Add the function name in the info col */
    if (check_col(pinfo->cinfo, COL_INFO)) 
	col_add_str(pinfo->cinfo, COL_INFO, function_id_str);
    
    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items. 
     */
    if (tree) {
	guint16 b;	
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
	b = tvb_get_ntohs(tvb, offset + 6);
	tflags = proto_tree_add_uint(isns_tree, hf_isns_flags, tvb, offset+6, 2, b);
	tt = proto_item_add_subtree(tflags, ett_isns_flags);

	proto_tree_add_boolean(tt, hf_isns_first_pdu, tvb, offset+6, 2, b); 
	proto_tree_add_boolean(tt, hf_isns_last_pdu, tvb, offset+6, 2, b); 
	proto_tree_add_boolean(tt, hf_isns_replace, tvb, offset+6, 2, b); 
	proto_tree_add_boolean(tt, hf_isns_server, tvb, offset+6, 2, b); 
	proto_tree_add_boolean(tt, hf_isns_client, tvb, offset+6, 2, b); 

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
	default:
	    while( offset < packet_len )
	    {
		offset += AddAttribute(tvb,tt,offset);
	    }
	}
    }

    return tvb_length(tvb);
}

static guint
AddAttribute(tvbuff_t *tvb, proto_tree *tree,guint offset )
{
    proto_tree *tt;
    proto_item *attribute;
    guint32 tag,len;

    /* Get the Tag */
    tag = tvb_get_ntohl(tvb, offset);

    /* Now the Length */
    len = tvb_get_ntohl(tvb, offset + 4);
    
    attribute = proto_tree_add_item(tree, hf_isns_attr_payload, tvb, offset , len + 8 , FALSE);
    tt = proto_item_add_subtree(attribute, ett_isns_payload);
    proto_tree_add_uint(tt,hf_isns_attr_tag, tvb, offset, 4, tag);
    proto_tree_add_uint(tt,hf_isns_attr_len, tvb, offset + 4, 4, len);
#if 0    
    fprintf(stderr,"packet_len=%i\noffset=%i\n(len <= (packet_len - (offset + 8))))=%i\n",
	    packet_len,
	    offset,
	    (len <= (packet_len - (offset + 8))));

    if( (len > 0) && (len <= (packet_len - (offset + 8))))
    {
	fprintf(stderr,"Payload");
	
    }
#endif

    if( len == 0 ) return 8;

    switch( tag )
    {
    case ISNS_ATTR_TAG_DELIMITER:                    goto none;
    case ISNS_ATTR_TAG_ENTITY_IDENTIFIER:            goto string;
    case ISNS_ATTR_TAG_ENTITY_PROTOCOL:              goto entity_protocol;
    case ISNS_ATTR_TAG_MGMT_IP_ADDRESS:              goto ip;
    case ISNS_ATTR_TAG_TIMESTAMP:                    goto seconds;
    case ISNS_ATTR_TAG_PROTOCOL_VERSION_RANGE:       goto version_range;
    case ISNS_ATTR_TAG_REGISTRATION_PERIOD:          goto seconds;
    case ISNS_ATTR_TAG_ENTITY_INDEX:                 goto identifier32;
    case ISNS_ATTR_TAG_ENTITY_NEXT_INDEX:            goto identifier32;
    case ISNS_ATTR_TAG_ENTITY_ISAKMP_PHASE_1:        goto will_not_decode;
    case ISNS_ATTR_TAG_ENTITY_CERTIFICATE:           goto will_not_decode;
    case ISNS_ATTR_TAG_PORTAL_IP_ADDRESS:            goto ip;
    case ISNS_ATTR_TAG_PORTAL_PORT:                  goto port;
    case ISNS_ATTR_TAG_PORTAL_SYMBOLIC_NAME:         goto string;
    case ISNS_ATTR_TAG_ESI_INTERVAL:                 goto seconds;
    case ISNS_ATTR_TAG_ESI_PORT:                     goto port;
    case ISNS_ATTR_TAG_PORTAL_GROUP:                 goto portal_group;
    case ISNS_ATTR_TAG_PORTAL_INDEX:                 goto identifier32;
    case ISNS_ATTR_TAG_SCN_PORT:                     goto port;
    case ISNS_ATTR_TAG_PORTAL_NEXT_INDEX:            goto identifier32;
    case ISNS_ATTR_TAG_PORTAL_SECURITY_BITMAP:       goto portal_security_bitmap;
    case ISNS_ATTR_TAG_PORTAL_ISAKMP_PHASE_1:        goto will_not_decode;
    case ISNS_ATTR_TAG_PORTAL_ISAKMP_PHASE_2:        goto will_not_decode;
    case ISNS_ATTR_TAG_PORTAL_CERTIFICATE:           goto will_not_decode;
    case ISNS_ATTR_TAG_ISCSI_NAME:                   goto string;
    case ISNS_ATTR_TAG_ISCSI_NODE_TYPE:              goto iscsi_node_type;
    case ISNS_ATTR_TAG_ISCSI_ALIAS:                  goto string;
    case ISNS_ATTR_TAG_ISCSI_SCN_BITMAP:             goto iscsi_scn_bitmap;
    case ISNS_ATTR_TAG_ISCSI_NODE_INDEX:             goto identifier32;
    case ISNS_ATTR_TAG_WWNN_TOKEN:                   goto identifier64;
    case ISNS_ATTR_TAG_ISCSI_NODE_NEXT_INDEX:        goto identifier32;
    case ISNS_ATTR_TAG_ISCSI_AUTH_METHOD:            goto string;
    case ISNS_ATTR_TAG_ISCSI_NODE_CERTIFICATE:       goto will_not_decode;
    case ISNS_ATTR_TAG_FC_PORT_NAME_WWPN:            goto identifier64;
    case ISNS_ATTR_TAG_PORT_ID:                      goto identifier24;
    case ISNS_ATTR_TAG_FC_PORT_TYPE:                 goto will_not_decode;
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
    case ISNS_ATTR_TAG_SYMBOLIC_PORT_NAME:           goto string;
    case ISNS_ATTR_TAG_FABRIC_PORT_NAME:             goto identifier64;
    case ISNS_ATTR_TAG_HARD_ADDRESS:                 goto identifier24;
    case ISNS_ATTR_TAG_PORT_IP_ADDRESS:              goto ip;
    case ISNS_ATTR_TAG_CLASS_OF_SERVICE:             goto will_not_decode;
	/*
	  bit 29             Fibre Channel Class 2 Supported
	  bit 28             Fibre Channel Class 3 Supported
	*/
    case ISNS_ATTR_TAG_FC4_TYPES:                    goto will_not_decode;
    case ISNS_ATTR_TAG_FC4_DESCRIPTOR:               goto string;
    case ISNS_ATTR_TAG_FC4_FEATURES:                 goto will_not_decode;
    case ISNS_ATTR_TAG_IFCP_SCN_BITMAP:              goto will_not_decode;
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
    case ISNS_ATTR_TAG_PORT_ROLE:                    goto will_not_decode;
	/*
	  bit 29              Control 
	  bit 30              FCP Initiator 
	  bit 31 (Lsb)        FCP Target 
	*/
    case ISNS_ATTR_TAG_PERMANENT_PORT_NAME:          goto identifier64;
    case ISNS_ATTR_TAG_PORT_CERTIFICATE:             goto will_not_decode;
    case ISNS_ATTR_TAG_FC4_TYPE_CODE:                goto will_not_decode;
	/* 8bit type code in byte0 */
    case ISNS_ATTR_TAG_FC_NODE_NAME_WWNN:            goto identifier64;
    case ISNS_ATTR_TAG_SYMBOLIC_NODE_NAME:           goto string;
    case ISNS_ATTR_TAG_NODE_IP_ADDRESS:              goto ip;
    case ISNS_ATTR_TAG_NODE_IPA:                     goto identifier64;
    case ISNS_ATTR_TAG_NODE_CERTIFICATE:             goto will_not_decode;
    case ISNS_ATTR_TAG_PROXY_ISCSI_NAME:             goto string;
    case ISNS_ATTR_TAG_SWITCH_NAME:                  goto identifier64;
    case ISNS_ATTR_TAG_PREFERRED_ID:                 goto identifier32;
    case ISNS_ATTR_TAG_ASSIGNED_ID:                  goto identifier32;
    case ISNS_ATTR_TAG_VIRTUAL_FABRIC_ID:            goto string;
    case ISNS_ATTR_TAG_VENDOR_OUI:                   goto identifier32;
    case ISNS_ATTR_TAG_DD_SET_ID:                    goto identifier32;
    case ISNS_ATTR_TAG_DD_SET_SYMBOLIC_NAME:         goto string;
    case ISNS_ATTR_TAG_DD_SET_STATUS:                goto dd_set_status;
    case ISNS_ATTR_TAG_DD_SET_NEXT_ID:               goto identifier32;
    case ISNS_ATTR_TAG_DD_ID:                        goto identifier32;
    case ISNS_ATTR_TAG_DD_SYMBOLIC_NAME:             goto string;
    case ISNS_ATTR_TAG_DD_MEMBER_ISCSI_INDEX:        goto identifier32;
    case ISNS_ATTR_TAG_DD_MEMBER_ISCSI_NAME:         goto string;
    case ISNS_ATTR_TAG_DD_MEMBER_IFCP_NODE:          goto identifier32;
    case ISNS_ATTR_TAG_DD_MEMBER_PORTAL_INDEX:       goto identifier32;
    case ISNS_ATTR_TAG_DD_MEMBER_PORTAL_IP_ADDRESS:  goto ip;
    case ISNS_ATTR_TAG_DD_MEMBER_PORTAL_PORT:        goto port;
    case ISNS_ATTR_TAG_DD_FEATURES:                  goto dd_features;
    case ISNS_ATTR_TAG_DD_ID_NEXT_ID:                goto identifier32;
    }

identifier24:
    /* 24-bit identifier (least significant 3 bytes) */
identifier64:
none:
    goto end;

identifier32:
    {
	guint32 i = tvb_get_ntohl(tvb, offset + 8);
	proto_tree_add_uint(tt,	hf_isns_attr_index, tvb, offset + 8, len, i);
	goto end;
    }
    goto end;

dd_features:
    /*
      31 (Lsb)      Boot List Enabled (1)/Boot List Disabled (0) 
    */
    goto end;

dd_set_status:
    /*
      31 (Lsb)      DDS Enabled (1) / DDS Disabled (0) 
    */
    goto end;

iscsi_scn_bitmap:
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
    {
	/*FLAGS*/
	proto_item *tscn_bitmap;
	proto_item *scn_bitmap_item;
	guint32 scn_bitmap = tvb_get_ntohl(tvb, offset + 8);

	scn_bitmap_item = proto_tree_add_uint(tt, hf_isns_scn_bitmap, tvb, offset+8, 4, scn_bitmap);
	tscn_bitmap = proto_item_add_subtree(scn_bitmap_item, ett_scn_bitmap);

	proto_tree_add_boolean(tt, hf_isns_scn_bitmap_initiator_and_self_information_only, tvb, offset+8, 4, scn_bitmap);
	proto_tree_add_boolean(tt, hf_isns_scn_bitmap_target_and_self_information_only,    tvb, offset+8, 4, scn_bitmap);
	proto_tree_add_boolean(tt, hf_isns_scn_bitmap_management_registration_scn,         tvb, offset+8, 4, scn_bitmap);
	proto_tree_add_boolean(tt, hf_isns_scn_bitmap_object_removed,                      tvb, offset+8, 4, scn_bitmap);
	proto_tree_add_boolean(tt, hf_isns_scn_bitmap_object_added,                        tvb, offset+8, 4, scn_bitmap);
	proto_tree_add_boolean(tt, hf_isns_scn_bitmap_object_updated,                      tvb, offset+8, 4, scn_bitmap);
	proto_tree_add_boolean(tt, hf_isns_scn_bitmap_dd_dds_member_removed,               tvb, offset+8, 4, scn_bitmap);
	proto_tree_add_boolean(tt, hf_isns_scn_bitmap_dd_dds_member_added,                 tvb, offset+8, 4, scn_bitmap);
    }
    goto end;

iscsi_node_type:
    {
	proto_item *tisnt;
	proto_item *isnt_item;
	guint32 isnt = tvb_get_ntohl(tvb, offset + 8);

	isnt_item = proto_tree_add_uint(tt, hf_isns_isnt, tvb, offset+8, 4, isnt);
	tisnt = proto_item_add_subtree(isnt_item, ett_isns_isnt);

	proto_tree_add_boolean(tisnt, hf_isns_isnt_control,   tvb, offset+8, 4, isnt);
	proto_tree_add_boolean(tisnt, hf_isns_isnt_initiator, tvb, offset+8, 4, isnt);
	proto_tree_add_boolean(tisnt, hf_isns_isnt_target,    tvb, offset+8, 4, isnt);
    }
    goto end;

portal_security_bitmap:
    {
	proto_item *tpsb;
	proto_item *psb_item;
	guint32 psb = tvb_get_ntohl(tvb, offset + 8);

	psb_item = proto_tree_add_uint(tt, hf_isns_psb, tvb, offset+8, 4, psb);
	tpsb = proto_item_add_subtree(psb_item, ett_isns_psb);

	proto_tree_add_boolean(tpsb, hf_isns_psb_tunnel_mode,     tvb, offset+8, 4, psb);
	proto_tree_add_boolean(tpsb, hf_isns_psb_transport_mode,  tvb, offset+8, 4, psb);
	proto_tree_add_boolean(tpsb, hf_isns_psb_pfs,             tvb, offset+8, 4, psb);
	proto_tree_add_boolean(tpsb, hf_isns_psb_aggressive_mode, tvb, offset+8, 4, psb);
	proto_tree_add_boolean(tpsb, hf_isns_psb_main_mode,       tvb, offset+8, 4, psb);
	proto_tree_add_boolean(tpsb, hf_isns_psb_ike_ipsec,       tvb, offset+8, 4, psb);
	proto_tree_add_boolean(tpsb, hf_isns_psb_bitmap,          tvb, offset+8, 4, psb);
    }
    goto end;

portal_group:
    /*
      16bit portal group identifier - least significant
    */
    goto end;

version_range:
    /*
      16bit minimum protocol supported - least significant
      16bit maximum protocol supported - most significant
    */
    goto end;

entity_protocol:
    proto_tree_add_uint(tt,hf_isns_entity_protocol, tvb, offset + 8, len, tag);
    goto end;

string:
    proto_tree_add_item(tt,hf_isns_attr_string, tvb, offset + 8, len, FALSE);
    goto end;

ip:
    proto_tree_add_item(tt,hf_isns_attr_ipaddr, tvb, offset + 8, len, FALSE);
    goto end;

seconds:
    {
	guint32 i = tvb_get_ntohl(tvb, offset + 8);

	proto_tree_add_uint(tt,	hf_isns_attr_seconds, tvb, offset + 8, 4, i);
	goto end;
    }

port:
    {
	proto_item *tport;
	proto_item *port_item;
	guint32 port = tvb_get_ntohl(tvb, offset + 8);
	guint16 port_type = tvb_get_ntohl(tvb, offset + 8);
	guint16 port_port = tvb_get_ntohl(tvb, offset + 10);

	port_item = proto_tree_add_uint(tt, hf_isns_port, tvb, offset+8, 4, port);
	tport = proto_item_add_subtree(port_item, ett_isns_port);

	proto_tree_add_boolean(tport, hf_isns_port_type, tvb, offset+8, 2, port_port);
	proto_tree_add_uint(tport,hf_isns_port_port, tvb, offset+10, 2, port_type);
    }
    goto end;

will_not_decode:
    goto end;

end:



    
    /* move on the offset to next attribute */
    

    return (8 + len);    
}



/* Register the protocol with Ethereal */

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
	    FT_BOOLEAN, 16, TFS(&isns_flag_client), 0x8000, /* bit 16 */
	    "iSNS Client" ,HFILL}
	},
	{ &hf_isns_server,
	  { "Server    ","isns.flags.server",
	    FT_BOOLEAN, 16, TFS(&isns_flag_server), 0x4000, /* bit 17 */
	    "iSNS Server" ,HFILL}
	},
	{ &hf_isns_replace,
	  { "Replace   ","isns.flags.replace",
	    FT_BOOLEAN, 16, TFS(&isns_flag_replace), 0x1000, /* bit 19 */
	    "iSNS Replace" ,HFILL}
	},
	{ &hf_isns_last_pdu,
	  { "Last PDU  ","isns.flags.lastpdu",
	    FT_BOOLEAN, 16, TFS(&isns_flag_last_pdu), 0x0800, /* bit 20 */
	    "iSNS Last PDU" ,HFILL}
	},
	{ &hf_isns_first_pdu,
	  { "First PDU ","isns.flags.firstpdu",
	    FT_BOOLEAN, 16, TFS(&isns_flag_first_pdu), 0x0400, /* bit 21 */
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
	    FT_UINT32, BASE_DEC,TFS(isns_entity_protocol),0,
	    "iSNS Entity Protocol" ,HFILL}
	},
	/* The Payload stuff */

	{ &hf_isns_port,
	  { "Port","isns.port",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "Port", HFILL }
	},

	{ &hf_isns_port_type,
	  { "Port Type","isns.port.port_type",
	    FT_BOOLEAN, 16, TFS(&isns_port_type), 0x01, /* bit 15 (or bit 1 of a 16bit word) */
	    "Port Type",HFILL }
	},

	{ &hf_isns_port_port,
	  { "Port","isns.port.port",
	    FT_UINT16, BASE_DEC, NULL, 0,
	    "Port", HFILL }
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


	{ &hf_isns_isnt,
	  { "iSCSI Node Type","isns.isnt",
	    FT_UINT32, BASE_HEX, NULL, 0,
	    "iSCSI Node Type", HFILL }
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

	{ &hf_isns_attr_payload,
	  { "Attribute Payload","isns.attr.payload",
	    FT_BYTES, BASE_HEX,NULL,0,
	    "iSNS Attribute Payload" ,HFILL}
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

	{ &hf_isns_attr_string,
	  { "Attribute String","isns.attrstring",
	    FT_STRING, BASE_NONE, NULL, 0x0,
	    "String", HFILL }},

	{ &hf_isns_attr_ipaddr,
	  { "Attribute IP Address","isns.ipv4",
	    FT_IPv6, BASE_NONE, NULL, 0x0,
	    "IPv6 Address", HFILL }},

	{ &hf_isns_attr_index,
	  { "Index","isns.index",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Index", HFILL }},

	{ &hf_isns_attr_seconds,
	  { "Seconds","isns.seconds",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    "Seconds", HFILL }},

	
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
	&ett_isns_port,
	&ett_isns_psb,
	&ett_isns_isnt,
	&ett_scn_bitmap
    };

/* Register the protocol name and description */
    proto_isns = proto_register_protocol("iSNS",
					 "iSNS", "isns");

    proto_register_field_array(proto_isns, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));

}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/

void
proto_reg_handoff_isns(void)
{
    dissector_handle_t isns_handle;
    isns_handle = new_create_dissector_handle(dissect_isns,proto_isns);
    dissector_add("udp.port",ISNS_UDP_PORT,isns_handle);
    dissector_add("tcp.port",ISNS_TCP_PORT,isns_handle);
}
