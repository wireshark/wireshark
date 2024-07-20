/* packet-wassp.c
 * Routines for the disassembly of the Chantry/Enterasys/ExtremeNetworks AP-Controller
 * tunneling protocol.
 *
 * By Zhong Wei Situ <zsitu@extremenetworks.com>
 * Copyright 2019 Extreme Networks
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
  https://tools.ietf.org/html/draft-singh-capwap-ctp-02
  looks very similar (but not always identical).

  AC: Access Controller
  MU: Mobile Unit (Wireless client)
  RU: Radio Unit (Access point)

 */

#include "config.h"
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>


#define PROTO_SHORT_NAME "WASSP"
#define PROTO_LONG_NAME "Wireless Access Station Session Protocol"
#define LBS_HDR_MAGIC 0x7c83
#define MU_NETFLOW_RECORD_SIZE 46
#define WASSP_SNMP 161

/* TLV structure offsets. */
#define TLV_TYPE 0
#define TLV_LENGTH 2
#define TLV_VALUE 4

/* header lengths */
#define WASSP_HDR_LEN 8
#define RU_HEADER_WITH_MAC_LEN 16
#define RU_HEADER_WITHOUT_MAC_LEN 12
#define WASSP_MU_HDR_LEN 14

/* WASSP header offsets in bytes */
#define WASSP_HDR_VERSION 0
#define WASSP_HDR_TYPE 1
#define WASSP_HDR_SEQ_NUM 2
#define WASSP_HDR_FLAGS 3
#define WASSP_HDR_SESSIONID 4
#define WASSP_HDR_PLENGTH 6


/* RU Discover header offsets in bytes */
#define RU_HDR_VERSION 0
#define RU_HDR_TYPE 1
#define RU_HDR_RAD_NUM 2
#define RU_HDR_LENGTH 4
#define RU_HDR_CHECKSUM 6
#define RU_HDR_AC_OP 8
#define RU_HDR_MAC  10
#define RU_HDR_AC_MODE  10


#define RU_HDR_CONTAIN_MAC 1
/* MU NetFlow header offsets in bytes */
#define MU_NETFLOW_HDR_VERSION 0
#define MU_NETFLOW_HDR_LENGTH 2
#define MU_NETFLOW_HDR_FLAG 4
#define MU_NETFLOW_HDR_UPTIME 6

#define MU_NETFLOW_HEADER_TOTAL_LENGTH 10


/* WASSP MU header offsets in bytes */
#define WASSP_MU_HDR_TYPE 0
#define WASSP_MU_HDR_QOS 1
#define WASSP_MU_HDR_ACTION_SSID 2
#define WASSP_MU_HDR_MAC 4
#define WASSP_MU_HDR_RESV_0 10
#define WASSP_MU_HDR_RESV_1 12
#define WASSP_MU_HDR_WITH_ASSO_STATUS_LEN 15
#define WASSP_MU_HDR_WITHOUT_ASSO_STATUS_LEN 14

#define RU_WASSP_FLAGS_MORE_FRAGMENTS_FOLLOWING 0x01
#define RU_WASSP_FLAGS_NOT_FIRST_FRAGMENT       0x04
#define RU_WASSP_FLAGS_USE_FRAGMENTATION        0x08
#define RU_WASSP_FLAGS                          0x3f

#define RU_DISCOVER_OP_MODE 1
#define WASSP_MOBILITY 0x10
#define WASSP_DATA_FRAGMENT 0x2

/* Define WASSP UDP port */
#define UDP_PORT_WASSP 13910
#define PORT_WASSP_DISCOVER 13907
#define PORT_WASSP_RANGE "13907,13910" /* Not IANA registered */

#define WASSP_DATA_FRAGMENT_BIT 0x2



typedef struct   tlv_mac_add
{
	uint16_t tlvType ;
	uint16_t tlvLen;
	uint8_t   tlvMac[6/* MAC_ADDR_SIZE */];
}  TLV_MAC_ADD;
#define TLV_MAC_ADD_SIZE sizeof (TLV_MAC_ADD)




typedef struct
{
	uint16_t     tlvType;
	uint16_t     tlvLen;
	TLV_MAC_ADD  tlvMacAddress;
	uint32_t     radioId;
} TLV_RADIO_BLOCK;


typedef struct tlvVnsBlock
{
	uint16_t     tlvType;
	uint16_t     tlvLen;
	uint32_t     radioId;
	uint32_t     bssidId;
	uint32_t     ssidId;
} TLV_VNS_BLOCK;


typedef struct
{
	TLV_MAC_ADD           tlvMacAddress;
	TLV_RADIO_BLOCK       tlvRadioB[2];
	TLV_VNS_BLOCK         tlvVnsB[16];
} tlvSsiddBssidMap;




/* @*@ */
typedef struct
{
	uint16_t   tlvId;
	char     *name;
	uint16_t   type;
	uint16_t   length;
#define WASSP_TAB_IDX length
	uint32_t   (*parseFunc)(void);
	uint32_t   (*setFunc)(void);
	uint32_t   offset;
	uint8_t    flags;
	uint32_t   minValue;
	uint32_t   maxValue;
	uint32_t   (*customCheckFunc)(void);
} TLV_PARSER_ENTRY;

/* @*@ */
#define TLV_TYPE_UNKNOWN         0
#define TLV_TYPE_STRING          1  //- PW_TYPE_STRING
#define TLV_TYPE_INT             2  //- PW_TYPE_INTEGER
#define TLV_TYPE_UINT            3  //- PW_TYPE_INTEGER
#define TLV_TYPE_BOOL            4  //- PW_TYPE_INTEGER
#define TLV_TYPE_OCTETS          5  //- PW_TYPE_OCTETS
#define TLV_TYPE_MACADD          6  //- PW_TYPE_MACADD
#define TLV_TYPE_BLOCK_TLV       7
#define TLV_TYPE_INDEX           8  //- PW_TYPE_INTEGER
#define TLV_TYPE_IP_ADDR         9  //- PW_TYPE_INTEGER

typedef enum
{
	CONFIG_GLOBAL_BLOCK,
	CONFIG_ERROR_BLOCK,
	TAB_CONFIG_MODIFIED,
	RADIO_CONFIG_BLOCK,
	VNS_CONFIG_BLOCK,
	MU_RF_STATS_BLOCK,
	AP_STATS_BLOCK,
	STATS_MU_BLOCK,
	TAB_STATS_RADIO,
	TAB_STATS_ETH,
	TAB_STATS_WDS,
	TAB_STATS_DOT1x,
	TAB_CONFIG_FILTER,
	TAB_STATS_VNS,
	TAB_CONFIG_RADIUS_SERVER,
	TAB_CONFIG_SITE,
	TAB_CONFIG_POLICY,
	TAB_CONFIG_COS,
	TAB_CONFIG_LOC_BASE_LP,
	TAB_CONFIG_RADIUS,
	EVENT_BLOCK,
	TAB_SSS_MU_BLOCK,
	TAB_EID_MU_BLOCK,
	BULK_MU_BLOCK,
	MU_BLOCK,
	BULK_VNS_BLOCK,
	VNS_BLOCK,
	TAB_SIAPP_PMK_BLOCK,
	TAB_SIAPP_RADIO_CONFIG_BLOCK,
	TAB_SIAPP_MU_STATS_BLOCK,
	TAB_SIAPP_THIN_BLOCK,
	TAB_SIAPP_BLOCK,
	TAB_ASSOC_SSID_ARRAY,
	TAB_ASSOC_SSID_BLOCK,
	TAB_AP_LIST_BLOCK,
	TAB_AP_LIST_ARRAY,
	TAB_SCAN_PROFILE_BLOCK,
	TAB_THREAT_DEF_ARRAY,
	TAB_THREAT_DEF_BLOCK,
	TAB_THREAT_PATTERN_ARRAY,
	TAB_THREAT_PATTERN_BLOCK,
	TAB_SURVEILLANCE_DATA_ARRAY,
	TAB_SURVEILLANCE_DATA_BLOCK,
	TAB_THREAT_DATA_ARRAY,
	TAB_THREAT_DATA_BLOCK,
	TAB_THREAT_CLASSIFY_ARRAY,
	TAB_THREAT_CLASSIFY_BLOCK,
	TAB_USER_CLASSIFY_ARRAY,
	TAB_USER_CLASSIFY_BLOCK,
	TAB_MU_EVENT_ARRAY,
	TAB_MU_EVENT_BLOCK,
	TAB_COUNTRY_ARRAY,
	TAB_COUNTRY_BLOCK,
	TAB_LOCATOR_LOC_BLOCK,
	TAB_LOCATOR_LOC_ARRAY,
	TAB_RSS_DATA_ARRAY,
	TAB_RSS_DATA_BLOCK,
	TAB_MCAST_FILTER_BLOCK,
	TAB_MCAST_FILTER_BLOCK_ENTRY,
	TAB_MU_SESSION_ARRAY,
	TAB_MU_SESSION_BLOCK,
	TAB_DETECTED_ROGUE_ARRAY,
	TAB_DETECTED_ROGUE_BLOCK,
	TAB_FILTER_RULES_EXT_BLOCK,
	TAB_APP_POLICY_FIXED_BLOCK,
	TAB_V_FILTER_RULES_EXT_BLOCK,
	TAB_V_SITE_FILTER_RULES_EXT_BLOCK,
	TAB_APP_POLICY_ENTRY_BLOCK,
	TAB_11U_ANQP_BLOCK,
	TAB_HS2_BLOCK,
	TAB_RU_ACK_RADIO_CONFIG,
	TAB_MU_APPL_STATS_BLOCK,
	TAB_EXTAPP_CONF_BLOCK,
	TAB_V_CP_CONFIG_BLOCK,
	TAB_TOPOLOGY_ARRAY_BLOCK,
	TAB_TOPOLOGY_STRUCT_BLOCK,
	TAB_FILTER_CONFIG_STRUCT_BLOCK,
	TAB_S_TOPOLOGY_ARRAY_BLOCK,
	TAB_S_TOPOLOGY_STRUCT_BLOCK,
	TAB_S_TOPO_MCAST_FILTER_CONFIG_BLOCK,
	TAB_S_TOPO_MCAST_FILTER_RULES_EXT_BLOCK,
	TAB_NAC_SERVER_CONFIG_ARRAY,
	TAB_NAC_SERVER_CONFIG_BLOCK,
	TAB_NAC_WEB_AUTH_USER_GROUP_ARRAY,
	TAB_NAC_WEB_AUTH_USER_GROUP_BLOCK,

	TAB_MAX
} WASSP_SUBTLV_TAB_e;


/* Wassp RU Message/Header Types */
typedef enum
{
	WASSP_RU_UNUSED_0 = 0,
	WASSP_RU_Discov,                           // 1
	WASSP_RU_Register_Req,                     // 2
	WASSP_RU_Register_Rsp,                     // 3
	WASSP_RU_Authentication_Req,               // 4
	WASSP_RU_Authentication_Rsp,               // 5
	WASSP_RU_SW_Version_Validate_Req,          // 6
	WASSP_RU_SW_Version_Validate_Rsp,          // 7
	WASSP_RU_Config_Req,                       // 8
	WASSP_RU_Config_Rsp,                       // 9
	WASSP_RU_Ack,                              // 10
	WASSP_RU_Config_Status_Notify,             // 11
	WASSP_RU_Set_State_Req,                    // 12
	WASSP_RU_Set_State_Rsp,                    // 13
	WASSP_RU_Stats_Notify,                     // 14
	WASSP_Data,                                // 15
	WASSP_RU_Poll,                             // 16
	WASSP_RU_SNMP_Req,                         // 17
	WASSP_RU_SNMP_Rsp,                         // 18
	WASSP_BP_Trap_Notify,                      // 19
	WASSP_BP_Scan_Req,                         // 20
	WASSP_RFM_Notify,                          // 21
	WASSP_RU_SNMP_Alarm_Notify,                // 22
	WASSP_RU_SNMP_Set_Alarm_Clear,             // 23
	WASSP_RU_SNMP_Set_Log_Status,              // 24
	WASSP_RU_SNMP_Get_Log_Req,                 // 25
	WASSP_RU_SNMP_Get_Log_Resp,                // 26
	WASSP_SEC_Update_Notify,                   // 27
	WASSP_RU_STATS_Req,                        // 28
	WASSP_RU_STATS_Rsp,                        // 29
	WASSP_RU_UNUSED_30,                        // 30
	WASSP_RU_UNUSED_31,                        // 31
	WASSP_RU_Get_Req,                          // 32
	WASSP_RU_Get_Rsp,                          // 33
	WASSP_RU_Alarm_Notify,                     // 34
	WASSP_RU_Set_Alarm_Clear,                  // 35
	WASSP_RU_Get_Log_Req,                      // 36
	WASSP_RU_Get_Log_Rsp,                      // 37
	WASSP_RU_UNUSED_38,                        // 38
	WASSP_RU_UNUSED_39,                        // 39
	WASSP_P_PEER_DOWN_NOTIFY,                  // 40
	WASSP_P_LINK_STATE_CHANGE_REQ,             // 41
	WASSP_P_LINK_STATE_CHANGE_RSP,             // 42
	WASSP_RU_AC_Poll,                          // 43
	WASSP_RU_GetIP_Req,                        // 44
	WASSP_RU_GetIP_Rsp,                        // 45
	WASSP_RU_LAMG_Update_Req,                  // 46
	WASSP_RU_LAMG_Update_Rsp,                  // 47
	WASSP_RU_Event_Req,                        // 48
	WASSP_RU_Event_Rsp,                        // 49
	WASSP_RU_BULK_MU_UPDATE_REQ,               // 50
	WASSP_RU_BULK_MU_UPDATE_RSP,               // 51
	WASSP_ROAMED_MU_FILTER_STATS_REQ,          // 52
	WASSP_ROAMED_MU_FILTER_STATS_RESP,         // 53
	WASSP_RU_UNUSED_54,                        // 54
	WASSP_LBS_TAG_REPORT,                      // 55
	WASSP_RU_AC_Event_Req,                     // 56
	WASSP_RU_AC_Event_Rsp,                     // 57
	WASSP_RU_Event_Notify,                     // 58
	WASSP_RU_AC_EVENT,                         // 59
	WASSP_WIDS_WIPS_Config_Req,                // 60
	WASSP_WIDS_WIPS_Config_Rsp,                // 61
	WASSP_Scan_Data_Notify,                    // 62
	WASSP_Scan_Data_Notify_Ack,                // 63
	WASSP_Loc_Data_Notify,                     // 64
	WASSP_Loc_Data_Notify_Ack,                 // 65
	WASSP_RU_SW_Version_Validate_Ack,          // 66
	WASSP_NEIGHBOUR_STATS_Rsp,                 // 67
	WASSP_APPL_STATS_RESP,                     // 68
	WASSP_RU_Capture_Req,                      // 69
	WASSP_RU_Capture_Rsp,                      // 70
	/* AC/AC tunneling */
	WASSP_AC_Register_Req = 101,               // 101
	WASSP_AC_Register_Rsp,                     // 102
	WASSP_AC_Deregister_Req,                   // 103
	WASSP_AC_Deregister_Rsp,                   // 104

	WASSP_P_MAX

} wassp_ru_msg_t;





/* Value string object enumerates wassp header type field */
static const value_string wassp_header_types[] =
{
	{ WASSP_RU_UNUSED_0, "WASSP Reserved 0"},
	{ WASSP_RU_Discov, "WASSP RU Discover"},
	{ WASSP_RU_Register_Req, "RU Registration Request"},
	{ WASSP_RU_Register_Rsp, "RU Registration Response"},
	{ WASSP_RU_Authentication_Req, "RU Authentication Request"},
	{ WASSP_RU_Authentication_Rsp, "RU Authentication Response"},
	{ WASSP_RU_SW_Version_Validate_Req, "RU Software Version Report"},
	{ WASSP_RU_SW_Version_Validate_Rsp, "RU Software Version Command"},
	{ WASSP_RU_Config_Req, "RU Configuration Request"},
	{ WASSP_RU_Config_Rsp, "RU Configuration Response"},
	{ WASSP_RU_Ack, "RU Acknowledge"},
	{ WASSP_RU_Config_Status_Notify, "RU Configuration Status Notify"},
	{ WASSP_RU_Set_State_Req, "RU Set State Request"},
	{ WASSP_RU_Set_State_Rsp, "RU Set State Response"},
	{ WASSP_RU_Stats_Notify, "RU Statistics Notify"},
	{ WASSP_Data, "WASSP Data"},
	{ WASSP_RU_Poll, "RU Poll"},
	{ WASSP_RU_SNMP_Req, "SNMP Request"},
	{ WASSP_RU_SNMP_Rsp, "SNMP Response"},
	{ WASSP_BP_Trap_Notify, "BP Trap Notify"},
	{ WASSP_BP_Scan_Req, "BP Trap Notify"},
	{ WASSP_RFM_Notify, "RFM Notify"},
	{ WASSP_RU_SNMP_Alarm_Notify, "RU SNMP Alarm Notify"},
	{ WASSP_RU_SNMP_Set_Alarm_Clear, "RU SNMP Set Alarm"},
	{ WASSP_RU_SNMP_Set_Log_Status, "RU SNMP Set Log Status"},
	{ WASSP_RU_SNMP_Get_Log_Req, "RU SNMP Get Log Request"},
	{ WASSP_RU_SNMP_Get_Log_Resp, "RU SNMP Get Log Response"},
	{ WASSP_SEC_Update_Notify, "SEC Update Notify"},
	{ WASSP_RU_STATS_Req, "RU Statistics Request"},
	{ WASSP_RU_STATS_Rsp, "RU Statistics Response"},
	{ WASSP_RU_UNUSED_30, "WASSP MU Statistics Request" },
	{ WASSP_RU_UNUSED_31, "WASSP MU Statistics Response" },
	{ WASSP_RU_Get_Req, "Dot1x Get Request"},
	{ WASSP_RU_Get_Rsp, "Dot1x Get Response"},
	{ WASSP_RU_Alarm_Notify, "RU Alarm Notify"},
	{ WASSP_RU_Set_Alarm_Clear, "RU Set Alarm Clear"},
	{ WASSP_RU_Get_Log_Req, "RU Get Log Request"},
	{ WASSP_RU_Get_Log_Rsp, "RU Get Log Response"},
	{ WASSP_RU_UNUSED_38, "WASSP UNUSED 38"},
	{ WASSP_RU_UNUSED_39, "WASSP UNUSED 39"},
	{ WASSP_P_PEER_DOWN_NOTIFY, "Availability Peer Controller down Notify"},
	{ WASSP_P_LINK_STATE_CHANGE_REQ, "Availability Peer Controller Link State Change Request"},
	{ WASSP_P_LINK_STATE_CHANGE_RSP, "Availability Peer Controller Link State Change Response"},
	{ WASSP_RU_AC_Poll, "RU Poll Controller"},
	{ WASSP_RU_GetIP_Req, "RU Get IP Request"},
	{ WASSP_RU_GetIP_Rsp, "RU Get IP Response"},
	{ WASSP_RU_LAMG_Update_Req, "WASSP reserved"},
	{ WASSP_RU_LAMG_Update_Rsp, "WASSP reserved"},
	{ WASSP_RU_Event_Req, "RU Event Request"},
	{ WASSP_RU_Event_Rsp, "RU Event Response"},
	{ WASSP_RU_BULK_MU_UPDATE_REQ, "RU Bulk MUs Update Request"},
	{ WASSP_RU_BULK_MU_UPDATE_RSP, "RU Bulk MUs Update Response"},
	{ WASSP_ROAMED_MU_FILTER_STATS_REQ, "Roamed MU Filter Statistics Request"},
	{ WASSP_ROAMED_MU_FILTER_STATS_RESP, "Roamed MU Filter Statistics Response"},
	{ WASSP_RU_UNUSED_54, "WASSP reserved"},
	{ WASSP_LBS_TAG_REPORT, "Location Base Service Tag Report"},
	{ WASSP_RU_AC_Event_Req, "RU Alarm Clear Event Request"},
	{ WASSP_RU_AC_Event_Rsp, "RU Alarm Clear Event Response"},
	{ WASSP_RU_Event_Notify, "RU Event Notify"},
	{ WASSP_RU_AC_EVENT, "RU Alarm Clear Event"},
	{ WASSP_WIDS_WIPS_Config_Req, "WIDS WIPS Configuration Request"},
	{ WASSP_WIDS_WIPS_Config_Rsp, "WIDS WIPS Configuration Response"},
	{ WASSP_Scan_Data_Notify, "Scan Data Notify"},
	{ WASSP_Scan_Data_Notify_Ack, "Scan Data Notify Acknowledge"},
	{ WASSP_Loc_Data_Notify, "Location Data Notify"},
	{ WASSP_Loc_Data_Notify_Ack, "Location Data Notify Acknowledge"},
	{ WASSP_RU_SW_Version_Validate_Ack, "RU Software Version Validate Acknowledge"},
	{ WASSP_NEIGHBOUR_STATS_Rsp, "Neighbor Statistics Response"},
	{ WASSP_APPL_STATS_RESP, "Application Statistics Response"},
	{ WASSP_RU_Capture_Req, "RU Capture Request"},
	{ WASSP_RU_Capture_Rsp, "RU Capture Response"},
	/* AC/AC tunneling */
	{ WASSP_AC_Register_Req, "Tunnel Register Request"},
	{ WASSP_AC_Register_Rsp, "Tunnel Register Response"},
	{ WASSP_AC_Deregister_Req, "Tunnel Deregister Request"},
	{ WASSP_AC_Deregister_Rsp, "Tunnel deregister Response"},
	{ 0, NULL }
};



/* Wassp MU Header Types */
typedef enum
{
	WASSP_MU_UNUSED_0 = 0,
	WASSP_MU_Associate_Req,           //  1
	WASSP_MU_Associate_Rsp,           //  2
	WASSP_MU_Data,                    //  3
	WASSP_MU_Disconnect_Req,          //  4
	WASSP_MU_Disconnect_Rsp,          //  5
	WASSP_MU_Roam_Notify,             //  6
	WASSP_MU_Disconnect_Notify,       //  7
	WASSP_MU_INVALID_PMK_REQ,         //  8
	WASSP_MU_Update_Req,              //  9
	WASSP_MU_Update_Rsp,              //  10
	WASSP_MU_MIRRORN,                 //  11
	WASSP_MU_NETFLOW,                 //  12
	WASSP_MU_Radius_Update,           //  13
	WASSP_AP2AC_MU_Inform_Req,        //  14
	WASSP_AP2AC_MU_Inform_Rsp,        //  15
	WASSP_MU_Eap_Last,                //  16
	WASSP_MU_PMIRROR,                 //  17
	WASSP_MU_UNUSED_18,               //  18
	WASSP_MU_UNUSED_19,               //  19
	WASSP_MU_UNUSED_20,               //  20
	WASSP_MU_UNUSED_21,               //  21
	WASSP_MU_UNUSED_22,               //  22
	WASSP_MU_UNUSED_23,               //  23
	WASSP_MU_UNUSED_24,               //  24
	WASSP_MU_UNUSED_25,               //  25
	WASSP_MU_UNUSED_26,               //  26
	WASSP_MU_UNUSED_27,               //  27
	WASSP_MU_UNUSED_28,               //  28
	WASSP_MU_UNUSED_29,               //  29
	WASSP_MU_STATS_Req,               //  30
	WASSP_MU_STATS_Rsp,               //  31
	WASSP_MU_UNUSED_32,               //  32
	WASSP_MU_UNUSED_33,               //  33
	WASSP_MU_UNUSED_34,               //  34
	WASSP_MU_UNUSED_35,               //  35
	WASSP_MU_UNUSED_36,               //  36
	WASSP_MU_UNUSED_37,               //  37
	WASSP_MU_BULK_Associate_Req,      //  38
	WASSP_MU_BULK_Associate_Rsp       //  39


} wassp_mu_msg_t;

/* Value string object enumerates wassp mu header type field */
static const value_string wassp_mu_header_types[] =
{
	{ WASSP_MU_UNUSED_0, "MU Unused 0"},
	{ WASSP_MU_Associate_Req, "MU Association Request"},
	{ WASSP_MU_Associate_Rsp, "MU Association Response"},
	{ WASSP_MU_Data, "MU Data"},
	{ WASSP_MU_Disconnect_Req, "MU Disconnect Request"},
	{ WASSP_MU_Disconnect_Rsp, "MU Disconnect Response"},
	{ WASSP_MU_Roam_Notify, "MU Roam Notify"},
	{ WASSP_MU_Disconnect_Notify, "MU Disconnect Notify"},
	{ WASSP_MU_INVALID_PMK_REQ, "MU Invalid PMK Request"},
	{ WASSP_MU_Update_Req, "MU Update Request"},
	{ WASSP_MU_Update_Rsp, "MU Update Response"},
	{ WASSP_MU_MIRRORN, "MU Mirror N"},
	{ WASSP_MU_NETFLOW, "MU Netflow"},
	{ WASSP_MU_Radius_Update, "MU Radius Update"},
	{ WASSP_AP2AC_MU_Inform_Req, "AccessPoint To Controller MU Info Request"},
	{ WASSP_AP2AC_MU_Inform_Rsp, "AccessPoint To Controller MU Info Response"},
	{ WASSP_MU_Eap_Last, "MU Extensible Authentication Protocol Last"},
	{ WASSP_MU_PMIRROR, "MU P Mirror"},
	{ WASSP_MU_UNUSED_18, "MU Unused 18"},
	{ WASSP_MU_UNUSED_19, "MU Unused 19"},
	{ WASSP_MU_UNUSED_20, "MU Unused 20"},
	{ WASSP_MU_UNUSED_21, "MU Unused 21"},
	{ WASSP_MU_UNUSED_22, "MU Unused 22"},
	{ WASSP_MU_UNUSED_23, "MU Unused 23"},
	{ WASSP_MU_UNUSED_24, "MU Unused 24"},
	{ WASSP_MU_UNUSED_25, "MU Unused 25"},
	{ WASSP_MU_UNUSED_26, "MU Unused 26"},
	{ WASSP_MU_UNUSED_27, "MU Unused 27"},
	{ WASSP_MU_UNUSED_28, "MU Unused 28"},
	{ WASSP_MU_UNUSED_29, "MU Unused 29"},
	{ WASSP_MU_STATS_Req, "MU Statistics Request"},
	{ WASSP_MU_STATS_Rsp, "MU Statistics Response"},
	{ WASSP_MU_UNUSED_32, "MU Unused 32"},
	{ WASSP_MU_UNUSED_33, "MU Unused 33"},
	{ WASSP_MU_UNUSED_34, "MU Unused 34"},
	{ WASSP_MU_UNUSED_35, "MU Unused 35"},
	{ WASSP_MU_UNUSED_36, "MU Unused 36"},
	{ WASSP_MU_UNUSED_37, "MU Unused 37"},
	{ WASSP_MU_BULK_Associate_Req, "MU Bulk Associate Request"},
	{ WASSP_MU_BULK_Associate_Rsp, "MU Bulk Associate Response"},
	{ 0, NULL }
};







/*****************************************************
* Main TLVs
****************************************************/

/* TLV Header Types */
typedef enum
{
	EID_UNUSED_0 = 0,          //  0
	EID_STATUS,                //  1
	EID_RU_SW_VERSION,         //  2
	EID_RU_SERIAL_NUMBER,      //  3
	EID_RU_REG_CHALLENGE,      //  4
	EID_RU_REG_RESPONSE,       //  5
	EID_AC_IPADDR,             //  6
	EID_RU_VNSID,              //  7
	EID_TFTP_SERVER,           //  8
	EID_IMAGE_PATH,            //  9
	EID_CONFIG,                //  10
	EID_RU_STATE,              //  11
	EID_SESSION_KEY,           //  12
	EID_RU_PROTOCOL,           //  13
	EID_RANDOM_NUMBER,         //  14
	EID_STANDBY_TIMEOUT,       //  15
	EID_RU_CHALLENGE_ID,       //  16
	EID_RU_MODEL,              //  17
	EID_RU_SCAN_MODE,          //  18
	EID_RU_SCAN_TYPE,          //  19
	EID_RU_SCAN_INTERVAL,      //  20
	EID_RU_RADIO_TYPE,         //  21
	EID_RU_CHANNEL_DWELL_TIME, //  22
	EID_RU_CHANNEL_LIST,       //  23
	EID_RU_TRAP,               //  24
	EID_RU_SCAN_TIMES,         //  25
	EID_RU_SCAN_DELAY,         //  26
	EID_RU_SCAN_REQ_ID,        //  27
	EID_STATIC_CONFIG,         //  28
	EID_LOCAL_BRIDGING,        //  29
	EID_STATIC_BP_IPADDR,      //  30
	EID_STATIC_BP_NETMASK,     //  31
	EID_STATIC_BP_GATEWAY,     //  32
	EID_STATIC_BM_IPADDR,      //  33
	EID_BP_BPSSID,             //  34
	EID_BP_WIRED_MACADDR,      //  35
	EID_RU_CAPABILITY,         //  36
	EID_RU_SSID_NAME,          //  37
	EID_ALARM,                 //  38
	EID_RU_PREAUTH,            //  39
	EID_RU_PMK,                //  40
	EID_AC_REG_CHALLENGE,      //  41
	EID_AC_REG_RESPONSE,       //  42
	EID_STATS,                 //  43
	EID_CERTIFICATE,           //  44
	EID_RADIO_ID,              //  45
	EID_REQ_ID,                //  46
	EID_NETWORK_ID,            //  47
	EID_MU_MAC,                //  48
	EID_TIME,                  //  49
	EID_NUM_RADIOS,            //  50
	EID_RADIO_INFO,            //  51
	EID_NETWORK_INFO,          //  52
	EID_VENDOR_ID,             //  53
	EID_PRODUCT_ID,            //  54
	EID_RADIO_INFO_ACK,        //  55
	EID_SECURE_TUNNEL,         //  56
	EID_MU_TOPOLOGY_ID,        //  57
	EID_SSID,                  //  58
	EID_EVENT_BLOCK,           //  59
	EID_SNMP_ERROR_STATUS,     //  60
	EID_SNMP_ERROR_INDEX,      //  61
	EID_RU_REAUTH_TIMER,       //  62
	EID_AP_IMG_TO_RAM,         //  63
	EID_AP_IMG_ROLE,           //  64
	EID_AP_STATS_BLOCK,        //  65
	EID_MU_RF_STATS_BLOCK,     //  66
	EID_STATS_REQUEST_TYPE,    //  67
	EID_STATS_LAST,            //  68
	EID_TLV_CONFIG,            //  69
	EID_CONFIG_ERROR_BLOCK,    //  70
	EID_CONFIG_MODIFIED_BLOCK, //  71
	EID_MU_PMKID_LIST,         //  72
	EID_MU_PMK_BP,             //  73
	EID_MU_PMKID_BP,           //  74
	EID_COUNTDOWN_TIME,        //  75
	EID_WASSP_VLAN_TAG,        //  76
	EID_SSID_ID,               //  77
	EID_BULK_MU_BLOCK,         //  78
	EID_MU_BLOCK,              //  79
	EID_PORT_OPEN_FLAG,        //  80
	EID_WASSP_TUNNEL_TYPE,     //  81
	EID_LOG_TYPE,              //  82
	EID_LOG_FILE,              //  83
	EID_ALARM_SEVERITY,        //  84
	EID_ALARM_DESCRIPTION,     //  85
	EID_BULK_VNS_BLOCK,        //  86
	EID_VNS_BLOCK,             //  87
	EID_AP_DHCP_MODE,          //  88
	EID_AP_IPADDR,             //  89
	EID_AP_NETMASK,            //  90
	EID_AP_GATEWAY,            //  91
	EID_BSSID2IP_BLOCK,        //  92
	EID_RU_BACKUP_VERSION,     //  93
	EID_AC_SW_VERSION,         //  94
	EID_MCAST_LAMG_LIST,       //  95
	EID_FILTER_NAME,           //  96
	EID_FILTER_RULES,          //  97
	EID_AUTH_STATE,            //  98
	EID_MU_DISC_AFTER_AUTH,    //  99
	EID_MU_MAC_LIST,           // 100
	EID_TRANS_ID,              // 101
	EID_TIMEZONE_OFFSET,       // 102
	EID_SENSOR_FORCE_DOWNLOAD, // 103
	EID_SENSOR_IMG_VERSION,    // 104
	EID_BRIDGE_MODE,           // 105
	EID_MU_VLAN_TAG,           // 106
	EID_RATECTRL_CIR_UL,       // 107
	EID_RATECTRL_CIR_DL,       // 108
	EID_RATECTRL_CBS_UL,       // 109
	EID_RATECTRL_CBS_DL,       // 110
	EID_RATECTRL_NAME_UL,      // 111
	EID_RATECTRL_NAME_DL,      // 112
	EID_POLICY_NAME,           // 113
	EID_SIAPP_PMK_BLOCK,                       //  114
	EID_SIAPP_PMKID,                           //  115
	EID_SIAPP_PMK_REAUTH,                      //  116
	EID_SIAPP_PMK_LIFETIME,                    //  117
	EID_SIAPP_PMKID_FLAG,                      //  118
	EID_SIAPP_MU_PMK,                          //  119
	EID_SIAPP_AP_NAME,                         //  120
	EID_SIAPP_RADIO_CONFIG_BLOCK,              //  121
	EID_SIAPP_CLUSTER_ACS_REQ,                 //  122
	EID_SIAPP_SIAPP_MU_STATS_BLOCK,            //  123
	EID_SIAPP_PACKET_RETRIES,                  //  124
	EID_SIAPP_ASSOC_IN_WLAN,                   //  125
	EID_SIAPP_ASSOC_IN_CLUSTER,                //  126
	EID_SIAPP_REASSOC_IN_CLUSTER,              //  127
	EID_SIAPP_THIN_BLOCK,                      //  128
	EID_SIAPP_NEWAP_BSSID,                     //  129
	EID_SIAPP_OLDAP_BSSID,                     //  130
	EID_SIAPP_RAD_CACS_REQ,                    //  131
	EID_SIAPP_RADIOBLOCK,                      //  132
	EID_SIAPP_CLIENT_COUNT,                    //  133
	EID_SIAPP_BLOCK,                           //  134
	EID_SIAPP_MU_TransmittedFrameCount,        //  135
	EID_SIAPP_MU_ReceivedFrameCount,           //  136
	EID_SIAPP_MU_TransmittedBytes,             //  137
	EID_SIAPP_MU_ReceivedBytes,                //  138
	EID_SIAPP_MU_UL_DroppedRateControlPackets, //  139
	EID_SIAPP_MU_DL_DroppedRateControlPackets, //  140
	EID_SIAPP_MU_DL_DroppedBufferFullPackets,  //  141
	EID_SIAPP_MU_DL_LostRetriesPackets,        //  142
	EID_SIAPP_MU_UL_DroppedRateControlBytes,   //  143
	EID_SIAPP_MU_DL_DroppedRateControlBytes,   //  144
	EID_SIAPP_MU_DL_DroppedBufferFullBytes,    //  145
	EID_SIAPP_MU_DL_LostRetriesBytes,          //  146
	EID_SIAPP_BP_BSSID,                        //  147
	EID_SIAPP_RADIO_ID,                        //  148
	EID_SIAPP_MACADDR,                         //  149
	EID_SIAPP_PREAUTH_REQ,                     //  150
	EID_SIAPP_USER_IDENTITY,                   //  151
	EID_SIAPP_LOADBAL_BLOCK,                   //  152
	EID_SIAPP_LOADBAL_PKT_TYPE,                //  153
	EID_SIAPP_LOADBAL_LOADGROUP_ID,            //  154
	EID_SIAPP_LOADBAL_LOAD_VALUE,              //  155
	EID_SIAPP_AC_MGMT_MAC,                     //  156
	EID_SIAPP_FILTER_COS,                      //  157
	EID_COS,                                   //  158
	EID_RATE_LIMIT_RESOURCE_TBL,               //  159
	EID_UCAST_FILTER_DISABLE,                  //  160
	EID_MU_INFORM_REASON,                      //  161
	EID_MU_FILTER_POLICY_NAME,                 //  162
	EID_MU_TOPOLOGY_POLICY_NAME,               //  163
	EID_MU_COS_POLICY_NAME,                    //  164
	EID_MU_FILTER_KEY,                         //  165
	EID_MU_TOPOLOGY_KEY,                       //  166
	EID_MU_COS_KEY,                            //  167
	EID_MU_SESSION_TIMEOUT,                    //  168
	EID_MU_ACCOUNTING_CLASS,                   //  169
	EID_MU_LOGIN_LAT_PORT,                     //  170
	EID_MU_IDLE_TIMEOUT,                       //  171
	EID_MU_ACCT_INTERIM_INTERVAL,              //  172
	EID_MU_IP_ADDR,                            //  173
	EID_MU_TERMINATE_ACTION,                   //  174
	EID_SITE_NAME,                             //  175
	EID_PEER_SITE_IP,                          //  176
	EID_INTERFERENCE_EVENTS_ENABLE,            //  177
	EID_EVENT_TYPE,                            //  178
	EID_EVENT_CHANNEL,                         //  179
	EID_EVENT_VALUE,                           //  180
	EID_SSS_MU_BLOCK,                          //  181
	EID_SSS_MU_ASSOC_TIME,                     //  182
	EID_SSS_TS64_MU_UPDATE,                    //  183
	EID_SSS_TS64_AP_CURRENT,                   //  184
	EID_SSS_MU_AUTH_STATE,                     //  185
	EID_SSS_AP_HOMEHASH,                       //  186
	EID_TIME_FIRST_DETECTED,                   //  187
	EID_TIME_LAST_REPORTED,                    //  188
	EID_EVENT_ARRAY,                           //  189
	EID_SSS_DEFAULT_SESSION_TIMEOUT,           //  190
	EID_SSS_SSID,                              //  191
	EID_SSS_PRIVACY_TYPE,                      //  192
	EID_POLICY_ZONE_NAME,                      //  193
	EID_RU_AC_EVENT_COMPONENT_ID,              //  194
	EID_MU_AUTH_STATE,                         //  195
	EID_MU_USER_NAME,                          //  196
	EID_BULK_TYPE,                             //  197
	EID_SENT_TIME,                             //  198
	EID_INFORM_MU_PMK,                         //  199
	EID_COLLECTOR_IP_ADDR,                     //  200
	EID_ARP_PROXY,                             //  201
	EID_MCAST_FILTER_RULES,                    //  202
	EID_AP_PARAMS,                             //  203
	EID_ASSOC_SSID_ARRAY,                      //  204
	EID_ASSOC_SSID_BLOCK,                      //  205
	EID_AP_LIST_BLOCK,                         //  206
	EID_AP_LIST_ARRAY,                         //  207
	EID_MAC_ADDR,                              //  208
	EID_SCAN_PROFILE_ID,                       //  209
	EID_ACTION_REQ,                            //  210
	EID_CHANNEL_LIST,                          //  211
	EID_COUNTERMEASURES_MAX_CH,                //  212
	EID_COUNTERMEASURES_SET,                   //  213
	EID_SCAN_PROFILE_BLOCK,                    //  214
	EID_SEQ_NUM,                               //  215
	EID_THREAT_DEF_ARRAY,                      //  216
	EID_THREAT_DEF_BLOCK,                      //  217
	EID_THREAT_TYPE,                           //  218
	EID_THREAT_ID,                             //  219
	EID_THREAT_STATS_F,                        //  220
	EID_THREAT_FR_SFR,                         //  221
	EID_THREAT_PATTERN_ARRAY,                  //  222
	EID_THREAT_PATTERN_BLOCK,                  //  223
	EID_THREAT_PATTERN,                        //  224
	EID_THREAT_ALERT_TH_DUR,                   //  225
	EID_THREAT_CLEAR_TH_DUR,                   //  226
	EID_THREAT_PRIORITY,                       //  227
	EID_THREAT_MITIGATION_LIST,                //  228
	EID_SSS_MU_IS_PORT_CLOSED,                 //  229
	EID_FULL_UPDATE,                           //  230
	EID_REASON,                                //  231
	EID_SURVEILLANCE_DATA_ARRAY,               //  232
	EID_SURVEILLANCE_DATA_BLOCK,               //  233
	EID_SCAN_BSSID,                            //  234
	EID_PARAMS,                                //  235
	EID_SCAN_RSS_RSSI,                         //  236
	EID_SCAN_SSID,                             //  237
	EID_SCAN_CAP,                              //  238
	EID_THREAT_CLASSIFICATION,                 //  239
	EID_THREAT_DATA_ARRAY,                     //  240
	EID_THREAT_DATA_BLOCK,                     //  241
	EID_STATE,                                 //  242
	EID_DROP_FR_CNT,                           //  243
	EID_STOP_ROAM_CNT,                         //  244
	EID_SPOOF_CNT,                             //  245
	EID_THREAT_CLASSIFY_ARRAY,                 //  246
	EID_THREAT_CLASSIFY_BLOCK,                 //  247
	EID_THREAT_NAME,                           //  248
	EID_LOCATION,                              //  249
	EID_ENCRYPTION_TYPE,                       //  250
	EID_MU_EVENT_ARRAY,                        //  251
	EID_MU_EVENT_BLOCK,                        //  252
	EID_COMPONENT_ID,                          //  253
	EID_MU_EVENT_STRING,                       //  254
	EID_BYPASS_BMCAST,                         //  255
	EID_GETTIMEOFDAY,                          //  256
	EID_COUNTRY_ID,                            //  257
	EID_COUNTRY_ARRAY,                         //  258
	EID_COUNTRY_BLOCK,                         //  259
	EID_MU_EVENT_TYPE,                         //  260
	EID_LOCATOR_FLOOR_ID,                      //  261
	EID_LOCATOR_LOC_TYPE,                      //  262
	EID_LOCATOR_LOC_BLOCK,                     //  263
	EID_LOCATOR_LOC_ARRAY,                     //  264
	EID_LOCATOR_LOC_POINT,                     //  265
	EID_MU_EVENT_DETAILS,                      //  266
	EID_MU_EVENT_FROM_AP,                      //  267
	EID_MU_EVENT_LOC_BLOCK,                     //  268
	EID_LOCATOR_LOC_AP_DISTANCE,               //  269
	EID_LOCATOR_LOC_PRECISION,                 //  270
	EID_RSS_DATA_ARRAY,                        //  271
	EID_RSS_DATA_BLOCK,                        //  272
	EID_LOCATOR_MU_ACTION,                     //  273
	EID_EFFECTIVE_EGRESS_VLAN,                 //  274
	EID_REBOOT_ACK,                            //  275
	EID_MU_BSSID,                              //  276
	EID_AUTH_FLAG,                             //  277
	EID_ROAMED_FLAG,                           //  278
	EID_MU_RSS,                                //  279
	EID_FILTER_RULES_VER,                      //  280
	EID_FILTER_TYPE,                           //  281
	EID_MCAST_FILTER_BLOCK,                    //  282
	EID_MCAST_FILTER_BLOCK_ENTRY,              //  283
	EID_DEFAULT_ACTION_TYPE,                   //  284
	EID_DEFAULT_CONTAIN_TO_VLAN,               //  285
	EID_DEFAULT_BRIDGE_MODE,                   //  286
	EID_INVALID_POLICY,                        //  287
	EID_LOCATOR_FLOOR_NAME,                    //  288
	EID_AP_FLAGS,                              //  289
	EID_AP_PVID,                               //  290
	EID_AP_REDIRECT,                           //  291
	EID_MU_CVLAN_BAP,                          //  292
	EID_MU_SESSION_ARRAY,                      //  293
	EID_MU_SESSION_BLOCK,                      //  294
	EID_MU_SESSION_ID,                         //  295
	EID_MU_RFS_NAME,                           //  296
	EID_MU_FLAGS,                              //  297
	EID_MU_ASSOC_TIME,                         //  298
	EID_MU_ACTIVE_TIME,                        //  299
	EID_REPORT_REQ,                            //  300
	EID_MU_URL,                                //  301
	EID_MU_SESSION_LIFETIME,                   //  302
	EID_MU_REAUTH_TIMER,                       //  303
	EID_MU_ACCT_SESSION_ID_STRING,             //  304
	EID_MU_ACCT_POLICY_NAME,                   //  305
	EID_MU_ACCT_START_TIME,                    //  306
	EID_MU_ACCT_CLASS,                         //  307
	EID_MU_LOGIN_LAT_GROUP,                    //  308
	EID_MU_TUNNEL_PRIVATE_GROUP_ID_STRING,     //  309
	EID_MU_USER_ID_STRING,                     //  310
	EID_MU_DEFENDED_STATE,                     //  311
	EID_MU_MOD_MASK,                           //  312
	EID_LOCATOR_TRACKED,                       //  313
	EID_PORT,                                  //  314
	EID_RETRIES_COUNT,                         //  315
	EID_MODULATION_TYPE,                       //  316
	EID_DETECTED_ROGUE_ARRAY,                  //  317
	EID_DETECTED_ROGUE_BLOCK,                  //  318
	EID_ROGUE_DETECTION,                       //  319
	EID_MAC_ADDR_TX,                           //  320
	EID_MAC_ADDR_RX,                           //  321
	EID_IP_ADDR_TX,                            //  322
	EID_IP_ADDR_RX,                            //  323
	EID_TTL,                                   //  324
	EID_GW_IP_ADDR,                            //  325
	EID_LOCATOR_STATE_DATA,                    //  326
	EID_LOCATOR_POINT_SET,                     //  327
	EID_FILTER_RULE_FIXED_APP_ID,              //  328
	EID_FILTER_RULES_EXT_BLOCK,                //  329
	EID_MU_AREA_BLOCK,                         //  330
	EID_MU_LOCATION,                           //  331
	EID_MU_LOCATION_TS,                        //  332
	EID_DNS_IP_ADDR,                           //  333
	EID_IN_SERVICE_AP_LIST,                    //  334
	EID_OUT_SERVICE_AP_LIST,                   //  335
	EID_LAST_RD_AP,                            //  336
	EID_ROGUE_INFO,                            //  337
	EID_MU_IS_FT,                              //  338
	EID_MU_PMK_R1,                             //  339
	EID_SIAPP_R0KHID,                          //  340
	EID_SIAPP_R1KHID,                          //  341
	EID_SIAPP_FT_NONCE,                        //  342
	EID_SIAPP_FT_PMKR0NAME,                    //  343
	EID_SIAPP_FT_R1KHID,                       //  344
	EID_SIAPP_FT_S1KHID,                       //  345
	EID_SIAPP_FT_PMKR1,                        //  346
	EID_SIAPP_FT_PMKR1NAME,                    //  347
	EID_SIAPP_FT_PAIRWISE,                     //  348
	EID_SIAPP_FT_LIFETIME,                     //  349
	EID_MU_POWER_CAP,                          //  350
	EID_AREA_NAME,                             //  351
	EID_PERIODIC_NEIGHBOUR_REPORT,             //  352
	EID_TIMESTAMP,                             //  353
	EID_NEIGHBOUR_ENTRY,                       //  354
	EID_MU_REQ,                                //  355
	EID_RU_REQ,                                //  356
	EID_NEIGHBOUR_REQ,                         //  357
	EID_SSS_FT_ASSOC,                          //  358
	EID_DEFAULT_MIRRORN,                       //  359
	EID_FILTER_RULE_EXT_ACT_FLAGS,             //  360
	EID_TOPO_GROUP_MAPPING,                    //  361
	EID_MU_PMK_R0NAME,                         //  362
	EID_CUI,                                   //  363
	EID_SSS_CAPINFO,                           //  364
	EID_SSS_CAPPOWER,                          //  365
	EID_WFA_VSA,                               //  366
	EID_WFA_HS20_REMED_METHOD,                 //  367
	EID_WFA_HS20_URL,                          //  368
	EID_WFA_HS20_DEAUTH_CODE,                  //  369
	EID_WFA_HS20_REAUTH_DELAY,                 //  370
	EID_WFA_HS20_SWT,                          //  371
	EID_POWER_STATUS,                          //  372
	EID_IPV6_ADDR,                             //  373
	EID_FILTER_RULES_APP_SIG_GROUP_ID,         //  374
	EID_FILTER_RULES_APP_SIG_DISP_ID,          //  375
	EID_MU_DEV_IDENTITY,                       //  376
	EID_APPL_STATS_REQ,                        //  377
	EID_MU_APPL_STATS_BLOCK,                   //  378
	EID_TOPOLOGY_ARRAY,                        //  379
	EID_TOPOLOGY_STRUCT,                       //  380
	EID_FILTER_CONFIG_STRUCT,                  //  381
	EID_DHCP_HOST_NAME,                        //  382
	EID_NEIGHBOUR_ENTRY_2,                     //  383
	EID_CHANNEL_ENTRY,                         //  384
	EID_MU_ECP_PW,                             //  385
	EID_MU_ECP_TOKEN,                          //  386
	EID_STATIC_VSA_IPADDR,                     //  387
	EID_STATIC_VSA_NETMASK,                    //  388
	EID_PKT_CAPTURE_STATUS,                    //  389
	EID_PKT_CAPTURE_FILTERS,                   //  390
	EID_PKT_F_WIRELESS,                        //  391
	EID_PKT_F_WIREDCLIENT,                     //  392
	EID_PKT_F_DIRECTION,                       //  393
	EID_PKT_F_RADIO,                           //  394
	EID_PKT_F_FLAGS,                           //  395
	EID_PKT_F_IP_ARRAY,                        //  396
	EID_PKT_F_MAC,                             //  397
	EID_PKT_F_PROTOCOL,                        //  398
	EID_PKT_F_PORT,                            //  399
	EID_VSA_SSID_ID,                           //  400
	EID_MU_AUTH_TYPE,                          //  401
	EID_PKT_F_MAX_PKT_COUNT,                   //  402
	EID_PKT_F_FLAG_2,                          //  403
	EID_IMAGE_PORT,                            //  404
	EID_FILTER_ROLE_ID,                        //  405
	EID_FILTER_ROLE_TIMESTAMP,                 //  406
	EID_MAX
} wassp_tlv_type_t;

/* Value string object enumerates wassp tlv type field */
static const value_string wassp_tlv_types[] =
{
	{ EID_STATUS, "Status/Action"},
	{ EID_RU_SW_VERSION, "Software Version"},
	{ EID_RU_SERIAL_NUMBER, "Serial Number"},
	{ EID_RU_REG_CHALLENGE, "Registration Challenge"},
	{ EID_RU_REG_RESPONSE, "Challenge Response"},
	{ EID_AC_IPADDR, "Controller IP Address"},
	{ EID_RU_VNSID, "AccessPoint VNS ID"},
	{ EID_TFTP_SERVER, "TFTP Server Address"},
	{ EID_IMAGE_PATH, "Path/Filename of Upgrade Image"},
	{ EID_CONFIG, "SNMP Encoded Configuration"},
	{ EID_RU_STATE, "AccessPoint State"},
	{ EID_SESSION_KEY, "Binding Key"},
	{ EID_RU_PROTOCOL, "Message Type"},
	{ EID_RANDOM_NUMBER, "Random Number"},
	{ EID_STANDBY_TIMEOUT, "Standby Timeout"},
	{ EID_RU_CHALLENGE_ID, "AccessPoint Challenge ID"},
	{ EID_RU_MODEL, "AccessPoint Model"},
	{ EID_RU_SCAN_MODE, "AccessPoint Scan Mode"},
	{ EID_RU_SCAN_TYPE, "AccessPoint Scan Type"},
	{ EID_RU_SCAN_INTERVAL, "AccessPoint Scan Interval"},
	{ EID_RU_RADIO_TYPE, "AccessPoint Radio Type"},
	{ EID_RU_CHANNEL_DWELL_TIME, "AccessPoint Channel Dwell Time"},
	{ EID_RU_CHANNEL_LIST, "AccessPoint Channel List"},
	{ EID_RU_TRAP, "AccessPoint Trap"},
	{ EID_RU_SCAN_TIMES, "AccessPoint Scan Times"},
	{ EID_RU_SCAN_DELAY, "AccessPoint Scan Delay"},
	{ EID_RU_SCAN_REQ_ID, "AccessPoint Scan Request ID"},
	{ EID_STATIC_CONFIG, "Static Configuration"},
	{ EID_LOCAL_BRIDGING, "Local Bridging"},
	{ EID_STATIC_BP_IPADDR, "Static AccessPoint IP Address"},
	{ EID_STATIC_BP_NETMASK, "Static AccessPoint NetMask"},
	{ EID_STATIC_BP_GATEWAY, "Static AccessPoint Gateway"},
	{ EID_STATIC_BM_IPADDR, "Static Controller IP Address"},
	{ EID_BP_BPSSID, "AccessPoint BSSID"},
	{ EID_BP_WIRED_MACADDR, "AccessPoint Wired MAC"},
	{ EID_RU_CAPABILITY, "AccessPoint Capability"},
	{ EID_RU_SSID_NAME, "AccessPoint SSID Name"},
	{ EID_ALARM, "Alarm"},
	{ EID_RU_PREAUTH, "AccessPoint Preauthorization"},
	{ EID_RU_PMK, "AccessPoint Pairwise Master Key"},
	{ EID_AC_REG_CHALLENGE, "Controller Register Challenge"},
	{ EID_AC_REG_RESPONSE, "Controller Register Response"},
	{ EID_STATS, "Stats"},
	{ EID_CERTIFICATE, "Certificate"},
	{ EID_RADIO_ID, "Radio ID"},
	{ EID_REQ_ID, "Request ID"},
	{ EID_NETWORK_ID, "Network ID"},
	{ EID_MU_MAC, "MU MAC Address"},
	{ EID_TIME, "Time"},
	{ EID_NUM_RADIOS, "Number of Radios"},
	{ EID_RADIO_INFO, "Radio Info"},
	{ EID_NETWORK_INFO, "Network Info"},
	{ EID_VENDOR_ID, "Vendor ID"},
	{ EID_PRODUCT_ID, "Product ID"},
	{ EID_RADIO_INFO_ACK, "Radio Info Acknowledge"},
	{ EID_SECURE_TUNNEL, "Secure Tunnel"},
	{ EID_MU_TOPOLOGY_ID, "MU Topology ID"},
	{ EID_SSID, "SSID"},
	{ EID_EVENT_BLOCK, "Event Block"},
	{ EID_SNMP_ERROR_STATUS, "SNMP Error Status"},
	{ EID_SNMP_ERROR_INDEX, "SNMP Error Index"},
	{ EID_RU_REAUTH_TIMER, "AccessPoint ReAuthentication Timer"},
	{ EID_AP_IMG_TO_RAM, "AccessPoint Image Store to RAM"},
	{ EID_AP_IMG_ROLE, "AccessPoint Image Type"},
	{ EID_AP_STATS_BLOCK, "AccessPoint Statistics Block"},
	{ EID_MU_RF_STATS_BLOCK, "AccessPoint RF Statistics Block"},
	{ EID_STATS_REQUEST_TYPE, "AccessPoint Statistics Request Type"},
	{ EID_STATS_LAST, "AccessPoint Statistics Last Flag"},
	{ EID_TLV_CONFIG, "TLV Configuration"},
	{ EID_CONFIG_ERROR_BLOCK, "AccessPoint Configuration Error Block"},
	{ EID_CONFIG_MODIFIED_BLOCK, "AccessPoint Configuration Modified Block"},
	{ EID_MU_PMKID_LIST, "MU Pairwise Master Key List"},
	{ EID_MU_PMK_BP, "MU and AccessPoint Pairwise Master Key"},
	{ EID_MU_PMKID_BP, "MU and AccessPoint Pairwise Master Key ID"},
	{ EID_COUNTDOWN_TIME, "CountDown Time"},
	{ EID_WASSP_VLAN_TAG, "VLAN Tag"},
	{ EID_SSID_ID, "SSID(Service Set Identifier)"},
	{ EID_BULK_MU_BLOCK, "Bulk MU Block"},
	{ EID_MU_BLOCK, "MU Block" },
	{ EID_PORT_OPEN_FLAG, "Port Open Flag"},
	{ EID_WASSP_TUNNEL_TYPE, "Tunnel Type"},
	{ EID_LOG_TYPE, "Log type"},
	{ EID_LOG_FILE, "Log File"},
	{ EID_ALARM_SEVERITY, "Alarm Severity"},
	{ EID_ALARM_DESCRIPTION, "Alarm Information"},
	{ EID_BULK_VNS_BLOCK, "Bulk VNS Block"},
	{ EID_VNS_BLOCK, "VNS Block"},
	{ EID_AP_DHCP_MODE, "AccessPoint DHCP Mode"},
	{ EID_AP_IPADDR, "AccessPoint IP Address"},
	{ EID_AP_NETMASK, "AccessPoint IP Netmask"},
	{ EID_AP_GATEWAY, "AccessPoint IP Gateway"},
	{ EID_BSSID2IP_BLOCK, "BSSID to IP Address Mapping Block"},
	{ EID_RU_BACKUP_VERSION, "AccessPoint Upgrade: Software Version of The Backup Image"},
	{ EID_AC_SW_VERSION, "AccessPoint Upgrade: Software Version"},
	{ EID_MCAST_LAMG_LIST, "Multicast Optimization"},
	{ EID_FILTER_NAME, "Filter Rule Name"},
	{ EID_FILTER_RULES, "Array of Filter Rules"},
	{ EID_AUTH_STATE, "Authentication State( MU Not Authenticate = 0, ANON_AUTHENTICATED=0, MU Authenticated = 1"},
	{ EID_MU_DISC_AFTER_AUTH, "After Authenticated MU State( Disconnected = 0, Connected = 1"},
	{ EID_MU_MAC_LIST, "Array of MAC Addresses"},
	{ EID_TRANS_ID, "Transaction ID of The Message Determined At The Home Controller"},
	{ EID_TIMEZONE_OFFSET, "Timezone Offset"},
	{ EID_SENSOR_FORCE_DOWNLOAD, "Force Download of Sensor Image"},
	{ EID_SENSOR_IMG_VERSION, "Sensor Image Version"},
	{ EID_BRIDGE_MODE, "Bridge Mode"},
	{ EID_MU_VLAN_TAG, "MU VLAN Tag"},
	{ EID_RATECTRL_CIR_UL, "Up Link Bandwidth Control: Committed Information Rate (CIR)"},
	{ EID_RATECTRL_CIR_DL, "Down Link Bandwidth Control: Committed Information Rate (CIR)"},
	{ EID_RATECTRL_CBS_UL, "Up Link Bandwidth Control: Committed Burst Size (CBS)"},
	{ EID_RATECTRL_CBS_DL, "Down Link Bandwidth Control: Committed Burst Size (CBS)"},
	{ EID_RATECTRL_NAME_UL, "Up Link Bandwidth Control Profile Name"},
	{ EID_RATECTRL_NAME_DL, "Down Link Bandwidth Control Profile Name"},
	{ EID_POLICY_NAME, "Policy Profile Name"},
	{ EID_SIAPP_PMK_BLOCK, "Secure Inter-Access Point Protocol(SIAPP) Pairwise Master Key Block"},
	{ EID_SIAPP_PMKID, "Secure Inter-Access Point Protocol(SIAPP) Pairwise Master Key ID"},
	{ EID_SIAPP_PMK_REAUTH, "Secure Inter-Access Point Protocol(SIAPP) Pairwise Master Key ReAuthenticate"},
	{ EID_SIAPP_PMK_LIFETIME, "Secure Inter-Access Point Protocol(SIAPP) Pairwise Master Key Life Time"},
	{ EID_SIAPP_PMKID_FLAG, "Secure Inter-Access Point Protocol(SIAPP) Pairwise Master Key ID Flag"},
	{ EID_SIAPP_MU_PMK, "MU Secure Inter-Access Point Protocol(SIAPP) Pairwise Master Key"},
	{ EID_SIAPP_AP_NAME, "SIAPP AP Name"},
	{ EID_SIAPP_RADIO_CONFIG_BLOCK, "SIAPP Radio Configuration Block"},
	{ EID_SIAPP_CLUSTER_ACS_REQ, "SIAPP Cluster ACS Request"},
	{ EID_SIAPP_SIAPP_MU_STATS_BLOCK, "SIAPP MU Statistics Block"},
	{ EID_SIAPP_PACKET_RETRIES, "SIAPP Packet Retries"},
	{ EID_SIAPP_ASSOC_IN_WLAN, "SIAPP MU Association With In Same WLAN"},
	{ EID_SIAPP_ASSOC_IN_CLUSTER, "SIAPP MU Association With In Same Cluster"},
	{ EID_SIAPP_REASSOC_IN_CLUSTER, "SIAPP MU Reassociation With In Same Cluster"},
	{ EID_SIAPP_THIN_BLOCK, "SIAPP Thin Access Points Block"},
	{ EID_SIAPP_NEWAP_BSSID, "SIAPP New Access Points BSSID"},
	{ EID_SIAPP_OLDAP_BSSID, "SIAPP Old Access Points BSSID"},
	{ EID_SIAPP_RAD_CACS_REQ, "SIAPP Radio CACS Request"},
	{ EID_SIAPP_RADIOBLOCK, "SIAPP Radio Block"},
	{ EID_SIAPP_CLIENT_COUNT, "SIAPP Client Count"},
	{ EID_SIAPP_BLOCK, "SIAPP Block"},
	{ EID_SIAPP_MU_TransmittedFrameCount, "SIAPP MU _Transmitted Frame Count"},
	{ EID_SIAPP_MU_ReceivedFrameCount, "SIAPP MU Received Frame Count"},
	{ EID_SIAPP_MU_TransmittedBytes, "SIAPP MU Transmitted Bytes"},
	{ EID_SIAPP_MU_ReceivedBytes, "SIAPP MU Received Bytes"},
	{ EID_SIAPP_MU_UL_DroppedRateControlPackets, "SIAPP MU Up Link Dropped Rate Control Packets"},
	{ EID_SIAPP_MU_DL_DroppedRateControlPackets, "SIAPP MU Down Link Dropped Rate Control Packets"},
	{ EID_SIAPP_MU_DL_DroppedBufferFullPackets, "SIAPP MU Down Link Dropped Buffer Full Packets"},
	{ EID_SIAPP_MU_DL_LostRetriesPackets, "SIAPP MU Down Link Lost Retries Packets"},
	{ EID_SIAPP_MU_UL_DroppedRateControlBytes, "SIAPP MU Up Link Dropped Rate Control Bytes"},
	{ EID_SIAPP_MU_DL_DroppedRateControlBytes, "SIAPP MU Down Link Dropped Rate Control Bytes"},
	{ EID_SIAPP_MU_DL_DroppedBufferFullBytes, "SIAPP MU Down Link Dropped Buffer Full Bytes"},
	{ EID_SIAPP_MU_DL_LostRetriesBytes, "SIAPP MU Down Link Lost Retries Bytes"},
	{ EID_SIAPP_BP_BSSID, "SIAPP  Access Points BSSID"},
	{ EID_SIAPP_RADIO_ID, "SIAPP Radio ID"},
	{ EID_SIAPP_MACADDR, "SIAPP Mac Address"},
	{ EID_SIAPP_PREAUTH_REQ, "SIAPP Preauthentication Request"},
	{ EID_SIAPP_USER_IDENTITY, "SIAPP Client IDY"},
	{ EID_SIAPP_LOADBAL_BLOCK, "SIAPP Load Balance block"},
	{ EID_SIAPP_LOADBAL_PKT_TYPE, "SIAPP Load Balance PKT Type"},
	{ EID_SIAPP_LOADBAL_LOADGROUP_ID, "SIAPP Load Balance Load Group ID"},
	{ EID_SIAPP_LOADBAL_LOAD_VALUE, "SIAPP Load Balance Load Value"},
	{ EID_SIAPP_AC_MGMT_MAC, "SIAPP Controller Management Mac Address"},
	{ EID_SIAPP_FILTER_COS, "SIAPP Filter Rule COS"},
	{ EID_COS, "Classes of Service(COS)"},
	{ EID_RATE_LIMIT_RESOURCE_TBL, "Bandwidth Control Rate Limit Resource Table"},
	{ EID_UCAST_FILTER_DISABLE, "Unicast Filter Disable Flag"},
	{ EID_MU_INFORM_REASON, "MU Information"},
	{ EID_MU_FILTER_POLICY_NAME, "MU Filter Rule Name"},
	{ EID_MU_TOPOLOGY_POLICY_NAME, "MU Topology Name"},
	{ EID_MU_COS_POLICY_NAME, "MU COS Name"},
	{ EID_MU_FILTER_KEY, "MU Filter Rule ID"},
	{ EID_MU_TOPOLOGY_KEY, "MU Topology ID"},
	{ EID_MU_COS_KEY, "MU COS ID"},
	{ EID_MU_SESSION_TIMEOUT, "MU Session Life Time"},
	{ EID_MU_ACCOUNTING_CLASS, "MU Accounting Class"},
	{ EID_MU_LOGIN_LAT_PORT, "MU Login authentication state(0 = Non-auth, 1 = Auth)"},
	{ EID_MU_IDLE_TIMEOUT, "MU Session Idle Timeout"},
	{ EID_MU_ACCT_INTERIM_INTERVAL, "Client Acct-Interim-Interval(RADIUS)"},
	{ EID_MU_IP_ADDR, "MU IP Address"},
	{ EID_MU_TERMINATE_ACTION, "MU Terminate Action"},
	{ EID_SITE_NAME, "Site Name"},
	{ EID_PEER_SITE_IP, "Peer Site IP Address"},
	{ EID_INTERFERENCE_EVENTS_ENABLE, "Interference Events Enable Flag"},
	{ EID_EVENT_TYPE, "Event Type"},
	{ EID_EVENT_CHANNEL, "Event Channel"},
	{ EID_EVENT_VALUE, "Event Value"},
	{ EID_SSS_MU_BLOCK, "Site Section MU Block"},
	{ EID_SSS_MU_ASSOC_TIME, "Site Section MU Association Time"},
	{ EID_SSS_TS64_MU_UPDATE, "Site Section MU Update Time Stamp"},
	{ EID_SSS_TS64_AP_CURRENT, "Site Section AccessPoint Current Time"},
	{ EID_SSS_MU_AUTH_STATE, "Site Section MU Authentication State"},
	{ EID_SSS_AP_HOMEHASH, "Site Section AccessPoint Home Hashed Value"},
	{ EID_TIME_FIRST_DETECTED, "First Detected Time"},
	{ EID_TIME_LAST_REPORTED, "Last Reported Time"},
	{ EID_EVENT_ARRAY, "Array Of Events"},
	{ EID_SSS_DEFAULT_SESSION_TIMEOUT, "Site Section Default Timeout Time"},
	{ EID_SSS_SSID, "Site Section SSID"},
	{ EID_SSS_PRIVACY_TYPE, "Site Section Privacy Type"},
	{ EID_POLICY_ZONE_NAME, "Policy Zone Name"},
	{ EID_RU_AC_EVENT_COMPONENT_ID, "Event Component ID"},
	{ EID_MU_AUTH_STATE, "MU Authentication State"},
	{ EID_MU_USER_NAME, "MU User Name"},
	{ EID_BULK_TYPE, "Bulk Type"},
	{ EID_SENT_TIME, "Sent Time"},
	{ EID_INFORM_MU_PMK, "Pairwise Master Key Informed From AP"},
	{ EID_COLLECTOR_IP_ADDR, "Collector IP Address"},
	{ EID_ARP_PROXY, "Enable/Disable Proxying of ARP Per Topology"},
	{ EID_MCAST_FILTER_RULES, "Multicast Filter Rules Per Topology"},
	{ EID_AP_PARAMS, "AP Parameters"},
	{ EID_ASSOC_SSID_ARRAY, "Array of Associated SSID"},
	{ EID_ASSOC_SSID_BLOCK, "Block of Associated SSID"},
	{ EID_AP_LIST_BLOCK, "Bloc of AP List"},
	{ EID_AP_LIST_ARRAY, "Array of AP List"},
	{ EID_MAC_ADDR, "MAC Address"},
	{ EID_SCAN_PROFILE_ID, "Scan Profile ID"},
	{ EID_ACTION_REQ, "Action Request"},
	{ EID_CHANNEL_LIST, "Channel List"},
	{ EID_COUNTERMEASURES_MAX_CH, "CounterMeasures Max Channel"},
	{ EID_COUNTERMEASURES_SET, "Enable/disable CounterMeasures"},
	{ EID_SCAN_PROFILE_BLOCK, "Scan Profile Block"},
	{ EID_SEQ_NUM, "Sequence Number"},
	{ EID_THREAT_DEF_ARRAY, "Array Of Threat Definition"},
	{ EID_THREAT_DEF_BLOCK, "Block Of Threat Definition"},
	{ EID_THREAT_TYPE, "Threat Type"},
	{ EID_THREAT_ID, "Threat ID"},
	{ EID_THREAT_STATS_F, "Threat State"},
	{ EID_THREAT_FR_SFR, "Threat FR SFR"},
	{ EID_THREAT_PATTERN_ARRAY, "Array Of Threat Pattern"},
	{ EID_THREAT_PATTERN_BLOCK, "Block Of Threat Pattern"},
	{ EID_THREAT_PATTERN, "Threat Pattern"},
	{ EID_THREAT_ALERT_TH_DUR, "Threat Alert"},
	{ EID_THREAT_CLEAR_TH_DUR, "Threat Clear"},
	{ EID_THREAT_PRIORITY, "Threat Priority"},
	{ EID_THREAT_MITIGATION_LIST, "Threat Mitigation List"},
	{ EID_SSS_MU_IS_PORT_CLOSED, "Enable/Disable Site Section MU Port"},
	{ EID_FULL_UPDATE, "Full Update"},
	{ EID_REASON, "Reason"},
	{ EID_SURVEILLANCE_DATA_ARRAY, "Array of Surveillance Data"},
	{ EID_SURVEILLANCE_DATA_BLOCK, "Block of Surveillance Data"},
	{ EID_SCAN_BSSID, "Scan BSSID"},
	{ EID_PARAMS, "Parameters"},
	{ EID_SCAN_RSS_RSSI, "Scan RSS and RSSI"},
	{ EID_SCAN_SSID, "Scan SSID"},
	{ EID_SCAN_CAP, "Scan Capability"},
	{ EID_THREAT_CLASSIFICATION, "Threat Classification"},
	{ EID_THREAT_DATA_ARRAY, "Array Of Threat Data"},
	{ EID_THREAT_DATA_BLOCK, "Block Of Threat Data"},
	{ EID_STATE, "State"},
	{ EID_DROP_FR_CNT, "Drop FR Count"},
	{ EID_STOP_ROAM_CNT, "Stop ROAM Count"},
	{ EID_SPOOF_CNT, "Spoof Count"},
	{ EID_THREAT_CLASSIFY_ARRAY, "Array Of Classify Threat"},
	{ EID_THREAT_CLASSIFY_BLOCK, "Block Of Classify Threat"},
	{ EID_THREAT_NAME, "Threat Name"},
	{ EID_LOCATION, "Location"},
	{ EID_ENCRYPTION_TYPE, "Encryption Type"},
	{ EID_MU_EVENT_ARRAY, "Array Of MU Events"},
	{ EID_MU_EVENT_BLOCK, "Block Of MU Events"},
	{ EID_COMPONENT_ID, "Component ID"},
	{ EID_MU_EVENT_STRING, "MU Event String"},
	{ EID_BYPASS_BMCAST, "Bypass Broadcast and Multicast"},
	{ EID_GETTIMEOFDAY, "Get Time of Day"},
	/* Dedicated scanner / Guardian */
	{ EID_COUNTRY_ID, "Country ID"},
	{ EID_COUNTRY_ARRAY, "Array of Country"},
	{ EID_COUNTRY_BLOCK, "Country Block"},
	/* Location Engine */
	{ EID_MU_EVENT_TYPE, "MU Event Type"},
	{ EID_LOCATOR_FLOOR_ID, "Floor ID"},
	{ EID_LOCATOR_LOC_TYPE, "Location Type"},
	{ EID_LOCATOR_LOC_BLOCK, "Block of Location Data"},
	{ EID_LOCATOR_LOC_ARRAY, "Array of Location Data"},
	{ EID_LOCATOR_LOC_POINT, "Location Point"},
	{ EID_MU_EVENT_DETAILS, "MU Event Details"},
	{ EID_MU_EVENT_FROM_AP, "MU Event From AP"},
	{ EID_MU_EVENT_LOC_BLOCK, "Block of MU Location Event"},
	{ EID_LOCATOR_LOC_AP_DISTANCE, "AP Location Distance"},
	{ EID_LOCATOR_LOC_PRECISION, "Location Precision"},
	{ EID_RSS_DATA_ARRAY, "Array of RSS Data"},
	{ EID_RSS_DATA_BLOCK, "Block  of RSS Data"},
	{ EID_LOCATOR_MU_ACTION, "Location MU Action"},
	{ EID_EFFECTIVE_EGRESS_VLAN, "Effective Egress Vlan"},
	{ EID_REBOOT_ACK, "Reboot Acknowledgement"},
	{ EID_MU_BSSID, "MU BSSID"},
	{ EID_AUTH_FLAG, "Authentication Flag"},
	{ EID_ROAMED_FLAG, "ROAMED Flag"},
	{ EID_MU_RSS, "MU RSS"},
	{ EID_FILTER_RULES_VER, "Filter Rule Struct Version"},
	{ EID_FILTER_TYPE, "Filter Rule Type"},
	{ EID_MCAST_FILTER_BLOCK, "Multicast Filter Rule Block"},
	{ EID_MCAST_FILTER_BLOCK_ENTRY, "Multicast Filter Rule Block Entry"},
	{ EID_DEFAULT_ACTION_TYPE, "Default Action Type"},
	{ EID_DEFAULT_CONTAIN_TO_VLAN, "Default Contain to Vlan Flag"},
	{ EID_DEFAULT_BRIDGE_MODE, "Default Bridge Mode Flag"},
	{ EID_INVALID_POLICY, "Invalid Policy Flag"},
	{ EID_LOCATOR_FLOOR_NAME, "Floor Name"},
	{ EID_AP_FLAGS, "AP Flags"},
	{ EID_AP_PVID, "AP PVID"},
	{ EID_AP_REDIRECT, "AP Redirect Flag"},
	{ EID_MU_CVLAN_BAP, "AP Contain to Vlan Has Bridge At AP Topology Flag"},
	{ EID_MU_SESSION_ARRAY, "Array Of MU Session"},
	{ EID_MU_SESSION_BLOCK, "MU Session Block"},
	{ EID_MU_SESSION_ID, "MU Session ID"},
	{ EID_MU_RFS_NAME, "MU RFS Name"},
	{ EID_MU_FLAGS, "MU Flags"},
	{ EID_MU_ASSOC_TIME, "MU Associated Time"},
	{ EID_MU_ACTIVE_TIME, "MU Active Time"},
	{ EID_REPORT_REQ, "Report Request"},
	{ EID_MU_URL, "MU Captive Portal Url"},
	{ EID_MU_SESSION_LIFETIME, "MU Session Life Time"},
	{ EID_MU_REAUTH_TIMER, "MU Re-Authentication Timer"},
	{ EID_MU_ACCT_SESSION_ID_STRING, "MU Acct Session ID String"},
	{ EID_MU_ACCT_POLICY_NAME, "MU Acct Policy Name"},
	{ EID_MU_ACCT_START_TIME, "MU Acct Start Time"},
	{ EID_MU_ACCT_CLASS, "MU Acct Class"},
	{ EID_MU_LOGIN_LAT_GROUP, "MU Login Group"},
	{ EID_MU_TUNNEL_PRIVATE_GROUP_ID_STRING, "MU Tunnel Private Group ID String"},
	{ EID_MU_USER_ID_STRING, "MU User ID String"},
	{ EID_MU_DEFENDED_STATE, "MU Defended State"},
	{ EID_MU_MOD_MASK, "MU Modulation Mask"},
	{ EID_LOCATOR_TRACKED, "Locator Tracked"},
	{ EID_PORT, "Port"},
	{ EID_RETRIES_COUNT, "Retries Count"},
	{ EID_MODULATION_TYPE, "Modulation Type"},
	{ EID_DETECTED_ROGUE_ARRAY, "Array Of Detected Rogue"},
	{ EID_DETECTED_ROGUE_BLOCK, "Detected Rogue Block"},
	{ EID_ROGUE_DETECTION, "Rogue Detection"},
	{ EID_MAC_ADDR_TX, "Tx Mac Address"},
	{ EID_MAC_ADDR_RX, "Rx Mac Address"},
	{ EID_IP_ADDR_TX, "Tx IP Address"},
	{ EID_IP_ADDR_RX, "Rx IP Address"},
	{ EID_TTL, "TTL"},
	{ EID_GW_IP_ADDR, "Gateway IP Address"},
	{ EID_LOCATOR_STATE_DATA, "Location State Data"},
	{ EID_LOCATOR_POINT_SET, "Location Point Set"},
	{ EID_FILTER_RULE_FIXED_APP_ID, "Filter Rule Fixed Application ID"},
	{ EID_FILTER_RULES_EXT_BLOCK, "Filter Rule Extended Block"},
	{ EID_MU_AREA_BLOCK, "MU Area Block"},
	{ EID_MU_LOCATION, "MU Location"},
	{ EID_MU_LOCATION_TS, "MU Location Time Stamp"},
	{ EID_DNS_IP_ADDR, "DNS IP Address"},
	{ EID_IN_SERVICE_AP_LIST, "In-Service AP List"},
	{ EID_OUT_SERVICE_AP_LIST, "Out of Service AP List"},
	{ EID_LAST_RD_AP, "Last RD AP"},
	{ EID_ROGUE_INFO, "Rogue Info"},
	{ EID_MU_IS_FT, "Enable/Disable MU Fast Transition"},
	{ EID_MU_PMK_R1, "MU Fast Transition Roaming"},
	{ EID_SIAPP_R0KHID, "SIAPP R0KH ID"},
	{ EID_SIAPP_R1KHID, "SIAPP R1KH ID"},
	{ EID_SIAPP_FT_NONCE, "SIAPP Fast Transition Nonce"},
	{ EID_SIAPP_FT_PMKR0NAME, "SIAPP Fast Transition PMKR0 Name"},
	{ EID_SIAPP_FT_R1KHID, "SIAPP Fast Transition R1KH ID"},
	{ EID_SIAPP_FT_S1KHID, "SIAPP Fast Transition S1KH ID"},
	{ EID_SIAPP_FT_PMKR1, "SIAPP Fast Transition PMKR1"},
	{ EID_SIAPP_FT_PMKR1NAME, "SIAPP Fast Transition PMKR1 Name"},
	{ EID_SIAPP_FT_PAIRWISE, "SIAPP Fast Transition Pairwise"},
	{ EID_SIAPP_FT_LIFETIME, "SIAPP Fast Transition Life Time"},
	{ EID_MU_POWER_CAP, "MU Power Capable"},
	{ EID_AREA_NAME, "Area Name"},
	{ EID_PERIODIC_NEIGHBOUR_REPORT, "Periodic Neighbour Report"},
	{ EID_TIMESTAMP, "Time Stamp"},
	{ EID_NEIGHBOUR_ENTRY, "Neighbour Entry"},
	{ EID_MU_REQ, "MU Request"},
	{ EID_RU_REQ, "RU Request"},
	{ EID_NEIGHBOUR_REQ, "Neighbour Request"},
	{ EID_SSS_FT_ASSOC, "Site Section Fast Transition Association"},
	{ EID_DEFAULT_MIRRORN, "Enables the First N Packets of a Flow to The Controller"},
	{ EID_FILTER_RULE_EXT_ACT_FLAGS, "Extension to Filter Rule Definition. Specifies Additional Actions Per Filter Rule"},
	{ EID_TOPO_GROUP_MAPPING, "Topology Group Mapping"},
	{ EID_MU_PMK_R0NAME, "MU Pairwise Master Key R0 Name"},
	{ EID_CUI, "CUI"},
	{ EID_SSS_CAPINFO, "Site Section CAP Info"},
	{ EID_SSS_CAPPOWER, "Site Section CAP Power"},
	{ EID_WFA_VSA, "WFA Vendor Specific Hotspot"},
	{ EID_WFA_HS20_REMED_METHOD, "Online Signup Method for HS2.0 Remediation"},
	{ EID_WFA_HS20_URL, "Remediation Server Url for Online Signup In HS2.0"},
	{ EID_WFA_HS20_DEAUTH_CODE, "WFA HS20 De-Authentication Code"},
	{ EID_WFA_HS20_REAUTH_DELAY, "WFA HS20 Re-Authentication Delay"},
	{ EID_WFA_HS20_SWT, "WFA HS20 SWT"},
	{ EID_POWER_STATUS, "Power Status"},
	{ EID_IPV6_ADDR, "IPV6 Address"},
	{ EID_FILTER_RULES_APP_SIG_GROUP_ID, "Filter Rule Application Signature Group ID"},
	{ EID_FILTER_RULES_APP_SIG_DISP_ID, "Filter Rule Application Signature Display ID"},
	{ EID_MU_DEV_IDENTITY, "MU Device ID"},
	{ EID_APPL_STATS_REQ, "Application Rule Stats Request"},
	{ EID_MU_APPL_STATS_BLOCK, "MU Application Rule Stats Block"},
	{ EID_TOPOLOGY_ARRAY, "Array of Topologies"},
	{ EID_TOPOLOGY_STRUCT, "Topology Struct"},
	{ EID_FILTER_CONFIG_STRUCT, "Filter Rule Configuration Struct"},
	{ EID_DHCP_HOST_NAME, "DHCP Host Name"},
	{ EID_NEIGHBOUR_ENTRY_2, "Neighbour Entry 2"},
	{ EID_CHANNEL_ENTRY, "Channel Entry"},
	{ EID_MU_ECP_PW, "MU External Captive Portal Password"},
	{ EID_MU_ECP_TOKEN, "MU External Captive Portal Token"},
	{ EID_STATIC_VSA_IPADDR, "AP Endpoint on Overlay Network IP Address"},
	{ EID_STATIC_VSA_NETMASK, "AP Endpoint on Overlay Network IP Mask"},
	{ EID_PKT_CAPTURE_STATUS, "Packet Capture Status"},
	{ EID_PKT_CAPTURE_FILTERS, "Packet Capture Filters"},
	{ EID_PKT_F_WIRELESS, "Enable Packet Capture On Wireless"},
	{ EID_PKT_F_WIREDCLIENT, "Enable Packet Capture on Wired Client"},
	{ EID_PKT_F_DIRECTION, "Packet Capture Direction"},
	{ EID_PKT_F_RADIO, "Packet Capture on Radio"},
	{ EID_PKT_F_FLAGS, "Packet Capture Flag"},
	{ EID_PKT_F_IP_ARRAY, "Array of Packet Capture IP Addresses"},
	{ EID_PKT_F_MAC, "Array of Packet Capture Mac Addresses"},
	{ EID_PKT_F_PROTOCOL, "Packet Capture On Protocol"},
	{ EID_PKT_F_PORT, "Packet Capture On Port"},
	{ EID_VSA_SSID_ID, "VSA SSID ID"},
	{ EID_MU_AUTH_TYPE, "MU Authentication Type"},
	{ EID_PKT_F_MAX_PKT_COUNT, "Max Captured Packet Count"},
	{ EID_PKT_F_FLAG_2, "Packet Capture Flag 2"},
	{ EID_IMAGE_PORT, "Image Port"},
	{ EID_FILTER_ROLE_ID, "Filter Rule ID"},
	{ EID_FILTER_ROLE_TIMESTAMP, "Time Stamp of When Role Was Last Changed"},
	{ 0, NULL }
};


static const TLV_PARSER_ENTRY tlvMainTable[]  =
{
	{ EID_UNUSED_0, "Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATUS, "Status/Action", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_SW_VERSION, "Software Version", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_SERIAL_NUMBER, "Serial Number", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_REG_CHALLENGE, "Registration Challenge", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_REG_RESPONSE, "Challenge Response", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AC_IPADDR, "Controller IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_VNSID, "AccessPoint VNS ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TFTP_SERVER, "TFTP Server Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IMAGE_PATH, "Path/Filename of Upgrade Image", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_CONFIG, "SNMP Encoded Configuration", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_STATE, "AccessPoint State", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SESSION_KEY, "Binding Key", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_PROTOCOL, "Message Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RANDOM_NUMBER, "Random Number", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STANDBY_TIMEOUT, "Standby Timeout", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_CHALLENGE_ID, "AccessPoint Challenge ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_MODEL, "AccessPoint Model", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_SCAN_MODE, "AccessPoint Scan Mode", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_SCAN_TYPE, "AccessPoint Scan Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_SCAN_INTERVAL, "AccessPoint Scan Interval", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_RADIO_TYPE, "AccessPoint Radio Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_CHANNEL_DWELL_TIME, "AccessPoint Channel Dwell Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_CHANNEL_LIST, "AccessPoint Channel List", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_TRAP, "AccessPoint Trap", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_SCAN_TIMES, "AccessPoint Scan Times", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_SCAN_DELAY, "AccessPoint Scan Delay", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_SCAN_REQ_ID, "AccessPoint Scan Request ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATIC_CONFIG, "Static Configuration", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCAL_BRIDGING, "Local Bridging", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATIC_BP_IPADDR, "Static AccessPoint IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATIC_BP_NETMASK, "Static AccessPoint NetMask", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATIC_BP_GATEWAY, "Static AccessPoint Gateway", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATIC_BM_IPADDR, "Static Controller IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BP_BPSSID, "AccessPoint BSSID", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BP_WIRED_MACADDR, "AccessPoint Wired MAC", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_CAPABILITY, "AccessPoint Capability", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_SSID_NAME, "AccessPoint SSID Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ALARM, "Alarm", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_PREAUTH, "AccessPoint Preauthorization", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_PMK, "AccessPoint Pairwise Master Key", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AC_REG_CHALLENGE, "Controller Register Challenge", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AC_REG_RESPONSE, "Controller Register Response", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS, "Stats", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_CERTIFICATE, "Certificate", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIO_ID, "Radio ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_REQ_ID, "Request ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NETWORK_ID, "Network ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_MAC, "MU MAC Address", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TIME, "Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NUM_RADIOS, "Number of Radios", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIO_INFO, "Radio Info", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NETWORK_INFO, "Network Info", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_VENDOR_ID, "Vendor ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PRODUCT_ID, "Product ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIO_INFO_ACK, "Radio Info Acknowledge", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SECURE_TUNNEL, " secure tunnel", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TOPOLOGY_ID, "MU topology ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSID, "SSID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_EVENT_BLOCK, "Event Block", TLV_TYPE_BLOCK_TLV, EVENT_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SNMP_ERROR_STATUS, "SNMP Error Status", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SNMP_ERROR_INDEX, "SNMP Error Index", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_REAUTH_TIMER, "AccessPoint ReAuthentication Timer", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_IMG_TO_RAM, "AccessPoint Image Store to RAM", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_IMG_ROLE, "AccessPoint Image Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_STATS_BLOCK, "AccessPoint Statistics Block", TLV_TYPE_BLOCK_TLV, AP_STATS_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_RF_STATS_BLOCK, "AccessPoint RF Statistics Block", TLV_TYPE_BLOCK_TLV, MU_RF_STATS_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_REQUEST_TYPE, "AccessPoint Statistics Request Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_LAST, "AccessPoint Statistics Last Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TLV_CONFIG, "TLV Configuration", TLV_TYPE_BLOCK_TLV, CONFIG_GLOBAL_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_CONFIG_ERROR_BLOCK, "AccessPoint Configuration Error Block", TLV_TYPE_BLOCK_TLV, CONFIG_ERROR_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_CONFIG_MODIFIED_BLOCK, "AccessPoint Configuration Modified Block", TLV_TYPE_BLOCK_TLV, CONFIG_ERROR_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_PMKID_LIST, "MU Pairwise Master Key List", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_PMK_BP, "MU and AccessPoint Pairwise Master Key", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_PMKID_BP, "MU and AccessPoint Pairwise Master Key ID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COUNTDOWN_TIME, "CountDown Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_WASSP_VLAN_TAG, "VLAN Tag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSID_ID, "SSID(Service Set Identifier)", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BULK_MU_BLOCK, "Bulk MU Block", TLV_TYPE_BLOCK_TLV, BULK_MU_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_BLOCK, "MU Block", TLV_TYPE_BLOCK_TLV, MU_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PORT_OPEN_FLAG, "Port Open Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_WASSP_TUNNEL_TYPE, "Tunnel Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOG_TYPE, "Log type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOG_FILE, "Log File", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ALARM_SEVERITY, "Alarm Severity", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ALARM_DESCRIPTION, "Alarm Information", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BULK_VNS_BLOCK, "Bulk VNS Block", TLV_TYPE_BLOCK_TLV, BULK_VNS_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_VNS_BLOCK, "VNS Block", TLV_TYPE_BLOCK_TLV, VNS_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_DHCP_MODE, "AccessPoint DHCP Mode", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_IPADDR, "AccessPoint IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_NETMASK, "AccessPoint IP Netmask", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_GATEWAY, "AccessPoint IP Gateway", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BSSID2IP_BLOCK, "BSSID to IP Address Mapping Block", TLV_TYPE_BLOCK_TLV, CONFIG_ERROR_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_BACKUP_VERSION, "AccessPoint Upgrade: Software Version of The Backup Image", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AC_SW_VERSION, "AccessPoint Upgrade: Software Version", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MCAST_LAMG_LIST, " Multicast Optimization", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_NAME, "Filter Rule Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_RULES, "Array of Filter Rules", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AUTH_STATE, "Authentication State( MU Not Authenticate = 0, ANON_AUTHENTICATED=0, MU Authenticated = 1", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_DISC_AFTER_AUTH, "After Authenticated MU State( Disconnected = 0, Connected = 1", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_MAC_LIST, "Array of MAC Addresses", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TRANS_ID, "Transaction ID of The Message Determined At The Home Controller", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TIMEZONE_OFFSET, "Timezone Offset", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SENSOR_FORCE_DOWNLOAD, " Force Download of Sensor Image", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SENSOR_IMG_VERSION, " Sensor Image Version", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BRIDGE_MODE, "Bridge Mode", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_VLAN_TAG, "MU VLAN Tag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RATECTRL_CIR_UL, "Up Link Bandwidth Control: Committed Information Rate (CIR)", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RATECTRL_CIR_DL, "Down Link Bandwidth Control: Committed Information Rate (CIR)", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RATECTRL_CBS_UL, "Up Link Bandwidth Control: Committed Burst Size (CBS)", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RATECTRL_CBS_DL, "Down Link Bandwidth Control: Committed Burst Size (CBS)", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RATECTRL_NAME_UL, "Up Link Bandwidth Control Profile Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RATECTRL_NAME_DL, "Down Link Bandwidth Control Profile Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_NAME, "Policy Profile Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_PMK_BLOCK, "Secure Inter-Access Point Protocol(SIAPP) Pairwise Master Key Block", TLV_TYPE_BLOCK_TLV, TAB_SIAPP_PMK_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_PMKID, "Secure Inter-Access Point Protocol(SIAPP) Pairwise Master Key ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_PMK_REAUTH, "Secure Inter-Access Point Protocol(SIAPP) Pairwise Master Key ReAuthenticate", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_PMK_LIFETIME, "Secure Inter-Access Point Protocol(SIAPP) Pairwise Master Key Life Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_PMKID_FLAG, "Secure Inter-Access Point Protocol(SIAPP) Pairwise Master Key ID Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_MU_PMK, "MU Secure Inter-Access Point Protocol(SIAPP) Pairwise Master Key", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_AP_NAME, "SIAPP AP Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_RADIO_CONFIG_BLOCK, "SIAPP Radio Configuration Block", TLV_TYPE_BLOCK_TLV, TAB_SIAPP_RADIO_CONFIG_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_CLUSTER_ACS_REQ, "SIAPP Cluster ACS Request", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_SIAPP_MU_STATS_BLOCK, "SIAPP MU Statistics Block", TLV_TYPE_BLOCK_TLV, TAB_SIAPP_MU_STATS_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_PACKET_RETRIES, "SIAPP Packet Retries", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_ASSOC_IN_WLAN, "SIAPP MU Association With In Same WLAN", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_ASSOC_IN_CLUSTER, "SIAPP MU Association With In Same Cluster", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_REASSOC_IN_CLUSTER, "SIAPP MU Reassociation With In Same Cluster", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_THIN_BLOCK, "SIAPP Thin Access Points Block", TLV_TYPE_BLOCK_TLV, TAB_SIAPP_THIN_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_NEWAP_BSSID, "SIAPP New Access Points BSSID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_OLDAP_BSSID, "SIAPP Old Access Points BSSID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_RAD_CACS_REQ, "SIAPP Radio CACS Request", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_RADIOBLOCK, "SIAPP Radio Block", TLV_TYPE_BLOCK_TLV, TAB_SIAPP_MU_STATS_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_CLIENT_COUNT, "SIAPP Client Count", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_BLOCK, "SIAPP Block", TLV_TYPE_BLOCK_TLV, TAB_SIAPP_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_MU_TransmittedFrameCount, "SIAPP MU Transmitted Frame Count", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_MU_ReceivedFrameCount, "SIAPP MU Received Frame Count", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_MU_TransmittedBytes, "SIAPP MU Transmitted Bytes", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_MU_ReceivedBytes, "SIAPP MU Received Bytes", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_MU_UL_DroppedRateControlPackets, "SIAPP MU Up Link Dropped Rate Control Packets", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_MU_DL_DroppedRateControlPackets, "SIAPP MU Down Link Dropped Rate Control Packets", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_MU_DL_DroppedBufferFullPackets, "SIAPP MU Down Link Dropped Buffer Full Packets", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_MU_DL_LostRetriesPackets, "SIAPP MU Down Link Lost Retries Packets", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_MU_UL_DroppedRateControlBytes, "SIAPP MU Up Link Dropped Rate Control Bytes", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_MU_DL_DroppedRateControlBytes, "SIAPP MU Down Link Dropped Rate Control Bytes", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_MU_DL_DroppedBufferFullBytes, "SIAPP MU Down Link Dropped Buffer Full Bytes", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_MU_DL_LostRetriesBytes, "SIAPP MU Down Link Lost Retries Bytes", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_BP_BSSID, "SIAPP  Access Points BSSID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_RADIO_ID, "SIAPP Radio ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_MACADDR, "SIAPP Mac Address", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_PREAUTH_REQ, "SIAPP Preauthentication Request", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_USER_IDENTITY, "SIAPP Client ID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_LOADBAL_BLOCK, "SIAPP Load Balance Block", TLV_TYPE_BLOCK_TLV, CONFIG_ERROR_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_LOADBAL_PKT_TYPE, "SIAPP Load Balance PKT Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_LOADBAL_LOADGROUP_ID, "SIAPP Load Balance Load Group ID", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_LOADBAL_LOAD_VALUE, "SIAPP Load Balance Load Value", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_AC_MGMT_MAC, "SIAPP Controller Management Mac Address", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_FILTER_COS, "SIAPP Filter Rule COS", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COS, "Classes of Service(COS)", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RATE_LIMIT_RESOURCE_TBL, "Bandwidth Control Rate Limit Resource Table", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_UCAST_FILTER_DISABLE, "Unicast Filter Disable Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_INFORM_REASON, "MU Information", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_FILTER_POLICY_NAME, "MU Filter Rule Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TOPOLOGY_POLICY_NAME, "MU Topology Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_COS_POLICY_NAME, "MU COS Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_FILTER_KEY, "MU Filter Rule ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TOPOLOGY_KEY, "MU Topology ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_COS_KEY, "MU COS ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_SESSION_TIMEOUT, "MU Session Life Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ACCOUNTING_CLASS, "MU Accounting Class", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_LOGIN_LAT_PORT, "MU Login authentication state(0 = Non-auth, 1 = Auth)", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_IDLE_TIMEOUT, "MU Session Idle Timeout", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ACCT_INTERIM_INTERVAL, "Client Acct-Interim-Interval(RADIUS)", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_IP_ADDR, "MU IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TERMINATE_ACTION, "MU Terminate Action", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SITE_NAME, "Site Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PEER_SITE_IP, "Peer Site IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_INTERFERENCE_EVENTS_ENABLE, "Interference Events Enable Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_EVENT_TYPE, "Event Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_EVENT_CHANNEL, " Event Channel", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_EVENT_VALUE, "Event Value", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSS_MU_BLOCK, "Site Section MU Block", TLV_TYPE_BLOCK_TLV, TAB_SSS_MU_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSS_MU_ASSOC_TIME, "Site Section MU Association Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSS_TS64_MU_UPDATE, "Site Section MU Update Time Stamp", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSS_TS64_AP_CURRENT, "Site Section AccessPoint Current Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSS_MU_AUTH_STATE, "Site Section MU Authentication State", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSS_AP_HOMEHASH, "Site Section AccessPoint Home Hashed Value", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TIME_FIRST_DETECTED, "First Detected Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TIME_LAST_REPORTED, "Last Reported Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_EVENT_ARRAY, "Array Of Events", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSS_DEFAULT_SESSION_TIMEOUT, "Site Section Default Timeout Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSS_SSID, "Site Section SSID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSS_PRIVACY_TYPE, "Site Section Privacy Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_ZONE_NAME, "Policy Zone Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_AC_EVENT_COMPONENT_ID, "Event Component ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_AUTH_STATE, "MU Authentication State", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_USER_NAME, "MU User Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BULK_TYPE, "Bulk Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SENT_TIME, "Sent Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_INFORM_MU_PMK, "Pairwise Master Key Informed From AP", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COLLECTOR_IP_ADDR, "Collector IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ EID_ARP_PROXY, "Enable/Disable Proxying of ARP Per Topology", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MCAST_FILTER_RULES, "Multicast Filter Rules Per Topology", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_PARAMS, "AP Parameters", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ASSOC_SSID_ARRAY, "Array of Associated SSID", TLV_TYPE_BLOCK_TLV, TAB_ASSOC_SSID_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ASSOC_SSID_BLOCK, "Block of Associated SSID", TLV_TYPE_BLOCK_TLV, TAB_ASSOC_SSID_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_LIST_BLOCK, "Bloc of AP List", TLV_TYPE_BLOCK_TLV, TAB_AP_LIST_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_LIST_ARRAY, " Array of AP List", TLV_TYPE_BLOCK_TLV, TAB_AP_LIST_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MAC_ADDR, "MAC Address", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SCAN_PROFILE_ID, "Scan Profile ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ACTION_REQ, "Action Request", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_CHANNEL_LIST, "Channel List", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COUNTERMEASURES_MAX_CH, "CounterMeasures Max Channel", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COUNTERMEASURES_SET, "Enable/disable CounterMeasures", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SCAN_PROFILE_BLOCK, "Scan Profile Block", TLV_TYPE_BLOCK_TLV, TAB_SCAN_PROFILE_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SEQ_NUM, "Sequence Number", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_DEF_ARRAY, "Array Of Threat Definition", TLV_TYPE_BLOCK_TLV, TAB_THREAT_DEF_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_DEF_BLOCK, "Block Of Threat Definition", TLV_TYPE_BLOCK_TLV, TAB_THREAT_DEF_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_TYPE, "Threat Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_ID, "Threat ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_STATS_F, "Threat State", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_FR_SFR, "Threat FR SFR", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_PATTERN_ARRAY, "Array Of Threat Pattern", TLV_TYPE_BLOCK_TLV, TAB_THREAT_PATTERN_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_PATTERN_BLOCK, "Block Of Threat Pattern", TLV_TYPE_BLOCK_TLV, TAB_THREAT_PATTERN_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_PATTERN, "Threat Pattern", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_ALERT_TH_DUR, "Threat Alert", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_CLEAR_TH_DUR, "Threat Clear", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_PRIORITY, "Threat Priority", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_MITIGATION_LIST, "Threat Mitigation List", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSS_MU_IS_PORT_CLOSED, "Enable/Disable Site Section MU Port", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FULL_UPDATE, "Full Update", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_REASON, "Reason", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SURVEILLANCE_DATA_ARRAY, "Array of Surveillance Data", TLV_TYPE_BLOCK_TLV, TAB_SURVEILLANCE_DATA_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SURVEILLANCE_DATA_BLOCK, "Block of Surveillance Data", TLV_TYPE_BLOCK_TLV, TAB_SURVEILLANCE_DATA_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SCAN_BSSID, "Scan BSSID", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PARAMS, "Parameters", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SCAN_RSS_RSSI, "Scan RSS and RSSI", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SCAN_SSID, "Scan SSID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SCAN_CAP, "Scan Capability", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_CLASSIFICATION, "Threat Classification", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_DATA_ARRAY, "Array Of Threat Data", TLV_TYPE_BLOCK_TLV, TAB_THREAT_DATA_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_DATA_BLOCK, "Block Of Threat Data", TLV_TYPE_BLOCK_TLV, TAB_THREAT_DATA_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATE, "State", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DROP_FR_CNT, "Drop FR Count", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STOP_ROAM_CNT, "Stop ROAM Count", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SPOOF_CNT, "Spoof Count", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_CLASSIFY_ARRAY, "Array Of Classify Threat", TLV_TYPE_BLOCK_TLV, TAB_THREAT_CLASSIFY_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_CLASSIFY_BLOCK, "Block Of Classify Threat", TLV_TYPE_BLOCK_TLV, TAB_THREAT_CLASSIFY_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_THREAT_NAME, "Threat Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATION, "Location", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ENCRYPTION_TYPE, "Encryption Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_EVENT_ARRAY, "Array Of MU Events", TLV_TYPE_BLOCK_TLV, TAB_MU_EVENT_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_EVENT_BLOCK, "Block Of MU Events", TLV_TYPE_BLOCK_TLV, TAB_MU_EVENT_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COMPONENT_ID, "Component ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_EVENT_STRING, "MU Event String", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BYPASS_BMCAST, "Bypass Broadcast and Multicast", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_GETTIMEOFDAY, "Get Time of Day", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COUNTRY_ID, "Country ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COUNTRY_ARRAY, "Array of Country", TLV_TYPE_BLOCK_TLV, TAB_COUNTRY_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COUNTRY_BLOCK, "Country Block", TLV_TYPE_BLOCK_TLV, TAB_COUNTRY_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_EVENT_TYPE, "MU Event Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATOR_FLOOR_ID, "Floor ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATOR_LOC_TYPE, "Location Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATOR_LOC_BLOCK, "Block of Location Data", TLV_TYPE_BLOCK_TLV, TAB_LOCATOR_LOC_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATOR_LOC_ARRAY, "Array of Location Data", TLV_TYPE_BLOCK_TLV, TAB_LOCATOR_LOC_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATOR_LOC_POINT, "Location Point", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_EVENT_DETAILS, "MU Event Details", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_EVENT_FROM_AP, "MU Event From AP", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_EVENT_LOC_BLOCK, "Block of MU Location Event", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATOR_LOC_AP_DISTANCE, "AP Location Distance", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATOR_LOC_PRECISION, "Location Precision", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RSS_DATA_ARRAY, "Array of RSS Data", TLV_TYPE_BLOCK_TLV, TAB_RSS_DATA_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RSS_DATA_BLOCK, "Block  of RSS Data", TLV_TYPE_BLOCK_TLV, TAB_RSS_DATA_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATOR_MU_ACTION, "Location MU Action", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_EFFECTIVE_EGRESS_VLAN, "Effective Egress Vlan", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_REBOOT_ACK, "Reboot Acknowledgement", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_BSSID, "MU BSSID", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AUTH_FLAG, "Authentication Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ROAMED_FLAG, "ROAMED Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_RSS, "MU RSS", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_RULES_VER, "Filter Rule Struct Version", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_TYPE, "Filter Rule Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MCAST_FILTER_BLOCK, "Multicast Filter Rule Block", TLV_TYPE_BLOCK_TLV, TAB_MCAST_FILTER_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MCAST_FILTER_BLOCK_ENTRY, "Multicast Filter Rule Block Entry", TLV_TYPE_BLOCK_TLV, TAB_MCAST_FILTER_BLOCK_ENTRY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DEFAULT_ACTION_TYPE, "Default Action Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DEFAULT_CONTAIN_TO_VLAN, "Default Contain to Vlan Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DEFAULT_BRIDGE_MODE, "Default Bridge Mode Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_INVALID_POLICY, "Invalid Policy Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATOR_FLOOR_NAME, "Floor Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_FLAGS, "AP Flags", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_PVID, "AP PVID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_REDIRECT, "AP Redirect Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_CVLAN_BAP, "AP Contain to Vlan Has Bridge At AP Topology Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_SESSION_ARRAY, "Array Of MU Session", TLV_TYPE_BLOCK_TLV, TAB_MU_SESSION_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_SESSION_BLOCK, "MU Session Block", TLV_TYPE_BLOCK_TLV, TAB_MU_SESSION_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_SESSION_ID, "MU Session ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_RFS_NAME, "MU RFS Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_FLAGS, "MU Flags", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ASSOC_TIME, "MU Associated Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ACTIVE_TIME, "MU Actived Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_REPORT_REQ, "Report Request", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_URL, "MU Captive Portal Url", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_SESSION_LIFETIME, "MU Session Life Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_REAUTH_TIMER, "MU Re-Authentication Timer", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ACCT_SESSION_ID_STRING, "MU Acct Session ID String", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ACCT_POLICY_NAME, "MU Acct Policy Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ACCT_START_TIME, "MU Acct Start Time", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ACCT_CLASS, "MU Acct Class", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_LOGIN_LAT_GROUP, "MU Login Group", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TUNNEL_PRIVATE_GROUP_ID_STRING, "MU Tunnel Private Group ID String", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_USER_ID_STRING, "MU User ID String", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_DEFENDED_STATE, "MU Defended State", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_MOD_MASK, "MU Modulation Maske", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATOR_TRACKED, "Locator Tracked", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PORT, "Port", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RETRIES_COUNT, "Retries Count", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MODULATION_TYPE, "Modulation Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DETECTED_ROGUE_ARRAY, "Array Of Detected Rogue", TLV_TYPE_BLOCK_TLV, TAB_DETECTED_ROGUE_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DETECTED_ROGUE_BLOCK, "Detected Rogue Block", TLV_TYPE_BLOCK_TLV, TAB_DETECTED_ROGUE_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ROGUE_DETECTION, "Rogue Detection", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MAC_ADDR_TX, "Tx Mac Address", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MAC_ADDR_RX, "Rx Mac Address", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IP_ADDR_TX, "Tx IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IP_ADDR_RX, "Rx IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TTL, "TTL", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_GW_IP_ADDR, "Gateway IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATOR_STATE_DATA, "Location State Data", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATOR_POINT_SET, "Location Point Set", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_RULE_FIXED_APP_ID, "Filter Rule Fixed Application ID", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_RULES_EXT_BLOCK, "Filter Rule Extended Block", TLV_TYPE_BLOCK_TLV, TAB_FILTER_RULES_EXT_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_AREA_BLOCK, "MU Area Block", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_LOCATION, "MU Location", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_LOCATION_TS, "MU Location Time Stamp", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DNS_IP_ADDR, "DNS IP Address", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IN_SERVICE_AP_LIST, "In-Service AP List", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_OUT_SERVICE_AP_LIST, "Out of Service AP List", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LAST_RD_AP, "Last RD AP", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ROGUE_INFO, "Rogue Info", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_IS_FT, "Enable/Disable MU Fast Transition", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_PMK_R1, "MU Fast Transition Roaming", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_R0KHID, "SIAPP R0KH ID", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_R1KHID, "SIAPP R1KH ID", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_FT_NONCE, "SIAPP Fast Transition Nonce", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_FT_PMKR0NAME, "SIAPP Fast Transition PMKR0 Name", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_FT_R1KHID, "SIAPP Fast Transition R1KH ID", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_FT_S1KHID, "SIAPP Fast Transition S1KH ID", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_FT_PMKR1, "SIAPP Fast Transition PMKR1", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_FT_PMKR1NAME, "SIAPP Fast Transition PMKR1 Name", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_FT_PAIRWISE, "SIAPP Fast Transition Pairwise", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_FT_LIFETIME, "SIAPP Fast Transition Life Time", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_POWER_CAP, "MU Power Capable", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AREA_NAME, "Area Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PERIODIC_NEIGHBOUR_REPORT, "Periodic Neighbour Report", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TIMESTAMP, "Time Stamp", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NEIGHBOUR_ENTRY, "Neighbour Entry", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_REQ, "MU Request", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RU_REQ, "RU Request", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NEIGHBOUR_REQ, "Neighbour Request", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSS_FT_ASSOC, "Site Section Fast Transition Association", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DEFAULT_MIRRORN, "Enables the First N Packets of a Flow to The Controller", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_RULE_EXT_ACT_FLAGS, "Extension to Filter Rule Definition. Specifies Additional Actions Per Filter Rule", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TOPO_GROUP_MAPPING, "Topology Group Mapping", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_PMK_R0NAME, "MU Pairwise Master Key R0 Name", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_CUI, "CUI", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSS_CAPINFO, "Site Section CAP Info", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SSS_CAPPOWER, "Site Section CAP Power", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_WFA_VSA, "WFA Vendor Specific Hotspot", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_WFA_HS20_REMED_METHOD, "Online Signup Method for HS2.0 Remediation", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_WFA_HS20_URL, "Remediation Server Url for Online Signup In HS2.0", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_WFA_HS20_DEAUTH_CODE, "WFA HS20 De-Authentication Code", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_WFA_HS20_REAUTH_DELAY, "WFA HS20 Re-Authentication Delay", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_WFA_HS20_SWT, "WFA HS20 SWT", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POWER_STATUS, "Power Status", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IPV6_ADDR, "IPV6 Address", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_RULES_APP_SIG_GROUP_ID, "Filter Rule Application Signature Group ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_RULES_APP_SIG_DISP_ID, "Filter Rule Application Signature Display ID", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_DEV_IDENTITY, "MU Device ID", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_APPL_STATS_REQ, "Application Rule Stats Request", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_APPL_STATS_BLOCK, "MU Application Rule Stats Block", TLV_TYPE_BLOCK_TLV, TAB_MU_APPL_STATS_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TOPOLOGY_ARRAY, "Array of Topologies", TLV_TYPE_BLOCK_TLV, TAB_TOPOLOGY_ARRAY_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TOPOLOGY_STRUCT, "Topology Struct", TLV_TYPE_BLOCK_TLV, TAB_TOPOLOGY_STRUCT_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_CONFIG_STRUCT, "Filter Rule Configuration Struct", TLV_TYPE_BLOCK_TLV, TAB_FILTER_CONFIG_STRUCT_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DHCP_HOST_NAME, "DHCP Host Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NEIGHBOUR_ENTRY_2, "Neighbour Entry 2", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_CHANNEL_ENTRY, "Channel Entry", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ECP_PW, "MU External Captive Portal Password", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ECP_TOKEN, "MU External Captive Portal Token", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATIC_VSA_IPADDR, "AP Endpoint on Overlay Network IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATIC_VSA_NETMASK, "AP Endpoint on Overlay Network IP Mask", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PKT_CAPTURE_STATUS, "Packet Capture Status", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PKT_CAPTURE_FILTERS, "Packet Capture Filters", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PKT_F_WIRELESS, "Enable Packet Capture On Wireless", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PKT_F_WIREDCLIENT, "Enable Packet Capture on Wired Client", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PKT_F_DIRECTION, "Packet Capture Direction", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PKT_F_RADIO, "Packet Capture on Radio", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PKT_F_FLAGS, "Packet Capture Flag", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PKT_F_IP_ARRAY, "Array of Packet Capture IP Addresses", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PKT_F_MAC, "Array of Packet Capture Mac Addresses", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PKT_F_PROTOCOL, "Packet Capture On Protocol", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PKT_F_PORT, "Packet Capture On Port", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_VSA_SSID_ID, "VSA SSID ID", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_AUTH_TYPE, "MU Authentication Type", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PKT_F_MAX_PKT_COUNT, "Max Captured Packet Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PKT_F_FLAG_2, "Packet Capture Flag 2", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IMAGE_PORT, "Image Port", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_ROLE_ID, " Filter Rule ID", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_ROLE_TIMESTAMP, " Time Stamp of When Role Was Last Changed", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MAX, "EID_MAX", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0}
};





typedef enum
{
	EID_CONFIG_UNUSED_0 = 0,
	EID_RADIO_CONFIG_BLOCK,
	EID_VNS_CONFIG_BLOCK,
	EID_AP_ROLE,
	EID_LOC_ACTION_REQ,
	EID_TRACE_STATUS_DEBUG,
	EID_TRACE_STATUS_CONFIG,
	EID_MIC_ERR,
	EID_USE_BCAST_FOR_DISASSC,
	EID_BANDWIDTH_VOICE_ASSC,
	EID_BANDWIDTH_VOICE_REASSC,
	EID_BANDWIDTH_VIDEO_ASSC,
	EID_BANDWIDTH_VIDEO_REASSC,
	EID_BANDWIDTH_VIDEO_RESERVE,
	EID_BANDWIDTH_ADM_CTRL_RESERVE,
	EID_VLAN_TAG,
	EID_COUNTRY_CODE,
	EID_POLL_DURATION,
	EID_POLL_INTERVAL,
	EID_LOC_AUTO_COLLECT_ENABLE,
	EID_POLL_MAINTAIN_CLIENT_SESSION,
	EID_TELNET_ENABLE,
	EID_TELNET_PASSWORD,
	EID_TELNET_PASSWORD_ENTRY_MODE,
	EID_OUTDOOR_ENABLE,
	EID_ON_DEMAND_ARRAY,
	EID_LAG_ENABLED,
	EID_APP_POLICY_FIXED_BLOCK,
	EID_SLP_RETRY_COUNT,
	EID_SLP_RETRY_DELAY,
	EID_DNS_RETRY_COUNT,
	EID_DNS_RETRY_DELAY,
	EID_MCAST_SLP_RETRY_COUNT,
	EID_MCAST_SLP_RETRY_DELAY,
	EID_DISC_RETRY_COUNT,
	EID_DISC_RETRY_DELAY,
	EID_LOGGING_ALARM_SEV,
	EID_BLACKLIST_ADD,
	EID_FAILOVER_AC_IP_ADDR,
	EID_STATIC_AC_IP_ADDR,
	EID_DHCP_ASSIGNMENT,
	EID_STATIC_AP_IP_ADDR,
	EID_STATIC_AP_IP_NETMASK,
	EID_STATIC_AP_DEFAULT_GW,
	EID_BLACKLIST_DEL,
	EID_MACADDR_REQ,
	EID_AVAILABILITY_MODE,
	EID_AP_PERSISTENCE,
	EID_FOREIGN_AP,
	EID_SUPP1X_CREDENTIAL_REMOVE,
	EID_SUPP1X_CERT_TFTP_IP,
	EID_SUPP1X_CERT_TFTP_PATH,
	EID_SUPP1X_PRIVATE,
	EID_SUPP1X_DOMAIN,
	EID_SUPP1X_USERID,
	EID_SUPP1X_PASSWORD,
	EID_SUPP1X_CREDENT,
	EID_SUPP1X_SERIAL,
	EID_SUPP1X_START_DATE,
	EID_SUPP1X_END_DATE,
	EID_SUPP1X_ISSUED_BY,
	EID_SUPP1X_ISSUED_TO,
	EID_SUPP1X_SUBJALTNAME,
	EID_NOT_USED_CONFIG_TLV_63,
	EID_FAILOVER_AC_HOME_IP_ADDR,
	EID_FAILOVER_AC_FOREIGN_IP_ADDR,
	EID_AP_HOSTNAME,
	EID_LLDP_ENABLED,
	EID_LLDP_TTL,
	EID_LLDP_ANNOUNCEMENT_INT,
	EID_LLDP_ANNOUNCEMENT_DELAY,
	EID_VOWIFI_EXPIRATION_TIME,
	EID_MOBILITY_SHARED_KEY,
	EID_CHANNEL_REPORT_2_4G,
	EID_CHANNEL_REPORT_5G,
	EID_RATE_CONTROL_BLOCK,
	EID_AP_DNS,
	EID_STATIC_MTU,
	EID_MACFILTER_MODE,
	EID_SITE_CONFIG_BLOCK,
	EID_TOPOLOGY_BLOCK,
	EID_AP_NAME,
	EID_ANTENNA_MODELS,
	EID_AIRTIME_FAIRNESS_LEVEL,
	EID_VLAN_DEFAULT,
	EID_CLUSTER_PASSWORD,
	EID_SIAPP_PRIVACY,
	EID_LED_STATUS,
	EID_LBS_SRC_IP,
	EID_LBS_SRC_PORT,
	EID_LBS_DST_IP,
	EID_LBS_DST_PORT,
	EID_LBS_MCAST,
	EID_LBS_TAG_MODE,
	EID_ETH_PORT_MODE,
	EID_INTER_AP_ROAM,
	EID_MGMT_MAC,
	EID_REAL_CAPTURE_TIMEOUT,
	EID_POLICY_BLOCK,
	EID_FILTER_CONFIG_BLOCK,
	EID_COS_CONFIG_BLOCK,
	EID_LOCATION_BASED_LOOKUP_BLOCK,
	EID_RADIUS_SERVER_BLOCK,
	EID_DISC_RETRY_DELAY_WOUI_ADD,
	EID_DISC_RETRY_DELAY_WOUI_DEL,
	EID_SNIFFER_RADIO_BITMAP,
	EID_MCAST_ASSEMB,
	EID_JUMBO_FRAME,
	EID_DYN_ON_DEMAND_ARRAY,
	EID_BANDWIDTH_BE_ASSC,
	EID_BANDWIDTH_BE_REASSC,
	EID_BANDWIDTH_BK_ASSC,
	EID_BANDWIDTH_BK_REASSC,
	EID_NETFLOW_EXPORT_INTERVAL,
	EID_MIRRORN_PACKETS,
	EID_ICON_NAME,
	EID_ICON_FILE,
	EID_ICON_BLOCK,
	EID_BOARD_STATUS,
	EID_CP_MU_AUTO_LOGIN,
	EID_EXTAPP_CONF_BLOCK,
	EID_RB_REDIRECT,
	EID_RB_REDIRECT_PORTS,
	EID_S_TOPOLOGY_ARRAY,
	EID_S_TOPOLOGY_STRUCT,
	EID_S_TOPOLOGY_KEY,
	EID_S_TOPOLOGY_VLAN_TAG,
	EID_S_TOPOLOGY_ARP_PROXY,
	EID_S_TOPO_MCAST_FILTER_CONFIG_BLOCK,
	EID_MCAST_PRIORITIZED_VOICE,
	EID_IOT_CONTROL,
	EID_IOT_APPLICATION_ID,
	EID_AP_LOCATION,
	EID_IOT_ADMIN,
	EID_IOT_IMAGE,
	EID_IOT_BLE_ADVERTISE_INTERVAL,
	EID_IOT_BLE_ADVERTISE_POWER,
	EID_IOT_IBEACON_MAJOR,
	EID_IOT_IBEACON_MINOR,
	EID_IOT_IBEACON_UUID,
	EID_STATIC_ADSP_IP_ADDR,
	EID_OBSS_CHAN_ADJ_ACTIVE,
	EID_IOT_BLE_SCAN_SRC_IP,
	EID_IOT_BLE_SCAN_SRC_PORT,
	EID_IOT_BLE_SCAN_DST_IP,
	EID_IOT_BLE_SCAN_DST_PORT,
	EID_IOT_BLE_SCAN_INTERVAL,
	EID_IOT_BLE_SCAN_WINDOW,
	EID_IOT_BLE_SCAN_MIN_RSSI,
	EID_LISENSE_SERVER,
	EID_LISENSE_MIN_RSSI,
	EID_LISENSE_REP_FREQ,
	EID_DPI_SIG_HASH,
	EID_ANT_MODELS_IOT,
	EID_FABRICATTACH_ARRAY,
	EID_IOT_THREAD_CHANNEL,
	EID_IOT_THREAD_FACTORY_RESET,
	EID_IOT_THREAD_SHORT_PAN_ID,
	EID_IOT_THREAD_SHORT_EUI,
	EID_IOT_THREAD_PSKD,
	EID_IOT_THREAD_MASTER_KEY,
	EID_IOT_THREAD_NWK_NAME,
	EID_IOT_THREAD_COMM_CREDENTIAL,
	EID_IOT_THREAD_LONG_EUI,
	EID_IOT_THREAD_EXTENDED_PAN_ID,
	EID_AP_VSA_SSID_ID,
	EID_AP_STATIC_VSA_IPADDR,
	EID_AP_STATIC_VSA_NETMASK,
	EID_IOT_BLE_URL,
	EID_AP_PERSONALITY,
	EID_ADSP_RADIO_SHARE,
	EID_LOCATION_TENANT_ID,
	EID_IOT_BLE_BEACON_MEASURED_RSSI,
	EID_MU_NUM_RADAR_BACK
} wassp_subtlv_config_type_t;

/***************************************************
  get define from packet-wassp.h 's   wassp_subtlv_config_type_t  struct

****************************************************/

static const TLV_PARSER_ENTRY tlvGlobalConfigTable[]  =
{
	{ EID_CONFIG_UNUSED_0, "Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIO_CONFIG_BLOCK, "Radio Configuration Block", TLV_TYPE_BLOCK_TLV, RADIO_CONFIG_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_VNS_CONFIG_BLOCK, "VNS Configuration Block", TLV_TYPE_BLOCK_TLV, VNS_CONFIG_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_ROLE, "AccessPoint Role(0 - Traffic Forwarder, 1 - Dedicated Scanner, 2 - ADSP Sensor)", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOC_ACTION_REQ, "Enable RSS Collection for Positioning Engine Request", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TRACE_STATUS_DEBUG, "Enable Trace Debug", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TRACE_STATUS_CONFIG, "Enable Trace Configuration", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MIC_ERR, "Message Integrity Check on AP26xx", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_USE_BCAST_FOR_DISASSC, "Use Broadcast for Client Disassociation", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BANDWIDTH_VOICE_ASSC, "Admission Control: Maximum Bandwidth for Voice Clients", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BANDWIDTH_VOICE_REASSC, "Admission Control: Maximum Bandwidth for Reassociation of Voice Clients", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BANDWIDTH_VIDEO_ASSC, "Admission Control: Maximum Bandwidth for Video Clients", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BANDWIDTH_VIDEO_REASSC, "Admission Control: Maximum Bandwidth for Reassociation of Video Clients", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BANDWIDTH_VIDEO_RESERVE, "Admission Control: Maximum Bandwidth for Reserve of Video Clients", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BANDWIDTH_ADM_CTRL_RESERVE, "Admission Control: Maximum Bandwidth for Reserve of Admin", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_VLAN_TAG, "VLAN Tag of AP Uplink", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COUNTRY_CODE, "Country Code", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLL_DURATION, "Poll Timeout in Seconds", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLL_INTERVAL, "Poll Interval in Seconds", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOC_AUTO_COLLECT_ENABLE, "Enable Auto Collection of RSS for Positioning Engine", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLL_MAINTAIN_CLIENT_SESSION, "Enable Maintaining of Client Session When Poll to Controller Times Out", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TELNET_ENABLE, "Enable SSH Access to AP", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TELNET_PASSWORD, "Hash SSH Password", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TELNET_PASSWORD_ENTRY_MODE, "Telnet Password Entry Mode", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_OUTDOOR_ENABLE, "AP Environment (1 - Indoor, 2 - Outdoor)", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ON_DEMAND_ARRAY, "Array of MAC Addresses to Collect RSS for Positioning Engine (each element is 6 bytes)", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LAG_ENABLED, "Enable Link Aggregation on Uplink Ethernet Ports", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_APP_POLICY_FIXED_BLOCK, "Application Definition for Layer 4 Filters ", TLV_TYPE_BLOCK_TLV, TAB_APP_POLICY_FIXED_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SLP_RETRY_COUNT, "Retry Count for SLP Discovery", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SLP_RETRY_DELAY, "Delay Between SLP Retries", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DNS_RETRY_COUNT, "Retry Count for DNS Discovery", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DNS_RETRY_DELAY, "Delay Between DNS Retries", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MCAST_SLP_RETRY_COUNT, "Retry Count for Multicast SLP Discovery", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MCAST_SLP_RETRY_DELAY, "Delay Between Multicast SLP Retries", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DISC_RETRY_COUNT, "Retry Count for Discovery", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DISC_RETRY_DELAY, "Delay Between Discovery Retries", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOGGING_ALARM_SEV, "Minimum Severity of Event to Report", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BLACKLIST_ADD, "Add Clients to MAC Access List", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FAILOVER_AC_IP_ADDR, "Array of Controllers IP Addresses for Legacy Failover", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATIC_AC_IP_ADDR, "Array of Static Controller IP Addresses", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DHCP_ASSIGNMENT, "Uplink IP Address Assignment (0 - Static, 1 - DHCP)", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATIC_AP_IP_ADDR, "Uplink Static IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATIC_AP_IP_NETMASK, "Uplink Netmask", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATIC_AP_DEFAULT_GW, "Uplink Default Gateway", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BLACKLIST_DEL, "Remove Clients from MAC Access List", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MACADDR_REQ, "Request to Send Radio BSSIDs in Config Acknowledge", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AVAILABILITY_MODE, "Availability Mode", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_PERSISTENCE, "Keep Client Sessions When Connection to Controller Times Out", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FOREIGN_AP, "Home AP = 0, Foreign AP = 1", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SUPP1X_CREDENTIAL_REMOVE, "Remove Credential from AP,type: bitmask (1 - EAP-TLS, 2 - PEAP)", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SUPP1X_CERT_TFTP_IP, "TFTP Server IP Address for EAP-TLS Credential", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SUPP1X_CERT_TFTP_PATH, "TFTP Path for EAP-TLS Credential", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SUPP1X_PRIVATE, "EAP-TLS Private Key, Blowfish Encrypted", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SUPP1X_DOMAIN, "Community Domain", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SUPP1X_USERID, "PEAP User Id", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SUPP1X_PASSWORD, "PEAP Password, Blowfish Encrypted", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SUPP1X_CREDENT, "Credential Configuration of AP", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SUPP1X_SERIAL, "Certificate Serial", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SUPP1X_START_DATE, "Certificate Start Date", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SUPP1X_END_DATE, "Certificate Expiry Date", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SUPP1X_ISSUED_BY, "Certificate Issuer Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SUPP1X_ISSUED_TO, "Certificate Issued to Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SUPP1X_SUBJALTNAME, "Certificate Subject Alternative Name (Required From Microsoft)", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NOT_USED_CONFIG_TLV_63, "Not Used", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FAILOVER_AC_HOME_IP_ADDR, "Array of Home Controller IP Addresses", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FAILOVER_AC_FOREIGN_IP_ADDR, "Array of Foreign Controller IP Addresses", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_HOSTNAME, "AP Hostname", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LLDP_ENABLED, "Enable LLDP", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LLDP_TTL, "LLDP Time To Live", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LLDP_ANNOUNCEMENT_INT, "LLDP Announcement Interval", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LLDP_ANNOUNCEMENT_DELAY, "LLDP Announcement Delay", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_VOWIFI_EXPIRATION_TIME, "Voice Over WiFi Expiration Time", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MOBILITY_SHARED_KEY, "Encrypted With Blowfish Using AP Serial Number As Seed", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_CHANNEL_REPORT_2_4G, "Channel Report Based On 2.4GHz", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_CHANNEL_REPORT_5G, "Channel Report Based On 5GHz", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RATE_CONTROL_BLOCK, "Rate Control Block For Site", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_DNS, "AP DNS", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATIC_MTU, "Uplink Static MTU", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MACFILTER_MODE, "MAC Access List Mode (1 - Blacklist, 2 - Whitelist)", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SITE_CONFIG_BLOCK, "Configuration Block for Site", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TOPOLOGY_BLOCK, "Topology Configuration Block for Site", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_NAME, "AP Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ANTENNA_MODELS, "Array of Antenna Model IDs", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AIRTIME_FAIRNESS_LEVEL, "Airtime Fairness Level: 0-4", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_VLAN_DEFAULT, "Thick AP Default Vlan (Untagged: -1,  Vlan: 0~4094)", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_CLUSTER_PASSWORD, "SIAPP Cluster Password", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SIAPP_PRIVACY, "Enable SIAPP Encryption", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LED_STATUS, "LED Status (0 - Off, 1 - WDS Signal Strength, 2 - Locate, 3 - Normal)", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LBS_SRC_IP, "Location Base Service Source IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LBS_SRC_PORT, "Location Base Service Source Port", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LBS_DST_IP, "Location Base Service Destination IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LBS_DST_PORT, "Location Base Service Destination Port", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LBS_MCAST, "Location Base Service Multicast", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LBS_TAG_MODE, "Location Base Service Tag Mode", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ETH_PORT_MODE, "Ethernet Port Mode", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_INTER_AP_ROAM, "Inter AP Roam", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MGMT_MAC, "Management Mac Address", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_REAL_CAPTURE_TIMEOUT, "Real Capture Time Out", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_BLOCK, "Policy Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_POLICY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_CONFIG_BLOCK, "Filter Rule Configuration Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_FILTER, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COS_CONFIG_BLOCK, "COS Configuration Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_COS, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATION_BASED_LOOKUP_BLOCK, "Location Based Lookup Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_LOC_BASE_LP, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIUS_SERVER_BLOCK, "RADIUS Server Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_RADIUS_SERVER, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DISC_RETRY_DELAY_WOUI_ADD, "Blacklist WOUI Add", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DISC_RETRY_DELAY_WOUI_DEL, "Blacklist WOUI Delete", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SNIFFER_RADIO_BITMAP, "Sniffer Radio Bit Map", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MCAST_ASSEMB, "Multicast Assemble", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_JUMBO_FRAME, "Jumbo Frame", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DYN_ON_DEMAND_ARRAY, "Location Dynamic On-demand MAC List", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BANDWIDTH_BE_ASSC, "Best Effort Bandwidth for Association", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BANDWIDTH_BE_REASSC, "Best Effort Bandwidth for Reassociation", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BANDWIDTH_BK_ASSC, "Background Bandwidth for Association", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BANDWIDTH_BK_REASSC, "Background Bandwidth for Reassociation", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NETFLOW_EXPORT_INTERVAL, "Netflow Export Interval", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MIRRORN_PACKETS, "MirrorN Packets", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ICON_NAME, "Hotspot 2.0 ICON Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ICON_FILE, "Hotspot 2.0 ICON File", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ICON_BLOCK, "Hotspot 2.0 ICON Block", TLV_TYPE_BLOCK_TLV, VNS_CONFIG_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BOARD_STATUS, "Board Status", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_CP_MU_AUTO_LOGIN, "Client Auto Login Handling: 0 : Hide Auto Login, 1 : Redirect Auto Login, 2 : Drop Auto Login", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_EXTAPP_CONF_BLOCK, "Application Control Configuration Block", TLV_TYPE_BLOCK_TLV, TAB_EXTAPP_CONF_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RB_REDIRECT, "Role Based Redirection", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RB_REDIRECT_PORTS, "Role Based Redirection Ports", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_S_TOPOLOGY_ARRAY, "Array of Site Topologies", TLV_TYPE_BLOCK_TLV, TAB_S_TOPOLOGY_ARRAY_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_S_TOPOLOGY_STRUCT, "Site Topology Struct", TLV_TYPE_BLOCK_TLV, TAB_S_TOPOLOGY_STRUCT_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_S_TOPOLOGY_KEY, "Site Topology Key", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_S_TOPOLOGY_VLAN_TAG, "Site Topology Vlan Tag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_S_TOPOLOGY_ARP_PROXY, "Site Topology Arp Proxy", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_S_TOPO_MCAST_FILTER_CONFIG_BLOCK, "Site Topology  Multicast Filter Configuration Block", TLV_TYPE_BLOCK_TLV, TAB_S_TOPO_MCAST_FILTER_CONFIG_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MCAST_PRIORITIZED_VOICE, "Multicast Prioritized Voice", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_CONTROL, "IOT Control", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_APPLICATION_ID, "IOT Application ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_LOCATION, "AP Location", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_ADMIN, "Enable/Disable IOT Admin", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_IMAGE, "Enable IoT-KW41Z Image Upgrade", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_BLE_ADVERTISE_INTERVAL, "IOT BLE Advertise Interval", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_BLE_ADVERTISE_POWER, "IOT BLE Advertise Power", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_IBEACON_MAJOR, "IOT Ibeacon Major", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_IBEACON_MINOR, "IOT Ibeacon Minor", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_IBEACON_UUID, "IOT Ibeacon  UUID", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATIC_ADSP_IP_ADDR, "Set ADSP Url", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_OBSS_CHAN_ADJ_ACTIVE, "Set Auto Channel Width", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_BLE_SCAN_SRC_IP, "IOT BLE Scan Source IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_BLE_SCAN_SRC_PORT, "IOT BLE Scan Source Port", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_BLE_SCAN_DST_IP, "IOT BLE Scan Destination IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_BLE_SCAN_DST_PORT, "IOT BLE Scan Destination Port", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_BLE_SCAN_INTERVAL, "IOT BLE Scan Interval In Milliseconds", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_BLE_SCAN_WINDOW, "IOT BLE Scan Window In Milliseconds", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_BLE_SCAN_MIN_RSSI, "IOT BLE Scan Min RSSI", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LISENSE_SERVER, "License Server", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LISENSE_MIN_RSSI, "License Min RSSI", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LISENSE_REP_FREQ, "License Report Frequency", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DPI_SIG_HASH, "Deep Packet Inspection Signature Hash", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ANT_MODELS_IOT, "Antanna Type for IOT Radio", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FABRICATTACH_ARRAY, "Array Of FabricAttach ID", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_THREAD_CHANNEL, "IoT-Thread Network Parameter 802.15.4 Channel", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_THREAD_FACTORY_RESET, "IoT-Thread Network Factory Reset", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_THREAD_SHORT_PAN_ID, "IoT-Thread Network Parameter PAN ID", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_THREAD_SHORT_EUI, "IoT-Thread network Parameter EUI", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_THREAD_PSKD, "IoT-Thread network Parameter PSKd - Pre-Shared Key for the Device", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_THREAD_MASTER_KEY, "IoT-Thread Network Parameter: Master Key", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_THREAD_NWK_NAME, "IoT-Thread Network Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_THREAD_COMM_CREDENTIAL, "IoT-Thread Commissioner Credential", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_THREAD_LONG_EUI, "IoT-Thread Network Parameter EUI", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_THREAD_EXTENDED_PAN_ID, "IoT-Thread Network Parameter PAN ID", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_VSA_SSID_ID, "Configure VSA Interface", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_STATIC_VSA_IPADDR, "Configure VSA IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_STATIC_VSA_NETMASK, "Configure VSA Network Mask", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IOT_BLE_URL, "IoT-Eddystone URL Parameter", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_AP_PERSONALITY, "WING Or Identifi AP 1: WING AP, 0 : Identifi AP", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ADSP_RADIO_SHARE, "ADSP Radio Share Mode", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOCATION_TENANT_ID, "Location Tenant ID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0}
};



/*Members of EID_S_TOPO_MCAST_FILTER_CONFIG_BLOCK: */
typedef enum
{
	EID_S_TOPO_MCAST_FILTER_NAME  = 1,
	EID_S_TOPO_MCAST_FILTER_RULES,
	EID_S_TOPO_MCAST_FILTER_RULES_EXT_BLOCK
} wassp_tlv_S_topo_mcast_type_t;


static const TLV_PARSER_ENTRY tlvSTopoMcastFilterBlock[] =
{
	{ EID_S_TOPO_MCAST_FILTER_NAME, "Site Topology  Multicast Filter Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_S_TOPO_MCAST_FILTER_RULES, "Site Topology  Multicast Filter Rules", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_S_TOPO_MCAST_FILTER_RULES_EXT_BLOCK, "Site Topology  Multicast Filter Rules Block", TLV_TYPE_BLOCK_TLV, TAB_S_TOPO_MCAST_FILTER_RULES_EXT_BLOCK, 0, 0, 0, 0, 0, 0, 0}

};



/* Members of EID_S_TOPO_MCAST_FILTER_RULES_EXT_BLOCK: */
typedef enum
{
	EID_S_TOPO_MCAST_FILTER_RULE_EXT_ACT_FLAGS  = 1,
	EID_S_TOPO_MCAST_FILTER_RULES_IPV6

} wassp_tlv_S_topo_mcast_rule_type_t;

static const TLV_PARSER_ENTRY  tlvSTopoMcastFilterRuleBlock[] =
{
	{ EID_S_TOPO_MCAST_FILTER_RULE_EXT_ACT_FLAGS, "Site Topology  Multicast Filter Rule Action Flags", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_S_TOPO_MCAST_FILTER_RULES_IPV6, "Site Topology  Multicast Filter Rule IPv6 Addresses", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0}
};





/* TLV Stats Types Layer 1 */
typedef enum
{
	EID_DOT11_NOT_USED = 0,                             // 0
	EID_DOT11_ACKFailureCount,                          // 1
	EID_DOT11_FCSErrorCount,                            // 2
	EID_DOT11_FailedCount,                              // 3
	EID_DOT11_FrameDuplicateCount,                      // 4
	EID_DOT11_MulticastReceivedFrameCount,              // 5
	EID_DOT11_MulticastTransmittedFrameCount,           // 6
	EID_DOT11_MultipleRetryCount,                       // 7
	EID_DOT11_RTSFailureCount,                          // 8
	EID_DOT11_RTSSuccessCount,                          // 9
	EID_DOT11_ReceivedFragmentCount,                   // 10
	EID_DOT11_RetryCount,                               // 11
	EID_DOT11_TransmittedFragmentCount,                 // 12
	EID_DOT11_TransmittedFrameCount,                    // 13
	EID_DOT11_WEBUndecryptableCount,                    // 14
	EID_DOT11_WEPExcludedCount,                         // 15
	EID_DOT11_WEPICVErrorCount,                         // 16
	EID_DRM_AllocFailures,                              // 17
	EID_DRM_CurrentChannel,                             // 18
	EID_DRM_CurrentPower,                               // 19
	EID_DRM_DataTxFailures,                             // 20
	EID_DRM_DeviceType,                                 // 21
	EID_DRM_InDataPackets,                              // 22
	EID_DRM_InMgmtPackets,                              // 23
	EID_DRM_LoadFactor,                                 // 24
	EID_DRM_MgmtTxFailures,                             // 25
	EID_DRM_MsgQFailures,                               // 26
	EID_DRM_NoDRMCurrentChannel,                        // 27
	EID_DRM_OutDataPackets,                             // 28
	EID_DRM_OutMgmtPackets,                             // 29
	EID_IF_InBcastPackets,                              // 30
	EID_IF_InDiscards,                                  // 31
	EID_IF_InErrors,                                    // 32
	EID_IF_InMcastPackets,                              // 33
	EID_IF_InOctets,                                    // 34
	EID_IF_InUcastPackets,                              // 35
	EID_IF_MTU,                                         // 36
	EID_IF_OutBcastPackets,                             // 37
	EID_IF_OutDiscards,                                 // 38
	EID_IF_OutErrors,                                   // 39
	EID_IF_OutOctets,                                   // 40
	EID_IF_OutUcastPackets,                             // 41
	EID_IF_OutMCastPackets,                             // 42
	EID_MU_Address,                                     // 43
	EID_MU_AssociationCount,                            // 44
	EID_MU_AuthenticationCount,                         // 45
	EID_MU_DeAssociationCount,                          // 46
	EID_MU_DeAuthenticationCount,                       // 47
	EID_MU_IfIndex,                                     // 48
	EID_MU_ReAssociationCount,                          // 49
	EID_MU_ReceivedBytes,                               // 50
	EID_MU_ReceivedErrors,                              // 51
	EID_MU_ReceivedFrameCount,                          // 52
	EID_MU_ReceivedRSSI,                                // 53
	EID_MU_ReceivedRate,                                // 54
	EID_MU_TransmittedBytes,                            // 55
	EID_MU_TransmittedErrors,                           // 56
	EID_MU_TransmittedFrameCount,                       // 57
	EID_MU_TransmittedRSSI,                             // 58
	EID_MU_TransmittedRate,                             // 59
	EID_MU_RF_STATS_END,                                // 60
	EID_RFC_1213_SYSUPTIME,                             // 61
	EID_STATS_ETHER_BLOCK,                              // 62
	EID_STATS_RADIO_A_BLOCK,                            // 63
	EID_STATS_RADIO_B_G_BLOCK,                          // 64
	EID_MU_STATS_BLOCK,                                 // 65
	EID_STATS_WDS_BLOCK,                                // 66
	EID_WDS_ROLE,                                       // 67
	EID_WDS_PARENTMAC,                                  // 68
	EID_WDS_SSID,                                       // 69
	EID_STATS_SUPP1x_BLOCK,                             // 70
	EID_STATS_SUPP1X_CREDENT,                           // 71
	EID_STATS_SUPP1X_END_DATE,                          // 72
	EID_DOT11_ProtectionMode,                           // 73
	EID_MU_TSPEC_Stats_Block,                           // 74
	EID_DOT11_ChannelBonding,                           // 75
	EID_DCS_STAS_NF,                                    // 76
	EID_DCS_STAS_CHANN_OCCUPANCY,                       // 77
	EID_DCS_STAS_TX_OCCUPANCY,                          // 78
	EID_DCS_STAS_RX_OCCUPANCY,                          // 79
	EID_CAC_DEAUTH,                                     // 80
	EID_MU_IP,                                          // 81
	EID_STATS_CHECK,                                    // 82
	EID_WDS_BONDING,                                    // 83
	EID_MU_ReceivedRSS,                                 // 84
	EID_MU_RadioIndex,                                  // 85
	EID_MU_FltPktAllowed,                               // 86
	EID_MU_FltPktDenied,                                // 87
	EID_MU_FltName,                                     // 88
	EID_MU_FltReset,                                    // 89
	EID_MU_DL_DroppedRateControlPackets,                // 90
	EID_MU_DL_DroppedRateControlBytes,                  // 91
	EID_MU_DL_DroppedBufferFullPackets,                 // 92
	EID_MU_DL_DroppedBufferFullBytes,                   // 93
	EID_MU_DL_LostRetriesPackets,                       // 94
	EID_MU_DL_LostRetriesBytes,                         // 95
	EID_MU_UL_DroppedRateControlPackets,                // 96
	EID_MU_UL_DroppedRateControlBytes,                  // 97
	EID_SiappClusterName,                               // 98
	EID_LB_LoadGroupID,                                 // 99
	EID_LB_LoadValue,                                   // 100
	EID_LB_MemberCount,                                 // 101
	EID_LB_ClientCount,                                 // 102
	EID_LB_LoadState,                                   // 103
	EID_LB_ProbeReqsDeclined,                           // 104
	EID_LB_AuthReqsDeclined,                            // 105
	EID_LB_RebalanceEvents,                             // 106
	EID_MU_DOT11_CAPABILITY,                            // 107
	EID_BAND_PREFERENCE_STATS,                          // 108
	EID_R_LC_STATUS,                                    // 109
	EID_WDS_ROAM_COUNT,                                 // 110
	EID_WDS_TX_RETRIES,                                 // 111
	EID_RealCaptureTimeout,                             // 112
	EID_MU_11N_ADVANCED,                                // 113
	EID_MU_Count,                                       // 114
	EID_R_Clear_channel,                                // 115
	EID_R_RX_Occupancy,                                 // 116
	EID_STATS_VNS_BLOCK,                                // 117
	EID_STATS_VNS_ENTRY,                                // 118
	EID_ETH_STATUS,                                     // 119
	EID_LAG_ACT_AGGREGATE_STATUS,                       // 120
	EID_PERFORMANCE_STATS,                              // 121
	EID_APPL_STATS,                                     // 122
	EID_APPL_COUNT,                                     // 123
	EID_APPL_MAC,                                       // 124
	EID_APPL_DISPLAY_ID,                                // 125
	EID_APPL_TX_BYTES,                                  // 126
	EID_APPL_RX_BYTES,                                  // 127
	EID_MU_TRANSMITTED_MCS,                             // 128
	EID_MU_TOTAL_LOST_FRAMES,                           // 129
	EID_MU_DL_AGGR_SIZE,                                // 130
	EID_RX_PHYS_ERRORS,                                 // 131
	EID_RADIO_HARDWARE_RESET,                           // 132
	EID_TOTAL_PACKET_ERROR_RATE,                        // 133
	EID_STATS_PORT_BLOCK,                               // 134
	EID_PORT_ID,                                        // 135
	EID_MU_RADIO_ID,                                    // 136
	EID_IF_LinkSpeed,                                   // 137
	EID_MU_DL_RETRY_ATTEMPTS,                           // 138
	EID_FILTER_STATS_BLOCK,                             // 139
	EID_FILTER_STATS_RULES_BLOCK,                       // 140
	EID_ROLE_ID,                                        // 141
	EID_ROLE_TIMESTAMP,                                 // 142
	EID_DEFAULT_HIT_COUNT_IN,                           // 143
	EID_DEFAULT_HIT_COUNT_OUT,                          // 144
	EID_RULE_HIT_COUNT_IN,                              // 145
	EID_RULE_HIT_COUNT_OUT,                             // 146
	EID_STATS_RADIO_ID,                          // 147
	EID_STATS_RADIO_BLOCK,                       // 148
	EID_MU_RFQI,                                 // 149
	EID_RADIO_RFQI,                              // 150
	EID_IF_InBcastPackets_D,                     // 151
	EID_IF_InDiscards_D,                         // 152
	EID_IF_InErrors_D,                           // 153
	EID_IF_InMcastPackets_D,                     // 154
	EID_IF_InOctets_D,                           // 155
	EID_IF_InUcastPackets_D,                     // 156
	EID_IF_OutBcastPackets_D,                    // 157
	EID_IF_OutDiscards_D,                        // 158
	EID_IF_OutErrors_D,                          // 159
	EID_IF_OutOctets_D,                          // 160
	EID_IF_OutUcastPackets_D,                    // 161
	EID_IF_OutMCastPackets_D,                    // 162
	EID_MU_ReceivedFrameCount_D,                 // 163
	EID_MU_TransmittedFrameCount_D,              // 164
	EID_MU_ReceivedErrors_D,                     // 165
	EID_MU_TransmittedErrors_D,                  // 166
	EID_MU_ReceivedBytes_D,                      // 167
	EID_MU_TransmittedBytes_D,                   // 168
	EID_MU_rc_ul_dropped_pkts_D,                 // 169
	EID_MU_rc_ul_dropped_bytes_D,                // 170
	EID_MU_rc_dl_dropped_pkts_D,                 // 171
	EID_MU_rc_dl_dropped_bytes_D,                // 172
	EID_STATS_TLV_MAX                            //  Make shure this is the MAX
} wassp_tlv_stats_1_type_t;


/* Value string object enumerates wassp tlv type field */
static const TLV_PARSER_ENTRY tlvBeastConfigTable[] =
{
	{ EID_DOT11_NOT_USED, "DOT11Unused 0", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_ACKFailureCount, "802.11 Ack Failure Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_FCSErrorCount, "802.11 FCS Error Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_FailedCount, "802.11 Failed Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_FrameDuplicateCount, "802.11 Frame Duplicated Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_MulticastReceivedFrameCount, "802.11 Multicast Received Frame Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_MulticastTransmittedFrameCount, "802.11 Multicast Transmitted Frame Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_MultipleRetryCount, "802.11 Multiple Retry Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_RTSFailureCount, "802.11 RTS Failure Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_RTSSuccessCount, "802.11 RTS Success Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_ReceivedFragmentCount, "802.11 Received Fragment Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_RetryCount, "802.11 Retry Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_TransmittedFragmentCount, "802.11 Transmitted Fragment Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_TransmittedFrameCount, "802.11 Transmitted Frame Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_WEBUndecryptableCount, "802.11 WEP Undecryptable Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_WEPExcludedCount, "802.11 WEP Excluded Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_WEPICVErrorCount, "802.11 WEP ICV Error Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DRM_AllocFailures, "802.11 DRM Allocated Failures", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DRM_CurrentChannel, "802.11 DRM Current Channel", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DRM_CurrentPower, "802.11 DRM Current Power", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DRM_DataTxFailures, "802.11 DRM Data Tx Failures", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DRM_DeviceType, "802.11 DRM Device Type", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DRM_InDataPackets, "802.11 DRM In Data Packets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DRM_InMgmtPackets, "802.11 DRM In Management Packets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DRM_LoadFactor, "802.11 DRM Load Factor", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DRM_MgmtTxFailures, "802.11 DRM Management Tx Failures", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DRM_MsgQFailures, "802.11 DRM Message Q Failures", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DRM_NoDRMCurrentChannel, "802.11 No DRM Current Channel", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DRM_OutDataPackets, "802.11 DRM Out Data Packets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DRM_OutMgmtPackets, "802.11 DRM Out Management Packets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_InBcastPackets, "Interface In Bcast Packets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_InDiscards, "Interface In Discards", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_InErrors, "Interface In Errors", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_InMcastPackets, "Interface In Mcast Packets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_InOctets, "Interface In Octets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_InUcastPackets, "Interface In Ucast Packets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_MTU, "Interface MTU", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_OutBcastPackets, "Interface Out Bcast Packets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_OutDiscards, "Interface Out Discards", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_OutErrors, "Interface Out Errors", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_OutOctets, "Interface Out Octets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_OutUcastPackets, "Interface Out Ucast Packets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_OutMCastPackets, "Interface Out MCast Packets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_Address, "MU Address", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_AssociationCount, "MU Association Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_AuthenticationCount, "MU Authentication Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_DeAssociationCount, "MU DeAssociation Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_DeAuthenticationCount, "MU DeAuthentication Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_IfIndex, "MU Interface Index", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ReAssociationCount, "MU ReAssociation Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ReceivedBytes, "MU Received Bytes", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ReceivedErrors, "MU Received Errors", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ReceivedFrameCount, "MU Received Frame Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ReceivedRSSI, "MU Received RSSI", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ReceivedRate, "MU Received Rate", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TransmittedBytes, "MU Transmitted Bytes", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TransmittedErrors, "MU Transmitted Errors", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TransmittedFrameCount, "MU Transmitted Frame Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TransmittedRSSI, "MU Transmitted RSSI", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TransmittedRate, "MU Transmitted Rate", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_RF_STATS_END, "MU RF Stats End", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RFC_1213_SYSUPTIME, "RFC1213 System Up Time", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_ETHER_BLOCK, "Stats Ethernet Block", TLV_TYPE_BLOCK_TLV, TAB_STATS_ETH, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_RADIO_A_BLOCK, "Stats Radio A Block", TLV_TYPE_BLOCK_TLV, TAB_STATS_RADIO, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_RADIO_B_G_BLOCK, "Stats Radio BG Block", TLV_TYPE_BLOCK_TLV, TAB_STATS_RADIO, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_STATS_BLOCK, "MU Stats Block", TLV_TYPE_BLOCK_TLV, STATS_MU_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_WDS_BLOCK, "Stats WDS Block", TLV_TYPE_BLOCK_TLV, TAB_STATS_WDS, 0, 0, 0, 0, 0, 0, 0},
	{ EID_WDS_ROLE, "WDS Role", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_WDS_PARENTMAC, "WDS Parent Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_WDS_SSID, "WDS SSID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_SUPP1x_BLOCK, "802.11X Stats Block", TLV_TYPE_BLOCK_TLV, TAB_STATS_WDS, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_SUPP1X_CREDENT, "802.11X Credent", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_SUPP1X_END_DATE, "802.11X Expiry Date", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_ProtectionMode, "802.11 Protection Mode", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TSPEC_Stats_Block, "MU TSPEC Stats Block", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DOT11_ChannelBonding, "802.11 Channel Bonding", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DCS_STAS_NF, "DCS STAS NF", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DCS_STAS_CHANN_OCCUPANCY, "DCS Stats Channel Occupancy", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DCS_STAS_TX_OCCUPANCY, "DCS Stats Tx Occupancy", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DCS_STAS_RX_OCCUPANCY, "DCS Stats Rx Occupancy", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_CAC_DEAUTH, "CAC DeAuthentication", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_IP, "MU IP", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_CHECK, "Stats Check", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_WDS_BONDING, "WDS Bonding", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ReceivedRSS, "MU Received RSS", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_RadioIndex, "MU Radio Index", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_FltPktAllowed, "MU Allowed Packet", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_FltPktDenied, "MU Denied Packet", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_FltName, "MU Filter Rule Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_FltReset, "MU Filter Reset", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_DL_DroppedRateControlPackets, "MU Down Link Dropped Rate Control Packets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_DL_DroppedRateControlBytes, "MU Down Link Dropped Rate Control Bytes", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_DL_DroppedBufferFullPackets, "MU Down Link Dropped Buffer Full Packets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_DL_DroppedBufferFullBytes, "MU Down Link Dropped Buffer Full Bytes", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_DL_LostRetriesPackets, "MU Down Link Lost Retries Packets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_DL_LostRetriesBytes, "MU Down Link Lost Retries Bytes", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_UL_DroppedRateControlPackets, "MU Up Link Dropped Rate Control Packets", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_UL_DroppedRateControlBytes, "MU Up Link Dropped Rate Control Bytes", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SiappClusterName, "Siapp Cluster Mac address", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LB_LoadGroupID, "Load Balance Load Group ID", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LB_LoadValue, "Load Balance Load value", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LB_MemberCount, "Load Balance Member Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LB_ClientCount, "Load Balance Client Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LB_LoadState, "Load Balance Load State", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LB_ProbeReqsDeclined, "Load Balance Probe Request Declined", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LB_AuthReqsDeclined, "Load Balance Authentication request Declined", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LB_RebalanceEvents, "Load Balance Rebalance Events", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_DOT11_CAPABILITY, "MU 802.11 Capability", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BAND_PREFERENCE_STATS, "Band Preference Stats", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_LC_STATUS, "Radio Load Control Stats", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_WDS_ROAM_COUNT, "WDS Roam Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_WDS_TX_RETRIES, "WDS Tx Retries", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RealCaptureTimeout, "Real Capture Timeout", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_11N_ADVANCED, "MU 802.11N Advanced", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_Count, "MU Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_Clear_channel, "Radio Clear Channel", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_RX_Occupancy, "Radio Rx Occupancy", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_VNS_BLOCK, "VNS Stats Block", TLV_TYPE_BLOCK_TLV, TAB_STATS_VNS, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_VNS_ENTRY, "VNS Stats Entry", TLV_TYPE_BLOCK_TLV, TAB_STATS_VNS, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ETH_STATUS, "Ethernet Stats", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LAG_ACT_AGGREGATE_STATUS, "LAG Aggregate Stats", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PERFORMANCE_STATS, "Performance Stats", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_APPL_STATS, "Application Stats", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_APPL_COUNT, "Application Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_APPL_MAC, "Application Mac Address", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_APPL_DISPLAY_ID, "Application Display ID", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_APPL_TX_BYTES, "Application Tx Bytes", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_APPL_RX_BYTES, "Application Rx Bytes", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TRANSMITTED_MCS, "MU Transmitted MCS", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TOTAL_LOST_FRAMES, "MU Total Lost Frames", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_DL_AGGR_SIZE, "MU Down Link Aggregate Size", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RX_PHYS_ERRORS, "Rx Phys Errors", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIO_HARDWARE_RESET, "Radio hardware Reset", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_TOTAL_PACKET_ERROR_RATE, "total Packet Error Rate", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_PORT_BLOCK, "ports Stats Block", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_PORT_ID, "Port ID", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_RADIO_ID, "MU Radio ID", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_LinkSpeed, "Interface Link Speed", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_DL_RETRY_ATTEMPTS, "MU Down Link Retry Attempts", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_STATS_BLOCK, "Filter Stats Block", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_FILTER_STATS_RULES_BLOCK, "Filter Stats Rules Block", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ROLE_ID, "Role ID", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_ROLE_TIMESTAMP, "Role Timestamp", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DEFAULT_HIT_COUNT_IN, "Default In Direction Hit Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_DEFAULT_HIT_COUNT_OUT, "Default Out Direction Hit Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RULE_HIT_COUNT_IN, "Role In Direction Hit Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RULE_HIT_COUNT_OUT, "Role Out Direction Hit Count", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_RADIO_ID, "Stats Radio ID", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_RADIO_BLOCK, "Stats Radio ID Block", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_RFQI, "MU RFQI", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIO_RFQI, "Radio RFQI", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_InBcastPackets_D, "Interface In Bcast Packets Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_InDiscards_D, "Interface In Discards Packets Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_InErrors_D, "Interface In Error Packets Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_InMcastPackets_D, "Interface In Mcast Packets Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_InOctets_D, "Interface In Octets Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_InUcastPackets_D, "Interface In Ucast Packets Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_OutBcastPackets_D, "Interface Out Bcast Packets Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_OutDiscards_D, "Interface Out Discards Packets Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_OutErrors_D, "Interface Out Error Packets Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_OutOctets_D, "Interface Out Octets Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_OutUcastPackets_D, "Interface Out Ucast Packets Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_IF_OutMCastPackets_D, "Interface Out Mcast Packets Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ReceivedFrameCount_D, "MU Received Fram Count Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TransmittedFrameCount_D, "MU Transmitted Fram Count Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ReceivedErrors_D, "MU Received Error Count Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TransmittedErrors_D, "MU Transmitted Error Count Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_ReceivedBytes_D, "MU Received Bytes Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_TransmittedBytes_D, "MU Transmitted Bytes Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_rc_ul_dropped_pkts_D, "MU Received Up Link Dropped Packets Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_rc_ul_dropped_bytes_D, "MU Received Up Link Dropped Bytes Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_rc_dl_dropped_pkts_D, "MU Received Down Link Dropped Packets Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_MU_rc_dl_dropped_bytes_D, "MU Received Down Link Dropped Bytes Delta Value Since Last Message", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_STATS_TLV_MAX, "Last Stats TLV",0, 0, 0, 0, 0, 0, 0, 0, 0}

};



#define WASSP_MAX_DECR_INFO_NUM 18
#define WASSP_MAX_SUBTREE_LEN 50
#define EID_PARSE_ERROR (EID_MAX+1)

#define SET_WASSP_TLV_VERSION(val) (g_wassp_ver = (val))
#define GET_WASSP_TLV_VERSION()    (g_wassp_ver)

// #define WASSP_PRINT printf
#define WASSP_PRINT

#define WASSP_SUBTLV_GET_NAME(in_ptr) ((in_ptr)->name)
#define WASSP_SUBTLV_GET_TYPE(in_ptr) ((in_ptr)->type)



typedef enum
{
	EID_R_UNUSED_0 = 0,
	EID_R_RADIO_ID,
	EID_R_ENABLE_RADIO,
	EID_R_CHANNEL,
	EID_R_OP_RATE_SET,
	EID_R_OP_RATE_MAX,
	EID_R_BEACON_PERIOD,
	EID_R_DTIM_PERIOD,
	EID_R_RTS_THRESHOLD,
	EID_R_ANTENNA_TYPE,
	EID_R_A_CHAN_PLAN_TYPE,
	EID_R_FRAGMENT_THRESHOLD,
	EID_R_POWER_LEVEL,
	EID_R_LC_ASSOC_TRY_MAX,
	EID_R_LC_STRICT_CLIENT_COUNT_LIMIT,
	EID_R_DIVERSITY_RX,
	EID_R_DIVERSITY_TX,
	EID_R_SHORT_PREAMBLE,
	EID_R_BASIC_RATE_MAX,
	EID_R_BASIC_RATE_MIN,
	EID_R_HW_RETRIES,
	EID_R_TX_POWER_MIN,
	EID_R_TX_POWER_MAX,
	EID_R_INTERFERENCE_EVENT_TYPE,
	EID_R_DOMAIN_ID,
	EID_R_B_ENABLE,
	EID_R_B_BASIC_RATES,
	EID_R_G_ENABLE,
	EID_R_G_PROTECT_MODE,
	EID_R_G_PROTECT_TYPE,
	EID_R_G_PROTECT_RATE,
	EID_R_G_BASIC_RATE,
	EID_R_A_SUPPORT_802_11_J,
	EID_R_ATPC_EN_INTERVAL,
	EID_R_ACS_CH_LIST,
	EID_R_TX_POWER_ADJ,
	EID_R_WIRELESS_MODE,
	EID_R_N_CHANNEL_BONDING,
	EID_R_N_CHANNEL_WIDTH,
	EID_R_N_GUARD_INTERVAL,
	EID_R_N_PROTECT_ENABLE,
	EID_R_N_PROTECT_TYPE,
	EID_R_N_PROTECT_OFFSET,
	EID_R_N_PROTECT_BUSY_THRESHOLD,
	EID_R_AGGREGATE_MSDU,
	EID_R_AGGREGATE_MSDU_MAX_LEN,
	EID_R_AGGREGATE_MPDU,
	EID_R_AGGREGATE_MPDU_MAX_LEN,
	EID_R_AGGREGATE_MPDU_SUBFRAMES,
	EID_R_ADDBA_SUPPORT,
	EID_R_DCS_MODE,
	EID_R_DCS_NOISE_THRESHOLD,
	EID_R_DCS_CHL_OCCUPANCY_THRESHOLD,
	EID_R_DCS_UPDATE_PERIOD,
	EID_R_ANTENNA_SELECTION,
	EID_R_BKGND_SCAN_ENABLE,
	EID_R_BKGND_SCAN_INTERVAL,
	EID_R_BCMCRATECTRL_AIRTIME,
	EID_R_CACS,
	EID_R_MAX_DISTANCE,
	EID_R_LOADGROUP_ID,
	EID_R_GROUP_BALANCING,
	EID_R_LC_CLIENT_COUNT_LIMIT,
	EID_R_ENABLE_LDPC,
	EID_R_ENABLE_TXSTBC,
	EID_R_ENABLE_RXSTBC,
	EID_R_ENABLE_TXBF,
	EID_R_TXBF_CLIENT_LIMIT,
	EID_R_INTERFERENCE_WAIT_TIME,
	EID_R_LC_ASSOC_TRY_TIMEOUT,
	EID_R_OPT_MCAST_PS,
	EID_R_MCAST_TO_UCAST_DELIVERY,
	EID_R_ADAPTABLE_RATE_FOR_MCAST,
	EID_R_ANTENNA_PORT_ATT,
	EID_R_PROBE_SUP_ENABLE,
	EID_R_PROBE_SUP_CAP,
	EID_R_PROBE_SUP_THRESH,
	EID_R_MU_NUM_RADAR_BACK,
	EID_R_ADSP_RADIO_SHARE,
	EID_R_OCS_CHANNEL_ENABLE,
	EID_R_OCS_CHANNEL_LIST,
	EID_R_OCS_SCAN_INTERVAL,
	EID_R_SENSOR_SCAN_MODE,
	EID_R_SENSOR_SCAN_LIST


} wassp_subtlv_radio_block_type_t;

static const TLV_PARSER_ENTRY tlvRadioConfigTable[]  =
{
	{ EID_R_UNUSED_0, "Radio Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_RADIO_ID, "Radio ID", TLV_TYPE_INDEX, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_ENABLE_RADIO, "Enable/Disable Radio", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_CHANNEL, "Radio Frequency In MHz", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_OP_RATE_SET, "Operation Rate", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_OP_RATE_MAX, "Max Operation Rate", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_BEACON_PERIOD, "Beacon Interval", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_DTIM_PERIOD, "DTIM Count", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_RTS_THRESHOLD, "RTS/CTS Threshold", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_ANTENNA_TYPE, "Radio Antenna Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_A_CHAN_PLAN_TYPE, "Radio Channel Plan Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_FRAGMENT_THRESHOLD, "Fragment Threshold", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_POWER_LEVEL, "Power Level", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_LC_ASSOC_TRY_MAX, "LC Association Max Try", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_LC_STRICT_CLIENT_COUNT_LIMIT, "LC Strict Client Count Limit", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_DIVERSITY_RX, "Rx Diversity", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_DIVERSITY_TX, "Tx Diversity", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_SHORT_PREAMBLE, "Radio Short Preamble", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_BASIC_RATE_MAX, "Max Basic Rate", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_BASIC_RATE_MIN, "Min Basic Rate", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_HW_RETRIES, "Hardware Retries", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_TX_POWER_MIN, "Min Tx Power", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_TX_POWER_MAX, "Max Tx Power", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_INTERFERENCE_EVENT_TYPE, "Interference Event Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_DOMAIN_ID, "Domain ID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_B_ENABLE, "Enable Radio B", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_B_BASIC_RATES, "Radio B Basic Rates", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_G_ENABLE, "Enable Radio G", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_G_PROTECT_MODE, "Radio G Protect Mode", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_G_PROTECT_TYPE, "Radio G Protect Type", TLV_TYPE_INDEX, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_G_PROTECT_RATE, "Radio G Protect Rate", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_G_BASIC_RATE, "Radio G Basic Rate", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_A_SUPPORT_802_11_J, "Radio A Support 802.11J", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_ATPC_EN_INTERVAL, "Automatic Transmit Power Control Interval", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_ACS_CH_LIST, "Radio ACS Channel List", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_TX_POWER_ADJ, "Radio Tx Power Adjustment", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_WIRELESS_MODE, "Wireless Radio Mode", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_N_CHANNEL_BONDING, "802.11n Channel Bonding: 0=No Bonding, 1=Bond-Up, 2=Bond-Down", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_N_CHANNEL_WIDTH, "802.11n Channel Width: 1=20Mhz, 2=40Mhz, 3=both", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_N_GUARD_INTERVAL, "802.11n Guard Interval: 1=short, 2=long", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_N_PROTECT_ENABLE, "802.11n Channel Protection Mode: 0=disabled, 1=enabled", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_N_PROTECT_TYPE, "802.11n 40Mhz Channel Protection: 0=None, 1=CTS only, 2=RTS/CTS", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_N_PROTECT_OFFSET, "802.11n Channel Protection Offset: 1=20Mhz, 2=25MHz", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_N_PROTECT_BUSY_THRESHOLD, "802.11n 40Mhz Channel Busy Threshold: 0...100", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_AGGREGATE_MSDU, "Aggregate MSDUs: 0=disabled, 1=enabled", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_AGGREGATE_MSDU_MAX_LEN, "Aggregate MSDU Max Length: 2290...4096", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_AGGREGATE_MPDU, "Aggregate MPDUs: 0=disabled, 1=enabled", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_AGGREGATE_MPDU_MAX_LEN, "Aggregate MPDU Max Length: 1024...65535", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_AGGREGATE_MPDU_SUBFRAMES, "Aggregate MPDU Max # of Sub-frames: 2...64", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_ADDBA_SUPPORT, "ADDBA Support: 0=disabled, 1=enabled", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_DCS_MODE, "Dynamic channel Selection Mode: 0=off, 1=monitor, 2=active", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_DCS_NOISE_THRESHOLD, "Dynamic channel Selection Noise Threshold", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_DCS_CHL_OCCUPANCY_THRESHOLD, "Dynamic channel Selection Channel Occupancy", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_DCS_UPDATE_PERIOD, "Dynamic channel Selection Update Period", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_ANTENNA_SELECTION, "Antenna selection. LSB 0 - Left, bit 1 - Middle, bit 2 - Right", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_BKGND_SCAN_ENABLE, "Voice Over WIFI:  0=off, 1=on ", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_BKGND_SCAN_INTERVAL, "Voice Over WIFI Interval", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_BCMCRATECTRL_AIRTIME, "Broadcast/Multicast Rate Control: The Percentage of Airtime Allowed for Broadcast/Multicast Traffic", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_CACS, "Thick/Thin AP: Cluster ACS", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_MAX_DISTANCE, "Radio Max Distance (used for WDS)", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_LOADGROUP_ID, "Radio Load Group or Balance Group ID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_GROUP_BALANCING, "Group Balancing Mode", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_LC_CLIENT_COUNT_LIMIT, "Radio Client Count Limit", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_ENABLE_LDPC, "Enable/Disable LDPC Coding: 0 = Disable, 1 = Enable", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_ENABLE_TXSTBC, "Enable/Disable Radio TxSTBC: 0 = Disable, 1 = Enable", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_ENABLE_RXSTBC, "Enable/Disable Radio RxSTBC: 0 = Disable, 1 = Enable", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_ENABLE_TXBF, "Set TxBF Mode", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_TXBF_CLIENT_LIMIT, "TxBF Client Limit", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_INTERFERENCE_WAIT_TIME, "Interference Wait Time", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_LC_ASSOC_TRY_TIMEOUT, "LC Association Try Time Out", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_OPT_MCAST_PS, "Enable/Disable Optimized Multicast Power Save: 0 = Disable, 1 = Enable", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_MCAST_TO_UCAST_DELIVERY, "Multicast to Unicast Delivery: 0 = Disable, 1 = Auto", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_ADAPTABLE_RATE_FOR_MCAST, "Enable/Disable Adaptable Rate for Multicast: 0 = Disable, 1 = Enable", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_ANTENNA_PORT_ATT, "Antenna Port ATT", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_PROBE_SUP_ENABLE, "Enable/Disable Probe Suppression: 0 = Disable, 1 = Enable", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_PROBE_SUP_CAP, "Probe Suppression Capacity", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_PROBE_SUP_THRESH, "Probe Suppression Threshold", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_MU_NUM_RADAR_BACK, "DFS Max Number of Clients Allow Return to Original Channel After DFS", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_ADSP_RADIO_SHARE, "ADSP Radio Share", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_OCS_CHANNEL_ENABLE, "Enable/Disable OCS", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_OCS_CHANNEL_LIST, "List Of OCS Channel", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_OCS_SCAN_INTERVAL, "OCS Scan Interval", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_SENSOR_SCAN_MODE, "Sensor Scan Mode", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_R_SENSOR_SCAN_LIST, "Sensor Scan List", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0}

};





typedef enum
{
	EID_V_UNUSED = 0,
	EID_V_RADIO_ID,
	EID_V_VNS_ID,
	EID_V_TURBO_VOICE,
	EID_V_PROP_IE,
	EID_V_ENABLE_802_11_H,
	EID_V_POWER_BACKOFF,
	EID_V_BRIDGE_MODE,
	EID_V_VLAN_TAG,
	EID_V_PROCESS_IE_REQ,
	EID_V_ENABLE_U_APSD,
	EID_V_ADM_CTRL_VOICE,
	EID_V_ADM_CTRL_VIDEO,
	EID_V_QOS_UP_VALUE,
	EID_V_PRIORITY_OVERRIDE,
	EID_V_DSCP_OVERRIDE_VALUE,
	EID_V_ENABLE_802_11_E,
	EID_V_ENABLE_WMM,
	EID_V_LEGACY_CLIENT_PRIORITY,
	EID_V_SSID_ID,
	EID_V_SSID_BCAST_STRING,
	EID_V_SSID_SUPPRESS,
	EID_V_802_1_X_ENABLE,
	EID_V_802_1_X_DYN_REKEY,
	EID_V_WPA_ENABLE,
	EID_V_WPA_V2_ENABLE,
	EID_V_WPA_PASSPHRASE,
	EID_V_WPA_CIPHER_TYPE,
	EID_V_WPA_V2_CIPHER_TYPE,
	EID_V_WEP_KEY_INDEX,
	EID_V_WEP_DEFAULT_KEY_VALUE,
	EID_V_CHANNEL_REPORT,
	EID_V_WDS_SERVICE,
	EID_V_WDS_BSSID_PARENT,
	EID_V_WDS_BRIDGE,
	EID_V_OKC_ENABLED,
	EID_V_MU_ASSOC_RETRIES,
	EID_V_MU_ASSOC_TIMEOUT,
	EID_V_WDS_PARENT,
	EID_V_WDS_BACK_PARENT,
	EID_V_WDS_NAME,
	EID_V_SESSION_AVAIL,
	EID_V_UL_POLICER_ACTION,
	EID_V_DL_POLICER_ACTION,
	EID_V_ENABLE_802_11_K,
	EID_V_ENABLE_802_11_H_BG,
	EID_V_SITE_EGRESS_FILTER_MODE,
	EID_V_DEFAULT_IDLE_PRE_TIMEOUT,
	EID_V_DEFAULT_IDLE_POST_TIMEOUT,
	EID_V_IGNORE_COS,
	EID_V_RADIUS_SERVER_INDEX2,
	EID_V_MCAST_OPTIMIZATION,
	EID_V_MCAST_IGMP_TIMEOUT,
	EID_V_MCAST_FILTER_ENABLE,
	EID_V_FILTER_CONFIG_BLOCK,
	EID_V_DATA_REASSEMBLY_ENABLE,
	EID_V_UCAST_FILTER_ENABLE,
	EID_V_RATECTRL_CIR_UL,
	EID_V_RATECTRL_CIR_DL,
	EID_V_RATECTRL_CBS_UL,
	EID_V_RATECTRL_CBS_DL,
	EID_V_AIRTIME_FAIRNESS_ENABLE,
	EID_V_POWERSAVE_ENABLE,
	EID_V_GROUP_KP_SAVE_RETRY,
	EID_V_BALANCE_GROUP,
	EID_V_MESH_TYPE,
	EID_V_MESH_ROAMING_THRESHOLD,
	EID_V_COS,
	EID_V_RATE_LIMIT_RESOURCE_TBL,
	EID_V_AP_AUTH_CLIENT_MODES,
	EID_V_DEFAULT_POLICY_INDEX,
	EID_V_AUTH_POLICY_INDEX,
	EID_V_NONAUTH_POLICY_INDEX,
	EID_V_RADIUS_SERVER_INDEX,
	EID_V_NAS_IP,
	EID_V_NAS_ID,
	EID_V_VSA_SELMASK,
	EID_V_MBA_OPTIONS_MASK,
	EID_V_MBA_TIMEOUT_POLICY_KEY,
	EID_V_WLAN_SERVICE_NAME,
	EID_V_DEFAULT_SESSION_TIMEOUT,
	EID_V_RADIUS_CALLED_STATION_ID,
	EID_V_CAPTIVE_PORTAL,
	EID_V_COS_CONFIG_BLOCK,
	EID_V_TOPOLOGY_KEY,
	EID_V_MU_INIT_PERIOD_BEHAVIOUR,
	EID_V_DYNAMIC_EGRESS_VLANS,
	EID_V_STATIC_EGRESS_VLANS,
	EID_V_FLAGS,
	EID_V_DEFAULT_ACTION,
	EID_V_CONTAIN_TO_VLAN,
	EID_V_PVID_TOPOLOGY_KEY,
	EID_V_AP_REDIRECT,
	EID_V_ADM_CTRL_BE,
	EID_V_ADM_CTRL_BK,
	EID_V_11K_ENABLE,
	EID_V_11K_RM_CAP,
	EID_V_11R_ENABLE,
	EID_V_11R_R0KH_ID,
	EID_V_11R_MD_ID,
	EID_V_MGMT_FRAME_PROTECTION,
	EID_V_NETFLOW,
	EID_V_WLAN_DEFAULT_MIRRORN,
	EID_V_DEFAULT_MIRRORN,
	EID_V_11U_ANQP_BLOCK,
	EID_V_HS2_BLOCK,
	EID_V_APP_IDENTIFICATION_ENABLED,
	EID_V_PRIVACY,
	EID_V_11U_OSEN,
	EID_V_QOS_IN_USE,
	EID_V_CP_CONFIG_BLOCK,
	EID_V_CP_IDENTITY,
	EID_V_CP_PASSPHRASE,
	EID_V_CP_REDIRECT_URL,
	EID_V_CP_USE_HTTPS,
	EID_V_CP_AUTH_URL,
	EID_V_CP_FLAGS,
	EID_V_CP_AP_FQDN,
	EID_V_VNS_NAME,
	EID_V_LDAP_SERVER_INDEX,
	EID_V_AIRTIME_RESERVATION,
	EID_V_MU_DISCON_REQ_ENABLE

} wassp_subtlv_vns_config_type_t;

static const TLV_PARSER_ENTRY tlvVnsConfigTable[]  =
{
	{ EID_V_UNUSED, "Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RADIO_ID, "Radio ID", TLV_TYPE_INDEX, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_VNS_ID, "VNS ID", TLV_TYPE_INDEX, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_TURBO_VOICE, "Enable Turbo Voice", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_PROP_IE, "Process IE", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_ENABLE_802_11_H, "Enable 802.11H", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_POWER_BACKOFF, "Enable 802.11H Power Back Off", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_BRIDGE_MODE, "VNS Bridge Mode: 0 = Tunnel, 1 = Bridge, 3 = WDS, 10 = Any ", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_VLAN_TAG, "Vlan Tag: -1 = Untagged, -2 = Tunnel, 0 = WDS, 1-4094 = Tagged", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_PROCESS_IE_REQ, "Process IE Request", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_ENABLE_U_APSD, "Enable UAPSD Mode", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_ADM_CTRL_VOICE, "Enable Admission Control for Voice", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_ADM_CTRL_VIDEO, "Enable Admission Control for Video", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_QOS_UP_VALUE, "DSCP to UP Mapping", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_PRIORITY_OVERRIDE, "Enable DSCP to UP Override", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_DSCP_OVERRIDE_VALUE, "DSCP to UP Override value", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_ENABLE_802_11_E, "Enable 802.11E", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_ENABLE_WMM, "Enable WMM Mode", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_LEGACY_CLIENT_PRIORITY, "Enable Legacy Value", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_SSID_ID, "Internal VID Number Assigned by Controller", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_SSID_BCAST_STRING, "SSID String", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_SSID_SUPPRESS, "Enable Suppress SSID", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_802_1_X_ENABLE, "Enable 802.11X", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_802_1_X_DYN_REKEY, "VAP Group Key Update Interval", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WPA_ENABLE, "Enable WPA", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WPA_V2_ENABLE, "Enable WPA V2", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WPA_PASSPHRASE, "WPA-PSK Passphrase", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WPA_CIPHER_TYPE, "WPA Cipher Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WPA_V2_CIPHER_TYPE, "WPA V2 Cipher Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WEP_KEY_INDEX, "WEP Key Index", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WEP_DEFAULT_KEY_VALUE, "WEP Default Key", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_CHANNEL_REPORT, "Channel Report", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WDS_SERVICE, "WDS Service Type: 0 = None, 1 = Child, 2 = Parent, 3 = Both", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WDS_BSSID_PARENT, "WDS Parent BSSID", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WDS_BRIDGE, "Enable WDS Bridge: 0 = Unknown, 1 = Enable, 2 = Disable", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_OKC_ENABLED, "OKC/Preauthentication", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_MU_ASSOC_RETRIES, "MU Association Retries", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_MU_ASSOC_TIMEOUT, "MU Association Request Time Out", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WDS_PARENT, "WDS Parent AP", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WDS_BACK_PARENT, "WDS Backup Parent AP", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WDS_NAME, "WDS AP Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_SESSION_AVAIL, "Enable Session Availability", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_UL_POLICER_ACTION, "Up Link Policer Action: Bit0 Set = Downgrade, Bit1 Set = Drop, Bit2 Set = Delete TSPEC", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_DL_POLICER_ACTION, "Down Link Policer Action: Bit0 Set = Downgrade, Bit1 Set = Drop, Bit2 Set = Delete TSPEC", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_ENABLE_802_11_K, "Enable 802.11K", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_ENABLE_802_11_H_BG, "Enable 802.11H For BG Radio", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_SITE_EGRESS_FILTER_MODE, "Site Egress Filter Mode", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_DEFAULT_IDLE_PRE_TIMEOUT, "Default Idle Pre Timeout", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_DEFAULT_IDLE_POST_TIMEOUT, "Default Idle Post Timeout", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_IGNORE_COS, "Ignore CoS In This VNS", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RADIUS_SERVER_INDEX2, "Secondary Radius Server Index", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_MCAST_OPTIMIZATION, "Multicast: IGMP Snooping Enable/Disable Per VNS", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_MCAST_IGMP_TIMEOUT, "Multicast: IGMP Snooping LDMG Entry Expire Timer In Minutes", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_MCAST_FILTER_ENABLE, "Enable Multicast Filtering at AP", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_FILTER_CONFIG_BLOCK, "Filter Config Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_FILTER, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_DATA_REASSEMBLY_ENABLE, "Enable Fragmentation", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_UCAST_FILTER_ENABLE, "Enable Unicast Filter", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RATECTRL_CIR_UL, "Uplink CIR", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RATECTRL_CIR_DL, "Downlink CIR", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RATECTRL_CBS_UL, "Uplink CBS", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RATECTRL_CBS_DL, "Downlink CBS", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_AIRTIME_FAIRNESS_ENABLE, "Enable Airtime Fairness", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_POWERSAVE_ENABLE, "Enable Power Save", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_GROUP_KP_SAVE_RETRY, "Group Power Save Retry", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_BALANCE_GROUP, "Enable Vlan Membership to The Radio Balance", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_MESH_TYPE, "Mesh Type: 0 = Static WDS, 1 = Dynamic WDS", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_MESH_ROAMING_THRESHOLD, "Mesh Roaming Threshold", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_COS, "AP COS", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RATE_LIMIT_RESOURCE_TBL, "Rate Limit Resource List", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_AP_AUTH_CLIENT_MODES, "Client Authentication Mode: Bit0 Set = MBA, Bit1 SET = Dot1x, Bit2 Set = CP", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_DEFAULT_POLICY_INDEX, "Default Policy Index", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_AUTH_POLICY_INDEX, "Authentication Policy Index", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_NONAUTH_POLICY_INDEX, "Non Authentication Policy Index", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RADIUS_SERVER_INDEX, "Primary Radius Server", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_NAS_IP, "NAS IP", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_NAS_ID, "NAS Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_VSA_SELMASK, "VSA Mask", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_MBA_OPTIONS_MASK, "MBA Options  Mask", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_MBA_TIMEOUT_POLICY_KEY, "MBA Timeout Policy Key", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WLAN_SERVICE_NAME, "WLAN Service Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_DEFAULT_SESSION_TIMEOUT, "Default Session Timeout", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RADIUS_CALLED_STATION_ID, "Radius Called Station ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_CAPTIVE_PORTAL, "Enable Captive Portal", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_COS_CONFIG_BLOCK, "COS Configuration Block Index", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_TOPOLOGY_KEY, "Topology Key", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_MU_INIT_PERIOD_BEHAVIOUR, "MU Init Behaviour: 0 = Discard Non Auth Traffic, 1 = Default Policy", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_DYNAMIC_EGRESS_VLANS, "Dynamic Egress Vlan list", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_STATIC_EGRESS_VLANS, "Static Egress Vlan list", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_FLAGS, "Policy Flags Based on Analyzing The Rules Inside The Policy", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_DEFAULT_ACTION, "Default Action", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_CONTAIN_TO_VLAN, "Default Contain Vlan", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_PVID_TOPOLOGY_KEY, "PVID Topology Key", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_AP_REDIRECT, "AP Redirect Mode: -1 = Invalid, 0 = Disable, 1 = At Controller, 2 = At AP", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_ADM_CTRL_BE, "Enable Admission Control For Best Effort", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_ADM_CTRL_BK, "Enable Admission Control For Background", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_11K_ENABLE, "Enable 802.11K", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_11K_RM_CAP, "802.11K RM Capacity", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_11R_ENABLE, "Enable 802.11R", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_11R_R0KH_ID, "802.11R R0 Key Holder ID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_11R_MD_ID, "802.11R Mobility Domain ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_MGMT_FRAME_PROTECTION, "Protected Management Frames: 0 = Enable, 1 = Disable, 2 = Require", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_NETFLOW, "Control for NetFlow: 1 = Enable, 2 = Disable", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_WLAN_DEFAULT_MIRRORN, "V_WLAN_DEFAULT_MIRRORN", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_DEFAULT_MIRRORN, "WLAN Default MirrorN: 0 = None, 1 = Prohibited, 2 = Enable, 3 = Enable TCP and UDP Both Direction, 4 = Enable TCP and UDP In Direction ", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_11U_ANQP_BLOCK, "802.11U ANQP Config Block", TLV_TYPE_BLOCK_TLV, TAB_11U_ANQP_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_HS2_BLOCK, "HS2 Configuration Block", TLV_TYPE_BLOCK_TLV, TAB_HS2_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_APP_IDENTIFICATION_ENABLED, "Enable/Disable Application Identification", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_PRIVACY, "Privacy", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_11U_OSEN, "Enable OSU Server-Only Authenticated L2 Encryption Network", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_QOS_IN_USE, "Bitmask Used to Select DHCP Values for QoS Mapping", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_CP_CONFIG_BLOCK, "CP Configuration Block", TLV_TYPE_BLOCK_TLV, TAB_V_CP_CONFIG_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_CP_IDENTITY, "User Identity", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_CP_PASSPHRASE, "Shared Secret in Encryption Form", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_CP_REDIRECT_URL, "Redirection Url for Non-auth Policy", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_CP_USE_HTTPS, "Enable HTTPS", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_CP_AUTH_URL, "Where to Redirect MU After Successful Authentication", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_CP_FLAGS, "Bitmap for Captive Portal Flags", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_CP_AP_FQDN, "AP FQDN Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_VNS_NAME, "VNS Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_LDAP_SERVER_INDEX, "LDAP Server for CP Authentication", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_AIRTIME_RESERVATION, "Assign Airtime to VNS  In Percentage In Steps of 10%", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0}

};





//EID_STATS_VNS_BLOCK
typedef enum
{
	EID_V_STATS_UNUSED0,
	EID_V_STATS_VNSID,
	EID_V_STATS_RADCL_REQS,
	EID_V_STATS_RADCL_FAILED,
	EID_V_STATS_RADCL_REJECTS,
	EID_V_STATS_VNS_ENTRY = 118
} wassp_subtlv_vns_status_type_t;

static const TLV_PARSER_ENTRY tlvVnsStatusTable[]  =
{
	{ EID_V_STATS_UNUSED0, "VNS Stats Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_STATS_VNSID, "VNS ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_STATS_RADCL_REQS, "VNS Radius Stats Request", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_STATS_RADCL_FAILED, "VNS Radius Stats Failed", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_STATS_RADCL_REJECTS, "VNS Radius Stats Reject", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_STATS_VNS_ENTRY, "VNS Stats Entry", TLV_TYPE_BLOCK_TLV, TAB_STATS_VNS, 0, 0, 0, 0, 0, 0, 0}

};





//RADIUS: Global Radius Config Block (V8R11: Site)

typedef enum
{
	EID_RADIUS_ID = 0,
	EID_RADIUS_IP_NAME,
	EID_RADIUS_SHAREDSECRET,
	EID_RADIUS_PROTOCOL,
	EID_RADIUS_PORT,
	EID_RADIUS_TIMEOUT,
	EID_RADIUS_RETRY,
	EID_RADIUS_MBA_MAC_FORMAT,
	EID_RADIUS_MBA_PASSWORD

} wassp_subtlv_radius_config_type_t;

static const TLV_PARSER_ENTRY tlvRadiusConfigTable[]  =
{
	{ EID_RADIUS_ID, "Radius ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIUS_IP_NAME, "Radius Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIUS_SHAREDSECRET, "Radius Shared Secret", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIUS_PROTOCOL, "Radius Protocol: 0 = PAP, 1 = CHAP, 2 = MS CHAP, 3 = MS CHAP2", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIUS_PORT, "Radius Port", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIUS_TIMEOUT, "Radius Timeout", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIUS_RETRY, "Radius Retry Count", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIUS_MBA_MAC_FORMAT, "Radius MBA MAC Format", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_RADIUS_MBA_PASSWORD, "Radius MBA Password", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0}

};



//RADSRV:Radius Server Config Block for a specific VNS (for V6R0: Branch 802.1x)
typedef enum
{
	EID_V_UNUSED0,
	EID_V_RADSRV_SRV_ID,
	EID_V_RADSRV_SRV_TYPE,
	EID_V_RADSRV_SRV_PORT,
	EID_V_RADSRV_SRV_RETRY,
	EID_V_RADSRV_SRV_TIMEOUT,
	EID_V_RADSRV_AUTH_TYPE,
	EID_V_RADSRV_PASSWORD,
	EID_V_RADSRV_NAS_IP,
	EID_V_RADSRV_NAS_ID

} wassp_subtlv_radius_server_config_type_t;

static const TLV_PARSER_ENTRY tlvRadiusServerConfigTable[]  =
{
	{ EID_V_UNUSED0, "V_UNUSED0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RADSRV_SRV_ID, "Radius Server ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RADSRV_SRV_TYPE, "Radius Server Type", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RADSRV_SRV_PORT, "Radius Server Port", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RADSRV_SRV_RETRY, "Radius Server Retry", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RADSRV_SRV_TIMEOUT, "Radius Server Timeout", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RADSRV_AUTH_TYPE, "Radius Server Authentication Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RADSRV_PASSWORD, "Radius Server Password", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RADSRV_NAS_IP, "Radius Server NAS IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_RADSRV_NAS_ID, "Radius Server NAS ID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0}
};


typedef enum
{
	EID_V_FILTER_UNUSED_0,
	EID_V_FILTER_NAME,
	EID_V_FILTER_RULES,
	EID_V_FILTER_TYPE,
	EID_V_FILTER_KEY,
	EID_V_SITE_FILTER_RULES,
	EID_V_FILTER_BYPASS_BMCAST,
	EID_V_FILTER_RULES_EXT_BLOCK,
	EID_V_SITE_FILTER_RULES_EXT_BLOCK


} wassp_subtlv_filter_block_type_t;


static const TLV_PARSER_ENTRY tlvFilterConfigTable[]  =
{
	{ EID_V_FILTER_UNUSED_0, "Filter Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_FILTER_NAME, "Filter Rule Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_FILTER_RULES, "Filter Rule Bit Mask", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_FILTER_TYPE, "Filter Rule Type", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_FILTER_KEY, "Filter Rule Key", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_SITE_FILTER_RULES, "Site Filter Rules", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_FILTER_BYPASS_BMCAST, "Bypass Broadcast and Multicast", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_FILTER_RULES_EXT_BLOCK, "Filter Rule Extended Block", TLV_TYPE_BLOCK_TLV, TAB_V_FILTER_RULES_EXT_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_SITE_FILTER_RULES_EXT_BLOCK, "Site Filter Rule Extended Block", TLV_TYPE_BLOCK_TLV, TAB_V_SITE_FILTER_RULES_EXT_BLOCK, 0, 0, 0, 0, 0, 0, 0}
};



typedef enum
{
	EID_V_FILTER_UNUSED0,
	EID_V_FILTER_RULE_FIXED_APP_ID,
	EID_V_FILTER_RULE_EXT_ACT_FLAGS,
	EID_V_FILTER_RULES_APP_SIG_GROUP_ID,
	EID_V_FILTER_RULES_APP_SIG_DISP_ID,
	EID_V_FILTER_RULES_IPV6_ADDR

} wassp_subtlv_filter_rule_ext_block_type_t;



static const TLV_PARSER_ENTRY tlvFilterRuleExtConfigTable[]  =
{
	{ EID_V_FILTER_UNUSED0, "Filter Rule Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_FILTER_RULE_FIXED_APP_ID, "Fixed Application Rule ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_FILTER_RULE_EXT_ACT_FLAGS, "Filter Rule Ext Act Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_FILTER_RULES_APP_SIG_GROUP_ID, "Application Signature group ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_FILTER_RULES_APP_SIG_DISP_ID, "Application Signature Display ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_FILTER_RULES_IPV6_ADDR, "Filter Rule IPV6 List", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0}

};


typedef enum
{
	EID_V_SITE_FILTER_UNUSED0,
	EID_V_SITE_FILTER_RULE_FIXED_APP_ID,
	EID_V_SITE_FILTER_RULE_EXT_ACT_FLAGS,
	EID_V_SITE_FILTER_RULES_APP_SIG_GROUP_ID,
	EID_V_SITE_FILTER_RULES_APP_SIG_DISP_ID,
	EID_V_SITE_FILTER_RULES_IPV6_ADDR

} wassp_subtlv_site_filter_rule_ext_block_type_t;



static const TLV_PARSER_ENTRY tlvSiteFilterRuleExtConfigTable[]  =
{
	{ EID_V_SITE_FILTER_UNUSED0, "Site Filter Rule Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_SITE_FILTER_RULE_FIXED_APP_ID, "Site Fixed Application Rule ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_SITE_FILTER_RULE_EXT_ACT_FLAGS, "Site Filter Rule Ext Act Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_SITE_FILTER_RULES_APP_SIG_GROUP_ID, "Site Application Signature group ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_SITE_FILTER_RULES_APP_SIG_DISP_ID, "Site Application Signature Display ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_V_SITE_FILTER_RULES_IPV6_ADDR, "Site Filter Rule IPV6 List", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0}
};



#if 0
//BSSID2IP: BSSID to IP mapping block (for V6R0: VoWIFI)
typedef enum
{
	EID_BSSID2IP_UNUSED0,
	EID_BSSID2IP_BSSID,
	EID_BSSID2IP_IP

} wassp_subtlv_bssid2ip_block_type_t;


static const TLV_PARSER_ENTRY tlvBssid2ipConfigTable[]  =
{
	{ EID_BSSID2IP_UNUSED0, "BSSID2IP Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BSSID2IP_BSSID, "BSSID2IP BSSID", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_BSSID2IP_IP, "BSSID2IP IP Address", TLV_TYPE_IP_ADDR, 0, 0, 0, 0, 0, 0, 0, 0}

};
#endif

//EID_SITE_CONFIG_BLOCK: Site Config Block (V8.11: Rad@AP)
typedef enum
{
	EID_G_SITE_ENABLE = 4,
	EID_G_SITE_NAME,
	EID_G_RADIUS_CLIENT_AT_AP,
	EID_G_HYBRID_POLICY_MODE,
	EID_G_LOCATION,
	EID_G_INVALID_POLICY,
	EID_NAC_MBA_LOCAL_AUTH,
	EID_NAC_RULE_ARRAY,
	EID_NAC_RULE_BLOCK,
	EID_NAC_RULE_FLAGS,
	EID_NAC_RULE_AUTH_TYPE,
	EID_NAC_RULE_USER_USERNAME_GROUP_KEY,
	EID_NAC_RULE_USER_LDAPUSER_GROUP_KEY,
	EID_NAC_RULE_ENDSYS_HOSTNAME_GROUP_KEY,
	EID_NAC_RULE_ENDSYS_LDAPHOST_GROUP_KEY,
	EID_NAC_RULE_ENDSYS_IPv4_GROUP_KEY,
	EID_NAC_RULE_ENDSYS_MAC_GROUP_KEY,
	EID_NAC_RULE_DEV_TYPE_GROUP_KEY,
	EID_NAC_RULE_LOCATION_GROUP_KEY,
	EID_NAC_RULE_TIME_GROUP_KEY,
	EID_NAC_RULE_POLICY_KEY,
	EID_NAC_LDAP_USER_GROUP_ARRAY,
	EID_NAC_LDAP_USER_GROUP_BLOCK,
	EID_NAC_LDAP_USER_GROUP_KEY,
	EID_NAC_LDAP_USER_GROUP_MATCH_MODE,
	EID_NAC_LDAP_USER_ATTR_ARRAY,
	EID_NAC_LDAP_USER_ATTR_BLOCK,
	EID_NAC_LDAP_USER_ATTR_KEY,
	EID_NAC_LDAP_USER_ATTR_VAL,
	EID_NAC_USERNAME_GROUP_ARRAY,
	EID_NAC_USERNAME_GROUP_BLOCK,
	EID_NAC_USERNAME_GROUP_KEY,
	EID_NAC_USERNAME_ARRAY,
	EID_NAC_USERNAME,
	EID_NAC_HOSTNAME_GROUP_ARRAY,
	EID_NAC_HOSTNAME_GROUP_BLOCK,
	EID_NAC_HOSTNAME_GROUP_KEY,
	EID_NAC_HOSTNAME_ARRAY,
	EID_NAC_HOSTNAME,
	EID_NAC_HOST_IPv4_GROUP_ARRAY,
	EID_NAC_HOST_IPv4_GROUP_BLOCK,
	EID_NAC_HOST_IPv4_GROUP_KEY,
	EID_NAC_HOST_IPv4_ARRAY,
	EID_NAC_HOST_IPv4_ADDRESS,
	EID_NAC_LDAP_HOST_GROUP_ARRAY,
	EID_NAC_LDAP_HOST_GROUP_BLOCK,
	EID_NAC_LDAP_HOST_GROUP_KEY,
	EID_NAC_LDAP_HOST_GROUP_MATCH_MODE,
	EID_NAC_LDAP_HOST_ATTR_ARRAY,
	EID_NAC_LDAP_HOST_ATTR_BLOCK,
	EID_NAC_LDAP_HOST_ATTR_KEY,
	EID_NAC_LDAP_HOST_ATTR_VAL,
	EID_NAC_HOST_MAC_GROUP_ARRAY,
	EID_NAC_HOST_MAC_GROUP_BLOCK,
	EID_NAC_HOST_MAC_GROUP_KEY,
	EID_NAC_HOST_MAC_ARRAY,
	EID_NAC_HOST_MAC,
	EID_NAC_DEV_TYPE_GROUP_ARRAY,
	EID_NAC_DEV_TYPE_GROUP_BLOCK,
	EID_NAC_DEV_TYPE_GROUP_KEY,
	EID_NAC_DEV_TYPE_ARRAY,
	EID_NAC_DEV_TYPE_ATTRIBUTE,
	EID_NAC_TIME_GROUP_ARRAY,
	EID_NAC_TIME_GROUP_BLOCK,
	EID_NAC_TIME_RANGE_GROUP_KEY,
	EID_NAC_TIME_RANGE_ARRAY,
	EID_NAC_TIME_RANGE,
	EID_NAC_LOC_GROUP_ARRAY,
	EID_NAC_LOC_GROUP_BLOCK,
	EID_NAC_LOC_GROUP_KEY,
	EID_NAC_LOC_ATTR_ARRAY,
	EID_SITE_RATE_CONTROL_BLOCK,
	EID_NAC_LOC_ATTR_BLOCK,
	EID_NAC_LOC_SSID,
	EID_NAC_LOC_APID,
	EID_NAC_LDAP_SRV_ARRAY,
	EID_SITE_TOPOLOGY_BLOCK,
	EID_NAC_LDAP_SRV_BLOCK,
	EID_NAC_LDAP_SRV_KEY,
	EID_NAC_LDAP_SRV_URL,
	EID_NAC_LDAP_SRV_TIMEOUT,
	EID_NAC_LDAP_USER_SRCH_ROOT,
	EID_NAC_LDAP_HOST_SRCH_ROOT,
	EID_NAC_LDAP_OU_SRCH_ROOT,
	EID_NAC_LDAP_USER_OBJ_CLASS,
	EID_NAC_LDAP_USER_SRCH_ATTR,
	EID_NAC_LDAP_HOST_OBJ_CLASS,
	EID_NAC_LDAP_HOST_SRCH_ATTR,
	EID_NAC_LDAP_FLAGS,
	EID_NAC_LDAP_USER_AUTH_TYPE,
	EID_NAC_LDAP_OU_OBJ_CLASS_ARRAY,
	EID_NAC_LDAP_OU_OBJ_CLASS,
	EID_NAC_KRB_REALM_ARRAY,
	EID_NAC_KRB_REALM_BLOCK,
	EID_SITE_POLICY_BLOCK,
	EID_SITE_FILTER_CONFIG_BLOCK,
	EID_SITE_COS_CONFIG_BLOCK,
	EID_SITE_LOCATION_BASED_LOOKUP_BLOCK,
	EID_SITE_RADIUS_SERVER_BLOCK,
	EID_NAC_KRB_KDCS,
	EID_NAC_LDAP_SERVER_INDEX,
	EID_NAC_SERVER_CONFIG_ARRAY,
	EID_NAC_SERVER_CONFIG_BLOCK,
	EID_NAC_SERVER_FQDN,
	EID_NAC_SERVER_IPV4_ADDR,
	EID_NAC_SERVER_DOMAIN,
	EID_NAC_SERVER_ADMIN_ID,
	EID_NAC_SERVER_ADMIN_PWD,
	EID_NAC_SERVER_WORKGROUP,
	EID_NAC_RULE_ENDSYS_WEB_AUTH_USER_GROUP_KEY,
	EID_NAC_WEB_AUTH_USER_GROUP_ARRAY,
	EID_NAC_WEB_AUTH_USER_GROUP_BLOCK,
	EID_NAC_WEB_AUTH_USER_GROUP_KEY,
	EID_NAC_WEB_AUTH_USER_ARRAY,
	EID_G_SITE_MAX

} wassp_subtlv_site_config_type_t;

static const TLV_PARSER_ENTRY tlvSiteConfigTable[]  =
{
	{ EID_G_SITE_ENABLE, "Enable Site", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_G_SITE_NAME, "Site Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_G_RADIUS_CLIENT_AT_AP, "Enables Radius Client At AP", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_G_HYBRID_POLICY_MODE, "Hybrid Policy Mode", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_G_LOCATION, "Location", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_G_INVALID_POLICY, "Invalid Policy Action", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_MBA_LOCAL_AUTH, "NAC MBA Authentication Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_ARRAY, "Array of NAC Rule Structures", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_BLOCK, "NAC Rule Configuration Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_FLAGS, "Negate Flags For Different Groups", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_AUTH_TYPE, "Authentication Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_USER_USERNAME_GROUP_KEY, "Key Identifier of User Name Group", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_USER_LDAPUSER_GROUP_KEY, "Key identifier of LDAP User Group", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_ENDSYS_HOSTNAME_GROUP_KEY, "Key Identifier of End System Host Name Group", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_ENDSYS_LDAPHOST_GROUP_KEY, "Key Identifier of End System LDAP Host Group", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_ENDSYS_IPv4_GROUP_KEY, "Key Identifier of End System IPv4 Group", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_ENDSYS_MAC_GROUP_KEY, "Key Identifier of End System Mac Group", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_DEV_TYPE_GROUP_KEY, "Key Identifier of Device", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_LOCATION_GROUP_KEY, "Key Identifier of Location Group", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_TIME_GROUP_KEY, "Key Identifier of Time Group", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_POLICY_KEY, "Policy ID", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_USER_GROUP_ARRAY, "NAC LDAP User Group Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_USER_GROUP_BLOCK, "NAC LDAP User Group Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_USER_GROUP_KEY, "Key Identifier of Specific LDAP User Group", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_USER_GROUP_MATCH_MODE, "Match Mode of LDAP User Group", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_USER_ATTR_ARRAY, "NAC LDAP User Attribute Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_USER_ATTR_BLOCK, "NAC LDAP User Attribute Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_USER_ATTR_KEY, "LDAP User Attribute Key", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_USER_ATTR_VAL, "LDAP User Attribute Value", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_USERNAME_GROUP_ARRAY, "NAC Username Group Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_USERNAME_GROUP_BLOCK, "NAC Username Group Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_USERNAME_GROUP_KEY, "Key Identifier of Specific Username Group", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_USERNAME_ARRAY, "NAC Username Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_USERNAME, "NAC Username", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOSTNAME_GROUP_ARRAY, "NAC Host Name Group Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOSTNAME_GROUP_BLOCK, "NAC Host Name Group Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOSTNAME_GROUP_KEY, "NAC Host Name Group Key", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOSTNAME_ARRAY, "NAC Host Name Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOSTNAME, "NAC Host Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOST_IPv4_GROUP_ARRAY, "Array of Host By IPv4 Groups", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOST_IPv4_GROUP_BLOCK, "NAC Host IPv4 Group Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOST_IPv4_GROUP_KEY, "NAC Host IPv4 Group key", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOST_IPv4_ARRAY, "NAC Host IPv4 Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOST_IPv4_ADDRESS, "NAC Host IPv4 Address", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_HOST_GROUP_ARRAY, "NAC LDAP Host Group Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_HOST_GROUP_BLOCK, "NAC LDAP Host Group Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_HOST_GROUP_KEY, "NAC LDAP Host Group Key", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_HOST_GROUP_MATCH_MODE, "Match Mode of Specific LDAP Host Group", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_HOST_ATTR_ARRAY, "NAC LDAP Host Attribute Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_HOST_ATTR_BLOCK, "NAC LDAP Host Attribute Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_HOST_ATTR_KEY, "NAC LDAP Host Attribute Key", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_HOST_ATTR_VAL, "NAC LDAP Host Attribute value", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOST_MAC_GROUP_ARRAY, "NAC Host Mac Group Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOST_MAC_GROUP_BLOCK, "NAC Host Mac Group Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOST_MAC_GROUP_KEY, "NAC Host Mac Group Key", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOST_MAC_ARRAY, "NAC Host Mac Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_HOST_MAC, "NAC Host Mac", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_DEV_TYPE_GROUP_ARRAY, "NAC Device Type Group Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_DEV_TYPE_GROUP_BLOCK, "NAC Device Type Group Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_DEV_TYPE_GROUP_KEY, "NAC Device Type Group Key", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_DEV_TYPE_ARRAY, "NAC Device Type Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_DEV_TYPE_ATTRIBUTE, "NAC Device Type Attribute", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_TIME_GROUP_ARRAY, "NAC Time Group Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_TIME_GROUP_BLOCK, "NAC Time Group Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_TIME_RANGE_GROUP_KEY, "NAC Time Group Key", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_TIME_RANGE_ARRAY, "NAC Time Range Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_TIME_RANGE, "NAC Time Range", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LOC_GROUP_ARRAY, "NAC Location Group Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LOC_GROUP_BLOCK, "NAC Location Group Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LOC_GROUP_KEY, "NAC Location Group Key", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LOC_ATTR_ARRAY, "NAC Location Attribute Array", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SITE_RATE_CONTROL_BLOCK, "Site Rate Control Block", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LOC_ATTR_BLOCK, "NAC Location Attribute Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LOC_SSID, "NAC Location SSID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LOC_APID, "NAC Location AP ID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_SRV_ARRAY, "NAC Array of LDAP Servers", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SITE_TOPOLOGY_BLOCK, "Site Topology Block", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_SRV_BLOCK, "NAC LDAP Server Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_SRV_KEY, "NAC LDAP Server Key", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_SRV_URL, "NAC LDAP Server Url", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_SRV_TIMEOUT, "Timeout for Response From LDAP Server", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_USER_SRCH_ROOT, "LDAP Server User Search Root", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_HOST_SRCH_ROOT, "LDAP Server Hostname Search Root", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_OU_SRCH_ROOT, "LDAP Server OU Search Root", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_USER_OBJ_CLASS, "LDAP Server User Object Class", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_USER_SRCH_ATTR, "LDAP Server User Search Attribute", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_HOST_OBJ_CLASS, "LDAP Server Host object Class", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_HOST_SRCH_ATTR, "LDAP Server Host Search Attribute", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_FLAGS, "LDAP Server Flag", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_USER_AUTH_TYPE, "User Authentication Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_OU_OBJ_CLASS_ARRAY, "Array of NAC LDAP Organizational Units (OU) Object Classes", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_OU_OBJ_CLASS, "NAC LDAP Organizational Units (OU) Object Class", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_KRB_REALM_ARRAY, "Array of NAC Kerberos Realms", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_KRB_REALM_BLOCK, "NAC Kerberos Realm Block", TLV_TYPE_BLOCK_TLV, TAB_CONFIG_SITE, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SITE_POLICY_BLOCK, "Policy Block", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SITE_FILTER_CONFIG_BLOCK, "Filter Configuration Block",TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SITE_COS_CONFIG_BLOCK, "COS Configuration Block", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SITE_LOCATION_BASED_LOOKUP_BLOCK, "Location Based Lookup Block", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_SITE_RADIUS_SERVER_BLOCK, "Radius Server Block", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_KRB_KDCS, "List of Kerberos KDC FQDN", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_LDAP_SERVER_INDEX, "LDAP Server for MU Authorization", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_SERVER_CONFIG_ARRAY, "Array of NAC Authentication Server Configurations", TLV_TYPE_BLOCK_TLV, TAB_NAC_SERVER_CONFIG_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_SERVER_CONFIG_BLOCK, "NAC Authentication Server Block", TLV_TYPE_BLOCK_TLV, TAB_NAC_SERVER_CONFIG_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_SERVER_FQDN, "Authentication Server FQDN", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_SERVER_IPV4_ADDR, "Authentication Server IPv4 address", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_SERVER_DOMAIN, "Authentication Server Domain", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_SERVER_ADMIN_ID, "NAC Authentication Server Admin ID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_SERVER_ADMIN_PWD, "NAC Authentication Server Admin Password", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_SERVER_WORKGROUP, "NAC Authentication Server Workgroup", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_RULE_ENDSYS_WEB_AUTH_USER_GROUP_KEY, "NAC Rule End System WEB Authentication User Group Key", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_WEB_AUTH_USER_GROUP_ARRAY, "NAC WEB Authentication User Group Array", TLV_TYPE_BLOCK_TLV, TAB_NAC_WEB_AUTH_USER_GROUP_ARRAY, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_WEB_AUTH_USER_GROUP_BLOCK, "NAC WEB Authentication User Group Block", TLV_TYPE_BLOCK_TLV, TAB_NAC_WEB_AUTH_USER_GROUP_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_WEB_AUTH_USER_GROUP_KEY, "NAC WEB Authentication User Group key", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_NAC_WEB_AUTH_USER_ARRAY, "NAC WEB Authentication User", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_G_SITE_MAX, "G_SITE_MAX",0, 0, 0, 0, 0, 0, 0, 0, 0}
};






//EID_POLICY_BLOCK: Policy Table
typedef enum
{
	EID_POLICY_UNUSED0,
	EID_POLICY_ENTRY_NAME,
	EID_POLICY_ENTRY_KEY,
	EID_POLICY_TOPOLOGY_KEY,
	EID_POLICY_TOPOLOGY_VLAN_ID,
	EID_POLICY_TOPOLOGY_TYPE,
	EID_POLICY_FILTER_KEY,
	EID_POLICY_COS_KEY,
	EID_POLICY_IGNORE_COS,
	EID_POLICY_DYNAMIC_EGRESS_VLANS,
	EID_POLICY_STATIC_EGRESS_VLANS,
	EID_POLICY_DEFAULT_ACTION,
	EID_POLICY_FLAGS,
	EID_POLICY_DEFAULT_MIRRORN,
	EID_POLICY_RB_REDIRECT_URL

	// update below tlvPolicyConfigTable
} wassp_subtlv_policy_config_type_t;

static const TLV_PARSER_ENTRY tlvPolicyConfigTable[]  =
{
	{ EID_POLICY_UNUSED0, "Policy Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_ENTRY_NAME, "Policy Entry name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_ENTRY_KEY, "Policy Entry Key", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_TOPOLOGY_KEY, "Policy Topology Key", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_TOPOLOGY_VLAN_ID, "Topology Vlan ID", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_TOPOLOGY_TYPE, "Policy Topology Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_FILTER_KEY, "Policy Filter Key", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_COS_KEY, "Policy COS Key", TLV_TYPE_INT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_IGNORE_COS, "Policy Ignore COS", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_DYNAMIC_EGRESS_VLANS, "list of Dynamic Egress VLAN IDs", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_STATIC_EGRESS_VLANS, "list of static egress VLAN IDs", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_DEFAULT_ACTION, "Default Action for Policy", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_FLAGS, "Policy Flags", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_DEFAULT_MIRRORN, "Set Default MirrorN", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_POLICY_RB_REDIRECT_URL, "Policy Redirect Url", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0}

};



//EID_COS_CONFIG_BLOCK
typedef enum
{
	EID_COS_UNUSED0,
	EID_COS_KEY,
	EID_COS_DEFINITION,
	EID_COS_IN_RATE_LIMIT,
	EID_COS_OUT_RATE_LIMIT
} wassp_subtlv_cos_config_type_t;

static const TLV_PARSER_ENTRY tlvCosConfigTable[]  =
{
	{ EID_COS_UNUSED0, "COS Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COS_KEY, "COS Key", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COS_DEFINITION, "Binary Encoded COS Definition", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COS_IN_RATE_LIMIT, "Input Rate Limit in Kbps", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_COS_OUT_RATE_LIMIT, "Output Rate Limit in Kbps", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0}

};

//EID_11U_ANQP_BLOCK
typedef enum
{
	EID_11U_UNUSED0,
	EID_11U_3GPP_CELL_NETWORK_ARRAY,
	EID_11U_3GPP_CELL_NETWORK_STRUCT,
	EID_11U_3GPP_CELL_NETWORK_MCC,
	EID_11U_3GPP_CELL_NETWORK_MNC,
	EID_11U_ACCESS_NETWORK_TYPE,
	EID_11U_ASRA,
	EID_11U_DOMAIN_NAME,
	EID_11U_EAP_AUTH_PARAM,
	EID_11U_EAP_AUTH_PARAM_ARRAY,
	EID_11U_EAP_AUTH_PARAM_STRUCT,
	EID_11U_EAP_AUTH_TYPE,
	EID_11U_EAP_METHOD,
	EID_11U_EAP_METHODS_ARRAY,
	EID_11U_EAP_METHODS_STRUCT,
	EID_11U_HESSID,
	EID_11U_INTERNET_AVAILABLE,
	EID_11U_IPV4_ADDR_TYPE_AVAIL,
	EID_11U_IPV6_ADDR_TYPE_AVAIL,
	EID_11U_NAI_REALM,
	EID_11U_NAI_REALM_ARRAY,
	EID_11U_NAI_REALM_STRUCT,
	EID_11U_NETWORK_AUTH_TYPE,
	EID_11U_ROAMING_CONSORTIUM,
	EID_11U_ROAMING_CONSORTIUM_ARRAY,
	EID_11U_VENUE_INFO_GROUP_CODE,
	EID_11U_VENUE_INFO_TYPE_ASSIGNMENTS,
	EID_11U_VENUE_NAME_ARRAY,
	EID_11U_VENUE_NAME,
	EID_11U_NETWORK_AUTH_TYPE_URL
} wassp_subtlv_11u_anqp_config_type_t;


static const TLV_PARSER_ENTRY tlv11U_ANQP_blockTable[]  =
{
	//Members of EID_11U_ANQP_BLOCK block
	{ EID_11U_UNUSED0, "11U Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_3GPP_CELL_NETWORK_ARRAY, "11U 3GPP Cell Network Array", TLV_TYPE_BLOCK_TLV, TAB_11U_ANQP_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_3GPP_CELL_NETWORK_STRUCT, "11U 3GPP Cell Network Struct", TLV_TYPE_BLOCK_TLV, TAB_11U_ANQP_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_3GPP_CELL_NETWORK_MCC, "11U 3GPP Cell Network MCC", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_3GPP_CELL_NETWORK_MNC, "11U 3GPP Cell Network MNC", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_ACCESS_NETWORK_TYPE, "11U Access network Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_ASRA, "11U ASRA", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_DOMAIN_NAME, "11U Domain Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_EAP_AUTH_PARAM, "11U EAP Authentication Parameter", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_EAP_AUTH_PARAM_ARRAY, "11U EAP Authentication Parameter Array", TLV_TYPE_BLOCK_TLV, TAB_11U_ANQP_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_EAP_AUTH_PARAM_STRUCT, "11U EAP Authentication Parameter Struct", TLV_TYPE_BLOCK_TLV, TAB_11U_ANQP_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_EAP_AUTH_TYPE, "11U EAP Authentication Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_EAP_METHOD, "11U EAP Authentication Method", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_EAP_METHODS_ARRAY, "11U EAP Authentication Methods Array", TLV_TYPE_BLOCK_TLV, TAB_11U_ANQP_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_EAP_METHODS_STRUCT, "11U EAP Authentication Method Struct", TLV_TYPE_BLOCK_TLV, TAB_11U_ANQP_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_HESSID, "11U HESSID", TLV_TYPE_MACADD, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_INTERNET_AVAILABLE, "11U Internet Available", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_IPV4_ADDR_TYPE_AVAIL, "11U IPv4 Address Type Availability", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_IPV6_ADDR_TYPE_AVAIL, "11U IPv6 Address Type Availability", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_NAI_REALM, "11U NAI Realm", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_NAI_REALM_ARRAY, "11U NAI Realm Array", TLV_TYPE_BLOCK_TLV, TAB_11U_ANQP_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_NAI_REALM_STRUCT, "11U NAI Realm Struct", TLV_TYPE_BLOCK_TLV, TAB_11U_ANQP_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_NETWORK_AUTH_TYPE, "11U Network Authentication Type", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_ROAMING_CONSORTIUM, "11U Roaming Consortium", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_ROAMING_CONSORTIUM_ARRAY, "11U Roaming Consortium Array", TLV_TYPE_BLOCK_TLV, TAB_11U_ANQP_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_VENUE_INFO_GROUP_CODE, "11U Venue Info Group Code", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_VENUE_INFO_TYPE_ASSIGNMENTS, "11U Venue Info Type Assignments", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_VENUE_NAME_ARRAY, "1U Venue Name Array", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_VENUE_NAME, "1U Venue Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_11U_NETWORK_AUTH_TYPE_URL, "11U Network Authentication Type Url", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0}



};


// AppVisibility Enforce config block EID_EXTAPP_CONF_BLOCK
typedef enum
{
	EID_EXTAPP_UNUSED0,
	EID_EXTAPP_DISP_NAME,
	EID_EXTAPP_DISP_ID,
	EID_EXTAPP_MATCH_STR,
	EID_EXTAPP_APP_ID,
	EID_EXTAPP_GROUP_ID
} wassp_subtlv_extapp_conf_block_type_t;

static const TLV_PARSER_ENTRY tlvExtapp_conf_blockTable[]  =
{
	{ EID_EXTAPP_UNUSED0, "EXTAPP Unused 0", TLV_TYPE_UNKNOWN, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_EXTAPP_DISP_NAME, "EXTAPP Display Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_EXTAPP_DISP_ID, "EXTAPP Display ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_EXTAPP_MATCH_STR, "EXTAPP Match String", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_EXTAPP_APP_ID, "EXTAPP Application ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_EXTAPP_GROUP_ID, "EXTAPP Application Group ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0}

};


//Members of EID_HS2_BLOCK block
typedef enum
{
	EID_HS2_UNUSED0,
	EID_HS2_ANQP_DOMAIN_ID,
	EID_HS2_CONNECTION_CAP,
	EID_HS2_CONNECTION_CAP_ARRAY,
	EID_HS2_DGAF,
	EID_HS2_ICON_NAME,
	EID_HS2_OPERATING_CLASS,
	EID_HS2_OP_FRIENDLY_NAME_ARRAY,
	EID_HS2_OP_FRIENDLY_NAME,
	EID_HS2_OSU_STRUCT,
	EID_HS2_OSU_SP_ARRAY,
	EID_HS2_OSU_SP_STRUCT,
	EID_HS2_OSU_SP_DESC_ARRAY,
	EID_HS2_OSU_SP_DESC,
	EID_HS2_OSU_SP_FRIENDLY_NAME_ARRAY,
	EID_HS2_OSU_SP_FRIENDLY_NAME,
	EID_HS2_OSU_SP_ICON_ARRAY,
	EID_HS2_OSU_SP_ICON_STRUCT,
	EID_HS2_OSU_SP_METHOD_LIST,
	EID_HS2_OSU_SP_NAI,
	EID_HS2_OSU_SP_SERVER_URI,
	EID_HS2_OSU_SSID,
	EID_HS2_RELEASE,
	EID_HS2_WAN_METRICS_STRUCT,
	EID_HS2_UPLINK_LOAD,
	EID_HS2_UPLINK_SPEED,
	EID_HS2_WIDTH,
	EID_HS2_DOWLINK_LOAD,
	EID_HS2_DOWLINK_SPEED,
	EID_HS2_HIGHT
} wassp_subtlv_hs2_block_type_t;

static const TLV_PARSER_ENTRY tlvHS2_blockTable[]  =
{
	{ EID_HS2_UNUSED0, "HS2 Unused 0", TLV_TYPE_UNKNOWN, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_ANQP_DOMAIN_ID, "HS2 ANQP Domain ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_CONNECTION_CAP, "HS2 Connection Capacity", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_CONNECTION_CAP_ARRAY, "HS2 Connection Capacity Array", TLV_TYPE_BLOCK_TLV, TAB_HS2_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_DGAF, "Enable HS2 DGAF", TLV_TYPE_BOOL, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_ICON_NAME, "HS2 Icon Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OPERATING_CLASS, "HS2 Operating Class", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OP_FRIENDLY_NAME_ARRAY, "HS2 Operation Friendly Name Array", TLV_TYPE_BLOCK_TLV, TAB_HS2_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OP_FRIENDLY_NAME, "HS2 Operation Friendly Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OSU_STRUCT, "HS2 OSU Struct", TLV_TYPE_BLOCK_TLV, TAB_HS2_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OSU_SP_ARRAY, "HS2 OSU SP Array", TLV_TYPE_BLOCK_TLV, TAB_HS2_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OSU_SP_STRUCT, "HS2 OSU SP Struct", TLV_TYPE_BLOCK_TLV, TAB_HS2_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OSU_SP_DESC_ARRAY, "HS2 OSU SP Description Array", TLV_TYPE_BLOCK_TLV, TAB_HS2_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OSU_SP_DESC, "HS2 OSU SP Description", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OSU_SP_FRIENDLY_NAME_ARRAY, "HS2 OSU SP Friendly Name Array", TLV_TYPE_BLOCK_TLV, TAB_HS2_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OSU_SP_FRIENDLY_NAME, "HS2 OSU SP Friendly Name", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OSU_SP_ICON_ARRAY, "HS2 OSU SP Icon Array", TLV_TYPE_BLOCK_TLV, TAB_HS2_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OSU_SP_ICON_STRUCT, "HS2 OSU SP Icon Struct", TLV_TYPE_BLOCK_TLV, TAB_HS2_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OSU_SP_METHOD_LIST, "HS2 OSU SP Method List", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OSU_SP_NAI, "HS2 OSU SP NAI", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OSU_SP_SERVER_URI, "HS2 OSU SP Server Uri", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_OSU_SSID, "HS2 OSU SSID", TLV_TYPE_STRING, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_RELEASE, "HS2 Release", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_WAN_METRICS_STRUCT, "HS2 WAN method Struct", TLV_TYPE_BLOCK_TLV, TAB_HS2_BLOCK, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_UPLINK_LOAD, "HS2 Uplink Load", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_UPLINK_SPEED, "HS2 Uplink Speed", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_WIDTH, "HS2 Width", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_DOWLINK_LOAD, "HS2 Downlink Load", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_DOWLINK_SPEED, "HS2 Downlink Speed", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_HS2_HIGHT, "HS2 Height", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0}


};

//EID_LOCATION_BASED_LOOKUP_BLOCK
typedef enum
{
	EID_LOC_UNUSED0,
	EID_LOC_VLAN_ID_KEY,           //    1
	EID_LOC_POLICY_TOPOLOGY_KEY    //    2
} wassp_subtlv_locationbased_lookup_type_t;


static const TLV_PARSER_ENTRY tlvLocationBaseLookUpTable[]  =
{
	{ EID_LOC_UNUSED0, "Location Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOC_VLAN_ID_KEY, "Location Vlan ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_LOC_POLICY_TOPOLOGY_KEY, "Location Topology ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0}


};


//EID_APP_POLICY_FIXED_BLOCK
typedef enum
{
	EID_APP_POLICY_UNUSED0,
	EID_APP_POLICY_ENTRY_BLOCK     //    1
} wassp_subtlv_app_policy_fixed_type_t;

static const TLV_PARSER_ENTRY tlvAppPolicyFixedTable[]  =
{
	{ EID_APP_POLICY_UNUSED0, "Application Policy Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_APP_POLICY_ENTRY_BLOCK, "Application Policy Entry Block", TLV_TYPE_BLOCK_TLV, TAB_APP_POLICY_ENTRY_BLOCK, 0, 0, 0, 0, 0, 0, 0}


};




// EID_APP_POLICY_ENTRY_BLOCK
typedef enum
{
	EID_APP_POLICY_ENTRY_UNUSED0,
	EID_APP_POLICY_APP_ID,             //   1
	EID_APP_POLICY_OFFSET_LW,          //   2
	EID_APP_POLICY_MASK,               //   3
	EID_APP_POLICY_VALUE               //   4
} wassp_subtlv_app_policy_entry_type_t;


static const TLV_PARSER_ENTRY tlvAppPolicyEntryTable[]  =
{
	{ EID_APP_POLICY_ENTRY_UNUSED0, "Application Policy Entry Unused 0", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_APP_POLICY_APP_ID, "Application Policy ID", TLV_TYPE_UINT, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_APP_POLICY_OFFSET_LW, "Application Policy Offset", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_APP_POLICY_MASK, "Application Policy Masks", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0},
	{ EID_APP_POLICY_VALUE, "Application Policy Values", TLV_TYPE_OCTETS, 0, 0, 0, 0, 0, 0, 0, 0}


};






typedef struct
{
	char subtree_name[WASSP_MAX_SUBTREE_LEN];
	int*  ett_num;
	int  max_entry;
	const TLV_PARSER_ENTRY *entry;
} WASSP_SUBTLV_DECODER_INFO_t;



/* EID_ACTION -- upgrade command */
#define UPGRADE_ACTION_REPORT         (0)    /* report current status  */
#define UPGRADE_ACTION_NO_CHANGE      (1)    /* no upgrade is required */
#define UPGRADE_ACTION_LEGACY         (2)    /* legacy upgrade, stop service and upgrade*/
#define UPGRADE_ACTION_BACKGROUND     (3)    /* background download, keep service then upgrade */
#define UPGRADE_ACTION_SAVE_BACKUP    (4)    /* download image, overwrite backup image*/
#define UPGRADE_ACTION_SWITCH_VERSION (5)    /* switch to a previously downloaded image */
#define UPGRADE_ACTION_ABORT          (6)    /* abort current download operation */
#define UPGRADE_ACTION_STOP_SERVICE   (7)    /* put AP on hold, stopping service */
#define UPGRADE_ACTION_HOLD           (8)    /* put AP on hold, continue providing service !!!*/
#define UPGRADE_ACTION_REBOOT         (9)    /* reboot AP */

/* EID_STATUS -- version report */
#define UPGRADE_STATUS_NONE             (0)    /* not used */
#define UPGRADE_STATUS_SUCCESS          (1)    /* command is successful  */
#define UPGRADE_STATUS_FAIL             (2)    /* command has failed */
#define UPGRADE_STATUS_INPROGRESS       (100)  /* download and writing to flash */
#define UPGRADE_STATUS_DOWNLOAD_FAIL    (101)  /* download and writing to flash */
#define UPGRADE_STATUS_WRITE_FAIL       (102)  /* writing to flash failed */
#define UPGRADE_STATUS_CORRUPTED_FILE   (103)  /*corrupted/unusable image */
#define UPGRADE_STATUS_REBOOTING        (104)  /*AP is rebooting*/
#define UPGRADE_STATUS_INVALID_FILE     (105)  /*invalid image file (checksum, type etc..)*/
#define UPGRADE_STATUS_VERSION_MISMATCH (106)  /* requested version is not found*/

/* Wassp EID Status Type */
typedef enum
{
	EID_STATUS_UNDEFINED = 0,
	EID_STATUS_SUCCESS,
	EID_STATUS_FAILURE,
	EID_STATUS_INPROGRESS,
	EID_STATUS_DOWNLOAD_FAIL,
	EID_STATUS_WRITE_FAIL,
	EID_STATUS_CORRUPTED_FILE,
	EID_STATUS_REBOOTING,
	EID_STATUS_INVALID_FILE,
	EID_STATUS_VERSION_MISMATCH
} wassp_eid_status_t;

/* Wassp EID action Type */
typedef enum
{
	EID_ACTION_REPORT = 0,
	EID_ACTION_NOCHANGE,
	EID_ACTION_LEGACY,
	EID_ACTION_BACKGROUND,
	EID_ACTION_SAVE_BACKUP,
	EID_ACTION_SWITCH_VERSION,
	EID_ACTION_ABORT,
	EID_ACTION_STOP_SERVICE,
	EID_ACTION_HOLD,
	EID_ACTION_REBOOT
} wassp_eid_action_t;







static const value_string wassp_eid_status_types[] =
{
	{ UPGRADE_STATUS_NONE, "Unused" },
	{ UPGRADE_STATUS_SUCCESS, "success" },
	{ UPGRADE_STATUS_FAIL, "failure" },
	{ UPGRADE_STATUS_INPROGRESS, "download in progress" },
	{ UPGRADE_STATUS_DOWNLOAD_FAIL, "image download failed" },
	{ UPGRADE_STATUS_WRITE_FAIL, "writing image to flash failed" },
	{ UPGRADE_STATUS_CORRUPTED_FILE, "main image file is corrupted/unusable" },
	{ UPGRADE_STATUS_REBOOTING, "AP is rebooting" },
	{ UPGRADE_STATUS_INVALID_FILE, "bad header in downloaded image" },
	{ UPGRADE_STATUS_VERSION_MISMATCH, "image version requested does not exist" },
	{ 0, NULL }
};

/* Value string object enumerates wassp action type field */
static const value_string wassp_eid_action_types[] =
{
	{ UPGRADE_ACTION_REPORT, "request status report" },
	{ UPGRADE_ACTION_NO_CHANGE, "no change required" },
	{ UPGRADE_ACTION_LEGACY, "legacy AP upgrade -no service" },
	{ UPGRADE_ACTION_BACKGROUND, "upgrade AP while providing service" },
	{ UPGRADE_ACTION_SAVE_BACKUP, "download and save to backup image" },
	{ UPGRADE_ACTION_SWITCH_VERSION, "switch to a given version" },
	{ UPGRADE_ACTION_ABORT, "abort current download" },
	{ UPGRADE_ACTION_STOP_SERVICE, "put AP on hold,stop wireless service" },
	{ UPGRADE_ACTION_HOLD, "put AP on hold,keep wireless service" },
	{ UPGRADE_ACTION_REBOOT, "reboot AP" },
	{ 0, NULL }
};

static const value_string mu_resv0_strings[] =
{
	{ 0x0000, "UnUsed" },
	{ 0x4000, "Netflow" },
	{ 0x8000, "Mirrorn & Netflow" },
	{ 0xc000, "Mirrorn" },
	{ 0, NULL }
};

static const value_string mu_action_field_strings[] =
{
	{ 0x0, "SSID" },
	{ 0x2, "Redirect With Vlan ID" },
	{ 0x3, "Vlan ID" },
	{ 0, NULL }
};

static const value_string threat_state_strings[] =
{
	{ 0x0, "NA" },
	{ 0x1, "Active" },
	{ 0x2, "Inactive" },
	{ 0, NULL }
};

static const value_string radio_params_strings[] =
{
	{ 0x0, "NONE" },
	{ 0x1, "WMM" },
	{ 0x2, "80211E" },
	{ 0x3, "WMM & 80211E" },
	{ 0x4, "NA" },
	{ 0, NULL }
};

/* True False string object masks RU state  boolean labels */
static const true_false_string wassp_eid_rustate_types =
{
	"Standby",
	"Active",
};


#define WASSP_SUBTLV_GET_SUBTREE(in_ptr) ((in_ptr)->subtree_name)
#define WASSP_SUBTLV_GET_ETTNUM(in_ptr) ((in_ptr)->ett_num)
#define WASSP_SUBTLV_GET_MAXENTRY(in_ptr) ((in_ptr)->max_entry)
#define WASSP_SUBTLV_GET_ENTRY(in_ptr) ((in_ptr)->entry)
#define WASSP_SUBTLV_GET_ENTRY_IDX(in_ptr, idx) ((in_ptr)->entry[(idx)])
#define WASSP_SUBTLV_GET_ENTRY_IDX_TYPE(in_ptr, idx) (((in_ptr)->entry[(idx)]).type)
#define WASSP_SUBTLV_GET_ENTRY_IDX_NAME(in_ptr, idx) (((in_ptr)->entry[(idx)]).name)
#define WASSP_SUBTLV_GET_ENTRY_IDX_TABIDX(in_ptr, idx) (((in_ptr)->entry[(idx)]).length)



/* Wassp protocol registered fields or ru discover fields*/
static int proto_wassp;
static int hf_wassp_version;
static int hf_wassp_type;
static int hf_ru_rad_num;
static int hf_ru_checksum;
static int hf_ru_ac_op;
static int hf_ru_mac;
static int hf_ru_ac_mode;
static int hf_wassp_seq_num_flag;
static int hf_seq_num;
static int hf_wassp_use_frag;
static int hf_wassp_data_frag;
static int hf_wassp_more_frag;
static int hf_wassp_first_frag;
static int hf_wassp_sessionid;
static int hf_wassp_length;
static int hf_wassp_header;
static int hf_ru_discover_header;

/* ----------- MU data --------------*/
static int hf_wassp_mu_type;
static int hf_wassp_mu_qos;
static int hf_wassp_mu_action_ssid;
static int hf_wassp_mu_mac;
static int hf_wassp_mu_data_tree;
static int hf_wassp_mu_resv0;
static int hf_wassp_mu_resv1;
static int hf_wassp_mu_assoc_status;
static int hf_wassp_mu_data_header;
static int hf_wassp_mu_action;
static int hf_wassp_mu_action_field_value;



// netflow
static int  hf_wassp_mu_netflow_version;
static int  hf_wassp_mu_netflow_length;
static int  hf_wassp_mu_netflow_flags;
static int  hf_wassp_mu_netflow_uptime;
static int  hf_wassp_mu_netflow_record;
static int  hf_wassp_mu_netflow_in_bytes;
static int  hf_wassp_mu_netflow_in_packets;
static int  hf_wassp_mu_netflow_ip_protocol_number;
static int  hf_wassp_mu_netflow_source_tos;
static int  hf_wassp_mu_netflow_source_port;
static int  hf_wassp_mu_netflow_source_ip;
static int  hf_wassp_mu_netflow_input_snmp;
static int  hf_wassp_mu_netflow_dest_port;
static int  hf_wassp_mu_netflow_dest_ip;
static int  hf_wassp_mu_netflow_output_snmp;
static int  hf_wassp_mu_netflow_last_time;
static int  hf_wassp_mu_netflow_first_time;
static int  hf_wassp_mu_netflow_in_source_mac;
static int  hf_wassp_mu_netflow_in_dest_mac;
static int  hf_wassp_mu_netflow_tree;
static int  hf_wassp_mu_netflow_header;



/* ------  wassp TLV -------*/
static int hf_wassp_tlv_value;
static int hf_wassp_tlv_type_main;
static int hf_wassp_tlv_type_sub;
static int hf_wassp_tlv_length;
static int hf_wassp_tlv_value_octext;    // PW_TYPE_OCTETS
static int hf_wassp_tlv_value_string;
static int hf_wassp_tlv_value_ip;
static int hf_wassp_tlv_value_int;
static int hf_wassp_tlv_eid_status;
static int hf_wassp_tlv_eid_action;
static int hf_wassp_tlv_eid_rustate;
static int hf_wassp_tlv_unknown;
static int hf_wassp_tlv_invalid;

static int hf_wassp_ipaddress;
static int hf_wassp_sub_tree;
static int hf_wassp_topologykey;
static int hf_wassp_vlanid;
static int hf_wassp_topology_mode;
static int hf_wassp_in_cir;
static int hf_wassp_out_cir;

static int hf_wassp_flag_1b;
static int hf_wassp_tos;
static int hf_cos_tos;
static int hf_cos_tos_mask;
static int hf_cos_priority_txq;

static int hf_wassp_tos_mask;
static int hf_filter_tos_maskbit_priority;
static int hf_wassp_priority;
static int hf_cos_rateid;
static int hf_wassp_filter_rule;
static int hf_wassp_filter_flag;
static int hf_filter_rule_port_range;
static int hf_wassp_ipprotocol;
static int hf_wassp_netmasklength;
static int hf_wassp_macaddr;
static int hf_wassp_macaddr_mask;
static int hf_wassp_ethernet_type;
static int hf_wassp_reserve;
static int hf_wassp_freq;
static int hf_wassp_rss;
static int hf_wassp_rssi;
static int hf_wassp_threatstate;
static int hf_wassp_radioparams;
static int hf_wassp_channelfreq;
static int hf_wassp_mu;
static int hf_wassp_apprules;
static int hf_wassp_displayid;
static int hf_wassp_txbytes;
static int hf_wassp_rxbytes;



/* ************************************************************************* */
/*                   Header values for reassembly                            */
/* ************************************************************************* */
static int hf_wassp_fragments;
static int hf_wassp_fragment;
static int hf_wassp_fragment_overlap;
static int hf_wassp_fragment_overlap_conflict;
static int hf_wassp_fragment_multiple_tails;
static int hf_wassp_fragment_too_long_fragment;
static int hf_wassp_fragment_error;
static int hf_wassp_fragment_count;
static int hf_wassp_reassembled_in;
static int hf_wassp_reassembled_length;
static int ett_wassp_fragment;
static int ett_wassp_fragments;


static const fragment_items wassp_frag_items =
{
	/* Fragment subtrees */
	&ett_wassp_fragment,
	&ett_wassp_fragments,
	/* Fragment fields */
	&hf_wassp_fragments,
	&hf_wassp_fragment,
	&hf_wassp_fragment_overlap,
	&hf_wassp_fragment_overlap_conflict,
	&hf_wassp_fragment_multiple_tails,
	&hf_wassp_fragment_too_long_fragment,
	&hf_wassp_fragment_error,
	&hf_wassp_fragment_count,
	&hf_wassp_reassembled_in,
	&hf_wassp_reassembled_length,
	NULL,
	"fragments"
};




/* Wassp protocol registered subtrees */
static int ett_wassp;
static int ett_seq_flags;
static int ett_wassp_header;
static int ett_mu_data_header;
static int ett_mu_action_field;

static int ett_ru_discover_header;
static int ett_wassp_tlv;
static int ett_wassp_filter_rule;
static int ett_lbs_header;

static int ett_wassp_mu_appl_stats;
static int ett_wassp_data;
static int ett_wassp_mu_data_netflow;
static int ett_wassp_mu_data_netflow_header;
static int ett_wassp_tlv_missing;
static int ett_wassp_ap_stats_block;
static int ett_wassp_mu_rf_stats_block;
static int ett_wassp_config_error_block;
static int ett_wassp_config_modified_block;
static int ett_wassp_global_config_block;
static int ett_wassp_radio_config_block;
static int ett_wassp_vns_config_block;
static int ett_wassp_mu_stats_block;
static int ett_wassp_radio_stats_block;
static int ett_wassp_ether_stats_block;
static int ett_wassp_wds_stats_block;
static int ett_wassp_dot1x_stats_block;
static int ett_wassp_filter_config_block;
static int ett_wassp_site_filter_config_block;
static int ett_wassp_filter_ext_config_block;
static int ett_wassp_vns_stats_block;
static int ett_wassp_radius_config_block;
static int ett_wassp_eid_main_tlv_block;
static int ett_wassp_radius_server_config_block;
static int ett_wassp_site_config_block;
static int ett_wassp_policy_config_block;
static int ett_wassp_cos_config_block;
static int ett_wassp_localbase_lookup_block;
static int ett_wassp_app_policy_fixed_block;
static int ett_wassp_app_policy_entry_block;
static int ett_wassp_s_topo_m_filter_entry_block;
static int ett_wassp_s_topo_m_filter_ext_entry_block;
static int ett_wassp_11u_config_entry_block;
static int ett_wassp_hs2_config_entry_block;
static int ett_wassp_extapp_config_entry_block;


/* aeroscout */
static int hf_aeroscout_header;
static int hf_aeroscout_header_magic_number;  // 2 bytes
static int hf_aeroscout_request_id;           // 2 bytes
static int hf_aeroscout_code;                 // 1 byte
static int hf_aeroscout_sub_code;             // 1 byte
static int hf_aeroscout_datalength;           // 2 bytes
static int hf_lbs_vendor_id;                  // 2 byte
static int hf_lbs_rsvd1;                      // 2 bytes
static int hf_lbs_ap_bssid;                   // 6 bytes
static int hf_lbs_rsvd2;                      // 1
static int hf_lbs_rxchan;                     // 1
static int hf_lsb_tstamp;                     // 4 bytes
static int hf_lsb_rsvd3;                      // 2 bytes
static int hf_lsb_rssi;                       // 1
static int hf_lsb_rsvd;                       // 1
static int hf_lsb_noise_floor;                // 1
static int hf_lsb_rsvd4;                      // 3 bytes
static int hf_lsb_chan_rate;                  // 1
static int hf_lsb_rsvd5;                      // 1
static int hf_lsb_wh_addr2;                   // 6 bytes
static int hf_lsb_wh_fc;                      // 2 bytes
static int hf_lsb_wh_seq;                     // 2 bytes
static int hf_lsb_rsvd6;                      // 2 bytes
static int hf_lsb_wh_addr3;                   // 6 bytes
static int hf_lsb_wh_addr4;                   // 6 bytes



/* Our dissector handle */
static dissector_handle_t wassp_handle;

/* Dissector handles used in dissector registration */
static dissector_handle_t data_handle;
static dissector_handle_t eth_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t ieee80211_handle;
static dissector_handle_t snmp_handle;


static const WASSP_SUBTLV_DECODER_INFO_t wassp_decr_info[TAB_MAX] =
{
	/*CONFIG_GLOBAL_BLOCK  */
	{"WASSP Global Config", &ett_wassp_global_config_block, array_length(tlvGlobalConfigTable), tlvGlobalConfigTable},
	/*CONFIG_ERROR_BLOCK */
	{"WASSP Config Error", &ett_wassp_config_error_block, array_length(tlvGlobalConfigTable), tlvGlobalConfigTable},
	/*TAB_CONFIG_MODIFIED */
	{"WASSP Config Modified", &ett_wassp_config_modified_block, array_length(tlvGlobalConfigTable), tlvGlobalConfigTable},
	/*RADIO_CONFIG_BLOCK */
	{"WASSP Radio Configure", &ett_wassp_radio_config_block, array_length(tlvRadioConfigTable), tlvRadioConfigTable},
	/*VNS_CONFIG_BLOCK */
	{"WASSP VNS Configure", &ett_wassp_vns_config_block, array_length(tlvVnsConfigTable), tlvVnsConfigTable},
	/*MU_RF_STATS_BLOCK */
	{"WASSP MU RF Stats", &ett_wassp_mu_rf_stats_block, array_length(tlvBeastConfigTable), tlvBeastConfigTable},
	/*AP_STATS_BLOCK */
	{"WASSP RU RF Stats", &ett_wassp_ap_stats_block, array_length(tlvBeastConfigTable), tlvBeastConfigTable},
	/*STATS_MU_BLOCK */
	{"WASSP MU Stats", &ett_wassp_mu_stats_block, array_length(tlvBeastConfigTable), tlvBeastConfigTable},
	/*TAB_STATS_RADIO */
	{"WASSP Radio Stats", &ett_wassp_radio_stats_block, array_length(tlvBeastConfigTable), tlvBeastConfigTable},
	/*TAB_STATS_ETH */
	{"WASSP Ethernet Stats", &ett_wassp_ether_stats_block, array_length(tlvBeastConfigTable), tlvBeastConfigTable},
	/*TAB_STATS_WDS */
	{"WASSP Wds Stats", &ett_wassp_wds_stats_block, array_length(tlvBeastConfigTable), tlvBeastConfigTable},
	/*TAB_STATS_DOT1x */
	{"WASSP Dot1x Stats", &ett_wassp_dot1x_stats_block, array_length(tlvBeastConfigTable), tlvBeastConfigTable},
	/*TAB_CONFIG_FILTER */
	{"WASSP Filter Config", &ett_wassp_filter_config_block, array_length(tlvFilterConfigTable), tlvFilterConfigTable},
	/*TAB_STATS_VNS */
	{"WASSP VNS Status", &ett_wassp_vns_stats_block, array_length(tlvVnsStatusTable), tlvVnsStatusTable},
	/*TAB_CONFIG_RADIUS_SERVER */
	{"WASSP Radius Server Config", &ett_wassp_radius_server_config_block, array_length(tlvRadiusServerConfigTable), tlvRadiusServerConfigTable},
	/*TAB_CONFIG_SITE */
	{"WASSP Site Config", &ett_wassp_site_config_block, array_length(tlvSiteConfigTable), tlvSiteConfigTable},
	/*TAB_CONFIG_POLICY */
	{"WASSP Policy Config", &ett_wassp_policy_config_block, array_length(tlvPolicyConfigTable), tlvPolicyConfigTable},
	/*TAB_CONFIG_COS */
	{"WASSP Class of Service Configuration", &ett_wassp_cos_config_block, array_length(tlvCosConfigTable), tlvCosConfigTable},
	/*TAB_CONFIG_LOC_BASE_LP */
	{"WASSP LocalBase Lookup", &ett_wassp_localbase_lookup_block, array_length(tlvLocationBaseLookUpTable), tlvLocationBaseLookUpTable},
	/*TAB_CONFIG_RADIUS */
	{"WASSP Radius Config", &ett_wassp_radius_config_block, array_length(tlvRadiusConfigTable), tlvRadiusConfigTable},
	/*EVENT_BLOCK */
	{"WASSP Event Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_SSS_MU_BLOCK */
	{"WASSP SSS MU Block",  &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_EID_MU_BLOCK */
	{"WASSP EID MU Block",  &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*BULK_MU_BLOCK */
	{"WASSP BULK MU Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*MU_BLOCK */
	{"WASSP MU Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*BULK_VNS_BLOCK */
	{"WASSP BULK VNS Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*VNS_BLOCK */
	{"WASSP VNS Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_SIAPP_PMK_BLOCK */
	{"SIAPP PMK Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_SIAPP_RADIO_CONFIG_BLOCK */
	{"SIAPP Radio Config Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_SIAPP_MU_STATS_BLOCK */
	{"SIAPP MU STATS Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_SIAPP_THIN_BLOCK */
	{"SIAPP THIN Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_SIAPP_BLOCK */
	{"SIAPP  Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_ASSOC_SSID_ARRAY*/
	{"Assoc SSID array", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_ASSOC_SSID_BLOCK*/
	{"Assoc SSID  Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_AP_LIST_BLOCK*/
	{"AP list  Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_AP_LIST_ARRAY*/
	{"AP list array", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_SCAN_PROFILE_BLOCK*/
	{"Scan profile  Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_THREAT_DEF_ARRAY*/
	{"Threat def array", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_THREAT_DEF_BLOCK*/
	{"Thread def  Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_THREAT_PATTERN_ARRAY*/
	{"Thread pattern array", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_THREAT_PATTERN_BLOCK*/
	{"Thread pattern  Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_SURVEILLANCE_DATA_ARRAY,*/
	{"Surveillance Data Array", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_SURVEILLANCE_DATA_BLOCK,*/
	{"Surveillance Data  Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_THREAT_DATA_ARRAY,*/
	{"Thread Data Array", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_THREAT_DATA_BLOCK,*/
	{"Thread Data  Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_THREAT_CLASSIFY_ARRAY,*/
	{"Thread Classify Array", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_THREAT_CLASSIFY_BLOCK,*/
	{"Thread Classify  Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_USER_CLASSIFY_ARRAY,*/
	{"User Classify Array", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_USER_CLASSIFY_BLOCK,*/
	{"User Classify  Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_MU_EVENT_ARRAY,  */
	{"MU Event Array", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_MU_EVENT_BLOCK,*/
	{"MU Event  Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_COUNTRY_ARRAY,*/
	{"Country Array", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_COUNTRY_BLOCK,*/
	{"Country  Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_LOCATOR_LOC_BLOCK,*/
	{"Locator LOC  Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_LOCATOR_LOC_ARRAY,*/
	{"Locator LOC Array", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_RSS_DATA_ARRAY,*/
	{"RSS Data  Array", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_RSS_DATA_BLOCK,*/
	{"RSS Data  Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_MCAST_FILTER_BLOCK, */
	{"MCAST Filter Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_MCAST_FILTER_BLOCK_ENTRY */
	{"MCAST Filter Block Entry", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_MU_SESSION_ARRAY,*/
	{"MU Session Array", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_MU_SESSION_BLOCK,*/
	{"MU Session Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_DETECTED_ROGUE_ARRAY,*/
	{"Detected Rogue Array", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_DETECTED_ROGUE_BLOCK,*/
	{"Detected Rogue Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_FILTER_RULES_EXT_BLOCK */
	{"Filter Rule Ext Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_APP_POLICY_FIXED_BLOCK */
	{"App Policy Fixed Block", &ett_wassp_app_policy_fixed_block, array_length(tlvAppPolicyFixedTable), tlvAppPolicyFixedTable},
	/*TAB_V_FILTER_RULES_EXT_BLOCK */
	{"FilterRules Ext Block", &ett_wassp_filter_ext_config_block, array_length(tlvFilterRuleExtConfigTable), tlvFilterRuleExtConfigTable},
	/*TAB_V_SITE_FILTER_RULES_EXT_BLOCK */
	{"Site FilterRules Ext Block", &ett_wassp_site_filter_config_block, array_length(tlvSiteFilterRuleExtConfigTable), tlvSiteFilterRuleExtConfigTable},
	/*TAB_APP_POLICY_ENTRY_BLOCK */
	{"App Policy Entry Block", &ett_wassp_app_policy_entry_block, array_length(tlvAppPolicyEntryTable), tlvAppPolicyEntryTable},
	/*TAB_11U_ANQP_BLOCK,  */
	{"11u Config Block", &ett_wassp_11u_config_entry_block, array_length(tlv11U_ANQP_blockTable), tlv11U_ANQP_blockTable},
	/*TAB_HS2_BLOCK,   */
	{"HS2 config Block", &ett_wassp_hs2_config_entry_block, array_length(tlvHS2_blockTable), tlvHS2_blockTable},
	/*TAB_RU_ACK_RADIO_CONFIG,*/
	{"WASSP RU Ack Radio Configure", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_MU_APPL_STATS_BLOCK */
	{"MU Appl Stats Block", &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_EXTAPP_CONF_BLOCK */
	{"Extend AppControl Config Block", &ett_wassp_extapp_config_entry_block, array_length(tlvExtapp_conf_blockTable), tlvExtapp_conf_blockTable},
	/*TAB_V_CP_CONFIG_BLOCK */
	{"CP Config Block", &ett_wassp_vns_config_block, array_length(tlvVnsConfigTable), tlvVnsConfigTable},
	/*TAB_TOPOLOGY_ARRAY_BLOCK */
	{"Topology Array Block",  &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_TOPOLOGY_STRUCT_BLOCK */
	{"Topology Struct Block",   &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_FILTER_CONFIG_STRUCT_BLOCK */
	{"Filter Config Struct Block",   &ett_wassp_eid_main_tlv_block, array_length(tlvMainTable), tlvMainTable},
	/*TAB_S_TOPOLOGY_ARRAY_BLOCK, */
	{"Site Topology Array Block",  &ett_wassp_site_config_block, array_length(tlvSiteConfigTable), tlvSiteConfigTable},
	/*TAB_S_TOPOLOGY_STRUCT_BLOCK,*/
	{"Site Topology Struct Block",  &ett_wassp_site_config_block, array_length(tlvSiteConfigTable), tlvSiteConfigTable},
	/*TAB_S_TOPO_MCAST_FILTER_CONFIG_BLOCK,*/
	{"Site Topology Mcast Filter Config Struct Block",  &ett_wassp_s_topo_m_filter_entry_block, array_length(tlvSTopoMcastFilterBlock), tlvSTopoMcastFilterBlock},
	/*TAB_S_TOPO_MCAST_FILTER_RULES_EXT_BLOCK,*/
	{"Site Topology Mcast Filter Rule Ext Block",  &ett_wassp_s_topo_m_filter_ext_entry_block, array_length(tlvSTopoMcastFilterRuleBlock), tlvSTopoMcastFilterRuleBlock},
	/*TAB_NAC_SERVER_CONFIG_ARRAY,*/
	{"NAC service config array",  &ett_wassp_site_config_block, array_length(tlvSiteConfigTable), tlvSiteConfigTable},
	/*TAB_NAC_SERVER_CONFIG_BLOCK,*/
	{"NAC service config Block",  &ett_wassp_site_config_block, array_length(tlvSiteConfigTable), tlvSiteConfigTable},
	/*TAB_NAC_WEB_AUTH_USER_GROUP_ARRAY,*/
	{"NAC WEB auth user group config array",  &ett_wassp_site_config_block, array_length(tlvSiteConfigTable), tlvSiteConfigTable},
	/*TAB_NAC_WEB_AUTH_USER_GROUP_BLOCK,*/
	{"NAC WEB auth user group  Block",  &ett_wassp_site_config_block, array_length(tlvSiteConfigTable), tlvSiteConfigTable},
};








static int wassp_type_converter(int in_tlv_type)
{
	int rtn_val = hf_wassp_tlv_value_octext;

	switch (in_tlv_type)
	{
	case 1:
		rtn_val = hf_wassp_tlv_value_string;
		break;
	case 2:
	case 3:
	case 4:
	case 7:
	case 8:
		rtn_val = hf_wassp_tlv_value_int;
		break;
	case 5:
		rtn_val = hf_wassp_tlv_value_octext;
		break;
	case 6:
		rtn_val = hf_wassp_mu_mac;
		break;
	case 9:
		rtn_val = hf_wassp_tlv_value_ip;
		break;

	default:
		break;
	}
	return rtn_val;
}




static int dissect_wassp_sub_tlv(proto_tree *wassp_tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int in_len, int which_tab, int ru_msg_type);
static int dissect_wassp_tlv(proto_tree *wassp_tree, tvbuff_t *tvb, packet_info *pinfo, int offset, wassp_ru_msg_t rumsg_type);



/* Registered WASSP subdissectors */
static dissector_table_t wassp_dissector_table;

/* WASSP dissector routines */
static int dissect_wassp_mu(proto_tree *, tvbuff_t *, packet_info *, int, int);
static int  dissect_wassp(tvbuff_t *, packet_info *, proto_tree *);

/* Dissector registration routines */
void proto_register_wassp(void);
void proto_reg_handoff_wassp(void);
static int dissect_wassp_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

static int g_wassp_ver;
static reassembly_table  wassp_reassembled_table;
static void wassp_defragment_init(void)
{
	reassembly_table_init(&wassp_reassembled_table, &addresses_reassembly_table_functions);
}

static const char* wassp_match_strval(const WASSP_SUBTLV_DECODER_INFO_t *in_ptr, int in_type)
{
	if (in_ptr == NULL)
	{
		return NULL;
	}
	if (in_ptr->max_entry <= in_type)
	{
		return NULL;
	}

	return in_ptr->entry[in_type].name;
}

static void
port_range_print(char *buf, uint32_t temp)
{
	snprintf(buf, ITEM_LABEL_LENGTH, " %d - %d", (temp & 0xffff), (temp >> 16));
}




static void topology_moder_print(char *buf, uint16_t temp)
{
	uint16_t temp3 = temp & 0xc000;
	uint16_t temp4 = temp & 0x0fff;
	switch (temp3)
	{
	case 0xc000:
		if (temp4)
			snprintf(buf, ITEM_LABEL_LENGTH, " Routed At Controller  with vlanId = %d  (0x%x)", temp4, temp);
		else
			snprintf(buf, ITEM_LABEL_LENGTH, " Routed At Controller,  Untagged (0x%x)", temp);
		break;
	case 0x4000:
		if (temp4)
			snprintf(buf, ITEM_LABEL_LENGTH, " Bridge At AP with vlanId = %d  (0x%x)", temp4, temp);
		else
			snprintf(buf, ITEM_LABEL_LENGTH, " Bridge At AP,  Untagged  (0x%x) ", temp);
		break;
	case 0x8000:
		if (temp4)
			snprintf(buf, ITEM_LABEL_LENGTH, " Bridge At Controller with vlanId = %d  (0x%x)  ", temp4, temp);
		else
			snprintf(buf, ITEM_LABEL_LENGTH, " Bridge At Controller,  Untagged  (0x%x) ", temp);
		break;
	default:
		if (temp4)
			snprintf(buf, ITEM_LABEL_LENGTH, " Unknown mode with vlanId = %d (0x%x)", temp4, temp);
		else
			snprintf(buf, ITEM_LABEL_LENGTH, " Unknown mode,  Untagged (0x%x) ", temp);
		break;
	}
}



static void
maskbit_priority_print(char *buf, uint8_t temp)
{
	snprintf(buf, ITEM_LABEL_LENGTH, " Type of Service Mask bits  : %d     Priority TxQ : %d", (temp >> 4) & 0xf, temp & 0xf);
}

static void
cos_priority_txq_print(char *buf, uint8_t temp)
{
	snprintf(buf, ITEM_LABEL_LENGTH, " Class of Service priority bits  : %d     Class of Service Transmit Queue : %d", (temp >> 4) & 0xf, temp & 0xf);
}

static void
cos_rate_id_print(char *buf, uint8_t temp)
{
	snprintf(buf, ITEM_LABEL_LENGTH, " Class of Service Inbound Rate Limit ID  : %d    Class of Service Outbound Rate Limit ID : %d", (temp >> 4) & 0xf, temp & 0xf);
}



#define V831_FILTER_RULE_FORMAT 4
#define BEFORE_V831_FILTER_RULE_FORMAT 2
#define AFTER_V831_FILTER_RULE_FORMAT 1
#define V831_FILTER_RULE_STRUCT_SIZE 36
#define BEFORE_V831_FILTER_RULE_STRUCT_SIZE 16
#define AFTER_V831_FILTER_RULE_STRUCT_SIZE 20
static void decode_filter_rule_octext_string(proto_tree *tree, tvbuff_t *tvb, int offset, int length )
{
	int flag = 0, suboffset, count, i;
	proto_tree *filter_rule_tree = proto_item_add_subtree(tree, ett_wassp_filter_rule);
	/* there are 3 kinds of filter rule struct.
	   before V8.31 -- 16 bytes
	   V83.1 -- 36 bytes
	   after V8.31 -- 20 bytes
	*/

	if (((length - 4) % V831_FILTER_RULE_STRUCT_SIZE) == 0)  // might be V8.31 filter struct
		flag |= V831_FILTER_RULE_FORMAT;

	if (((length - 4) % AFTER_V831_FILTER_RULE_STRUCT_SIZE) == 0)  // might be new filter struct
		flag |= AFTER_V831_FILTER_RULE_FORMAT;

	if (((length - 4) % BEFORE_V831_FILTER_RULE_STRUCT_SIZE) == 0)  // might be old filter struct
		flag |= BEFORE_V831_FILTER_RULE_FORMAT;



	if (flag & V831_FILTER_RULE_FORMAT) // display as V8.31 filter struct
	{
		suboffset = offset + 4;
		//proto_tree_add_debug_text(filter_rule_tree, "-----------Display Filter Rule(s) in V3 Struct  Format------------");
		count = (length - 4) / V831_FILTER_RULE_STRUCT_SIZE;
		for (i = 0; i < count; i++)
		{
			//proto_tree_add_debug_text(filter_rule_tree, " filter rule %d", i + 1);
			proto_tree_add_item(filter_rule_tree, hf_wassp_filter_rule, tvb, suboffset, V831_FILTER_RULE_STRUCT_SIZE, ENC_NA);
			proto_tree_add_item(filter_rule_tree, hf_wassp_filter_flag, tvb, suboffset, 4, ENC_BIG_ENDIAN);
			suboffset += 4;
			proto_tree_add_item(filter_rule_tree, hf_wassp_ipaddress, tvb, suboffset, 4, ENC_BIG_ENDIAN);
			suboffset += 4;
			proto_tree_add_item(filter_rule_tree, hf_filter_rule_port_range, tvb, suboffset, 4, ENC_BIG_ENDIAN);
			suboffset += 4;
			proto_tree_add_item(filter_rule_tree, hf_wassp_ipprotocol, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_wassp_netmasklength, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_wassp_tos, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_filter_tos_maskbit_priority, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_cos_tos, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_cos_tos_mask, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_cos_priority_txq, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_cos_rateid, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_wassp_macaddr, tvb, suboffset, 6, ENC_NA);
			suboffset += 6;
			proto_tree_add_item(filter_rule_tree, hf_wassp_macaddr_mask, tvb, suboffset, 6, ENC_NA);
			suboffset += 6;
			proto_tree_add_item(filter_rule_tree, hf_wassp_vlanid, tvb, suboffset, 2, ENC_BIG_ENDIAN);
			suboffset += 2;
			proto_tree_add_item(filter_rule_tree, hf_wassp_ethernet_type, tvb, suboffset, 2, ENC_BIG_ENDIAN);
			suboffset += 2;
		}
	}

	if (flag & AFTER_V831_FILTER_RULE_FORMAT) // display as new filter struct
	{
		suboffset = offset + 4;
		//proto_tree_add_debug_text(filter_rule_tree, "-----------Display Filter Rule(s) in V2 Struct  Format------------");
		count = (length - 4) / AFTER_V831_FILTER_RULE_STRUCT_SIZE;
		for (i = 0; i < count; i++)
		{
			//proto_tree_add_debug_text(filter_rule_tree, " filter rule %d", i + 1);
			proto_tree_add_item(filter_rule_tree, hf_wassp_filter_rule, tvb, suboffset, AFTER_V831_FILTER_RULE_STRUCT_SIZE, ENC_NA);
			proto_tree_add_item(filter_rule_tree, hf_wassp_filter_flag, tvb, suboffset, 4, ENC_BIG_ENDIAN);
			suboffset += 4;
			proto_tree_add_item(filter_rule_tree, hf_wassp_ipaddress, tvb, suboffset, 4, ENC_BIG_ENDIAN);
			suboffset += 4;
			proto_tree_add_item(filter_rule_tree, hf_filter_rule_port_range, tvb, suboffset, 4, ENC_BIG_ENDIAN);
			suboffset += 4;
			proto_tree_add_item(filter_rule_tree, hf_wassp_ipprotocol, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_wassp_netmasklength, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_wassp_tos, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_filter_tos_maskbit_priority, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_cos_tos, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_cos_tos_mask, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_cos_priority_txq, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_cos_rateid, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
		}
	}

	if (flag & BEFORE_V831_FILTER_RULE_FORMAT)
	{
		suboffset = offset + 4;
		//proto_tree_add_debug_text(filter_rule_tree, "-----------Display Filter Rule(s) in V1 Struct  Format------------");
		count = (length - 4) / BEFORE_V831_FILTER_RULE_STRUCT_SIZE;
		for (i = 0; i < count; i++)
		{
			//proto_tree_add_debug_text(filter_rule_tree, "      filter rule %d", i + 1);
			proto_tree_add_item(filter_rule_tree, hf_wassp_filter_rule, tvb, suboffset, BEFORE_V831_FILTER_RULE_STRUCT_SIZE, ENC_NA);
			proto_tree_add_item(filter_rule_tree, hf_wassp_filter_flag, tvb, suboffset, 4, ENC_BIG_ENDIAN);
			suboffset += 4;
			proto_tree_add_item(filter_rule_tree, hf_wassp_ipaddress, tvb, suboffset, 4, ENC_BIG_ENDIAN);
			suboffset += 4;
			proto_tree_add_item(filter_rule_tree, hf_filter_rule_port_range, tvb, suboffset, 4, ENC_BIG_ENDIAN);
			suboffset += 4;
			proto_tree_add_item(filter_rule_tree, hf_wassp_ipprotocol, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_wassp_netmasklength, tvb, suboffset, 1, ENC_BIG_ENDIAN);
			suboffset += 1;
			proto_tree_add_item(filter_rule_tree, hf_wassp_reserve, tvb, suboffset, 2, ENC_BIG_ENDIAN);
			suboffset += 2;
		}
	}
}


static void decode_mu_appl_stats_block(proto_tree *tree, tvbuff_t *tvb, int offset )
{
	int suboffset, count, i;
	proto_tree *tlv_tree = proto_item_add_subtree(tree, ett_wassp_mu_appl_stats);

	suboffset = offset;
	count = tvb_get_ntohl(tvb, suboffset);
	proto_tree_add_item(tlv_tree, hf_wassp_mu, tvb, suboffset, 4, ENC_BIG_ENDIAN);
	suboffset += 4;
	for (i = 1; i <= count; i++)
	{
		//proto_tree_add_debug_text(tlv_tree, "MU_%d", i);
		proto_tree_add_item(tlv_tree, hf_wassp_macaddr, tvb, suboffset, 6, ENC_NA);
		suboffset += 6;
		proto_tree_add_item(tlv_tree, hf_wassp_apprules, tvb, suboffset, 2, ENC_BIG_ENDIAN);
		suboffset += 2;
		proto_tree_add_item(tlv_tree, hf_wassp_displayid, tvb, suboffset, 2, ENC_BIG_ENDIAN);
		suboffset += 2;
		proto_tree_add_item(tlv_tree, hf_wassp_txbytes, tvb, suboffset, 4, ENC_BIG_ENDIAN);
		suboffset += 4;
		proto_tree_add_item(tlv_tree, hf_wassp_rxbytes, tvb, suboffset, 4, ENC_BIG_ENDIAN);
		suboffset += 4;
	}

}



static void decode_cos_struct(proto_tree *tree, tvbuff_t *tvb, int offset )
{
	int suboffset = offset;
	proto_tree_add_item(tree, hf_wassp_flag_1b, tvb, suboffset, 1, ENC_BIG_ENDIAN);
	suboffset += 1;
	proto_tree_add_item(tree, hf_wassp_tos, tvb, suboffset, 1, ENC_BIG_ENDIAN);
	suboffset += 1;
	proto_tree_add_item(tree, hf_wassp_tos_mask, tvb, suboffset, 1, ENC_BIG_ENDIAN);
	suboffset += 1;
	proto_tree_add_item(tree, hf_wassp_priority, tvb, suboffset, 1, ENC_BIG_ENDIAN);
	suboffset += 1;
	proto_tree_add_item(tree, hf_cos_rateid, tvb, suboffset, 1, ENC_BIG_ENDIAN);

}

static void decode_rate_limit_struct(proto_tree *tree, tvbuff_t *tvb, int offset, int length )
{
	int suboffset = offset, count = length / 4, i;

	for (i = 0; i < count; i++)
	{
		proto_tree_add_item(tree, hf_wassp_in_cir, tvb, suboffset, 2, ENC_BIG_ENDIAN);
		suboffset += 2;
		proto_tree_add_item(tree, hf_wassp_out_cir, tvb, suboffset, 2, ENC_BIG_ENDIAN);
		suboffset += 2;
	}

}

static void decode_mac_list_struct(proto_tree *tree, tvbuff_t *tvb, int offset, int length )
{
	int suboffset = offset, count = length / 6, i;

	for (i = 0; i < count; i++)
	{
		proto_tree_add_item(tree, hf_wassp_macaddr, tvb, suboffset, 6, ENC_NA);
		suboffset += 6;
	}
}


static void decode_ipv4_list_struct(proto_tree *tree, tvbuff_t *tvb, int offset, int length )
{
	int suboffset = offset, count = length / 4, i;

	for (i = 0; i < count; i++)
	{
		proto_tree_add_item(tree, hf_wassp_ipaddress, tvb, suboffset, 4, ENC_BIG_ENDIAN);
		suboffset += 4;
	}
}

static void decode_Channel_list(proto_tree *tree, tvbuff_t *tvb, int offset, int length )
{
	int suboffset = offset, count = length / 2, i;

	for (i = 0; i < count; i++)
	{
		proto_tree_add_item(tree, hf_wassp_freq, tvb, suboffset, 2, ENC_BIG_ENDIAN);
		suboffset += 2;
	}
}



static int decode_lbs_tag_header(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	int suboffset = offset;
	proto_item *temp;
	proto_tree *lbs_header_tree;

	temp = proto_tree_add_item(tree, hf_aeroscout_header, tvb, suboffset, 64, ENC_NA);
	lbs_header_tree = proto_item_add_subtree(temp, ett_wassp_header);
	proto_tree_add_item(lbs_header_tree, hf_aeroscout_header_magic_number, tvb, suboffset, 2, ENC_BIG_ENDIAN);
	suboffset += 2;
	proto_tree_add_item(lbs_header_tree, hf_aeroscout_request_id, tvb, suboffset, 2, ENC_BIG_ENDIAN);
	suboffset += 2;
	proto_tree_add_item(lbs_header_tree, hf_aeroscout_code, tvb, suboffset, 1, ENC_BIG_ENDIAN);
	suboffset += 1;
	proto_tree_add_item(lbs_header_tree, hf_aeroscout_sub_code, tvb, suboffset, 1, ENC_BIG_ENDIAN);
	suboffset += 1;
	proto_tree_add_item(lbs_header_tree, hf_aeroscout_datalength, tvb, suboffset, 2, ENC_BIG_ENDIAN);
	suboffset += 2;
	proto_tree_add_item(lbs_header_tree, hf_wassp_mu_mac, tvb, suboffset, 6, ENC_NA);
	suboffset += 6;
	proto_tree_add_item(lbs_header_tree, hf_lbs_vendor_id, tvb, suboffset, 2, ENC_BIG_ENDIAN);
	suboffset += 2;
	proto_tree_add_item(lbs_header_tree, hf_lbs_rsvd1, tvb, suboffset, 2, ENC_BIG_ENDIAN);
	suboffset += 2;
	proto_tree_add_item(lbs_header_tree, hf_lbs_ap_bssid, tvb, suboffset, 6, ENC_NA);
	suboffset += 6;
	proto_tree_add_item(lbs_header_tree, hf_lbs_rsvd2, tvb, suboffset, 1, ENC_BIG_ENDIAN);
	suboffset += 1;
	proto_tree_add_item(lbs_header_tree, hf_lbs_rxchan, tvb, suboffset, 1, ENC_BIG_ENDIAN);
	suboffset += 1;
	proto_tree_add_item(lbs_header_tree, hf_lsb_tstamp, tvb, suboffset, 4, ENC_BIG_ENDIAN);
	suboffset += 4;
	proto_tree_add_item(lbs_header_tree, hf_lsb_rsvd3, tvb, suboffset, 2, ENC_BIG_ENDIAN);
	suboffset += 2;
	proto_tree_add_item(lbs_header_tree, hf_lsb_rssi, tvb, suboffset, 1, ENC_BIG_ENDIAN);
	suboffset += 1;
	proto_tree_add_item(lbs_header_tree, hf_lsb_rsvd, tvb, suboffset, 1, ENC_BIG_ENDIAN);
	suboffset += 1;
	proto_tree_add_item(lbs_header_tree, hf_lsb_noise_floor, tvb, suboffset, 1, ENC_BIG_ENDIAN);
	suboffset += 1;
	proto_tree_add_item(lbs_header_tree, hf_lsb_rsvd4, tvb, suboffset, 3, ENC_BIG_ENDIAN);
	suboffset += 3;
	proto_tree_add_item(lbs_header_tree, hf_lsb_chan_rate, tvb, suboffset, 1, ENC_BIG_ENDIAN);
	suboffset += 1;
	proto_tree_add_item(lbs_header_tree, hf_lsb_rsvd5, tvb, suboffset, 1, ENC_BIG_ENDIAN);
	suboffset += 1;
	proto_tree_add_item(lbs_header_tree, hf_lsb_wh_addr2, tvb, suboffset, 6, ENC_NA);
	suboffset += 6;
	proto_tree_add_item(lbs_header_tree, hf_lsb_wh_fc, tvb, suboffset, 2, ENC_BIG_ENDIAN);
	suboffset += 2;
	proto_tree_add_item(lbs_header_tree, hf_lsb_wh_seq, tvb, suboffset, 2, ENC_BIG_ENDIAN);
	suboffset += 2;
	proto_tree_add_item(lbs_header_tree, hf_lsb_rsvd6, tvb, suboffset, 2, ENC_BIG_ENDIAN);
	suboffset += 2;
	proto_tree_add_item(lbs_header_tree, hf_lsb_wh_addr3, tvb, suboffset, 6, ENC_NA);
	suboffset += 6;
	proto_tree_add_item(lbs_header_tree, hf_lsb_wh_addr4, tvb, suboffset, 6, ENC_NA);
	suboffset += 6;
	return suboffset;
}







// NOLINTNEXTLINE(misc-no-recursion)
int dissect_wassp_sub_tlv(proto_tree *wassp_tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int in_len, int which_tab, int ru_msg_type)
{
	proto_item *tlvi;
	proto_item *ti;
	proto_tree *tmp_tree;
	const char *label;
	uint32_t value;
	uint16_t tlv_type = EID_PARSE_ERROR;
	uint16_t length = 0, org_offset = offset;
	const WASSP_SUBTLV_DECODER_INFO_t *tmp_decr = NULL;
	uint32_t i, tableNo;
	int suboffset;

	if (which_tab >= TAB_MAX)
	{
		return offset;
	}

	tmp_decr = &wassp_decr_info[which_tab];

	if (tvb_reported_length_remaining(tvb, offset) > 0)
	{
		ti = proto_tree_add_item(wassp_tree, hf_wassp_sub_tree, tvb, offset, in_len, ENC_NA);
		proto_item_append_text(ti, " : %s", tmp_decr->subtree_name);
		tmp_tree = proto_item_add_subtree(ti, *((int*)(WASSP_SUBTLV_GET_ETTNUM(tmp_decr))));

		while (((value = tvb_reported_length_remaining(tvb, offset)) >= 4) && (offset - org_offset < in_len))
		{
			tlv_type = tvb_get_ntohs(tvb, offset + TLV_TYPE);
			length = tvb_get_ntohs(tvb, offset + TLV_LENGTH);
			if (tlv_type >= WASSP_SUBTLV_GET_MAXENTRY(tmp_decr))
			{
				proto_tree_add_uint_format_value(tmp_tree, hf_wassp_tlv_unknown, tvb, offset, 4, tlv_type, "Unknown Wassp TLV (%d)", tlv_type);
				proto_tree_add_item(tmp_tree, hf_wassp_tlv_length, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(tmp_tree, hf_wassp_tlv_value_octext, tvb, offset + TLV_VALUE, length - 4, ENC_NA);
				offset += length;
				continue;
			}

			label = wassp_match_strval(tmp_decr, tlv_type);
			label = (label == NULL) ? "Unknown Type" : label;

			if (length > value)
			{
				proto_tree_add_item(tmp_tree, hf_wassp_tlv_invalid, tvb, offset, 4, ENC_BIG_ENDIAN);
				tlv_type = EID_PARSE_ERROR;
			}
			else if (length < 4)
			{
				proto_tree_add_item(tmp_tree, hf_wassp_tlv_invalid, tvb, offset, 4, ENC_BIG_ENDIAN);
				tlv_type = EID_PARSE_ERROR;
			}
			else if (length == 4)
			{
				if ((which_tab == TAB_RSS_DATA_ARRAY) && (tlv_type == EID_RSS_DATA_BLOCK))
				{
					proto_tree_add_item(tmp_tree, hf_wassp_tlv_value_octext, tvb, offset, length, ENC_NA);
				}
				else
				{
					tlvi = proto_tree_add_item(tmp_tree, hf_wassp_tlv_value, tvb, offset, length, ENC_NA);
					proto_item_append_text(tlvi, " : %s (%d)", label, tlv_type);
				}
				offset += length;
				continue;
			}
			else
			{
				if ((which_tab == TAB_RSS_DATA_ARRAY) && (tlv_type == EID_RSS_DATA_BLOCK))
				{
					proto_tree_add_item(tmp_tree, hf_wassp_tlv_value_octext, tvb, offset, length, ENC_NA);
				}
				else
				{
					tlvi = proto_tree_add_item(tmp_tree, hf_wassp_tlv_value, tvb, offset, length, ENC_NA);
					proto_item_append_text(tlvi, " : %s (%d)", label, tlv_type);
				}
			}

			tlvi =   proto_tree_add_item(tmp_tree, hf_wassp_tlv_type_sub, tvb, offset + TLV_TYPE, 2, ENC_NA);
			proto_item_append_text(tlvi, " : %s (%d)", label, tlv_type);
			proto_tree_add_item(tmp_tree, hf_wassp_tlv_length, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);

			if (tlv_type == EID_PARSE_ERROR)
			{
				proto_tree_add_item(wassp_tree, hf_wassp_tlv_invalid, tvb, offset, value, ENC_BIG_ENDIAN);
				offset += length;
				break;
			}
			else
			{
				if (WASSP_SUBTLV_GET_ENTRY_IDX_TYPE(tmp_decr, tlv_type) != TLV_TYPE_BLOCK_TLV)
				{
					proto_tree_add_item(tmp_tree, wassp_type_converter(WASSP_SUBTLV_GET_ENTRY_IDX_TYPE(tmp_decr, tlv_type)), tvb, offset + TLV_VALUE, length - 4, false);
					if ((which_tab == TAB_CONFIG_SITE) && (tlv_type == EID_SITE_TOPOLOGY_BLOCK))
					{
						suboffset = offset + 4;
						for (i = 0; i < (uint32_t)(length / 4 - 1); i++)
						{
							proto_tree_add_item(tmp_tree, hf_wassp_topologykey, tvb, suboffset, 2, ENC_BIG_ENDIAN);
							suboffset += 2;
							proto_tree_add_item(tmp_tree, hf_wassp_topology_mode, tvb, suboffset, 2, ENC_BIG_ENDIAN);
							suboffset += 2;
						}
					}

					if (which_tab == VNS_CONFIG_BLOCK)
					{
						if (tlv_type == EID_V_COS)
						{
							decode_cos_struct(tmp_tree, tvb, offset + 4 );
						}
						else if (tlv_type == EID_V_RATE_LIMIT_RESOURCE_TBL)
						{
							decode_rate_limit_struct(tmp_tree,tvb,  offset + 4,length-4 );
						}
					}

					if (which_tab == TAB_CONFIG_FILTER || which_tab == TAB_FILTER_CONFIG_STRUCT_BLOCK)
					{
						if (tlv_type == EID_V_FILTER_RULES || tlv_type == EID_FILTER_RULES || tlv_type == EID_V_SITE_FILTER_RULES )
						{
							if (length < 20)
								break;
							decode_filter_rule_octext_string(tmp_tree, tvb, offset + 4, length );

						}
					}


					if (which_tab == TAB_SCAN_PROFILE_BLOCK)
					{
						if (tlv_type == EID_CHANNEL_LIST)
						{
							decode_Channel_list(tmp_tree, tvb, offset + 4,  length -4 );
						}
					}

					if (which_tab == TAB_SURVEILLANCE_DATA_BLOCK)
					{
						if (tlv_type == EID_SCAN_RSS_RSSI)
						{
							suboffset = offset + 4;
							proto_tree_add_item(tmp_tree, hf_wassp_rss, tvb, suboffset, 2, ENC_BIG_ENDIAN);
							suboffset += 2;
							proto_tree_add_item(tmp_tree, hf_wassp_rssi, tvb, suboffset, 2, ENC_BIG_ENDIAN);
						}

						if (tlv_type == EID_PARAMS)
						{
							suboffset = offset + 4;
							proto_tree_add_item(tmp_tree, hf_wassp_threatstate, tvb, suboffset, 1, ENC_BIG_ENDIAN);
							suboffset += 1;
							proto_tree_add_item(tmp_tree, hf_wassp_radioparams, tvb, suboffset, 1, ENC_BIG_ENDIAN);
							suboffset += 1;
							proto_tree_add_item(tmp_tree, hf_wassp_channelfreq, tvb, suboffset, 2, ENC_BIG_ENDIAN);
						}

					}


					if (which_tab == CONFIG_GLOBAL_BLOCK)
					{
						if (tlv_type == EID_ON_DEMAND_ARRAY || tlv_type == EID_DYN_ON_DEMAND_ARRAY)
						{
							decode_mac_list_struct(tmp_tree, tvb, offset + 4,  length -4 );
						}
					}

					if (which_tab == TAB_DETECTED_ROGUE_BLOCK)
					{
						if (tlv_type == EID_DNS_IP_ADDR)
						{
							decode_ipv4_list_struct(tmp_tree, tvb, offset + 4,  length -4 );
						}
					}

					offset += length;
				}
				else
				{

					tableNo = WASSP_SUBTLV_GET_ENTRY_IDX_TABIDX(tmp_decr, tlv_type);
					if ((tableNo == RADIO_CONFIG_BLOCK) && (ru_msg_type == WASSP_RU_Ack))
					{
						// We recurse here, but we'll run out of packet before we run out of stack.
						offset = dissect_wassp_sub_tlv(tmp_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_RU_ACK_RADIO_CONFIG, ru_msg_type);
					}
					else
						// We recurse here, but we'll run out of packet before we run out of stack.
						offset = dissect_wassp_sub_tlv(tmp_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, tableNo, ru_msg_type);
				}

			}
		}
	}
	return offset;
}


int dissect_wassp_tlv(proto_tree *wassp_tree, tvbuff_t *tvb, packet_info *pinfo, int offset, wassp_ru_msg_t rumsg_type)
{
	proto_item *tlvi = NULL;
	proto_tree *tlv_tree;
	uint16_t tlv_type = WASSP_RU_UNUSED_0;
	uint16_t length;
	uint32_t value;
	int suboffset;
	wassp_ru_msg_t ru_msg_type = rumsg_type;
	const char *label;



	SET_WASSP_TLV_VERSION(0);
	while ((value = tvb_reported_length_remaining(tvb, offset)) >= 4)
	{
		tlv_type = tvb_get_ntohs(tvb, offset + TLV_TYPE);
		length = tvb_get_ntohs(tvb, offset + TLV_LENGTH);
		label = try_val_to_str(tlv_type, wassp_tlv_types);
		label = (label == NULL) ? "Unknown Type" : label;

		if (length > value)
		{
			tlvi = proto_tree_add_item(wassp_tree, hf_wassp_tlv_invalid, tvb, offset, 4, ENC_BIG_ENDIAN);
			tlv_type = EID_UNUSED_0;
		}
		else if (length < 4)
		{
			tlvi = proto_tree_add_item(wassp_tree, hf_wassp_tlv_invalid, tvb, offset, 4, ENC_BIG_ENDIAN);
			tlv_type = EID_UNUSED_0;
		}
		else
		{
			tlvi = proto_tree_add_item(wassp_tree, hf_wassp_tlv_value, tvb, offset, length, ENC_NA);
			proto_item_append_text(tlvi, " : %s (%d)", label, tlv_type);

		}

		tlv_tree = proto_item_add_subtree(tlvi, ett_wassp_tlv);
		proto_tree_add_item(tlv_tree, hf_wassp_tlv_type_main, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tlv_tree, hf_wassp_tlv_length, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);

		switch (tlv_type)
		{
		case EID_UNUSED_0:                  // 0
			offset += 4;
			break;

		case EID_STATUS:                    // 1
			ru_msg_type = (wassp_ru_msg_t) tvb_get_uint8(tvb, WASSP_HDR_TYPE);

			/*this is an action TLV*/
			if (WASSP_RU_SW_Version_Validate_Rsp == ru_msg_type)
			{
				proto_item_append_text(tlvi, " (upgrade action)");
				proto_tree_add_item(tlv_tree, hf_wassp_tlv_eid_action, tvb, offset + TLV_VALUE, length - 4, ENC_BIG_ENDIAN);
			}
			else  /*assume status TLV*/
			{
				proto_item_append_text(tlvi, " (status)");
				proto_tree_add_item(tlv_tree, hf_wassp_tlv_eid_status, tvb, offset + TLV_VALUE, length - 4, ENC_BIG_ENDIAN);
			}
			offset += length;
			break;

		/* display as string */
		case EID_RU_SW_VERSION:                       // 2
		case EID_RU_SERIAL_NUMBER:                    // 3
		case EID_IMAGE_PATH:                          // 9
		case EID_RANDOM_NUMBER:                       // 14
		case EID_RU_MODEL:                            // 17
		case EID_RU_TRAP:                             // 24
		case EID_RU_SSID_NAME:                        // 37
		case EID_AC_REG_CHALLENGE:                    // 41
		case EID_AC_REG_RESPONSE:                     // 42
		case EID_STATS:                               // 43
		case EID_CERTIFICATE:                         // 44
		case EID_RADIO_INFO:                          // 51
		case EID_NETWORK_INFO:                        // 52
		case EID_PRODUCT_ID:                          // 54
		case EID_RADIO_INFO_ACK:                      // 55
		case EID_SSID:                                // 58
		case EID_MU_PMKID_LIST:                       // 72
		case EID_MU_PMK_BP:                           // 73
		case EID_MU_PMKID_BP:                         // 74
		case EID_LOG_FILE:                            // 83
		case EID_ALARM_DESCRIPTION:                   // 85
		case EID_RU_BACKUP_VERSION:                   // 93
		case EID_AC_SW_VERSION:                       // 94
		case EID_MCAST_LAMG_LIST:                     // 95
		case EID_FILTER_NAME:                         // 96
		case EID_SENSOR_IMG_VERSION:                  // 104
		case EID_RATECTRL_NAME_UL:                    // 111
		case EID_RATECTRL_NAME_DL:                    // 112
		case EID_POLICY_NAME:                         // 113
		case EID_SIAPP_AP_NAME:                       // 120
		case EID_SIAPP_USER_IDENTITY:                 // 151
		case EID_MU_FILTER_POLICY_NAME:               // 162
		case EID_MU_TOPOLOGY_POLICY_NAME:             // 163
		case EID_MU_COS_POLICY_NAME:                  // 164
		case EID_SITE_NAME:                           // 175
		case EID_SSS_SSID:                            // 191
		case EID_POLICY_ZONE_NAME:                    // 193
		case EID_MU_USER_NAME:                        // 196
		case EID_SCAN_SSID:                           // 237
		case EID_THREAT_NAME:                         // 248
		case EID_LOCATION:                            // 249
		case EID_MU_EVENT_STRING:                     // 254
		case EID_LOCATOR_FLOOR_NAME:                  // 288
		case EID_MU_RFS_NAME:                         // 296
		case EID_MU_URL:                              // 301
		case EID_MU_ACCT_SESSION_ID_STRING:           // 304
		case EID_MU_ACCT_POLICY_NAME:                 // 305
		case EID_MU_TUNNEL_PRIVATE_GROUP_ID_STRING:   // 309
		case EID_MU_USER_ID_STRING:                   // 310
		case EID_MU_LOCATION:                         // 331
		case EID_AREA_NAME:                           // 335
		case EID_CUI:                                 // 363
		case EID_WFA_HS20_URL:                        // 368
		case EID_DHCP_HOST_NAME:                      // 382
		case EID_MU_ECP_PW:                           // 385
		case EID_MU_ECP_TOKEN:                        // 386
			proto_tree_add_item(tlv_tree, hf_wassp_tlv_value_string, tvb, offset + TLV_VALUE, length - 4, ENC_ASCII);
			offset += length;
			break;

		/* display as octext string */
		case EID_RU_REG_CHALLENGE:                      // 4
		case EID_RU_REG_RESPONSE:                       // 5
		case EID_RU_VNSID:                              // 7
		case EID_SESSION_KEY:                           // 12
		case EID_RU_PREAUTH:                            // 39
		case EID_RU_PMK:                                // 40
		case EID_SIAPP_PMKID:                           // 115
		case EID_SIAPP_PMK_REAUTH:                      // 116
		case EID_SIAPP_PMK_LIFETIME:                    // 117
		case EID_SIAPP_PMKID_FLAG:                      // 118
		case EID_SIAPP_MU_PMK:                          // 119
		case EID_SIAPP_CLUSTER_ACS_REQ:                 // 122
		case EID_SIAPP_PACKET_RETRIES:                  // 124
		case EID_SIAPP_ASSOC_IN_WLAN:                   // 125
		case EID_SIAPP_ASSOC_IN_CLUSTER:                // 126
		case EID_SIAPP_REASSOC_IN_CLUSTER:              // 127
		case EID_SIAPP_NEWAP_BSSID:                     // 129
		case EID_SIAPP_OLDAP_BSSID:                     // 130
		case EID_SIAPP_RAD_CACS_REQ:                    // 131
		case EID_SIAPP_CLIENT_COUNT:                    // 133
		case EID_SIAPP_MU_TransmittedFrameCount:        // 135
		case EID_SIAPP_MU_ReceivedFrameCount:           // 136
		case EID_SIAPP_MU_TransmittedBytes:             // 137
		case EID_SIAPP_MU_ReceivedBytes:                // 138
		case EID_SIAPP_MU_UL_DroppedRateControlPackets: // 139
		case EID_SIAPP_MU_DL_DroppedRateControlPackets: // 140
		case EID_SIAPP_MU_DL_DroppedBufferFullPackets:  // 141
		case EID_SIAPP_MU_DL_LostRetriesPackets:        // 142
		case EID_SIAPP_MU_UL_DroppedRateControlBytes:   // 143
		case EID_SIAPP_MU_DL_DroppedRateControlBytes:   // 144
		case EID_SIAPP_MU_DL_DroppedBufferFullBytes:    // 145
		case EID_SIAPP_MU_DL_LostRetriesBytes:          // 146
		case EID_SIAPP_BP_BSSID:                        // 147
		case EID_SIAPP_RADIO_ID:                        // 148
		case EID_SIAPP_PREAUTH_REQ:                     // 150
		case EID_SIAPP_LOADBAL_LOADGROUP_ID:            // 154
		case EID_MU_ACCOUNTING_CLASS:                   // 169
		case EID_SSS_TS64_MU_UPDATE:                    // 183
		case EID_SSS_TS64_AP_CURRENT:                   // 184
		case EID_SSS_AP_HOMEHASH:                       // 186
		case EID_EVENT_ARRAY:                           // 189
		case EID_INFORM_MU_PMK:                         // 199
		case EID_ARP_PROXY:                             // 201
		case EID_MCAST_FILTER_RULES:                    // 202
		case EID_AP_PARAMS:                             // 203
		case EID_THREAT_STATS_F:                        // 220
		case EID_THREAT_PATTERN:                        // 224
		case EID_LOCATOR_LOC_POINT:                     // 265
		case EID_MU_EVENT_DETAILS:                      // 266
		case EID_MU_EVENT_LOC_BLOCK:                    // 268
		case EID_AP_REDIRECT:                           // 291
		case EID_MU_CVLAN_BAP:                          // 292
		case EID_MU_SESSION_ID:                         // 295
		case EID_MU_FLAGS:                              // 297
		case EID_MU_ASSOC_TIME:                         // 298
		case EID_MU_ACTIVE_TIME:                        // 299
		case EID_REPORT_REQ:                            // 300
		case EID_MU_SESSION_LIFETIME:                   // 302
		case EID_MU_REAUTH_TIMER:                       // 303
		case EID_MU_ACCT_START_TIME:                    // 306
		case EID_MU_ACCT_CLASS:                         // 307
		case EID_MU_LOGIN_LAT_GROUP:                    // 308
		case EID_MU_DEFENDED_STATE:                     // 311
		case EID_MU_MOD_MASK:                           // 312
		case EID_LOCATOR_TRACKED:                       // 313
		case EID_PORT:                                  // 314
		case EID_RETRIES_COUNT:                         // 315
		case EID_MODULATION_TYPE:                       // 316
		case EID_ROGUE_DETECTION:                       // 319
		case EID_TTL:                                   // 324
		case EID_LOCATOR_STATE_DATA:                    // 326
		case EID_LOCATOR_POINT_SET:                     // 327
		case EID_FILTER_RULE_FIXED_APP_ID:              // 328
		case EID_MU_AREA_BLOCK:                         // 330
		case EID_IN_SERVICE_AP_LIST:                    // 334
		case EID_OUT_SERVICE_AP_LIST:                   // 335
		case EID_LAST_RD_AP:                            // 336
		case EID_ROGUE_INFO:                            // 337
		case EID_MU_PMK_R1:                             // 339
		case EID_SIAPP_R0KHID:                          // 340
		case EID_SIAPP_R1KHID:                          // 341
		case EID_SIAPP_FT_NONCE:                        // 342
		case EID_SIAPP_FT_PMKR0NAME:                    // 343
		case EID_SIAPP_FT_R1KHID:                       // 344
		case EID_SIAPP_FT_S1KHID:                       // 345
		case EID_SIAPP_FT_PMKR1:                        // 346
		case EID_SIAPP_FT_PMKR1NAME:                    // 347
		case EID_SIAPP_FT_PAIRWISE:                     // 348
		case EID_SIAPP_FT_LIFETIME:                     // 349
		case EID_MU_POWER_CAP:                          // 350
		case EID_PERIODIC_NEIGHBOUR_REPORT:             // 352
		case EID_NEIGHBOUR_ENTRY:                       // 354
		case EID_MU_PMK_R0NAME:                         // 362
		case EID_IPV6_ADDR:                             // 373
		case EID_MU_DEV_IDENTITY:                       // 376
		case EID_NEIGHBOUR_ENTRY_2:                     // 383
		case EID_CHANNEL_ENTRY:                         // 384
		case EID_PKT_F_WIRELESS:                        // 391
		case EID_PKT_F_WIREDCLIENT:                     // 392
		case EID_PKT_F_DIRECTION:                       // 393
		case EID_PKT_F_IP_ARRAY:                        // 396
		case EID_PKT_F_RADIO:                           // 394
		case EID_VSA_SSID_ID:                           // 400
			proto_tree_add_item(tlv_tree, hf_wassp_tlv_value_octext, tvb, offset + TLV_VALUE, length - 4, ENC_NA);
			offset += length;
			break;

		/* display as IP address format */
		case EID_AC_IPADDR:                    // 6
		case EID_TFTP_SERVER:                  // 8
		case EID_STATIC_BP_IPADDR:             // 30
		case EID_STATIC_BP_NETMASK:            // 31
		case EID_STATIC_BP_GATEWAY:            // 32
		case EID_STATIC_BM_IPADDR:             // 33
		case EID_AP_IPADDR:                    // 89
		case EID_AP_NETMASK:                   // 90
		case EID_AP_GATEWAY:                   // 91
		case EID_MU_IP_ADDR:                   // 173
		case EID_PEER_SITE_IP:                 // 176
		case EID_COLLECTOR_IP_ADDR:            // 200
		case EID_IP_ADDR_TX:                   // 322
		case EID_IP_ADDR_RX:                   // 323
		case EID_GW_IP_ADDR:                   // 325
		case EID_STATIC_VSA_IPADDR:            // 387
		case EID_STATIC_VSA_NETMASK:           // 388
			proto_tree_add_item(tlv_tree, hf_wassp_tlv_value_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += length;
			break;

		case EID_CONFIG:                       // 10
		case EID_ALARM:                        // 38
			/* Dissect SNMP encoded configuration */
			dissector_try_uint(wassp_dissector_table, WASSP_SNMP, tvb_new_subset_length(tvb, offset + TLV_VALUE, length - 4), pinfo, tlv_tree);
			offset += length;
			break;

		case EID_RU_STATE:                     // 11
			proto_tree_add_item(tlv_tree, hf_wassp_tlv_eid_rustate, tvb, offset + TLV_VALUE, length - 4, ENC_BIG_ENDIAN);
			proto_item_append_text(tlvi, ": %s",
					       tfs_get_string(tvb_get_uint8(tvb, offset + TLV_VALUE), &wassp_eid_rustate_types));
			offset += length;
			break;

		/* display as int */
		case EID_RU_PROTOCOL:                     // 13
		case EID_STANDBY_TIMEOUT:                 // 15
		case EID_RU_CHALLENGE_ID:                 // 16
		case EID_RU_SCAN_MODE:                    // 18
		case EID_RU_SCAN_TYPE:                    // 19
		case EID_RU_SCAN_INTERVAL:                // 20
		case EID_RU_RADIO_TYPE:                   // 21
		case EID_RU_CHANNEL_DWELL_TIME:           // 22
		case EID_RU_CHANNEL_LIST:                 // 23
		case EID_RU_SCAN_TIMES:                   // 25
		case EID_RU_SCAN_DELAY:                   // 26
		case EID_RU_SCAN_REQ_ID:                  // 27
		case EID_STATIC_CONFIG:                   // 28
		case EID_LOCAL_BRIDGING:                  // 29
		case EID_RU_CAPABILITY:                   // 36
		case EID_RADIO_ID:                        // 45
		case EID_REQ_ID:                          // 46
		case EID_NETWORK_ID:                      // 47
		case EID_TIME:                            // 49
		case EID_NUM_RADIOS:                      // 50
		case EID_VENDOR_ID:                       // 53
		case EID_SECURE_TUNNEL:                   // 56
		case EID_MU_TOPOLOGY_ID:                  // 57
		case EID_SNMP_ERROR_STATUS:               // 60
		case EID_SNMP_ERROR_INDEX:                // 61
		case EID_RU_REAUTH_TIMER:                 // 62
		case EID_AP_IMG_TO_RAM:                   // 63
		case EID_AP_IMG_ROLE:                     // 64
		case EID_STATS_REQUEST_TYPE:              // 67
		case EID_STATS_LAST:                      // 68
		case EID_COUNTDOWN_TIME:                  // 75
		case EID_WASSP_VLAN_TAG:                  // 76
		case EID_SSID_ID:                         // 77
		case EID_PORT_OPEN_FLAG:                  // 80
		case EID_WASSP_TUNNEL_TYPE:               // 81
		case EID_LOG_TYPE:                        // 82
		case EID_ALARM_SEVERITY:                  // 84
		case EID_AP_DHCP_MODE:                    // 88
		case EID_AUTH_STATE:                      // 98
		case EID_MU_DISC_AFTER_AUTH:              // 99
		case EID_TRANS_ID:                        // 101
		case EID_TIMEZONE_OFFSET:                 // 102
		case EID_SENSOR_FORCE_DOWNLOAD:           // 103
		case EID_BRIDGE_MODE:                     // 105
		case EID_MU_VLAN_TAG:                     // 106
		case EID_RATECTRL_CIR_UL:                 // 107
		case EID_RATECTRL_CIR_DL:                 // 108
		case EID_RATECTRL_CBS_UL:                 // 109
		case EID_RATECTRL_CBS_DL:                 // 110
		case EID_SIAPP_LOADBAL_PKT_TYPE:          // 153
		case EID_SIAPP_LOADBAL_LOAD_VALUE:        // 155
		case EID_SIAPP_FILTER_COS:                // 157
		case EID_UCAST_FILTER_DISABLE:            // 160
		case EID_MU_INFORM_REASON:                // 161
		case EID_MU_FILTER_KEY:                   // 165
		case EID_MU_TOPOLOGY_KEY:                 // 166
		case EID_MU_COS_KEY:                      // 167
		case EID_MU_SESSION_TIMEOUT:              // 168
		case EID_MU_LOGIN_LAT_PORT:               // 170
		case EID_MU_IDLE_TIMEOUT:                 // 171
		case EID_MU_ACCT_INTERIM_INTERVAL:        // 172
		case EID_MU_TERMINATE_ACTION:             // 174
		case EID_INTERFERENCE_EVENTS_ENABLE:      // 177
		case EID_EVENT_TYPE:                      // 178
		case EID_EVENT_CHANNEL:                   // 179
		case EID_EVENT_VALUE:                     // 180
		case EID_SSS_MU_ASSOC_TIME:               // 182
		case EID_SSS_MU_AUTH_STATE:               // 185
		case EID_TIME_FIRST_DETECTED:             // 187
		case EID_TIME_LAST_REPORTED:              // 188
		case EID_SSS_DEFAULT_SESSION_TIMEOUT:     // 190
		case EID_SSS_PRIVACY_TYPE:                // 192
		case EID_RU_AC_EVENT_COMPONENT_ID:        // 194
		case EID_MU_AUTH_STATE:                   // 195
		case EID_BULK_TYPE:                       // 197
		case EID_SENT_TIME:                       // 198
		case EID_SCAN_PROFILE_ID:                 // 209
		case EID_ACTION_REQ:                      // 210
		case EID_COUNTERMEASURES_MAX_CH:          // 212
		case EID_COUNTERMEASURES_SET:             // 213
		case EID_SEQ_NUM:                         // 215
		case EID_THREAT_TYPE:                     // 218
		case EID_THREAT_ID:                       // 219
		case EID_THREAT_FR_SFR:                   // 221
		case EID_THREAT_ALERT_TH_DUR:             // 225
		case EID_THREAT_CLEAR_TH_DUR:             // 226
		case EID_THREAT_PRIORITY:                 // 227
		case EID_THREAT_MITIGATION_LIST:          // 228
		case EID_PARAMS:                          // 235
		case EID_MU_EVENT_TYPE:                   // 260
		case EID_SSS_MU_IS_PORT_CLOSED:           // 229
		case EID_FULL_UPDATE:                     // 230
		case EID_REASON:                          // 231
		case EID_SCAN_CAP:                        // 238
		case EID_THREAT_CLASSIFICATION:           // 239
		case EID_STATE:                           // 242
		case EID_DROP_FR_CNT:                     // 243
		case EID_STOP_ROAM_CNT:                   // 244
		case EID_SPOOF_CNT:                       // 245
		case EID_ENCRYPTION_TYPE:                 // 250
		case EID_COMPONENT_ID:                    // 253
		case EID_BYPASS_BMCAST:                   // 255
		case EID_GETTIMEOFDAY:                    // 256
		case EID_COUNTRY_ID:                      // 257
		case EID_LOCATOR_FLOOR_ID:                // 261
		case EID_LOCATOR_LOC_TYPE:                // 262
		case EID_MU_EVENT_FROM_AP:                // 267
		case EID_LOCATOR_LOC_AP_DISTANCE:         // 269
		case EID_LOCATOR_LOC_PRECISION:           // 270
		case EID_LOCATOR_MU_ACTION:               // 273
		case EID_EFFECTIVE_EGRESS_VLAN:           // 274
		case EID_REBOOT_ACK:                      // 275
		case EID_AUTH_FLAG:                       // 277
		case EID_ROAMED_FLAG:                     // 278
		case EID_MU_RSS:                          // 279
		case EID_FILTER_RULES_VER:                // 280
		case EID_FILTER_TYPE:                     // 281
		case EID_DEFAULT_ACTION_TYPE:             // 284
		case EID_DEFAULT_CONTAIN_TO_VLAN:         // 285
		case EID_DEFAULT_BRIDGE_MODE:             // 286
		case EID_INVALID_POLICY:                  // 287
		case EID_AP_FLAGS:                        // 289
		case EID_AP_PVID:                         // 290
		case EID_MU_LOCATION_TS:                  // 332
		case EID_MU_IS_FT:                        // 338
		case EID_TIMESTAMP:                       // 353
		case EID_MU_REQ:                          // 355
		case EID_RU_REQ:                          // 356
		case EID_NEIGHBOUR_REQ:                   // 357
		case EID_SSS_FT_ASSOC:                    // 358
		case EID_DEFAULT_MIRRORN:                 // 359
		case EID_FILTER_RULE_EXT_ACT_FLAGS:       // 360
		case EID_TOPO_GROUP_MAPPING:              // 361
		case EID_SSS_CAPINFO:                     // 364
		case EID_SSS_CAPPOWER:                    // 365
		case EID_WFA_VSA:                         // 366
		case EID_WFA_HS20_REMED_METHOD:           // 367
		case EID_WFA_HS20_DEAUTH_CODE:            // 369
		case EID_WFA_HS20_REAUTH_DELAY:           // 370
		case EID_WFA_HS20_SWT:                    // 371
		case EID_POWER_STATUS:                    // 372
		case EID_FILTER_RULES_APP_SIG_GROUP_ID:   // 374
		case EID_FILTER_RULES_APP_SIG_DISP_ID:    // 375
		case EID_APPL_STATS_REQ:                  // 377
		case EID_PKT_CAPTURE_STATUS:              // 389
		case EID_PKT_CAPTURE_FILTERS:             // 390
		case EID_PKT_F_FLAGS:                     // 395
		case EID_PKT_F_PROTOCOL:                  // 398
		case EID_PKT_F_PORT:                      // 399
		case EID_MU_AUTH_TYPE:                    // 401
		case EID_PKT_F_MAX_PKT_COUNT:             // 402
		case EID_PKT_F_FLAG_2:                    // 403
		case EID_IMAGE_PORT:                      // 404
			proto_tree_add_item(tlv_tree, hf_wassp_tlv_value_int, tvb, offset + TLV_VALUE, length - 4, ENC_NA);
			offset += length;
			break;
		/* display as Mac address */
		case EID_BP_BPSSID:                 // 34
		case EID_BP_WIRED_MACADDR:          // 35
		case EID_SIAPP_MACADDR:             // 149
		case EID_SIAPP_AC_MGMT_MAC:         // 156
		case EID_MAC_ADDR:                  // 208
		case EID_SCAN_BSSID:                // 233
		case EID_MU_BSSID:                  // 276
		case EID_MAC_ADDR_TX:               // 320
		case EID_MAC_ADDR_RX:               // 321
			proto_tree_add_item(tlv_tree, hf_wassp_macaddr, tvb, offset + TLV_VALUE, length - 4, ENC_NA);
			offset += length;
			break;
		case EID_MU_MAC:                    // 48
		case EID_PKT_F_MAC:                 // 397
			proto_tree_add_item(tlv_tree, hf_wassp_mu_mac, tvb, offset + TLV_VALUE, length - 4, ENC_NA);
			offset += length;
			break;

		/*  call sub tlv  */
		case EID_EVENT_BLOCK:                                // 59
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, EVENT_BLOCK, ru_msg_type);
			break;
		case EID_AP_STATS_BLOCK:                             // 65
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, AP_STATS_BLOCK, ru_msg_type);
			break;
		case EID_MU_RF_STATS_BLOCK:                          // 66
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, MU_RF_STATS_BLOCK, ru_msg_type);
			break;
		case EID_TLV_CONFIG:                                 // 69
		case EID_BSSID2IP_BLOCK:                             // 92
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, CONFIG_GLOBAL_BLOCK, ru_msg_type);
			break;
		case EID_CONFIG_ERROR_BLOCK:                         // 70
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, CONFIG_ERROR_BLOCK, ru_msg_type);
			break;
		case EID_CONFIG_MODIFIED_BLOCK:                      // 71
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_CONFIG_MODIFIED, ru_msg_type);
			break;
		case EID_BULK_MU_BLOCK:                              // 78
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, BULK_MU_BLOCK, ru_msg_type);
			break;
		case EID_MU_BLOCK:                                   // 79
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, MU_BLOCK, ru_msg_type);
			break;
		case EID_BULK_VNS_BLOCK:                             // 86
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, BULK_VNS_BLOCK, ru_msg_type);
			break;
		case EID_VNS_BLOCK:                                  // 87
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, VNS_BLOCK, ru_msg_type);
			break;
		case EID_SIAPP_PMK_BLOCK:                            // 114
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_SIAPP_PMK_BLOCK, ru_msg_type);
			break;
		case EID_SIAPP_RADIO_CONFIG_BLOCK:                   // 121
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_SIAPP_RADIO_CONFIG_BLOCK, ru_msg_type);
			break;
		case EID_SIAPP_SIAPP_MU_STATS_BLOCK:                 // 123
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_SIAPP_MU_STATS_BLOCK, ru_msg_type);
			break;
		case EID_SIAPP_THIN_BLOCK:                           // 128
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_SIAPP_THIN_BLOCK, ru_msg_type);
			break;
		case EID_SIAPP_RADIOBLOCK:                           // 132
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_SIAPP_MU_STATS_BLOCK, ru_msg_type);
			break;
		case EID_SIAPP_BLOCK:                                // 134
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_SIAPP_BLOCK, ru_msg_type);
			break;
		case EID_SIAPP_LOADBAL_BLOCK:                        // 152
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, VNS_BLOCK, ru_msg_type);
			break;
		case EID_SSS_MU_BLOCK:                               // 181
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_SSS_MU_BLOCK, ru_msg_type);
			break;
		case EID_ASSOC_SSID_ARRAY:                           // 204
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_ASSOC_SSID_ARRAY, ru_msg_type);
			break;
		case EID_ASSOC_SSID_BLOCK:                           // 205
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_ASSOC_SSID_BLOCK, ru_msg_type);
			break;
		case EID_AP_LIST_BLOCK:                              // 206
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_AP_LIST_BLOCK, ru_msg_type);
			break;
		case EID_AP_LIST_ARRAY:                              // 207
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_AP_LIST_ARRAY, ru_msg_type);
			break;
		case EID_SCAN_PROFILE_BLOCK:                         // 214
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_SCAN_PROFILE_BLOCK, ru_msg_type);
			break;
		case EID_THREAT_DEF_ARRAY:                           // 216
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_THREAT_DEF_ARRAY, ru_msg_type);
			break;
		case EID_THREAT_DEF_BLOCK:                           // 217
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_THREAT_DEF_BLOCK, ru_msg_type);
			break;
		case EID_THREAT_PATTERN_ARRAY:                       // 222
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_THREAT_PATTERN_ARRAY, ru_msg_type);
			break;
		case EID_THREAT_PATTERN_BLOCK:                       // 223
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_THREAT_PATTERN_BLOCK, ru_msg_type);
			break;
		case EID_SURVEILLANCE_DATA_ARRAY:                    // 231
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_SURVEILLANCE_DATA_ARRAY, ru_msg_type);
			break;
		case EID_SURVEILLANCE_DATA_BLOCK:                    // 232
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_SURVEILLANCE_DATA_BLOCK, ru_msg_type);
			break;
		case EID_THREAT_DATA_ARRAY:                          // 239
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_THREAT_DATA_ARRAY, ru_msg_type);
			break;
		case EID_THREAT_DATA_BLOCK:                          // 240
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_THREAT_DATA_BLOCK, ru_msg_type);
			break;
		case EID_THREAT_CLASSIFY_ARRAY:                      // 245
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_THREAT_CLASSIFY_ARRAY, ru_msg_type);
			break;
		case EID_THREAT_CLASSIFY_BLOCK:                      // 246
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_THREAT_CLASSIFY_BLOCK, ru_msg_type);
			break;
		case EID_MU_EVENT_ARRAY:                             // 251
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_MU_EVENT_ARRAY, ru_msg_type);
			break;
		case EID_MU_EVENT_BLOCK:                             // 252
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_MU_EVENT_BLOCK, ru_msg_type);
			break;
		case EID_COUNTRY_ARRAY:                              // 258
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_COUNTRY_ARRAY, ru_msg_type);
			break;
		case EID_COUNTRY_BLOCK:                              // 259
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_COUNTRY_BLOCK, ru_msg_type);
			break;
		case EID_LOCATOR_LOC_BLOCK:                          // 263
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_LOCATOR_LOC_BLOCK, ru_msg_type);
			break;
		case EID_LOCATOR_LOC_ARRAY:                          // 264
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_LOCATOR_LOC_ARRAY, ru_msg_type);
			break;
		case EID_RSS_DATA_ARRAY:                             // 271
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_RSS_DATA_ARRAY, ru_msg_type);
			break;
		case EID_RSS_DATA_BLOCK:                             // 272
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_RSS_DATA_BLOCK, ru_msg_type);
			break;
		case EID_MCAST_FILTER_BLOCK:                         // 282
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_MCAST_FILTER_BLOCK, ru_msg_type);
			break;
		case EID_MCAST_FILTER_BLOCK_ENTRY:                   // 283
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_MCAST_FILTER_BLOCK_ENTRY, ru_msg_type);
			break;
		case EID_MU_SESSION_ARRAY:                           // 293
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_MU_SESSION_ARRAY, ru_msg_type);
			break;
		case EID_MU_SESSION_BLOCK:                           // 294
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_MU_SESSION_BLOCK, ru_msg_type);
			break;
		case EID_DETECTED_ROGUE_ARRAY:                       // 317
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_DETECTED_ROGUE_ARRAY, ru_msg_type);
			break;
		case EID_DETECTED_ROGUE_BLOCK:                       // 318
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_DETECTED_ROGUE_BLOCK, ru_msg_type);
			break;
		case EID_FILTER_RULES_EXT_BLOCK:                     // 329
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_FILTER_RULES_EXT_BLOCK, ru_msg_type);
			break;
		case EID_TOPOLOGY_ARRAY:                             // 379
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_TOPOLOGY_ARRAY_BLOCK, ru_msg_type);
			break;
		case EID_TOPOLOGY_STRUCT:                            // 380
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_TOPOLOGY_STRUCT_BLOCK, ru_msg_type);
			break;
		case EID_FILTER_CONFIG_STRUCT:                       // 381
			offset = dissect_wassp_sub_tlv(tlv_tree, tvb, pinfo, offset + TLV_VALUE, length - TLV_VALUE, TAB_FILTER_CONFIG_STRUCT_BLOCK, ru_msg_type);
			break;

		case EID_FILTER_RULES:                              // 97
			proto_tree_add_item(tlv_tree, hf_wassp_tlv_value_octext, tvb, offset + TLV_VALUE, length - 4, ENC_NA);
			decode_filter_rule_octext_string(tlv_tree, tvb, offset + 4, length );
			offset += length;
			break;
		case EID_MU_MAC_LIST:                              // 100
			proto_tree_add_item(tlv_tree, hf_wassp_tlv_value_octext, tvb, offset + TLV_VALUE, length - 4, ENC_NA);
			decode_mac_list_struct(tlv_tree, tvb, offset + 4,  length -4 );
			offset += length;
			break;
		case EID_COS:                                      // 158
			proto_tree_add_item(tlv_tree, hf_wassp_tlv_value_octext, tvb, offset + TLV_VALUE, length - 4, ENC_NA);
			decode_cos_struct(tlv_tree, tvb, offset + 4 );
			offset += length;
			break;
		case EID_RATE_LIMIT_RESOURCE_TBL:                  // 159
			proto_tree_add_item(tlv_tree, hf_wassp_tlv_value_octext, tvb, offset + TLV_VALUE, length - 4, ENC_NA);
			decode_rate_limit_struct(tlv_tree,tvb,  offset + 4,length-4 );
			offset += length;
			break;
		case EID_CHANNEL_LIST:                             // 211
			proto_tree_add_item(tlv_tree, hf_wassp_tlv_value_octext, tvb, offset + TLV_VALUE, length - 4, ENC_NA);
			decode_Channel_list(tlv_tree, tvb, offset + 4,  length -4 );
			offset += length;
			break;
		case EID_DNS_IP_ADDR:                              // 333
			proto_tree_add_item(tlv_tree, hf_wassp_tlv_value_octext, tvb, offset + TLV_VALUE, length - 4, ENC_NA);
			decode_ipv4_list_struct(tlv_tree, tvb, offset + 4,  length -4 );
			offset += length;
			break;
		case EID_MU_APPL_STATS_BLOCK:                      // 378
			proto_tree_add_item(tlv_tree, hf_wassp_tlv_value_octext, tvb, offset + TLV_VALUE, length - 4, ENC_NA);
			decode_mu_appl_stats_block(tlv_tree, tvb, offset + 4 );
			offset += length;
			break;

		case EID_SCAN_RSS_RSSI:                            // 236
			proto_tree_add_item(tlv_tree, hf_wassp_tlv_value_int, tvb, offset + TLV_VALUE, length - 4, ENC_NA);
			suboffset = offset + 4;
			proto_tree_add_item(tlv_tree, hf_wassp_rss, tvb, suboffset, 2, ENC_BIG_ENDIAN);
			suboffset += 2;
			proto_tree_add_item(tlv_tree, hf_wassp_rssi, tvb, suboffset, 2, ENC_BIG_ENDIAN);
			offset += length;
			break;

		default:
			/* If tlv isn't in the list, then just display the raw data*/
			proto_tree_add_item(tlv_tree, hf_wassp_tlv_value_octext, tvb, offset + TLV_VALUE, length - 4, ENC_NA);
			call_dissector(data_handle, tvb_new_subset_length(tvb, offset + TLV_VALUE, length - 4), pinfo, wassp_tree);
			offset += length;
		}

		if (tlv_type == EID_UNUSED_0)
		{
			proto_tree_add_item(wassp_tree, hf_wassp_tlv_invalid, tvb, offset, value, ENC_BIG_ENDIAN);
			offset += length;
		}
	}
	return offset;
}



static void
mu_association_status(char *buf, uint8_t value)
{
	if (value == 1)
		snprintf(buf, ITEM_LABEL_LENGTH, " Success (%d)", value);
	else if (value == 2)
		snprintf(buf, ITEM_LABEL_LENGTH, " Reject (%d)", value);
	else
		snprintf(buf, ITEM_LABEL_LENGTH, " Failure (%d)", value);
}



static int dissect_mu_netflow(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_item *ti, *temp;
	proto_tree *wassp_mu_netflow_tree, *mu_netflow_header_tree;
	uint16_t netflowLen, totalRecord, i;

	ti = proto_tree_add_item(tree, hf_wassp_mu_netflow_tree, tvb, offset, -1, ENC_NA);
	wassp_mu_netflow_tree = proto_item_add_subtree(ti, ett_wassp_mu_data_netflow);

	temp = proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_header, tvb, MU_NETFLOW_HDR_VERSION, MU_NETFLOW_HEADER_TOTAL_LENGTH, ENC_NA);
	mu_netflow_header_tree = proto_item_add_subtree(temp, ett_wassp_mu_data_netflow_header);
	proto_tree_add_item(mu_netflow_header_tree, hf_wassp_mu_netflow_version, tvb, MU_NETFLOW_HDR_VERSION, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(mu_netflow_header_tree, hf_wassp_mu_netflow_length, tvb, MU_NETFLOW_HDR_LENGTH, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(mu_netflow_header_tree, hf_wassp_mu_netflow_flags, tvb, MU_NETFLOW_HDR_FLAG, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(mu_netflow_header_tree, hf_wassp_mu_netflow_uptime, tvb, MU_NETFLOW_HDR_UPTIME, 4, ENC_NA);
	offset += MU_NETFLOW_HEADER_TOTAL_LENGTH;

	netflowLen = tvb_get_ntohs(tvb, MU_NETFLOW_HDR_LENGTH);
	totalRecord = (netflowLen - MU_NETFLOW_HEADER_TOTAL_LENGTH) / MU_NETFLOW_RECORD_SIZE;  //netflow record size is 46 bytes
	if (totalRecord > 0)
	{
		for (i = 1; i <= totalRecord; i++)
		{
			//proto_tree_add_debug_text(wassp_mu_netflow_tree, "      WASSP MU Netflow  Record %d ", i);
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_record, tvb, offset, MU_NETFLOW_RECORD_SIZE, ENC_NA);
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_in_bytes, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_in_packets, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_ip_protocol_number, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_source_tos, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_source_port, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_source_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_input_snmp, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_dest_port, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_dest_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_output_snmp, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_last_time, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_first_time, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_in_source_mac, tvb, offset, 6, ENC_NA);
			offset += 6;
			proto_tree_add_item(wassp_mu_netflow_tree, hf_wassp_mu_netflow_in_dest_mac, tvb, offset, 6, ENC_NA);
			offset += 6;
		}
	}
	else
	{
		//proto_tree_add_debug_text(wassp_mu_netflow_tree, "WASSP MU Netflow  Records are incomplete ");
		offset += netflowLen;
	}

	return offset;
}




/* Dissect Wassp MU message: return offset in current tvb */
static int dissect_wassp_mu(proto_tree *wassp_tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int plength)
{
	proto_item *ti, *temp;
	proto_tree *wassp_mu_tree, *mu_data_header_tree, *mu_action_field_tree;
	wassp_mu_msg_t mu_msg_type;
	char *label;
	uint16_t length = WASSP_MU_HDR_WITHOUT_ASSO_STATUS_LEN;

	if (tvb_reported_length_remaining(tvb, offset) > 0)
	{
		mu_msg_type = (wassp_mu_msg_t)tvb_get_uint8(tvb, offset + WASSP_MU_HDR_TYPE);
		ti = proto_tree_add_item(wassp_tree, hf_wassp_mu_data_tree, tvb, offset, -1, ENC_NA);
		wassp_mu_tree = proto_item_add_subtree(ti, ett_wassp_data);
		label = (char*)try_val_to_str(mu_msg_type, wassp_mu_header_types);
		label = (label == NULL) ? "Unknown Type" : label;
		proto_item_append_text(ti, ", %s", label);

		if ( mu_msg_type == WASSP_MU_Associate_Rsp )
			length = WASSP_MU_HDR_WITH_ASSO_STATUS_LEN;

		/* Dissect the WASSP MU header */
		temp = proto_tree_add_item(wassp_mu_tree, hf_wassp_mu_data_header, tvb, WASSP_MU_HDR_TYPE, length, ENC_NA);
		mu_data_header_tree = proto_item_add_subtree(temp, ett_mu_data_header);
		proto_tree_add_item(mu_data_header_tree, hf_wassp_mu_type, tvb, offset + WASSP_MU_HDR_TYPE, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(mu_data_header_tree, hf_wassp_mu_qos, tvb, offset + WASSP_MU_HDR_QOS, 1, ENC_BIG_ENDIAN);
		temp = proto_tree_add_item(mu_data_header_tree, hf_wassp_mu_action_ssid, tvb, offset + WASSP_MU_HDR_ACTION_SSID, 2, ENC_BIG_ENDIAN);
		mu_action_field_tree = proto_item_add_subtree(temp, ett_mu_action_field);
		proto_tree_add_item(mu_action_field_tree, hf_wassp_mu_action, tvb, offset + WASSP_MU_HDR_ACTION_SSID, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(mu_action_field_tree, hf_wassp_mu_action_field_value, tvb, offset + WASSP_MU_HDR_ACTION_SSID, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(mu_data_header_tree, hf_wassp_mu_mac, tvb, offset + WASSP_MU_HDR_MAC, 6, ENC_NA);
		proto_tree_add_item(mu_data_header_tree, hf_wassp_mu_resv0, tvb, offset + WASSP_MU_HDR_RESV_0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(mu_data_header_tree, hf_wassp_mu_resv1, tvb, offset + WASSP_MU_HDR_RESV_1, 2, ENC_BIG_ENDIAN);
		if ( mu_msg_type == WASSP_MU_Associate_Rsp )
			proto_tree_add_item(mu_data_header_tree, hf_wassp_mu_assoc_status, tvb, offset + WASSP_MU_HDR_RESV_1 + 2, 1, ENC_BIG_ENDIAN);

		offset += length;
		/* WASSP MU payload length */
		plength -= length;

		/* Dissect the WASSP MU payload */
		switch (mu_msg_type)
		{
		case WASSP_MU_NETFLOW:
			offset = dissect_mu_netflow(wassp_mu_tree, tvb, offset);
			break;
		case WASSP_MU_Associate_Req:
		case WASSP_MU_Update_Req:
		case WASSP_MU_Update_Rsp:
		case WASSP_AP2AC_MU_Inform_Req:
		case WASSP_AP2AC_MU_Inform_Rsp:
		case WASSP_MU_BULK_Associate_Req:
		case WASSP_MU_BULK_Associate_Rsp:
		case WASSP_MU_Disconnect_Req:
		case WASSP_MU_Disconnect_Rsp:
		case WASSP_MU_Associate_Rsp:
			offset = dissect_wassp_tlv(wassp_mu_tree, tvb, pinfo, offset, WASSP_RU_UNUSED_0);
			break;
		case WASSP_MU_MIRRORN:
		case WASSP_MU_Data:
		case WASSP_MU_Eap_Last:
			/* Dissect the WASSP MU ethernet frame */
			call_dissector(eth_handle, tvb_new_subset_length(tvb, offset, plength), pinfo, wassp_mu_tree);
			offset += plength;
			break;
		case WASSP_MU_Roam_Notify:
		case WASSP_MU_Disconnect_Notify:
			offset += plength;
			break;
		default:
			/* Dissect the WASSP MU payload as data by default */
			call_dissector(data_handle, tvb_new_subset_length(tvb, offset, plength), pinfo, wassp_mu_tree);
			offset += plength;
			break;
		}
	}
	return offset;
}




static void dissect_unfragmented_wassp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint16_t plength2, wassp_ru_msg_t ru_msg_type, int offset2)
{
	proto_tree *wassp_tree;
	int offset = offset2;
	uint16_t plength = plength2;
	uint16_t lsbHeaderMagic = 0;

	if (tree)
	{
		wassp_tree = tree;
		plength -= WASSP_HDR_LEN;

		switch (ru_msg_type)
		{
		case WASSP_RU_Discov:                            // 1
		case WASSP_RU_Register_Req:                      // 2
		case WASSP_RU_Register_Rsp:                      // 3
		case WASSP_RU_Authentication_Req:                // 4
		case WASSP_RU_Authentication_Rsp:                // 5
		case WASSP_RU_SW_Version_Validate_Req:           // 6
		case WASSP_RU_SW_Version_Validate_Rsp:           // 7
		case WASSP_RU_Config_Req:                        // 8
		case WASSP_RU_Config_Rsp:                        // 9
		case WASSP_RU_Ack:                               // 10
		case WASSP_RU_Config_Status_Notify:              // 11
		case WASSP_RU_Set_State_Req:                     // 12
		case WASSP_RU_Set_State_Rsp:                     // 13
		case WASSP_RU_Poll:                              // 16
		case WASSP_RU_SNMP_Req:                          // 17
		case WASSP_RU_SNMP_Rsp:                          // 18
		case WASSP_BP_Trap_Notify:                       // 19
		case WASSP_BP_Scan_Req:                          // 20
		case WASSP_RFM_Notify:                           // 21
		case WASSP_RU_SNMP_Alarm_Notify:                 // 22
		case WASSP_RU_SNMP_Set_Alarm_Clear:              // 23
		case WASSP_RU_SNMP_Set_Log_Status:               // 24
		case WASSP_RU_SNMP_Get_Log_Req:                  // 25
		case WASSP_RU_SNMP_Get_Log_Resp:                 // 26
		case WASSP_SEC_Update_Notify:                    // 27
		case WASSP_RU_STATS_Req:                         // 28
		case WASSP_RU_STATS_Rsp:                         // 29
		case WASSP_RU_UNUSED_30:                         // 30
		case WASSP_RU_UNUSED_31:                         // 31
		case WASSP_RU_Get_Req:                           // 32
		case WASSP_RU_Get_Rsp:                           // 33
		case WASSP_RU_Alarm_Notify:                      // 34
		case WASSP_RU_Set_Alarm_Clear:                   // 35
		case WASSP_RU_Get_Log_Req:                       // 36
		case WASSP_RU_Get_Log_Rsp:                       // 37
		case WASSP_RU_UNUSED_38:                         // 38
		case WASSP_RU_UNUSED_39:                         // 39
		case WASSP_P_PEER_DOWN_NOTIFY:                   // 40
		case WASSP_P_LINK_STATE_CHANGE_REQ:              // 41
		case WASSP_P_LINK_STATE_CHANGE_RSP:              // 42
		case WASSP_RU_GetIP_Req:                         // 44
		case WASSP_RU_GetIP_Rsp:                         // 45
		case WASSP_RU_LAMG_Update_Req:                   // 46
		case WASSP_RU_LAMG_Update_Rsp:                   // 47
		case WASSP_RU_Event_Req:                         // 48
		case WASSP_RU_Event_Rsp:                         // 49
		case WASSP_RU_BULK_MU_UPDATE_REQ:                // 50
		case WASSP_RU_BULK_MU_UPDATE_RSP:                // 51
		case WASSP_ROAMED_MU_FILTER_STATS_REQ:           // 52
		case WASSP_ROAMED_MU_FILTER_STATS_RESP:          // 53
		case WASSP_RU_AC_Event_Req:                      // 56
		case WASSP_RU_AC_Event_Rsp:                      // 57
		case WASSP_RU_Event_Notify:                      // 58
		case WASSP_RU_AC_EVENT:                          // 59
		case WASSP_WIDS_WIPS_Config_Req:                 // 60
		case WASSP_WIDS_WIPS_Config_Rsp:                 // 61
		case WASSP_Scan_Data_Notify:                     // 62
		case WASSP_Scan_Data_Notify_Ack:                 // 63
		case WASSP_Loc_Data_Notify:                      // 64
		case WASSP_Loc_Data_Notify_Ack:                  // 65
		case WASSP_RU_SW_Version_Validate_Ack:           // 66
		case WASSP_NEIGHBOUR_STATS_Rsp:                  // 67
		case WASSP_APPL_STATS_RESP:                      // 68
		case WASSP_AC_Register_Req:                      // 101
		case WASSP_AC_Register_Rsp:                      // 102
		case WASSP_AC_Deregister_Req:                    // 103
		case WASSP_AC_Deregister_Rsp:                    // 104
			goto tlv_dissect;
		case WASSP_RU_Stats_Notify:                      // 14
			/* Dissect SNMP encoded RU statistics */
			dissector_try_uint(wassp_dissector_table, WASSP_SNMP, tvb_new_subset_length(tvb, offset, plength), pinfo, wassp_tree);
			offset += plength;
			goto data_dissect;
		case WASSP_LBS_TAG_REPORT:                       // 55
			lsbHeaderMagic = tvb_get_ntohs(tvb, 36);
			call_dissector(ip_handle, tvb_new_subset_length(tvb, offset, plength), pinfo, wassp_tree);
			if (lsbHeaderMagic == LBS_HDR_MAGIC)
				offset = decode_lbs_tag_header(wassp_tree, tvb, offset + 28);
			else
			{
				return;
			}
			goto data_dissect;
		case WASSP_Data:                            // 15
			offset = dissect_wassp_mu(wassp_tree, tvb, pinfo, offset, plength);
			goto data_dissect;
		default:
			offset += plength;
			goto data_dissect;
		}
tlv_dissect:
		/* Dissect all RU messages containing TLVs */
		offset = dissect_wassp_tlv(wassp_tree, tvb, pinfo, offset, ru_msg_type);
data_dissect:
		/* Call data dissector on any remaining bytes */
		call_dissector(data_handle, tvb_new_subset_length(tvb, offset, -1), pinfo, wassp_tree);
	}
}




static int dissect_wassp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{

	proto_item *ti, *temp;
	proto_tree *wassp_tree;
	proto_tree *wassp_header_tree, *ru_discover_header_tree, *wassp_seq_flag_tree;
	wassp_ru_msg_t ru_msg_type;
	int offset = 0;
	uint16_t flag = 0, seq_number = 0;
	uint32_t fragment = false, complete = true;
	uint32_t remain_len = 0, length;
	fragment_head *wassp_frag_msg = NULL;
	bool       save_fragmented;
	tvbuff_t *next_tvb = NULL, *combined_tvb = NULL;
	const char *label;
	conversation_t  *conv = NULL;
	uint32_t reassembly_id;

	/**********************************************************************************************************************************************************
	   UDP Port = 13910 --> Wassp Protocol
	   UDP port = 13907 --> Access Point Discover

	   Wassp header format:
		 Byte 1    Byte 2   Byte 3 and Byte 4    Byte 5 and Byte 6    Byte 7 and Byte 8
	   | Version | Type   | Seq. Number & Flag |     Session ID    |  Length of Payload |

	  RU discover header format:
		Byte 1    Byte 2   Byte 3 and Byte 4    Byte 5 and Byte 6    Byte 7 and Byte 8   Byte 7 and Byte 8      Byte 9 to Byte 12 if mac, else Byte 9 to Byte 10 for operation
	  | Version | Type   |   Random Number   | Length of Payload    |  Check Sum       | Controller Operation |  Mac or Operation

	************************************************************************************************************************************************************/

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	remain_len = tvb_reported_length_remaining(tvb, WASSP_HDR_VERSION);
	next_tvb = tvb;
	ru_msg_type = (wassp_ru_msg_t)tvb_get_uint8(tvb, WASSP_HDR_TYPE);

	if ( ru_msg_type == WASSP_Data ) // wassp mu header
	{
		label = val_to_str_const(tvb_get_uint8(tvb, WASSP_HDR_LEN + WASSP_MU_HDR_TYPE), wassp_mu_header_types, "Unknown WASSP MU Message Type");
		col_add_str(pinfo->cinfo, COL_INFO, label);
	}
	else if (ru_msg_type == WASSP_RU_Discov) /* ap discover header*/
	{
		if (tvb_get_ntohs(tvb, RU_HDR_AC_OP) == RU_DISCOVER_OP_MODE)
			col_add_str(pinfo->cinfo, COL_INFO, "RU Discover Request");
		else
			col_add_str(pinfo->cinfo, COL_INFO, "RU Discover Response");
	}
	else
        {
		col_add_str(pinfo->cinfo, COL_INFO, val_to_str_const(tvb_get_uint8(tvb, WASSP_HDR_TYPE), wassp_header_types, "Unknown WASSP Message Type"));
        }

	save_fragmented = pinfo->fragmented;

	ti = proto_tree_add_item(tree, proto_wassp, tvb, offset, -1, ENC_NA);
	wassp_tree = proto_item_add_subtree(ti, ett_wassp);

	if (ru_msg_type == WASSP_RU_Discov)  /* UDP port = 13907, ap discover tlv, decode AP discover header */
	{
		flag = tvb_get_ntohs(tvb, RU_HDR_AC_OP);
		if ( flag == RU_HDR_CONTAIN_MAC) // ru mac or ac-mode
			length = RU_HEADER_WITH_MAC_LEN;
		else
			length = RU_HEADER_WITHOUT_MAC_LEN;

		temp = proto_tree_add_item(wassp_tree, hf_ru_discover_header, tvb, RU_HDR_VERSION, length, ENC_NA);
		ru_discover_header_tree = proto_item_add_subtree(temp, ett_ru_discover_header);
		proto_tree_add_item(ru_discover_header_tree, hf_wassp_version, tvb, RU_HDR_VERSION, 1, ENC_BIG_ENDIAN);
		proto_item_append_text(ti, ", %s", (char*)try_val_to_str(ru_msg_type, wassp_header_types)); //Update WASSP protocol with message type
		proto_tree_add_item(ru_discover_header_tree, hf_wassp_type, tvb, RU_HDR_TYPE, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(ru_discover_header_tree, hf_ru_rad_num, tvb, RU_HDR_RAD_NUM, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(ru_discover_header_tree, hf_wassp_length, tvb, RU_HDR_LENGTH, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(ru_discover_header_tree, hf_ru_checksum, tvb, RU_HDR_CHECKSUM, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(ru_discover_header_tree, hf_ru_ac_op, tvb, RU_HDR_AC_OP, 2, ENC_BIG_ENDIAN);
		if ( flag == RU_HDR_CONTAIN_MAC) // ru mac or ac-mode
			proto_tree_add_item(ru_discover_header_tree, hf_ru_mac, tvb, RU_HDR_MAC, 6, ENC_NA);
		else
			proto_tree_add_item(ru_discover_header_tree, hf_ru_ac_mode, tvb, RU_HDR_AC_MODE, 2, ENC_BIG_ENDIAN);
		offset = length;
	}
	else /* UDP port = 13910, decode Wassp protocol header */
	{
		temp = proto_tree_add_item(wassp_tree, hf_wassp_header, tvb, WASSP_HDR_VERSION, WASSP_HDR_LEN, ENC_NA);
		wassp_header_tree = proto_item_add_subtree(temp, ett_wassp_header);
		flag = tvb_get_ntohs(tvb, WASSP_HDR_SEQ_NUM);
		/* seq_number used 10 bits only */
		seq_number = flag >> 6;
		proto_tree_add_item(wassp_header_tree, hf_wassp_version, tvb, WASSP_HDR_VERSION, 1, ENC_NA);
		proto_item_append_text(ti, ", %s", (char*)try_val_to_str(ru_msg_type, wassp_header_types)); //Update WASSP protocol with message type
		proto_tree_add_item(wassp_header_tree, hf_wassp_type, tvb, WASSP_HDR_TYPE, 1, ENC_BIG_ENDIAN);
		temp = proto_tree_add_item(wassp_header_tree, hf_wassp_seq_num_flag, tvb, WASSP_HDR_SEQ_NUM, 2, ENC_BIG_ENDIAN);
		wassp_seq_flag_tree = proto_item_add_subtree(temp, ett_seq_flags);
		proto_tree_add_item(wassp_seq_flag_tree, hf_seq_num, tvb, WASSP_HDR_SEQ_NUM, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(wassp_seq_flag_tree, hf_wassp_use_frag, tvb, WASSP_HDR_SEQ_NUM, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(wassp_seq_flag_tree, hf_wassp_data_frag, tvb, WASSP_HDR_SEQ_NUM, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(wassp_seq_flag_tree, hf_wassp_more_frag, tvb, WASSP_HDR_SEQ_NUM, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(wassp_seq_flag_tree, hf_wassp_first_frag, tvb, WASSP_HDR_SEQ_NUM, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(wassp_header_tree, hf_wassp_sessionid, tvb, WASSP_HDR_SESSIONID, 2, ENC_BIG_ENDIAN);/* display session id  */
		proto_tree_add_item(wassp_header_tree, hf_wassp_length, tvb, WASSP_HDR_PLENGTH, 2, ENC_BIG_ENDIAN);

		if ( flag & RU_WASSP_FLAGS_USE_FRAGMENTATION)
		{
			fragment = true;
			complete = false;
		}
		offset = WASSP_HDR_LEN;
	}


	if (fragment)   /* fragmented */
	{
		pinfo->fragmented = true;
		offset = WASSP_HDR_LEN;
		conv = find_conversation_pinfo(pinfo, 0);
		DISSECTOR_ASSERT(conv);
		reassembly_id = (((conv->conv_index) & 0x00FFFFFF) << 8) + ru_msg_type;
		wassp_frag_msg = fragment_add_seq_next(&wassp_reassembled_table, tvb, offset, pinfo, reassembly_id, NULL, remain_len - WASSP_HDR_LEN, flag & RU_WASSP_FLAGS_MORE_FRAGMENTS_FOLLOWING);
		if ( wassp_frag_msg )
			combined_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled Wassp", wassp_frag_msg, &wassp_frag_items, NULL, wassp_tree);

		if ( combined_tvb)
		{
			col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)");
			next_tvb = combined_tvb;
			complete = true;
			offset = 0;
		}
		else
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, " (Message fragment %u)", seq_number);
			next_tvb = tvb_new_subset_length(tvb, WASSP_HDR_LEN, -1);
		}
	}


	if (complete)
		dissect_unfragmented_wassp(next_tvb, pinfo, wassp_tree, remain_len, ru_msg_type, offset);

	pinfo->fragmented = save_fragmented;
	return 1;
}





/* Register WASSP protocol */
void proto_register_wassp(void)
{
	static hf_register_info hf[] =
	{
		{
			&hf_aeroscout_header,
			{
				"Location Base Service Header", "wassp.aeroscout.header", FT_BYTES, BASE_NONE, NULL,
				0x0, "Aeroscout header", HFILL
			}
		},
		{
			&hf_aeroscout_header_magic_number,
			{
				"Header Magic Number", "wassp.aeroscout.header_magic", FT_UINT16, BASE_HEX, NULL,
				0x0, "Aeroscout header magic number", HFILL
			}
		},
		{
			&hf_aeroscout_request_id,
			{
				"Request ID", "wassp.aeroscout.request_id", FT_UINT16, BASE_DEC, NULL,
				0x0, "Aeroscout Request ID", HFILL
			}
		},
		{
			&hf_aeroscout_code,
			{
				"Operation Code", "wassp.aeroscout.code", FT_UINT8, BASE_DEC, NULL,
				0x0, "Aeroscout Operation Code", HFILL
			}
		},

		{
			&hf_aeroscout_sub_code,
			{
				"Operation Sub Code", "wassp.aeroscout.sub_code", FT_UINT8, BASE_DEC, NULL,
				0x0, "Aeroscout Operation Sub Code", HFILL
			}
		},
		{
			&hf_aeroscout_datalength,
			{
				"Length of Data Payload", "wassp.aeroscout.datalength", FT_UINT16, BASE_DEC, NULL,
				0x0, "Aeroscout Length of Data Payload", HFILL
			}
		},
		{
			&hf_lbs_vendor_id,
			{
				"Location Base Service Vendor ID", "wassp.lbs.vendor_id", FT_UINT16, BASE_DEC, NULL,
				0x0, "LBS TAG Vendor ID", HFILL
			}
		},
		{
			&hf_lbs_rsvd1,
			{
				"LBS Rsvd", "wassp.lbs.rsvd1", FT_UINT16, BASE_HEX, NULL,
				0x0, "LBS TAG rsvd", HFILL
			}
		},
		{
			&hf_lbs_ap_bssid,
			{
				"Location Base Service AccessPoint BSSID", "wassp.lbs.ap_bssid", FT_BYTES, BASE_NONE, NULL,
				0x0, "LBS TAG ap bssid", HFILL
			}
		},
		{
			&hf_lbs_rsvd2,
			{
				"LBS Rsvd", "wassp.lbs.rsvd2", FT_UINT8, BASE_HEX, NULL,
				0x0, "LBS TAG rsvd2", HFILL
			}
		},
		{
			&hf_lbs_rxchan,
			{
				"LBS rxchan", "wassp.lbs.rxchan", FT_UINT8, BASE_DEC, NULL,
				0x0, "LBS TAG rxchan", HFILL
			}
		},

		{
			&hf_lsb_tstamp,
			{
				"Location Base Service Time Stamp", "wassp.lbs.tstamp", FT_UINT32, BASE_DEC, NULL,
				0x0, "LBS TAG tstamp", HFILL
			}
		},
		{
			&hf_lsb_rsvd3,
			{
				"LBS Rsvd", "wassp.lbs.rsvd3", FT_UINT16, BASE_HEX, NULL,
				0x0, "LBS TAG  rsvd3", HFILL
			}
		},
		{
			&hf_lsb_rssi,
			{
				"Location Base Service RSSI", "wassp.lbs.rssi", FT_INT8, BASE_DEC, NULL,
				0x0, "LBS TAG rssi", HFILL
			}
		},
		{
			&hf_lsb_rsvd,
			{
				"LBS Rsvd", "wassp.lbs.rsvd", FT_UINT8, BASE_HEX, NULL,
				0x0, "LBS TAG rsvd4", HFILL
			}
		},
		{
			&hf_lsb_noise_floor,
			{
				"LBS Noise Floor", "wassp.lsb.noise_floor", FT_INT8, BASE_DEC, NULL,
				0x0, "LBS TAG noise floor", HFILL
			}
		},
		{
			&hf_lsb_rsvd4,
			{
				"LBS Rsvd", "wassp.lsb.rsvd4", FT_UINT24, BASE_HEX, NULL,
				0x0, "LBS TAG rsvd5", HFILL
			}
		},
		{
			&hf_lsb_chan_rate,
			{
				"LBS channel Rate", "wassp.lsb.chan_rate", FT_UINT8, BASE_DEC, NULL,
				0x0, "LBS TAG channel rate", HFILL
			}
		},
		{
			&hf_lsb_rsvd5,
			{
				"LBS Rsvd", "wassp.lsb.rsvd5", FT_UINT8, BASE_HEX, NULL,
				0x0, "LBS TAG rsvd6", HFILL
			}
		},
		{
			&hf_lsb_wh_fc,
			{
				"LBS Wireless Header Frame Control", "wassp.lsb.wh_fc", FT_UINT16, BASE_HEX, NULL,
				0x0, "LBS TAG Frame Control", HFILL
			}
		},
		{
			&hf_lsb_wh_seq,
			{
				"LBS Wireless Header Sequence Number", "wassp.hf_lsb_wh_seq", FT_UINT16, BASE_HEX, NULL,
				0x0, "LBS TAG Sequence Number", HFILL
			}
		},
		{
			&hf_lsb_rsvd6,
			{
				"LBS Rsvd", "wassp.lsb.rsvd6", FT_UINT16, BASE_HEX, NULL,
				0x0, "LBS TAG rsvd7", HFILL
			}
		},
		{
			&hf_lsb_wh_addr2,
			{
				"MAC address2", "wassp.data.mu_mac", FT_ETHER, BASE_NONE, NULL,
				0x0, "Mobile Unit Ethernet address", HFILL
			}
		},
		{
			&hf_lsb_wh_addr3,
			{
				"MAC address3", "wassp.data.mu_mac", FT_ETHER, BASE_NONE, NULL,
				0x0, "Mobile Unit Ethernet address", HFILL
			}
		},
		{
			&hf_lsb_wh_addr4,
			{
				"MAC address4", "wassp.data.mu_mac", FT_ETHER, BASE_NONE, NULL,
				0x0, "Mobile Unit Ethernet address", HFILL
			}
		},
		{
			&hf_wassp_version,
			{
				"Version", "wassp.version", FT_UINT8, BASE_DEC, NULL,
				0x0, "Wassp Protocol Version", HFILL
			}
		},
		/* ru discover header */
		{
			&hf_ru_rad_num,
			{
				"RU Random Number", "wassp.ru_xid", FT_UINT16, BASE_DEC, NULL,
				0x0, "random number for checking the session", HFILL
			}
		},
		{
			&hf_ru_checksum,
			{
				"RU Messages Checksum", "wassp.ru_checksum", FT_UINT16, BASE_DEC, NULL,
				0x0, "AccessPoint messages checksum", HFILL
			}
		},
		{
			&hf_ru_ac_op,
			{
				"Controller Operation", "wassp.ru_ac_op", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL
			}
		},
		{
			&hf_ru_ac_mode,
			{
				"Controller Operation Mode", "wassp.ru_ac_mode", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL
			}
		},
		{
			&hf_ru_mac,
			{
				"AP MAC address", "wassp.ru_mac", FT_ETHER, BASE_NONE, NULL,
				0x0, "AP Ethernet address", HFILL
			}
		},
		{
			&hf_ru_discover_header,
			{
				"RU Discover Header", "wassp.ru.header", FT_BYTES, BASE_NONE, NULL ,
				0x0, "AccessPoint Discover Header", HFILL
			}
		},
		{
			&hf_wassp_header,
			{
				"Wassp Header", "wassp.header", FT_BYTES, BASE_NONE, NULL ,
				0x0, "Wassp Message Header", HFILL
			}
		},
		{
			&hf_wassp_type,
			{
				"WASSP Type", "wassp.type", FT_UINT8, BASE_DEC,
				VALS(wassp_header_types), 0x0, "Wassp message type", HFILL
			}
		},
		{
			&hf_wassp_seq_num_flag,
			{
				"Sequence Number & Flag", "wassp.seq_num_flag", FT_UINT16, BASE_DEC,  NULL,
				0x0, "Sequence number and flag for multi-message", HFILL
			}
		},
		{
			&hf_seq_num,
			{
				"Sequence Number", "wassp.seq_num", FT_UINT16, BASE_DEC,  NULL,
				0xffc0, "Sequence number for multi-message", HFILL
			}
		},
		{
			&hf_wassp_use_frag,
			{
				"Wassp Use Fragmentation", "wassp.use_frag", FT_BOOLEAN, 6,  NULL,
				0x8, "Wassp Packet Use Fragmentation", HFILL
			}
		},
		{
			&hf_wassp_data_frag,
			{
				"Wassp Data Fragmentation", "wassp.data_frag", FT_BOOLEAN, 6,  NULL,
				0x2, NULL, HFILL
			}
		},
		{
			&hf_wassp_more_frag,
			{
				"Fragments following", "wassp.following_frag", FT_BOOLEAN, 6,  NULL,
				0x1, "Wassp Fragments following", HFILL
			}
		},
		{
			&hf_wassp_first_frag,
			{
				"Not First fragment packet", "wassp.no_first_frag", FT_BOOLEAN, 6, NULL,
				0x4, "Wassp Not First Fragment Packet", HFILL
			}
		},
		{
			&hf_wassp_sessionid,
			{
				"Session ID", "wassp.session_id", FT_UINT16, BASE_DEC, NULL,
				0x0, "Concentrator Session ID", HFILL
			}
		},
		{
			&hf_wassp_length,
			{
				"Length", "wassp.length", FT_UINT16, BASE_DEC, NULL,
				0x0, "Length of Payload", HFILL
			}
		},
		/* wassp MU data  ---  start */
		{
			&hf_wassp_mu_data_tree,
			{
				"WASSP MU Data tree", "wassp.mu.data.subtree",
				FT_NONE, BASE_NONE, NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_wassp_mu_data_header,
			{
				"Wassp MU Data Header", "wassp.mu_data_header", FT_BYTES, BASE_NONE, NULL,
				0x0, NULL, HFILL
			}
		},
		{
			&hf_wassp_mu_type,
			{
				"Type", "wassp.data.mu_type", FT_UINT8, BASE_DEC, NULL,
				0x0, "Wassp MU message type", HFILL
			}
		},
		{
			&hf_wassp_mu_qos,
			{
				"QOS", "wassp.data.mu_qos", FT_UINT8, BASE_DEC, NULL,
				0x0, "Quality of Service identifier", HFILL
			}
		},
		{
			&hf_wassp_mu_action_ssid,
			{
				"Action & SSID/Vlan ID", "wassp.data.mu_action_ssid",  FT_UINT16, BASE_DEC,  NULL,
				0x0, "Action and where device is currently registered", HFILL
			}
		},
		{
			&hf_wassp_mu_action,
			{
				"Action", "wassp.data.mu_action",  FT_UINT16, BASE_HEX, VALS(mu_action_field_strings),
				0xf000, "Notify what kind of action", HFILL
			}
		},

		{
			&hf_wassp_mu_action_field_value,
			{
				"SSID/Vlan ID", "wassp.data.mu_action_field_value",  FT_UINT16, BASE_DEC,  NULL,
				0x0fff, "SSID value or VlanID value", HFILL
			}
		},
		{
			&hf_wassp_mu_resv0,
			{
				"Reserved0", "wassp.data.mu_resv0", FT_UINT16, BASE_HEX, VALS(mu_resv0_strings),
				0x0, "MU data Reserved0 or Flag", HFILL
			}
		},
		{
			&hf_wassp_mu_resv1,
			{
				"Reserved1", "wassp.data.mu_resv1", FT_UINT16, BASE_DEC, NULL,
				0x0, "MU data Reserved 1", HFILL
			}
		},
		{
			&hf_wassp_mu_assoc_status,
			{
				"Association Status", "wassp.data.mu_assoc_status", FT_UINT8, BASE_CUSTOM,  CF_FUNC(mu_association_status),
				0x0, "MU Association Status", HFILL
			}
		},
		{
			&hf_wassp_mu_mac,
			{
				"MAC address", "wassp.data.mu_mac", FT_ETHER, BASE_NONE, NULL,
				0x0, "Mobile Unit Ethernet address", HFILL
			}
		},
		/*  netflow  */
		{
			&hf_wassp_mu_netflow_tree,
			{
				"WASSP MU Data NetFlow Tree", "wassp.mu.data.netflow.subtree", FT_NONE, BASE_NONE, NULL,
				0x0, NULL, HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_header,
			{
				"Wassp MU Data NetFlow Header", "wassp.mu_data_netflow_header", FT_BYTES, BASE_NONE, NULL,
				0x0, NULL, HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_version,
			{
				"Version", "wassp.data.mu_netflow_version", FT_UINT16, BASE_DEC, NULL,
				0x0, "MU NetFlow Version", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_length,
			{
				"Length", "wassp.data.mu_netflow_length", FT_UINT16, BASE_DEC, NULL,
				0x0, "MU NetFlow Length", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_flags,
			{
				"Flag", "wassp.data.mu_netflow_flag", FT_UINT16, BASE_HEX, NULL,
				0x0, "MU NetFlow Flag", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_uptime,
			{
				"UpTime", "wassp.data.mu_netflow_uptime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL,
				0x0, "MU NetFlow Up Time", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_record,
			{
				"Record", "wassp.data.mu_netflow_record", FT_BYTES, BASE_NONE, NULL,
				0x0, "MU NetFlow Record", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_in_bytes,
			{
				"InBytes", "wassp.data.mu_netflow_inbytes", FT_UINT32, BASE_DEC, NULL,
				0x0, "MU NetFlow In Bytes", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_in_packets,
			{
				"InPackets", "wassp.data.mu_netflow_inpackets", FT_UINT32, BASE_DEC, NULL,
				0x0, "MU NetFlow In Packets", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_ip_protocol_number,
			{
				"Protocol", "wassp.data.mu_netflow_protocol", FT_UINT8, BASE_DEC, NULL,
				0x0, "MU NetFlow IP Protocol", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_source_tos,
			{
				"Source TOS", "wassp.data.mu_netflow_tos", FT_UINT8, BASE_HEX, NULL,
				0x0, "MU NetFlow Source TOS", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_source_port,
			{
				"Source Port", "wassp.data.mu_netflow_source_port", FT_INT16, BASE_DEC, NULL,
				0x0, "MU NetFlow Source Port", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_source_ip,
			{
				"IP", "wassp.data.mu_netflow_source_ip", FT_IPv4, BASE_NONE, NULL,
				0x0, "MU NetFlow Source IP", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_input_snmp,
			{
				"In SNMP", "wassp.data.mu_netflow_in_snmp", FT_UINT16, BASE_DEC, NULL,
				0x0, "MU NetFlow In Snmp", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_dest_port,
			{
				"Dest Port", "wassp.data.mu_netflow_dest_port", FT_INT16, BASE_DEC, NULL,
				0x0, "MU NetFlow Dest Port", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_dest_ip,
			{
				"Dest IP", "wassp.data.mu_netflow_dest_ip", FT_IPv4, BASE_NONE, NULL,
				0x0, "MU NetFlow Dest IP", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_output_snmp,
			{
				"Out SNMP", "wassp.data.mu_netflow_out_snmp", FT_UINT16, BASE_DEC, NULL,
				0x0, "MU NetFlow Out Snmp", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_last_time,
			{
				"Last Time", "wassp.data.mu_netflow_last_time", FT_UINT32, BASE_DEC, NULL,
				0x0, "MU NetFlow Last Time", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_first_time,
			{
				"First Time", "wassp.data.mu_netflow_first_time", FT_UINT32, BASE_DEC, NULL,
				0x0, "MU NetFlow First Time", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_in_source_mac,
			{
				"Source Mac", "wassp.data.mu_netflow_source_mac", FT_ETHER, BASE_NONE, NULL,
				0x0, "MU NetFlow Source MAC Address", HFILL
			}
		},
		{
			&hf_wassp_mu_netflow_in_dest_mac,
			{
				"Dest Mac", "wassp.data.mu_netflow_dest_mac", FT_ETHER, BASE_NONE, NULL,
				0x0, "MU NetFlow Dest MAC Address", HFILL
			}
		},
		/* wassp TLV   */
		{
			&hf_wassp_tlv_value,
			{
				"Wassp TLV", "wassp.tlv.value", FT_NONE, BASE_NONE, NULL,
				0x0, "Wassp TLV in hexadecimal", HFILL
			}
		},
		{
			&hf_wassp_tlv_type_main,
			{
				"Type", "wassp.tlv.type", FT_UINT16, BASE_DEC, VALS(wassp_tlv_types),
				0x0, "Wassp TLV type", HFILL
			}
		},
		{
			&hf_wassp_tlv_type_sub,
			{
				"Type", "wassp.tlv.type", FT_NONE, BASE_NONE, NULL,
				0x0, "Wassp TLV type", HFILL
			}
		},
		{
			&hf_wassp_tlv_length,
			{
				"Length", "wassp.tlv.length", FT_UINT16, BASE_DEC, NULL,
				0x0, "Wassp TLV length", HFILL
			}
		},
		{
			&hf_wassp_tlv_value_octext,
			{
				"value", "wassp.tlv.value_octext", FT_BYTES, BASE_NONE, NULL,
				0x0, "Wassp TLV Value in hexadecimal", HFILL
			}
		},
		{
			&hf_wassp_tlv_value_string,
			{
				"Value", "wassp.tlv.valuestr", FT_STRING, BASE_NONE, NULL,
				0x0, "Wassp TLV Value in string format", HFILL
			}
		},
		{
			&hf_wassp_tlv_value_ip,
			{
				"Value", "wassp.tlv.valueip", FT_IPv4, BASE_NONE, NULL,
				0x0, "Wassp TLV Value in IP format", HFILL
			}
		},
		{
			&hf_wassp_tlv_value_int,
			{
				"Value", "wassp.tlv.valueint", FT_UINT8, BASE_DEC, NULL,
				0x0, "Wassp TLV Value in an integer", HFILL
			}
		},
		{
			&hf_wassp_tlv_eid_status,
			{
				"Status", "wassp.tlv.eid.status", FT_UINT32, BASE_DEC, VALS(wassp_eid_status_types),
				0x0, "Explicit indication of request's status", HFILL
			}
		},
		{
			&hf_wassp_tlv_eid_action,
			{
				"action", "wassp.tlv.eid.action", FT_UINT32, BASE_DEC, VALS(wassp_eid_action_types),
				0x0, "upgrade action request", HFILL
			}
		},
		{
			&hf_wassp_tlv_eid_rustate,
			{
				"RU State", "wassp.tlv.eid.rustate", FT_BOOLEAN, BASE_NONE, TFS(&wassp_eid_rustate_types),
				0x0, "Remote Unit State", HFILL
			}
		},
		{
			&hf_wassp_ipaddress,
			{
				"IPv4 address", "wassp.ipaddress", FT_IPv4, BASE_NONE, NULL,
				0x0, "IPv4 IP address", HFILL
			}
		},
		/*  fragmentation */
		{
			&hf_wassp_fragment_overlap,
			{
				"Fragment overlap",    "wassp.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL,
				0x0, "Fragment overlaps with other fragments", HFILL
			}
		},
		{
			&hf_wassp_fragment_overlap_conflict,
			{
				"Conflicting data in fragment overlap",    "wassp.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL,
				0x0, "Overlapping fragments contained conflicting data", HFILL
			}
		},
		{
			&hf_wassp_fragment_multiple_tails,
			{
				"Multiple tail fragments found",    "wassp.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL,
				0x0, "Several tails were found when defragmenting the packet", HFILL
			}
		},
		{
			&hf_wassp_fragment_too_long_fragment,
			{
				"Fragment too long",    "wassp.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"Fragment contained data past end of packet", HFILL
			}
		},
		{
			&hf_wassp_fragment_error,
			{
				"Defragmentation error", "wassp.fragment.error", FT_FRAMENUM, BASE_NONE, NULL,
				0x0, "Defragmentation error due to illegal fragments", HFILL
			}
		},
		{
			&hf_wassp_fragment,
			{
				"WASSP Fragment", "wassp.fragment", FT_FRAMENUM, BASE_NONE, NULL,
				0x0, "wassp Fragmented", HFILL
			}
		},
		{
			&hf_wassp_fragments,
			{
				"WASSP Fragments", "wassp.fragments", FT_NONE, BASE_NONE, NULL,
				0x0, "wassp more Fragments", HFILL
			}
		},
		{
			&hf_wassp_fragment_count,
			{
				"WASSP Fragment count", "wassp.fragment.count", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL
			}
		},
		{
			&hf_wassp_reassembled_in,
			{
				"Reassembled WASSP in frame", "wassp.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL,
				0x0, "This WASSP frame is reassembled in this frame", HFILL
			}
		},
		{
			&hf_wassp_reassembled_length,
			{
				"Reassembled WASSP length", "wassp.reassembled.length", FT_UINT32, BASE_DEC, NULL,
				0x0, "The total length of the reassembled payload", HFILL
			}
		},
		{
			&hf_wassp_sub_tree,
			{
				"WASSP Sub TLV Block", "wassp.subtree", FT_NONE, BASE_NONE, NULL,
				0x0, "WASSP sub tree", HFILL
			}
		},
		{
			&hf_wassp_tlv_unknown,
			{
				"WASSP unknown tlv", "wassp.tlv.unknown", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL
			}
		},
		{
			&hf_wassp_tlv_invalid,
			{
				"WASSP invalid tlv", "wassp.tlv.invalid", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL
			}
		},
		{
			&hf_wassp_topologykey,
			{
				"Topology Key", "wassp.topology_key", FT_UINT16, BASE_DEC, NULL,
				0x0, "Topology ID", HFILL
			}
		},
		{
			&hf_wassp_vlanid,
			{
				"Vlan ID", "wassp.vlan_id", FT_UINT16, BASE_DEC, NULL,
				0x0, "Vlan Number", HFILL
			}
		},
		{
			&hf_wassp_topology_mode,
			{
				"Topology Mode", "wassp.topology_mode", FT_UINT16,BASE_CUSTOM,  CF_FUNC(topology_moder_print),
				0x0, "Wassp Topology Mode", HFILL
			}
		},
		{
			&hf_wassp_in_cir,
			{
				"Committed Information Rate(In direction)", "wassp.in_cir", FT_UINT16, BASE_DEC, NULL,
				0x0, "Committed Information Rate", HFILL
			}
		},
		{
			&hf_wassp_out_cir,
			{
				"Committed Information Rate(out direction)", "wassp.out_cir", FT_UINT16, BASE_DEC, NULL,
				0x0, "Committed Information Rate", HFILL
			}
		},
		{
			&hf_wassp_flag_1b,
			{
				"Flag (1 byte)", "wassp.flag.1b", FT_UINT8, BASE_HEX, NULL,
				0x0, NULL, HFILL
			}
		},
		{
			&hf_wassp_tos,
			{
				"Type of Service", "wassp.tos", FT_UINT8, BASE_HEX, NULL,
				0x0, "Tos", HFILL
			}
		},
		{
			&hf_cos_tos,
			{
				"COS Tos", "wassp.cos_tos", FT_UINT8, BASE_HEX, NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_wassp_tos_mask,
			{
				"Type of Service Mask", "wassp.tos.mask", FT_UINT8, BASE_HEX, NULL,
				0x0, "ToS Mask", HFILL
			}
		},
		{
			&hf_cos_tos_mask,
			{
				"Class of Service ToS Mask", "wassp.cos_tos.mask", FT_UINT8, BASE_HEX, NULL,
				0x0, "Cos Tos Mask", HFILL
			}
		},
		{
			&hf_filter_tos_maskbit_priority,
			{
				"Mask bit and Priority", "wassp.mask_bit", FT_UINT8,  BASE_CUSTOM,  CF_FUNC(maskbit_priority_print),
				0xff, NULL, HFILL
			}
		},
		{
			&hf_wassp_priority,
			{
				"Priority bit", "wassp.priority", FT_BOOLEAN, 8, NULL,
				0xff, NULL, HFILL
			}
		},
		{
			&hf_cos_priority_txq,
			{
				"COS Priority and TxQ", "wassp.cos_priority_txq", FT_UINT8,  BASE_CUSTOM,  CF_FUNC(cos_priority_txq_print),
				0x0, "Cos Priority and Transmit Queue", HFILL
			}
		},
		{
			&hf_cos_rateid,
			{
				"COS In&Out Rate Id", "wassp.rate_id", FT_UINT8,  BASE_CUSTOM,  CF_FUNC(cos_rate_id_print),
				0x0, NULL, HFILL
			}
		},
		{
			&hf_wassp_filter_rule,
			{
				"WASSP Filter Rule", "wassp.filter.rule", FT_BYTES, BASE_NONE, NULL,
				0x0, NULL, HFILL
			}
		},
		{
			&hf_wassp_filter_flag,
			{
				"WASSP Filter Flag", "wassp.filter.flag", FT_UINT32, BASE_HEX, NULL,
				0x0, NULL, HFILL
			}
		},
		{
			&hf_filter_rule_port_range,
			{
				"TCP/UDP Port range", "wassp.port", FT_UINT32, BASE_CUSTOM,  CF_FUNC(port_range_print),
				0x0, "WASSP TCP/UDP Port", HFILL
			}
		},
		{
			&hf_wassp_ipprotocol,
			{
				"IP Protocol", "wassp.ip_protocol", FT_UINT8, BASE_DEC, NULL,
				0x0, "WASSP IP Protocol", HFILL
			}
		},
		{
			&hf_wassp_netmasklength,
			{
				"Netmask Length Bit", "wassp.netmask_length", FT_UINT8, BASE_DEC, NULL,
				0x0, "WASSP Netmask Length Bit", HFILL
			}
		},
		{
			&hf_wassp_macaddr,
			{
				"MAC address", "wassp.mac_address", FT_ETHER, BASE_NONE, NULL,
				0x0, "WASSP MAC address", HFILL
			}
		},
		{
			&hf_wassp_macaddr_mask,
			{
				"MAC address mask", "wassp.mac_address.mask", FT_ETHER, BASE_NONE, NULL,
				0x0, NULL, HFILL
			}
		},
		{
			&hf_wassp_ethernet_type,
			{
				"Ethernet Type", "wassp.ethernet_type", FT_UINT16, BASE_HEX, NULL,
				0x0, "Ethernet Type Field", HFILL
			}
		},
		{
			&hf_wassp_reserve,
			{
				"Reserve", "wassp.reserve", FT_UINT16, BASE_DEC, NULL,
				0x0, "Reserve value", HFILL
			}
		},
		{
			&hf_wassp_freq,
			{
				"Freq in MHz", "wassp.freq", FT_UINT16, BASE_DEC, NULL,
				0x0, "WASSP Freq", HFILL
			}
		},
		{
			&hf_wassp_rss,
			{
				"RSS", "wassp.rss", FT_UINT16, BASE_DEC, NULL,
				0x0, "WASSP RSS", HFILL
			}
		},
		{
			&hf_wassp_rssi,
			{
				"RSSI", "wassp.rssi", FT_UINT16, BASE_DEC, NULL,
				0x0, "WASSP RSSI", HFILL
			}
		},
		{
			&hf_wassp_threatstate,
			{
				"WASSP Threat State", "wassp.threat_state", FT_UINT8, BASE_HEX, VALS(threat_state_strings),
				0x0, "WASSP Threat State (NA/Active/Inactive)", HFILL
			}
		},
		{
			&hf_wassp_radioparams,
			{
				"Radio Params QOS", "wassp.radio_params", FT_UINT8, BASE_HEX, VALS(radio_params_strings),
				0x0, "WASSP Radio Params QOS", HFILL
			}
		},
		{
			&hf_wassp_channelfreq,
			{
				"Channel Frequency", "wassp.channel_freq", FT_UINT16, BASE_DEC, NULL,
				0x0, "WASSP Channel Frequency", HFILL
			}
		},
		{
			&hf_wassp_mu,
			{
				"Total Mu", "wassp.mu", FT_UINT32, BASE_DEC, NULL,
				0x0, "WASSP Total Mu", HFILL
			}
		},
		{
			&hf_wassp_apprules,
			{
				"Number of Application Rules", "wassp.num_apprules", FT_UINT16, BASE_DEC, NULL,
				0x0, "WASSP number of app rules", HFILL
			}
		},
		{
			&hf_wassp_displayid,
			{
				"Display ID", "wassp.display_id", FT_UINT16, BASE_DEC, NULL,
				0x0, "WASSP display ID", HFILL
			}
		},
		{
			&hf_wassp_txbytes,
			{
				"Tx Bytes", "wassp.tx_bytes", FT_UINT32, BASE_DEC, NULL,
				0x0, "WASSP Tx Bytes", HFILL
			}
		},
		{
			&hf_wassp_rxbytes,
			{
				"Rx Bytes", "wassp.rx_bytes", FT_UINT32, BASE_DEC, NULL,
				0x0, "WASSP Rx Bytes", HFILL
			}
		},
	};

	static int * ett[] =
	{
		&ett_wassp,
		&ett_wassp_tlv,
		&ett_wassp_filter_rule,
		&ett_lbs_header,
		&ett_wassp_mu_appl_stats,
		&ett_wassp_header,
		&ett_ru_discover_header,
		&ett_mu_data_header,
		&ett_mu_action_field,
		&ett_wassp_data,
		&ett_wassp_mu_data_netflow,
		&ett_wassp_mu_data_netflow_header,
		&ett_seq_flags,
		&ett_wassp_tlv_missing,
		&ett_wassp_ap_stats_block,
		&ett_wassp_mu_rf_stats_block,
		&ett_wassp_config_error_block,
		&ett_wassp_config_modified_block,
		&ett_wassp_global_config_block,
		&ett_wassp_radio_config_block,
		&ett_wassp_vns_config_block,
		&ett_wassp_mu_stats_block,
		&ett_wassp_radio_stats_block,
		&ett_wassp_ether_stats_block,
		&ett_wassp_wds_stats_block,
		&ett_wassp_dot1x_stats_block,
		&ett_wassp_fragment,
		&ett_wassp_fragments,
		&ett_wassp_filter_config_block,
		&ett_wassp_filter_ext_config_block,
		&ett_wassp_site_filter_config_block,
		&ett_wassp_vns_stats_block,
		&ett_wassp_radius_server_config_block,
		&ett_wassp_site_config_block,
		&ett_wassp_policy_config_block,
		&ett_wassp_cos_config_block,
		&ett_wassp_localbase_lookup_block,
		&ett_wassp_radius_config_block,
		&ett_wassp_eid_main_tlv_block,
		&ett_wassp_app_policy_fixed_block,
		&ett_wassp_app_policy_entry_block,
		&ett_wassp_s_topo_m_filter_entry_block,
		&ett_wassp_s_topo_m_filter_ext_entry_block,
		&ett_wassp_11u_config_entry_block,
		&ett_wassp_hs2_config_entry_block,
		&ett_wassp_extapp_config_entry_block,

	};


	/* Register wassp protocol */
	proto_wassp = proto_register_protocol("Wireless Access Station Session Protocol", "WASSP", "wassp");
	/* Register wassp protocol fields */
	proto_register_field_array(proto_wassp, hf, array_length(hf));
	/* Register dissector handle */
	wassp_handle = register_dissector("wassp", dissect_wassp_static, proto_wassp);
	/* Register wassp protocol sub-trees */
	proto_register_subtree_array(ett, array_length(ett));
	wassp_dissector_table = register_dissector_table("wassp.subd", "WASSP subdissectors", proto_wassp, FT_UINT16, BASE_DEC);
	register_init_routine(&wassp_defragment_init);
}


static bool
test_wassp(tvbuff_t *tvb)
{
	/* Minimum of 8 bytes, first byte (version) has value of 3 */
	if (tvb_captured_length(tvb) < 8
			|| tvb_get_uint8(tvb, 0) != 3
			/* || tvb_get_uint8(tvb, 2) != 0
			|| tvb_get_ntohs(tvb, 6) > tvb_reported_length(tvb) */
	   )
	{
		return false;
	}
	return true;
}



static bool
dissect_wassp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if (!test_wassp(tvb))
	{
		return false;
	}
	dissect_wassp(tvb, pinfo, tree);
	return true;
}

static int
dissect_wassp_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if (!test_wassp(tvb))
	{
		return 0;
	}
	return dissect_wassp(tvb, pinfo, tree);
}


/* The registration hand-off routing for WASSP */

void
proto_reg_handoff_wassp(void)
{
	dissector_add_uint_range_with_preference("udp.port", PORT_WASSP_RANGE, wassp_handle);
	heur_dissector_add("udp", dissect_wassp_heur, "WASSP over UDP", "wassp_udp", proto_wassp, HEURISTIC_DISABLE);

	snmp_handle = find_dissector_add_dependency("snmp", proto_wassp);
	ieee80211_handle = find_dissector_add_dependency("wlan_withoutfcs", proto_wassp);
	eth_handle = find_dissector("eth_withoutfcs");
	data_handle = find_dissector("data");
	ip_handle = find_dissector("ip");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
