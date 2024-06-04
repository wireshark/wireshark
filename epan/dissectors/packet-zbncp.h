
/* packet-zbncp.h
 * Dissector routines for the ZBOSS Network Co-Processor (NCP)
 * Copyright 2021 DSR Corporation, http://dsr-wireless.com/
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_ZBNCP_H
#define _PACKET_ZBNCP_H

#define ZBNCP_HIGH_LVL_PACKET_TYPE_REQUEST    0x00
#define ZBNCP_HIGH_LVL_PACKET_TYPE_RESPONSE   0x01
#define ZBNCP_HIGH_LVL_PACKET_TYPE_INDICATION 0x02

#define ZBNCP_HIGH_LVL_STAT_CAT_GENERIC 0x00
#define ZBNCP_HIGH_LVL_STAT_CAT_SYSTEM  0x01
#define ZBNCP_HIGH_LVL_STAT_CAT_MAC     0x02
#define ZBNCP_HIGH_LVL_STAT_CAT_NWK     0x03
#define ZBNCP_HIGH_LVL_STAT_CAT_APS     0x04
#define ZBNCP_HIGH_LVL_STAT_CAT_ZDO     0x05
#define ZBNCP_HIGH_LVL_STAT_CAT_CBKE    0x06

#define ZBNCP_CMD_GET_MODULE_VERSION            0x0001
#define ZBNCP_CMD_NCP_RESET                     0x0002
#define ZBNCP_CMD_NCP_FACTORY_RESET             0x0003
#define ZBNCP_CMD_GET_ZIGBEE_ROLE               0x0004
#define ZBNCP_CMD_SET_ZIGBEE_ROLE               0x0005
#define ZBNCP_CMD_GET_ZIGBEE_CHANNEL_MASK       0x0006
#define ZBNCP_CMD_SET_ZIGBEE_CHANNEL_MASK       0x0007
#define ZBNCP_CMD_GET_ZIGBEE_CHANNEL            0x0008
#define ZBNCP_CMD_GET_PAN_ID                    0x0009
#define ZBNCP_CMD_SET_PAN_ID                    0x000A
#define ZBNCP_CMD_GET_LOCAL_IEEE_ADDR           0x000B
#define ZBNCP_CMD_SET_LOCAL_IEEE_ADDR           0x000C
#define ZBNCP_CMD_SET_TRACE                     0x000D
#define ZBNCP_CMD_GET_KEEPALIVE_TIMEOUT         0x000E
#define ZBNCP_CMD_SET_KEEPALIVE_TIMEOUT         0x000F
#define ZBNCP_CMD_GET_TX_POWER                  0x0010
#define ZBNCP_CMD_SET_TX_POWER                  0x0011
#define ZBNCP_CMD_GET_RX_ON_WHEN_IDLE           0x0012
#define ZBNCP_CMD_SET_RX_ON_WHEN_IDLE           0x0013
#define ZBNCP_CMD_GET_JOINED                    0x0014
#define ZBNCP_CMD_GET_AUTHENTICATED             0x0015
#define ZBNCP_CMD_GET_ED_TIMEOUT                0x0016
#define ZBNCP_CMD_SET_ED_TIMEOUT                0x0017
#define ZBNCP_CMD_ADD_VISIBLE_DEV               0x0018
#define ZBNCP_CMD_ADD_INVISIBLE_SHORT           0x0019
#define ZBNCP_CMD_RM_INVISIBLE_SHORT            0x001A
#define ZBNCP_CMD_SET_NWK_KEY                   0x001B
#define ZBNCP_CMD_GET_SERIAL_NUMBER             0x001C
#define ZBNCP_CMD_GET_VENDOR_DATA               0x001D
#define ZBNCP_CMD_GET_NWK_KEYS                  0x001E
#define ZBNCP_CMD_GET_APS_KEY_BY_IEEE           0x001F
#define ZBNCP_CMD_BIG_PKT_TO_NCP                0x0020
#define ZBNCP_CMD_GET_PARENT_ADDR               0x0022
#define ZBNCP_CMD_GET_EXT_PAN_ID                0x0023
#define ZBNCP_CMD_GET_COORDINATOR_VERSION       0x0024
#define ZBNCP_CMD_GET_SHORT_ADDRESS             0x0025
#define ZBNCP_CMD_GET_TRUST_CENTER_ADDRESS      0x0026
#define ZBNCP_CMD_DEBUG_WRITE                   0x0027
#define ZBNCP_CMD_GET_CONFIG_PARAMETER          0x0028
#define ZBNCP_CMD_GET_LOCK_STATUS               0x0029
#define ZBNCP_CMD_GET_TRACE                     0x002A
#define ZBNCP_CMD_NCP_RESET_IND                 0x002B
#define ZBNCP_CMD_SET_NWK_LEAVE_ALLOWED         0x002C
#define ZBNCP_CMD_GET_NWK_LEAVE_ALLOWED         0x002D
#define ZBNCP_CMD_NVRAM_WRITE                   0x002E
#define ZBNCP_CMD_NVRAM_READ                    0x002F
#define ZBNCP_CMD_NVRAM_ERASE                   0x0030
#define ZBCNP_CMD_NVRAM_CLEAR                   0x0031
#define ZBNCP_CMD_SET_TC_POLICY                 0x0032
#define ZBNCP_CMD_SET_EXTENDED_PAN_ID           0x0033
#define ZBNCP_CMD_SET_ED_CAPACITY               0x0034
#define ZBNCP_CMD_GET_ED_CAPACITY               0x0035
#define ZBNCP_CMD_SET_ZDO_LEAVE_ALLOWED         0x0036
#define ZBNCP_CMD_GET_ZDO_LEAVE_ALLOWED         0x0037
#define ZBNCP_CMD_SET_LEAVE_WO_REJOIN_ALLOWED   0x0038
#define ZBNCP_CMD_GET_LEAVE_WO_REJOIN_ALLOWED   0x0039
#define ZBNCP_CMD_DISABLE_GPPB                  0x003A
#define ZBNCP_CMD_GP_SET_SHARED_KEY_TYPE        0x003B
#define ZBNCP_CMD_GP_SET_DEFAULT_LINK_KEY       0x003C
#define ZBNCP_CMD_PRODUCTION_CONFIG_READ        0x003D
#define ZBNCP_CMD_SET_MAX_JOINS                 0x003E
#define ZBNCP_CMD_GET_MAX_JOINS                 0x003F
#define ZBNCP_CMD_TRACE_IND                     0x0040
#define ZBNCP_CMD_GET_KEY_NEG_METHOD            0x0041
#define ZBNCP_CMD_SET_KEY_NEG_METHOD            0x0042
#define ZBNCP_CMD_GET_PSK_SECRETS               0x0043
#define ZBNCP_CMD_SET_PSK_SECRETS               0x0044
#define ZBNCP_CMD_SET_R22_JOIN_USAGE            0x0045
#define ZBNCP_CMD_SET_NWK_CONF_PRESET           0x0046
#define ZBNCP_CMD_DEBUG_BROAD_NWK_KEY           0x0047
#define ZBNCP_CMD_DEBUG_BROAD_APS_KEY           0x0048

#define ZBNCP_CMD_AF_SET_SIMPLE_DESC      0x0101
#define ZBNCP_CMD_AF_DEL_EP               0x0102
#define ZBNCP_CMD_AF_SET_NODE_DESC        0x0103
#define ZBNCP_CMD_AF_SET_POWER_DESC       0x0104
#define ZBNCP_CMD_AF_SUBGHZ_SUSPEND_IND   0x0105
#define ZBNCP_CMD_AF_SUBGHZ_RESUME_IND    0x0106

#define ZBNCP_CMD_ZDO_NWK_ADDR_REQ                      0x0201
#define ZBNCP_CMD_ZDO_IEEE_ADDR_REQ                     0x0202
#define ZBNCP_CMD_ZDO_POWER_DESC_REQ                    0x0203
#define ZBNCP_CMD_ZDO_NODE_DESC_REQ                     0x0204
#define ZBNCP_CMD_ZDO_SIMPLE_DESC_REQ                   0x0205
#define ZBNCP_CMD_ZDO_ACTIVE_EP_REQ                     0x0206
#define ZBNCP_CMD_ZDO_MATCH_DESC_REQ                    0x0207
#define ZBNCP_CMD_ZDO_BIND_REQ                          0x0208
#define ZBNCP_CMD_ZDO_UNBIND_REQ                        0x0209
#define ZBNCP_CMD_ZDO_MGMT_LEAVE_REQ                    0x020A
#define ZBNCP_CMD_ZDO_PERMIT_JOINING_REQ                0x020B
#define ZBNCP_CMD_ZDO_DEV_ANNCE_IND                     0x020C
#define ZBNCP_CMD_ZDO_REJOIN                            0x020D
#define ZBNCP_CMD_ZDO_SYSTEM_SRV_DISCOVERY_REQ          0x020E
#define ZBNCP_CMD_ZDO_MGMT_BIND_REQ                     0x020F
#define ZBNCP_CMD_ZDO_MGMT_LQI_REQ                      0x0210
#define ZBNCP_CMD_ZDO_MGMT_NWK_UPDATE_REQ               0x0211
#define ZBNCP_CMD_ZDO_REMOTE_CMD_IND                    0x0212
#define ZBNCP_CMD_ZDO_GET_STATS                         0x0213
#define ZBNCP_CMD_ZDO_DEV_AUTHORIZED_IND                0x0214
#define ZBNCP_CMD_ZDO_DEV_UPDATE_IND                    0x0215
#define ZBNCP_CMD_ZDO_SET_NODE_DESC_MANUF_CODE          0x0216
#define ZBNCP_CMD_HL_ZDO_GET_DIAG_DATA_REQ              0x0217
#define ZBNCP_CMD_HL_ZDO_RAW_REQ                        0x0218
#define ZBNCP_CMD_HL_ZDO_SEND_CONF_PARAMS_REQ           0x0219
#define ZBNCP_CMD_HL_ZDO_MGMT_BEACON_SURVEY_REQ         0x021A
#define ZBNCP_CMD_HL_ZDO_DECOMMISSION_REQ               0x021B
#define ZBNCP_CMD_HL_ZDO_GET_AUTH_LEVEL_REQ             0x021C

#define ZBNCP_CMD_APSDE_DATA_REQ                0x0301
#define ZBNCP_CMD_APSME_BIND                    0x0302
#define ZBNCP_CMD_APSME_UNBIND                  0x0303
#define ZBNCP_CMD_APSME_ADD_GROUP               0x0304
#define ZBNCP_CMD_APSME_RM_GROUP                0x0305
#define ZBNCP_CMD_APSDE_DATA_IND                0x0306
#define ZBNCP_CMD_APSME_RM_ALL_GROUPS           0x0307
#define ZBNCP_CMD_APS_GET_GROUP_TABLE           0x0309
#define ZBNCP_CMD_APSME_UNBIND_ALL              0x030A
#define ZBNCP_CMD_APSME_GET_BIND_ENTRY_BY_ID    0x030B
#define ZBNCP_CMD_APSME_RM_BIND_ENTRY_BY_ID     0x030C
#define ZBNCP_CMD_APSME_CLEAR_BIND_TABLE        0x030D
#define ZBNCP_CMD_APSME_REMOTE_BIND_IND         0x030E
#define ZBNCP_CMD_APSME_REMOTE_UNBIND_IND       0x030F
#define ZBNCP_CMD_APSME_SET_REMOTE_BIND_OFFSET  0x0310
#define ZBNCP_CMD_APSME_GET_REMOTE_BIND_OFFSET  0x0311

#define ZBNCP_CMD_NWK_FORMATION                                   0x0401
#define ZBNCP_CMD_NWK_DISCOVERY                                   0x0402
#define ZBNCP_CMD_NWK_NLME_JOIN                                   0x0403
#define ZBNCP_CMD_NWK_PERMIT_JOINING                              0x0404
#define ZBNCP_CMD_NWK_GET_IEEE_BY_SHORT                           0x0405
#define ZBNCP_CMD_NWK_GET_SHORT_BY_IEEE                           0x0406
#define ZBNCP_CMD_NWK_GET_NEIGHBOR_BY_IEEE                        0x0407
#define ZBNCP_CMD_NWK_STARTED_IND                                 0x0408
#define ZBNCP_CMD_NWK_REJOINED_IND                                0x0409
#define ZBNCP_CMD_NWK_REJOIN_FAILED_IND                           0x040A
#define ZBNCP_CMD_NWK_LEAVE_IND                                   0x040B
#define ZBNCP_CMD_PIM_SET_FAST_POLL_INTERVAL                      0x040E
#define ZBNCP_CMD_PIM_SET_LONG_POLL_INTERVAL                      0x040F
#define ZBNCP_CMD_PIM_START_FAST_POLL                             0x0410
#define ZBNCP_CMD_PIM_START_POLL                                  0x0412
#define ZBNCP_CMD_PIM_SET_ADAPTIVE_POLL                           0x0413
#define ZBNCP_CMD_PIM_STOP_FAST_POLL                              0x0414
#define ZBNCP_CMD_PIM_STOP_POLL                                   0x0415
#define ZBNCP_CMD_PIM_ENABLE_TURBO_POLL                           0x0416
#define ZBNCP_CMD_PIM_DISABLE_TURBO_POLL                          0x0417
#define ZBNCP_CMD_NWK_GET_FIRST_NBT_ENTRY                         0x0418
#define ZBNCP_CMD_NWK_GET_NEXT_NBT_ENTRY                          0x0419
#define ZBNCP_CMD_NWK_PAN_ID_CONFLICT_RESOLVE                     0x041A
#define ZBNCP_CMD_NWK_PAN_ID_CONFLICT_IND                         0x041B
#define ZBNCP_CMD_NWK_ADDRESS_UPDATE_IND                          0x041C
#define ZBNCP_CMD_NWK_START_WITHOUT_FORMATION                     0x041D
#define ZBNCP_CMD_NWK_NLME_ROUTER_START                           0x041E
#define ZBNCP_CMD_PIM_SINGLE_POLL                                 0x041F
#define ZBNCP_CMD_PARENT_LOST_IND                                 0x0420
#define ZBNCP_CMD_PIM_START_TURBO_POLL_PACKETS                    0x0424
#define ZBNCP_CMD_PIM_START_TURBO_POLL_CONTINUOUS                 0x0425
#define ZBNCP_CMD_PIM_TURBO_POLL_CONTINUOUS_LEAVE                 0x0426
#define ZBNCP_CMD_PIM_TURBO_POLL_PACKETS_LEAVE                    0x0427
#define ZBNCP_CMD_PIM_PERMIT_TURBO_POLL                           0x0428
#define ZBNCP_CMD_PIM_SET_FAST_POLL_TIMEOUT                       0x0429
#define ZBNCP_CMD_PIM_GET_LONG_POLL_INTERVAL                      0x042A
#define ZBNCP_CMD_PIM_GET_IN_FAST_POLL_FLAG                       0x042B
#define ZBNCP_CMD_SET_KEEPALIVE_MODE                              0x042C
#define ZBNCP_CMD_START_CONCENTRATOR_MODE                         0x042D
#define ZBNCP_CMD_STOP_CONCENTRATOR_MODE                          0x042E
#define ZBNCP_CMD_NWK_ENABLE_PAN_ID_CONFLICT_RESOLUTION           0x042F
#define ZBNCP_CMD_NWK_ENABLE_AUTO_PAN_ID_CONFLICT_RESOLUTION      0x0430
#define ZBNCP_CMD_PIM_TURBO_POLL_CANCEL_PACKET                    0x0431
#define ZBNCP_CMD_SET_FORCE_ROUTE_RECORD                          0x0432
#define ZBNCP_CMD_GET_FORCE_ROUTE_RECORD                          0x0433
#define ZBNCP_CMD_NWK_NBR_ITERATOR_NEXT                           0x0434

#define ZBNCP_CMD_ZB_DEBUG_SIGNAL_TCLK_READY_IND                  0x0435
#define ZBNCP_CMD_ZB_DEVICE_READY_FOR_INTERVIEW_IND               0x0436
#define ZBNCP_CMD_ZB_DEVICE_INTERVIEW_FINISHED_IND                0x0437
#define ZBNCP_CMD_ZB_PREPARE_NETWORK_FOR_CHANNEL_PAN_ID_CHANGE    0x0438
#define ZBNCP_CMD_ZB_PREPARE_NETWORK_FOR_CHANNEL_CHANGE           0x0439
#define ZBNCP_CMD_ZB_START_CHANNEL_CHANGE                         0x043A
#define ZBNCP_CMD_ZB_START_PAN_ID_CHANGE                          0x043B

#define ZBNCP_CMD_SECUR_SET_LOCAL_IC                              0x0501
#define ZBNCP_CMD_SECUR_ADD_IC                                    0x0502
#define ZBNCP_CMD_SECUR_DEL_IC                                    0x0503
#define ZBNCP_CMD_SECUR_ADD_CERT                                  0x0504
#define ZBNCP_CMD_SECUR_DEL_CERT                                  0x0505
#define ZBNCP_CMD_SECUR_START_KE                                  0x0506
#define ZBNCP_CMD_SECUR_START_PARTNER_LK                          0x0507
#define ZBNCP_CMD_SECUR_CBKE_SRV_FINISHED_IND                     0x0508
#define ZBNCP_CMD_SECUR_PARTNER_LK_FINISHED_IND                   0x0509
#define ZBNCP_CMD_SECUR_JOIN_USES_IC                              0x050A
#define ZBNCP_CMD_SECUR_GET_IC_BY_IEEE                            0x050B
#define ZBNCP_CMD_SECUR_GET_CERT                                  0x050C
#define ZBNCP_CMD_SECUR_GET_LOCAL_IC                              0x050D
#define ZBNCP_CMD_SECUR_TCLK_IND                                  0x050E
#define ZBNCP_CMD_SECUR_TCLK_EXCHANGE_FAILED_IND                  0x050F
#define ZBNCP_CMD_SECUR_KE_WHITELIST_ADD                          0x0510
#define ZBNCP_CMD_SECUR_KE_WHITELIST_DEL                          0x0511
#define ZBNCP_CMD_SECUR_KE_WHITELIST_DEL_ALL                      0x0512
#define ZBNCP_CMD_SECUR_GET_KEY_IDX                               0x0513
#define ZBNCP_CMD_SECUR_GET_KEY                                   0x0514
#define ZBNCP_CMD_SECUR_ERASE_KEY                                 0x0515
#define ZBNCP_CMD_SECUR_CLEAR_KEY_TABLE                           0x0516
#define ZBNCP_CMD_SECUR_NWK_INITIATE_KEY_SWITCH_PROCEDURE         0x0517
#define ZBNCP_CMD_SECUR_GET_IC_LIST                               0x0518
#define ZBNCP_CMD_SECUR_GET_IC_BY_IDX                             0x0519
#define ZBNCP_CMD_SECUR_REMOVE_ALL_IC                             0x051A
#define ZBNCP_CMD_SECUR_PARTNER_LK_ENABLE                         0x051B
#define ZBNCP_CMD_SECUR_AUTH_DEVICE_AFTER_INTERVIEW               0x051C
#define ZBNCP_CMD_ZDO_SECUR_UPDATE_DEVICE_TCLK                    0x051D

#define ZBNCP_CMD_MANUF_MODE_START                0x0601
#define ZBNCP_CMD_MANUF_MODE_END                  0x0602
#define ZBNCP_CMD_MANUF_SET_CHANNEL               0x0603
#define ZBNCP_CMD_MANUF_GET_CHANNEL               0x0604
#define ZBNCP_CMD_MANUF_SET_POWER                 0x0605
#define ZBNCP_CMD_MANUF_GET_POWER                 0x0606
#define ZBNCP_CMD_MANUF_START_TONE                0x0607
#define ZBNCP_CMD_MANUF_STOP_TONE                 0x0608
#define ZBNCP_CMD_MANUF_START_STREAM_RANDOM       0x0609
#define ZBNCP_CMD_MANUF_STOP_STREAM_RANDOM        0x060A
#define ZBNCP_CMD_NCP_HL_MANUF_SEND_SINGLE_PACKET 0x060B
#define ZBNCP_CMD_MANUF_START_TEST_RX             0x060C
#define ZBNCP_CMD_MANUF_STOP_TEST_RX              0x060D
#define ZBNCP_CMD_MANUF_RX_PACKET_IND             0x060E

#define ZBNCP_CMD_OTA_RUN_BOOTLOADER      0x0701
#define ZBNCP_CMD_OTA_START_UPGRADE_IND   0x0702
#define ZBNCP_CMD_OTA_SEND_PORTION_FW     0x0703

#define ZBNCP_CMD_READ_NVRAM_RESERVED     0x0801
#define ZBNCP_CMD_WRITE_NVRAM_RESERVED    0x0802
#define ZBNCP_CMD_GET_CALIBRATION_INFO    0x0803

/* MAC enums */
#define MAC_ENUM_SUCCESS                 0x00
#define MAC_ENUM_BEACON_LOSS             0xe0
#define MAC_ENUM_CHANNEL_ACCESS_FAILURE  0xe1
#define MAC_ENUM_COUNTER_ERROR           0xdb
#define MAC_ENUM_DENIED                  0xe2
#define MAC_ENUM_DISABLE_TRX_FAILURE     0xe3
#define MAC_ENUM_FRAME_TOO_LONG          0xe5
#define MAC_ENUM_IMPROPER_KEY_TYPE       0xdc
#define MAC_ENUM_IMPROPER_SECURITY_LEVEL 0xdd
#define MAC_ENUM_INVALID_ADDRESS         0xf5
#define MAC_ENUM_INVALID_GTS             0xe6
#define MAC_ENUM_INVALID_HANDLE          0xe7
#define MAC_ENUM_INVALID_INDEX           0xf9
#define MAC_ENUM_INVALID_PARAMETER       0xe8
#define MAC_ENUM_LIMIT_REACHED           0xfa
#define MAC_ENUM_NO_ACK                  0xe9
#define MAC_ENUM_NO_BEACON               0xea
#define MAC_ENUM_NO_DATA                 0xeb
#define MAC_ENUM_NO_SHORT_ADDRESS        0xec
#define MAC_ENUM_ON_TIME_TOO_LONG        0xf6
#define MAC_ENUM_OUT_OF_CAP              0xed
#define MAC_ENUM_PAN_ID_CONFLICT         0xee
#define MAC_ENUM_PAST_TIME               0xf7
#define MAC_ENUM_READ_ONLY               0xfb
#define MAC_ENUM_REALIGNMENT             0xef
#define MAC_ENUM_SCAN_IN_PROGRESS        0xfc
#define MAC_ENUM_SECURITY_ERROR          0xe4
#define MAC_ENUM_SUPERFRAME_OVERLAP      0xfd
#define MAC_ENUM_TRACKING_OFF            0xf8
#define MAC_ENUM_TRANSACTION_EXPIRED     0xf0
#define MAC_ENUM_TRANSACTION_OVERFLOW    0xf1
#define MAC_ENUM_TX_ACTIVE               0xf2
#define MAC_ENUM_UNAVAILABLE_KEY         0xf3
#define MAC_ENUM_UNSUPPORTED_LEGACY      0xde
#define MAC_ENUM_UNSUPPORTED_SECURITY    0xdf

/* NVRAM database types enum */
#define ZB_NVRAM_RESERVED                0      /**< Reserved value */
#define ZB_NVRAM_COMMON_DATA             1      /**< Dataset, contains common Zigbee data */
#define ZB_NVRAM_HA_DATA                 2      /**< Dataset, contains HA profile Zigbee data */
#define ZB_NVRAM_ZCL_REPORTING_DATA      3      /**< Dataset, contains ZCL reporting data */
#define ZB_NVRAM_APS_SECURE_DATA_GAP     4      /**< Reserved value */
#define ZB_NVRAM_APS_BINDING_DATA_GAP    5      /**< Reserved value */
#define ZB_NVRAM_HA_POLL_CONTROL_DATA    6      /**< Dataset, contains HA POLL CONTROL data */
#define ZB_IB_COUNTERS                   7      /**< Dataset, contains NIB outgoing frame counter */
#define ZB_NVRAM_DATASET_GRPW_DATA       8      /**< Green Power dataset */
#define ZB_NVRAM_APP_DATA1               9      /**< Application-specific data #1 */
#define ZB_NVRAM_APP_DATA2               10     /**< Application-specific data #2 */
#define ZB_NVRAM_ADDR_MAP                11     /**< Dataset stores address map info */
#define ZB_NVRAM_NEIGHBOUR_TBL           12     /**< Dataset stores Neighbor table info */
#define ZB_NVRAM_INSTALLCODES            13     /**< Dataset contains APS installcodes data */
#define ZB_NVRAM_APS_SECURE_DATA         14     /**< Dataset, contains APS secure keys data */
#define ZB_NVRAM_APS_BINDING_DATA        15     /**< Dataset, contains APS binding data */
#define ZB_NVRAM_DATASET_GP_PRPOXYT      16     /**< Green Power Proxy table */
#define ZB_NVRAM_DATASET_GP_SINKT        17     /**< Green Power Sink table */
#define ZB_NVRAM_DATASET_GP_CLUSTER      18     /**< Green Power Cluster data */
#define ZB_NVRAM_APS_GROUPS_DATA         19     /**< Dataset, contains APS groups data */
#define ZB_NVRAM_DATASET_SE_CERTDB       20     /**< Smart Energy Dataset - Certificates DataBase */
#define ZB_NVRAM_DATASET_GP_APP_TBL      22     /**< Dataset, contains ZCL WWAH data */
#define ZB_NVRAM_APP_DATA3               27     /**< Application-specific data #3 */
#define ZB_NVRAM_APP_DATA4               28     /**< Application-specific data #4 */
#define ZB_NVRAM_KE_WHITELIST            29
#define ZB_NVRAM_ZDO_DIAGNOSTICS_DATA    31     /**< Dataset of the Diagnostics cluster */
#define ZB_NVRAM_DATASET_NUMBER          32     /**< Count of Dataset */
#define ZB_NVRAM_DATA_SET_TYPE_PAGE_HDR  30     /**< Special internal dataset type  */


/* NWK statuses */
#define ZBNCP_NWK_STATUS_SUCCESS                0x00
#define ZBNCP_NWK_STATUS_INVALID_PARAMETER      0xc1
#define ZBNCP_NWK_STATUS_INVALID_REQUEST        0xc2
#define ZBNCP_NWK_STATUS_NOT_PERMITTED          0xc3
#define ZBNCP_NWK_STATUS_ALREADY_PRESENT        0xc5
#define ZBNCP_NWK_STATUS_SYNC_FAILURE           0xc6
#define ZBNCP_NWK_STATUS_NEIGHBOR_TABLE_FULL    0xc7
#define ZBNCP_NWK_STATUS_UNKNOWN_DEVICE         0xc8
#define ZBNCP_NWK_STATUS_UNSUPPORTED_ATTRIBUTE  0xc9
#define ZBNCP_NWK_STATUS_NO_NETWORKS            0xca
#define ZBNCP_NWK_STATUS_MAX_FRM_COUNTER        0xcc
#define ZBNCP_NWK_STATUS_NO_KEY                 0xcd
#define ZBNCP_NWK_STATUS_ROUTE_DISCOVERY_FAILED 0xd0
#define ZBNCP_NWK_STATUS_ROUTE_ERROR            0xd1
#define ZBNCP_NWK_STATUS_BT_TABLE_FULL          0xd2
#define ZBNCP_NWK_STATUS_FRAME_NOT_BUFFERED     0xd3
#define ZBNCP_NWK_STATUS_INVALID_INTERFACE      0xd5

/* CBKE statuses */
#define ZBNCP_CBKE_STATUS_OK                    0x00
#define ZBNCP_CBKE_STATUS_UNKNOWN_ISSUER        0x01
#define ZBNCP_CBKE_STATUS_BAD_KEY_CONFIRM       0x02
#define ZBNCP_CBKE_STATUS_BAD_MESSAGE           0x03
#define ZBNCP_CBKE_STATUS_NO_RESOURCES          0x04
#define ZBNCP_CBKE_STATUS_UNSUPPORTED_SUITE     0x05
#define ZBNCP_CBKE_STATUS_INVALID_CERTIFICATE   0x06
#define ZBNCP_CBKE_STATUS_NO_KE_EP              0x07

/* ZB NCP LL HDR PACKET FLAGS BITS */
#define ZBNCP_GET_PACKET_FLAGS_ACK_BIT(x)         ((x) & 0x1)
#define ZBNCP_GET_PACKET_FLAGS_RETRANS_BIT(x)     (((x) >> 1) & 0x1)
#define ZBNCP_GET_PACKET_FLAGS_SECNUM_BIT(x)      (((x) >> 2) & 0x3)
#define ZBNCP_GET_PACKET_FLAGS_ACKNUM_BIT(x)      (((x) >> 4) & 0x3)
#define ZBNCP_GET_PACKET_FLAGS_FIRST_FRAG_BIT(x)  (((x) >> 6) & 0x1)
#define ZBNCP_GET_PACKET_FLAGS_LAST_FRAG_BIT(x)   (((x) >> 7) & 0x1)

/* Parameter ID enum */
#define ZBNCP_PARAMETER_ID_IEEE_ADDR_TABLE_SIZE            1
#define ZBNCP_PARAMETER_ID_NEIGHBOR_TABLE_SIZE             2
#define ZBNCP_PARAMETER_ID_APS_SRC_BINDING_TABLE_SIZE      3
#define ZBNCP_PARAMETER_ID_APS_GROUP_TABLE_SIZE            4
#define ZBNCP_PARAMETER_ID_NWK_ROUTING_TABLE_SIZE          5
#define ZBNCP_PARAMETER_ID_NWK_ROUTE_DISCOVERY_TABLE_SIZE  6
#define ZBNCP_PARAMETER_ID_IOBUF_POOL_SIZE                 7
#define ZBNCP_PARAMETER_ID_PANID_TABLE_SIZE                8
#define ZBNCP_PARAMETER_ID_APS_DUPS_TABLE_SIZE             9
#define ZBNCP_PARAMETER_ID_APS_BIND_TRANS_TABLE_SIZE       10
#define ZBNCP_PARAMETER_ID_N_APS_RETRANS_ENTRIES           11
#define ZBNCP_PARAMETER_ID_NWK_MAX_HOPS                    12
#define ZBNCP_PARAMETER_ID_NIB_MAX_CHILDREN                13
#define ZBNCP_PARAMETER_ID_N_APS_KEY_PAIR_ARR_MAX_SIZE     14
#define ZBNCP_PARAMETER_ID_NWK_MAX_SRC_ROUTES              15
#define ZBNCP_PARAMETER_ID_APS_MAX_WINDOW_SIZE             16
#define ZBNCP_PARAMETER_ID_APS_INTERFRAME_DELAY            17
#define ZBNCP_PARAMETER_ID_ZDO_ED_BIND_TIMEOUT             18
#define ZBNCP_PARAMETER_ID_NIB_PASSIVE_ASK_TIMEOUT         19
#define ZBNCP_PARAMETER_ID_APS_ACK_TIMEOUTS                20
#define ZBNCP_PARAMETER_ID_MAC_BEACON_JITTER               21
#define ZBNCP_PARAMETER_ID_TX_POWER                        22
#define ZBNCP_PARAMETER_ID_ZLL_DEFAULT_RSSI_THRESHOLD      23
#define ZBNCP_PARAMETER_ID_NIB_MTORR                       24

#define ZB_APSDE_DST_ADDR_MODE_DST_ADDR_ENDP_NOT_PRESENT  0x00 /*!< DstAddress and DstEndpoint not present  */
#define ZB_APSDE_DST_ADDR_MODE_16_GROUP_ENDP_NOT_PRESENT  0x01 /*!< 16-bit group address for DstAddress; DstEndpoint not present */
#define ZB_APSDE_DST_ADDR_MODE_16_ENDP_PRESENT            0x02 /*!< 16-bit address for DstAddress and DstEndpoint present */
#define ZB_APSDE_DST_ADDR_MODE_64_ENDP_PRESENT            0x03 /*!< 64-bit extended address for DstAddress and DstEndpoint present  */
#define ZB_APSDE_DST_ADDR_MODE_BIND_TBL_ID                0x04 /*!< According to the dst binding table */

/* ZDO Auth types */
#define ZB_ZDO_AUTH_LEGACY_TYPE                           0x00
#define ZB_ZDO_AUTH_TCLK_TYPE                             0x01

#define ZBNCP_CMD_APSDE_DATA_REQ_DST_ADDR_MODE_OFFSET ( \
    8    /* union - short or long addr */               \
    + 2  /* profile id */                               \
    + 2  /* cluster id */                               \
    + 1  /* dst ep */                                   \
    + 1  /* src ep */                                   \
    + 1) /* radius */

#define ZBNCP_CMD_APSDE_DATA_REQ_RSP_DST_ADDR_MODE_OFFSET ( \
8    /* union - short or long addr */                   \
+ 1  /* dst ep */                                       \
+ 1  /* src ep */                                       \
+ 4) /* tx time */

#endif
