/* packet-acn.c
 * Routines for ACN packet disassembly
 *
 * Copyright (c) 2003 by Erwin Rol <erwin@erwinrol.com>
 * Copyright (c) 2006 by Electronic Theatre Controls, Inc.
 *                    Bill Florac <bflorac@etcconnect.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*
    Todo:
      Add reading of DDL files so we can futher explode DMP packets
      For some of the Set/Get properties where we have a range of data
      it would be better to show the block of data rather and
      address-data pair on each line...

      Build CID to "Name" table from file so we can display real names
      rather than CIDs
 */

/* Include files */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include <epan/expert.h>

#include "packet-rdm.h"
#include "packet-tcp.h"

/* Forward declarations */
void proto_register_acn(void);
void proto_reg_handoff_acn(void);

/* pdu flags */
#define ACN_PDU_FLAG_L     0x80
#define ACN_PDU_FLAG_V     0x40
#define ACN_PDU_FLAG_H     0x20
#define ACN_PDU_FLAG_D     0x10

#define ACN_DMX_OPTION_P   0x80
#define ACN_DMX_OPTION_S   0x40

#define ACN_DMP_ADT_FLAG_V 0x80 /* V = Specifies whether address is a virtual address or not. */
#define ACN_DMP_ADT_FLAG_R 0x40 /* R = Specifies whether address is relative to last valid address in packet or not. */
#define ACN_DMP_ADT_FLAG_D 0x30 /* D1, D0 = Specify non-range or range address, single data, equal size
                                   or mixed size data array */
#define ACN_DMP_ADT_EXTRACT_D(f)        (((f) & ACN_DMP_ADT_FLAG_D) >> 4)

#define ACN_DMP_ADT_FLAG_X 0x0c /* X1, X0 = These bits are reserved and their values shall be set to 0
                                   when encoded. Their values shall be ignored when decoding. */

#define ACN_DMP_ADT_FLAG_A 0x03 /* A1, A0 = Size of Address elements */
#define ACN_DMP_ADT_EXTRACT_A(f)        ((f) & ACN_DMP_ADT_FLAG_A)

#define ACN_DMP_ADT_V_ACTUAL    0
#define ACN_DMP_ADT_V_VIRTUAL   1

#define ACN_DMP_ADT_R_ABSOLUTE  0
#define ACN_DMP_ADT_R_RELATIVE  1

#define ACN_DMP_ADT_D_NS        0
#define ACN_DMP_ADT_D_RS        1
#define ACN_DMP_ADT_D_RE        2
#define ACN_DMP_ADT_D_RM        3

#define ACN_DMP_ADT_A_1         0
#define ACN_DMP_ADT_A_2         1
#define ACN_DMP_ADT_A_4         2
#define ACN_DMP_ADT_A_R         3

#define ACN_PROTOCOL_ID_SDT           0x00000001
#define ACN_PROTOCOL_ID_DMP           0x00000002
#define ACN_PROTOCOL_ID_DMX           0x00000003
#define ACN_PROTOCOL_ID_DMX_2         0x00000004
#define ACN_PROTOCOL_ID_RPT           0x00000005
#define ACN_PROTOCOL_ID_BROKER        0x00000009
#define ACN_PROTOCOL_ID_LLRP          0x0000000A
#define ACN_PROTOCOL_ID_EPT           0x0000000B

#define ACN_ADDR_NULL                 0
#define ACN_ADDR_IPV4                 1
#define ACN_ADDR_IPV6                 2
#define ACN_ADDR_IPPORT               3

/* SDT Messages */
#define ACN_SDT_VECTOR_UNKNOWN          0
#define ACN_SDT_VECTOR_REL_WRAP         1
#define ACN_SDT_VECTOR_UNREL_WRAP       2
#define ACN_SDT_VECTOR_CHANNEL_PARAMS   3
#define ACN_SDT_VECTOR_JOIN             4
#define ACN_SDT_VECTOR_JOIN_REFUSE      5
#define ACN_SDT_VECTOR_JOIN_ACCEPT      6
#define ACN_SDT_VECTOR_LEAVE            7
#define ACN_SDT_VECTOR_LEAVING          8
#define ACN_SDT_VECTOR_CONNECT          9
#define ACN_SDT_VECTOR_CONNECT_ACCEPT  10
#define ACN_SDT_VECTOR_CONNECT_REFUSE  11
#define ACN_SDT_VECTOR_DISCONNECT      12
#define ACN_SDT_VECTOR_DISCONNECTING   13
#define ACN_SDT_VECTOR_ACK             14
#define ACN_SDT_VECTOR_NAK             15
#define ACN_SDT_VECTOR_GET_SESSION     16
#define ACN_SDT_VECTOR_SESSIONS        17

#define ACN_REFUSE_CODE_NONSPECIFIC     1
#define ACN_REFUSE_CODE_ILLEGAL_PARAMS  2
#define ACN_REFUSE_CODE_LOW_RESOURCES   3
#define ACN_REFUSE_CODE_ALREADY_MEMBER  4
#define ACN_REFUSE_CODE_BAD_ADDR_TYPE   5
#define ACN_REFUSE_CODE_NO_RECIP_CHAN   6

#define ACN_REASON_CODE_NONSPECIFIC          1
/*#define ACN_REASON_CODE_                   2 */
/*#define ACN_REASON_CODE_                   3 */
/*#define ACN_REASON_CODE_                   4 */
/*#define ACN_REASON_CODE_                   5 */
#define ACN_REASON_CODE_NO_RECIP_CHAN        6
#define ACN_REASON_CODE_CHANNEL_EXPIRED      7
#define ACN_REASON_CODE_LOST_SEQUENCE        8
#define ACN_REASON_CODE_SATURATED            9
#define ACN_REASON_CODE_TRANS_ADDR_CHANGING 10
#define ACN_REASON_CODE_ASKED_TO_LEAVE      11
#define ACN_REASON_CODE_NO_RECIPIENT        12

/* Blob Information */
#define ACN_BLOB_FIELD_TYPE1             1
#define ACN_BLOB_FIELD_TYPE2             2
#define ACN_BLOB_FIELD_TYPE3             3
#define ACN_BLOB_FIELD_TYPE4             4
#define ACN_BLOB_FIELD_TYPE5             5
#define ACN_BLOB_FIELD_TYPE6             6
#define ACN_BLOB_FIELD_TYPE7             7
#define ACN_BLOB_FIELD_TYPE8             8
#define ACN_BLOB_FIELD_TYPE9             9
#define ACN_BLOB_FIELD_TYPE10            10
#define ACN_BLOB_FIELD_TYPE11            11
#define ACN_BLOB_FIELD_TYPE12            12

#define ACN_BLOB_RANGE_MID               0
#define ACN_BLOB_RANGE_START             1
#define ACN_BLOB_RANGE_END               2
#define ACN_BLOB_RANGE_SINGLE            3

#define ACN_BLOB_IPV4                               1
#define ACN_BLOB_IPV6                               2
#define ACN_BLOB_ERROR1                             3
#define ACN_BLOB_ERROR2                             4
#define ACN_BLOB_METADATA                           5
#define ACN_BLOB_METADATA_DEVICES                   6
#define ACN_BLOB_METADATA_TYPES                     7
#define ACN_BLOB_TIME1                              8
#define ACN_BLOB_DIMMER_PROPERTIES                  9
#define ACN_BLOB_DIMMER_LOAD_PROPERTIES             10
#define ACN_BLOB_DIMMING_RACK_PROPERTIES            11
#define ACN_BLOB_DIMMING_RACK_STATUS_PROPERTIES     12
#define ACN_BLOB_DIMMER_STATUS_PROPERTIES           13
#define ACN_BLOB_SET_LEVELS_OPERATION               14
#define ACN_BLOB_PRESET_OPERATION                   15
#define ACN_BLOB_ADVANCED_FEATURES_OPERATION        16
#define ACN_BLOB_DIRECT_CONTROL_OPERATION           17
#define ACN_BLOB_GENERATE_CONFIG_OPERATION          18
#define ACN_BLOB_ERROR3                             19
#define ACN_BLOB_DIMMER_PROPERTIES2                 20
#define ACN_BLOB_DIMMER_LOAD_PROPERTIES2            21
#define ACN_BLOB_DIMMER_RACK_PROPERTIES2            22
#define ACN_BLOB_DIMMER_RACK_STATUS_PROPERTIES2     23
#define ACN_BLOB_DIMMER_STATUS_PROPERTIES2          24
#define ACN_BLOB_TIME2                              25
#define ACN_BLOB_RPC                                26
#define ACN_BLOB_DHCP_CONFIG_SUBNET                 27
#define ACN_BLOB_DHCP_CONFIG_STATIC_ROUTE           28
#define ACN_BLOB_ENERGY_MANAGEMENT                  29
#define ACN_BLOB_TIME3                              30
#define ACN_BLOB_ENERGY_COST                        31
#define ACN_BLOB_SEQUENCE_OPERATIONS                32
#define ACN_BLOB_SEQUENCE_STEP_PROPERTIES           33

#define ACN_BLOB_PRESET_PROPERTIES                  250

#define ACN_DMP_VECTOR_UNKNOWN               0
#define ACN_DMP_VECTOR_GET_PROPERTY          1
#define ACN_DMP_VECTOR_SET_PROPERTY          2
#define ACN_DMP_VECTOR_GET_PROPERTY_REPLY    3
#define ACN_DMP_VECTOR_EVENT                 4
#define ACN_DMP_VECTOR_MAP_PROPERTY          5
#define ACN_DMP_VECTOR_UNMAP_PROPERTY        6
#define ACN_DMP_VECTOR_SUBSCRIBE             7
#define ACN_DMP_VECTOR_UNSUBSCRIBE           8
#define ACN_DMP_VECTOR_GET_PROPERTY_FAIL     9
#define ACN_DMP_VECTOR_SET_PROPERTY_FAIL    10
#define ACN_DMP_VECTOR_MAP_PROPERTY_FAIL    11
#define ACN_DMP_VECTOR_SUBSCRIBE_ACCEPT     12
#define ACN_DMP_VECTOR_SUBSCRIBE_REJECT     13
#define ACN_DMP_VECTOR_ALLOCATE_MAP         14
#define ACN_DMP_VECTOR_ALLOCATE_MAP_REPLY   15
#define ACN_DMP_VECTOR_DEALLOCATE_MAP       16
#define ACN_DMP_VECTOR_SYNC_EVENT           17

#define ACN_DMP_REASON_CODE_NONSPECIFIC                  1
#define ACN_DMP_REASON_CODE_NOT_A_PROPERTY               2
#define ACN_DMP_REASON_CODE_WRITE_ONLY                   3
#define ACN_DMP_REASON_CODE_NOT_WRITABLE                 4
#define ACN_DMP_REASON_CODE_DATA_ERROR                   5
#define ACN_DMP_REASON_CODE_MAPS_NOT_SUPPORTED           6
#define ACN_DMP_REASON_CODE_SPACE_NOT_AVAILABLE          7
#define ACN_DMP_REASON_CODE_PROP_NOT_MAPPABLE            8
#define ACN_DMP_REASON_CODE_MAP_NOT_ALLOCATED            9
#define ACN_DMP_REASON_CODE_SUBSCRIPTION_NOT_SUPPORTED  10
#define ACN_DMP_REASON_CODE_NO_SUBSCRIPTIONS_SUPPORTED  11

#define ACN_DMX_VECTOR      2

#define ACN_PREF_DMX_DISPLAY_HEX  0
#define ACN_PREF_DMX_DISPLAY_DEC  1
#define ACN_PREF_DMX_DISPLAY_PER  2

#define ACN_PREF_DMX_DISPLAY_20PL 0
#define ACN_PREF_DMX_DISPLAY_16PL 1


#define MAGIC_V1           0    /* 1.0 default version */
#define MAGIC_COMMAND      1    /* 2.0 command         */
#define MAGIC_REPLY        2    /* 2.0 reply           */
#define MAGIC_REPLY_TYPE_3 3    /* 2.0 reply type 3    */

#define V1_SWITCH_TO_NET1       1
#define V1_SWITCH_TO_NET2       2
#define V1_BOOTP          1114467

#define V2_CMD_SWITCH_TO_NET1               1
#define V2_CMD_SWITCH_TO_NET2               2
#define V2_CMD_DOWNLOAD                     3
#define V2_CMD_SOFTBOOT                     4
#define V2_CMD_PHYSICAL_BEACON              5
#define V2_CMD_NETWORK_BEACON               6
#define V2_CMD_SWITCH_TO_ACN                7
#define V2_CMD_SWITCH_TO_DYNAMIC_IP         8
#define V2_CMD_EXTENDED_NETWORK_BEACON      9
#define V2_CMD_IP_CONFIGURATION            10
#define V2_CMD_RESTORE_FACTORY_DEFAULT     11
#define V2_CMD_PHYSICAL_BEACON_BY_CID      12
#define V2_CMD_NET2_DOWNLOAD           110163

#define MAGIC_SWITCH_TO_DYNAMIC_MAINTAIN_LEASE 0
#define MAGIC_SWITCH_TO_DYNAMIC_RESET_LEASE    1

#define MAGIC_DYNAMIC_IP_MAINTAIN_LEASE 0
#define MAGIC_DYNAMIC_IP_RESET_LEASE    1
#define MAGIC_STATIC_IP                 2

/* E1.33 Table A-1  Broadcast UID Defines */
#define ACN_RPT_ALL_CONTROLLERS                    0xFFFCFFFFFFFF
#define ACN_RPT_ALL_DEVICES                        0xFFFDFFFFFFFF
#define ACN_RPT_ALL_MID_DEVICES                    0xFFFDmmmmFFFF /*Addresses all Devices with the specific Manufacturer ID 0xmmmm*/

/* E1.33 Table A-2  LLRP Constants */
#define ACN_LLRP_MULTICAST_IPV4_ADDRESS_REQUEST    239.255.250.133
#define ACN_LLRP_MULTICAST_IPV4_ADDRESS_RESPONSE   239.255.250.134
#define ACN_LLRP_MULTICAST_IPV6_ADDRESS_REQUEST    ff18::85:0:0:85
#define ACN_LLRP_MULTICAST_IPV6_ADDRESS_RESPONSE   ff18::85:0:0:86
#define ACN_LLRP_PORT                              5569
#define ACN_LLRP_TIMEOUT                           2  /*seconds*/
#define ACN_LLRP_TARGET_TIMEOUT                    500 /*milliseconds*/
#define ACN_LLRP_MAX_BACKOFF                       1.5 /*seconds*/
#define ACN_LLRP_KNOWN_UID_SIZE                    200
#define ACN_LLRP_BROADCAST_CID                     FBAD822C-BD0C-4D4C-BDC8-7EABEBC85AFF

/* E1.33 Table A-3  Vector Defines for Root Layer PDU */
/* (already defined above)
 * #define ACN_PDU_VECTOR_ROOT_LLRP        0x0000000A
 * #define ACN_PDU_VECTOR_ROOT_RPT         0x00000005
 * #define ACN_PDU_VECTOR_ROOT_BROKER      0x00000009
 * #define ACN_PDU_VECTOR_ROOT_EPT         0x0000000B
 */

/* E1.33 Table A-4  LLRP Messages */
#define RDMNET_LLRP_VECTOR_PROBE_REQUEST   0x00000001
#define RDMNET_LLRP_VECTOR_PROBE_REPLY     0x00000002
#define RDMNET_LLRP_VECTOR_RDM_CMD         0x00000003

#define RDMNET_LLRP_VECTOR_PROBE_REQUEST_CLIENT_TCP_INACTIVE  0x01
#define RDMNET_LLRP_VECTOR_PROBE_REQUEST_BROKERS_ONLY         0x02

#define RDMNET_LLRP_VECTOR_RDM_CMD_START_CODE                 0xCC

/* E1.33 Table A-5  LLRP Probe Request Messages */
#define VECTOR_PROBE_REQUEST_DATA   0x01

/* E1.33 Table A-6  LLRP Probe Reply Messages */
#define VECTOR_PROBE_REPLY_DATA     0x01

/* E1.33 Table A-7  Broker Messages */
#define RDMNET_BROKER_VECTOR_CONNECT                 0x0001
#define RDMNET_BROKER_VECTOR_CONNECT_REPLY           0x0002
#define RDMNET_BROKER_VECTOR_CLIENT_ENTRY_UPDATE     0x0003
#define RDMNET_BROKER_VECTOR_REDIRECT_V4             0x0004
#define RDMNET_BROKER_VECTOR_REDIRECT_V6             0x0005
#define RDMNET_BROKER_VECTOR_FETCH_CLIENT_LIST       0x0006
#define RDMNET_BROKER_VECTOR_CONNECTED_CLIENT_LIST   0x0007
#define RDMNET_BROKER_VECTOR_CLIENT_ADD              0x0008
#define RDMNET_BROKER_VECTOR_CLIENT_REMOVE           0x0009
#define RDMNET_BROKER_VECTOR_CLIENT_ENTRY_CHANGE     0x000A
#define RDMNET_BROKER_VECTOR_REQUEST_DYNAMIC_UIDS    0x000B
#define RDMNET_BROKER_VECTOR_ASSIGNED_DYNAMIC_UIDS   0x000C
#define RDMNET_BROKER_VECTOR_FETCH_DYNAMIC_UID_LIST  0x000D
#define RDMNET_BROKER_VECTOR_DISCONNECT              0x000E
#define RDMNET_BROKER_VECTOR_NULL                    0x000F

#define RDMNET_BROKER_VECTOR_CONNECT_INCREMENTAL_UPDATES  0x01

/* E1.33 Table A-8  RPT Messages */
#define RDMNET_RPT_VECTOR_REQUEST        0x00000001
#define RDMNET_RPT_VECTOR_STATUS         0x00000002
#define RDMNET_RPT_VECTOR_NOTIFICATION   0x00000003

/* E1.33 Table A-9  RPT Request PDUs */
#define RDMNET_RPT_VECTOR_REQUEST_RDM_CMD   0x01

/* E1.33 Table A-10  RPT Status PDUs */
#define RDMNET_RPT_VECTOR_STATUS_UNKNOWN_RPT_UID         0x0001
#define RDMNET_RPT_VECTOR_STATUS_RDM_TIMEOUT             0x0002
#define RDMNET_RPT_VECTOR_STATUS_RDM_INVALID_RESPONSE    0x0003
#define RDMNET_RPT_VECTOR_STATUS_UNKNOWN_RDM_UID         0x0004
#define RDMNET_RPT_VECTOR_STATUS_UNKNOWN_ENDPOINT        0x0005
#define RDMNET_RPT_VECTOR_STATUS_BROADCAST_COMPLETE      0x0006
#define RDMNET_RPT_VECTOR_STATUS_UNKNOWN_VECTOR          0x0007
#define RDMNET_RPT_VECTOR_STATUS_INVALID_MESSAGE         0x0008
#define RDMNET_RPT_VECTOR_STATUS_INVALID_COMMAND_CLASS   0x0009

/* E1.33 Table A-11  RPT Notification PDUs */
#define RDMNET_RPT_VECTOR_NOTIFICATION_RDM_CMD   0x01

/* E1.33 Table A-12  RDM Command PDUs */
#define RDMNET_RPT_VECTOR_RDM_CMD_RD_DATA   0xCC

/* E1.33 Table A-13  EPT PDUs */
#define RDMNET_EPT_VECTOR_DATA     0x00000001
#define RDMNET_EPT_VECTOR_STATUS   0x00000002

/* E1.33 Table A-14  EPT Status PDUs */
#define RDMNET_EPT_VECTOR_UNKNOWN_CID      0x0001
#define RDMNET_EPT_VECTOR_UNKNOWN_VECTOR   0x0002

/* E1.33 Table A-15  RDM Parameter IDs (only used in packet-rdm.c) */

/* E1.33 Table A-16  RDM NACK Reason Codes (only used in packet-rdm.c) */

/* E1.33 Table A-17 Static Config Types for Component Scope Messages (only used in packet-rdm.c) */

/* E1.33 Table A-18 Broker States for Broker Status Messages (only used in packet-rdm.c) */

/* E1.33 Table A-19 Connection Status Codes for Broker Connect */
#define RDMNET_BROKER_CONNECT_OK                     0x0000
#define RDMNET_BROKER_CONNECT_SCOPE_MISMATCH         0x0001
#define RDMNET_BROKER_CONNECT_CAPACITY_EXCEEDED      0x0002
#define RDMNET_BROKER_CONNECT_DUPLICATE_UID          0x0003
#define RDMNET_BROKER_CONNECT_INVALID_CLIENT_ENTRY   0x0004
#define RDMNET_BROKER_CONNECT_INVALID_UID            0x0005

/* E1.33 Table A-20 Status Codes for Dynamic UID Mapping*/
#define RDMNET_DYNAMIC_UID_STATUS_OK                  0x0000
#define RDMNET_DYNAMIC_UID_STATUS_INVALID_REQUEST     0x0001
#define RDMNET_DYNAMIC_UID_STATUS_UID_NOT_FOUND       0x0002
#define RDMNET_DYNAMIC_UID_STATUS_DUPLICATE_RID       0x0003
#define RDMNET_DYNAMIC_UID_STATUS_CAPACITY_EXHAUSTED  0x0004

/* E1.33 Table A-21 Client Protocol Codes */
#define RDMNET_CLIENT_PROTOCOL_RPT          0x00000005
#define RDMNET_CLIENT_PROTOCOL_EPT          0x0000000B

/* E1.33 Table A-22 RPT Client Type Codes */
#define RDMNET_RPT_CLIENT_TYPE_DEVICE       0x00
#define RDMNET_RPT_CLIENT_TYPE_CONTROLLER   0x01

/* E1.33 Table A-23 LLRP Component Type Codes - LLRP TARGETS */
#define RDMNET_LLRP_COMPONENT_TYPE_RPT_DEVICE       0x00 /* Target is a Device */
#define RDMNET_LLRP_COMPONENT_TYPE_RPT_CONTROLLER   0x01 /* Target is a Controller */
#define RDMNET_LLRP_COMPONENT_TYPE_BROKER           0x02 /* Target is a Broker */
#define RDMNET_LLRP_COMPONENT_TYPE_NON_RDMNET       0xFF /* Target does not implement RDMnet other than LLRP */

/* E1.33 Table A-24 RPT Client Disconnect Reason Codes */
#define RDMNET_RPT_DISCONNECT_SHUTDOWN                   0x0000  /* Sent by Components to indicate that they are  */
                                                                 /* about to shut down.                           */
#define RDMNET_RPT_DISCONNECT_CAPACITY_EXHAUSTED         0x0001  /* Sent by Components when they do not           */
                                                                 /* have the ability to support this connection.  */
                                                                 /* Note that a Component must reserve certain    */
                                                                 /* resources to be able to send this message     */
                                                                 /* when it is in such a state.                   */
#define RDMNET_RPT_DISCONNECT_HARDWARE_FAULT             0x0002  /* Sent by Components which must terminate a     */
                                                                 /* connection due to an internal hardware fault  */
#define RDMNET_RPT_DISCONNECT_SOFTWARE_FAULT             0x0003  /* Sent by Components which must terminate a     */
                                                                 /* connection due to a software fault.           */
#define RDMNET_RPT_DISCONNECT_SOFTWARE_RESET             0x0004  /* Sent by Components which must terminate a     */
                                                                 /* connection because of a software reset.       */
                                                                 /* This message should not be sent in the case   */
                                                                 /* of a reboot, as the Shutdown message          */
                                                                 /* is preferred.                                 */
#define RDMNET_RPT_DISCONNECT_INCORRECT_SCOPE            0x0005  /* Sent by Brokers that are not on the           */
                                                                 /* desired Scope.                                */
#define RDMNET_RPT_DISCONNECT_RPT_RECONFIGURE            0x0006  /* Sent by components which must terminate a     */
                                                                 /* connection because they were reconfigured     */
                                                                 /* using RPT                                     */
#define RDMNET_RPT_DISCONNECT_LLRP_RECONFIGURE           0x0007  /* Sent by Components which must terminate a     */
                                                                 /* connection because they were reconfigured     */
                                                                 /* using LLRP.                                   */
#define RDMNET_RPT_DISCONNECT_USER_RECONFIGURE           0x0008  /* Sent by Components which must terminate a     */
                                                                 /* connection because they were reconfigured     */
                                                                 /* through some means outside the scope of this  */
                                                                 /* standard (i.e. front panel configuration)     */

typedef struct
{
  guint32 start;
  guint32 vector;
  guint32 header;
  guint32 data;
  guint32 data_length;
} acn_pdu_offsets;

typedef struct
{
  guint8  flags;
  guint32 address;  /* or first address */
  guint32 increment;
  guint32 count;
  guint32 size;
  guint32 data_length;
} acn_dmp_adt_type;

/*
 * See
 * ANSI BSR E1.17 Architecture for Control Networks
 * ANSI BSR E1.31
 * ANSI BSR E1.33 RDMnet
 */

#define ACTUAL_ADDRESS  0
/* forward reference */
static guint32 acn_add_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, const char *label);
static int     dissect_acn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int     dissect_rdmnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 data_offset, gboolean is_udp);

/* Global variables */
static int proto_acn = -1;
static gint ett_acn = -1;
static gint ett_acn_channel_owner_info_block = -1;
static gint ett_acn_channel_member_info_block = -1;
static gint ett_acn_channel_parameter = -1;
static gint ett_acn_address = -1;
static gint ett_acn_address_type = -1;
static gint ett_acn_blob = -1;
static gint ett_acn_pdu_flags = -1;
static gint ett_acn_dmp_pdu = -1;
static gint ett_acn_sdt_pdu = -1;
static gint ett_acn_sdt_client_pdu = -1;
static gint ett_acn_sdt_base_pdu = -1;
static gint ett_acn_root_pdu = -1;

static gint ett_acn_dmx_address = -1;
static gint ett_acn_dmx_2_options = -1;
static gint ett_acn_dmx_data_pdu = -1;
static gint ett_acn_dmx_pdu = -1;

static gint ett_rdmnet_pdu_flags = -1;
static gint ett_rdmnet_llrp_base_pdu = -1;
static gint ett_rdmnet_llrp_probe_request_pdu = -1;
static gint ett_rdmnet_llrp_probe_request_filter_flags = -1;
static gint ett_rdmnet_llrp_probe_reply_pdu = -1;
static gint ett_rdmnet_llrp_rdm_command_pdu = -1;

static gint ett_rdmnet_broker_base_pdu = -1;
static gint ett_rdmnet_broker_client_entry_pdu = -1;
static gint ett_rdmnet_broker_client_entry_manufacturer_protocol_ids = -1;
static gint ett_rdmnet_broker_connect_connection_flags = -1;
static gint ett_rdmnet_broker_client_entry_update_connection_flags = -1;

static gint ett_rdmnet_rpt_base_pdu = -1;
static gint ett_rdmnet_rpt_request_pdu = -1;
static gint ett_rdmnet_rpt_status_pdu = -1;
static gint ett_rdmnet_rpt_notification_pdu = -1;

static gint ett_rdmnet_ept_base_pdu = -1;
static gint ett_rdmnet_ept_data_pdu = -1;
static gint ett_rdmnet_ept_data_vector_pdu = -1;
static gint ett_rdmnet_ept_status_pdu = -1;

/*  Register fields */
/* In alphabetical order */
static int hf_acn_association = -1;
static int hf_acn_blob = -1;
/* static int hf_acn_blob_dimmer_load_properties2_type = -1; */
static int hf_acn_blob_field_length = -1;
static int hf_acn_blob_field_type = -1;
static int hf_acn_blob_field_value_number = -1;
static int hf_acn_blob_field_value_number64 = -1;
static int hf_acn_blob_field_value_ipv4 = -1;
static int hf_acn_blob_field_value_ipv6 = -1;
static int hf_acn_blob_field_value_float = -1;
static int hf_acn_blob_field_value_double = -1;
static int hf_acn_blob_field_value_guid = -1;
static int hf_acn_blob_field_value_string = -1;
/* static int hf_acn_blob_metadata_types_type = -1; */
static int hf_acn_blob_range_number = -1;
/* static int hf_acn_blob_range_start = -1; */
static int hf_acn_blob_range_type = -1;
static int hf_acn_blob_tree_field_type = -1;
static int hf_acn_blob_type = -1;
static int hf_acn_blob_version = -1;
static int hf_acn_blob_time_zone = -1;
static int hf_acn_blob_dst_type = -1;
static int hf_acn_blob_dst_start_day = -1;
static int hf_acn_blob_dst_stop_day = -1;
static int hf_acn_blob_dst_start_locality = -1;
static int hf_acn_blob_dst_stop_locality = -1;
static int hf_acn_channel_number = -1;
static int hf_acn_cid = -1;
/* static int hf_acn_client_protocol_id = -1; */
static int hf_acn_data = -1;
static int hf_acn_data8 = -1;
static int hf_acn_data16 = -1;
static int hf_acn_data24 = -1;
static int hf_acn_data32 = -1;
/* static int hf_acn_dmp_adt = -1; */ /* address and data type*/
static int hf_acn_dmp_adt_a = -1;
static int hf_acn_dmp_adt_v = -1;
static int hf_acn_dmp_adt_r = -1;
static int hf_acn_dmp_adt_d = -1;
static int hf_acn_dmp_adt_x = -1;
static int hf_acn_dmp_reason_code = -1;
static int hf_acn_dmp_vector = -1;
static int hf_acn_dmp_actual_address = -1;
static int hf_acn_dmp_virtual_address = -1;
static int hf_acn_dmp_actual_address_first = -1;
static int hf_acn_dmp_virtual_address_first = -1;
static int hf_acn_expiry = -1;
static int hf_acn_first_member_to_ack = -1;
static int hf_acn_first_missed_sequence = -1;
static int hf_acn_ip_address_type = -1;
static int hf_acn_ipv4 = -1;
static int hf_acn_ipv6 = -1;
static int hf_acn_last_member_to_ack = -1;
static int hf_acn_last_missed_sequence = -1;
static int hf_acn_mak_threshold = -1;
static int hf_acn_member_id = -1;
static int hf_acn_nak_holdoff = -1;
static int hf_acn_nak_max_wait = -1;
static int hf_acn_nak_modulus = -1;
static int hf_acn_nak_outbound_flag = -1;
static int hf_acn_oldest_available_wrapper = -1;
static int hf_acn_packet_identifier = -1;
static int hf_acn_pdu = -1;
static int hf_acn_pdu_flag_d = -1;
static int hf_acn_pdu_flag_h = -1;
static int hf_acn_pdu_flag_l = -1;
static int hf_acn_pdu_flag_v = -1;
static int hf_acn_pdu_flags = -1;
static int hf_acn_pdu_length = -1;
static int hf_acn_port = -1;
static int hf_acn_postamble_size = -1;
static int hf_acn_preamble_size = -1;
static int hf_acn_protocol_id = -1;
static int hf_acn_reason_code = -1;
static int hf_acn_reciprocal_channel = -1;
static int hf_acn_refuse_code = -1;
static int hf_acn_reliable_sequence_number = -1;
static int hf_acn_adhoc_expiry = -1;
/* static int hf_acn_sdt_pdu = -1; */
static int hf_acn_sdt_vector = -1;

static int hf_acn_dmx_vector = -1;
/* static int hf_acn_session_count = -1; */
static int hf_acn_total_sequence_number = -1;
static int hf_acn_dmx_source_name = -1;
static int hf_acn_dmx_priority = -1;
static int hf_acn_dmx_2_reserved = -1;
static int hf_acn_dmx_sequence_number = -1;
static int hf_acn_dmx_2_options = -1;
static int hf_acn_dmx_2_option_p = -1;
static int hf_acn_dmx_2_option_s = -1;
static int hf_acn_dmx_universe = -1;

static int hf_acn_dmx_start_code = -1;
static int hf_acn_dmx_2_first_property_address = -1;
static int hf_acn_dmx_increment = -1;
static int hf_acn_dmx_count = -1;
static int hf_acn_dmx_2_start_code = -1;
static int hf_acn_dmx_data = -1;

/* static int hf_acn_dmx_dmp_vector = -1; */

/* Try heuristic ACN decode */
static gboolean global_acn_dmx_enable = FALSE;
static gint     global_acn_dmx_display_view = 0;
static gint     global_acn_dmx_display_line_format = 0;
static gboolean global_acn_dmx_display_zeros = FALSE;
static gboolean global_acn_dmx_display_leading_zeros = FALSE;

static int proto_magic = -1;
static gint ett_magic = -1;

/* Register fields */
static int hf_magic_protocol_id = -1;
static int hf_magic_pdu_subtype = -1;
static int hf_magic_major_version = -1;
static int hf_magic_minor_version = -1;

static int hf_magic_v1command_vals = -1;

static int hf_magic_command_vals = -1;
static int hf_magic_command_beacon_duration = -1;
static int hf_magic_command_tftp = -1;
static int hf_magic_command_reset_lease = -1;
static int hf_magic_command_cid = -1;
static int hf_magic_command_ip_configuration = -1;
static int hf_magic_command_ip_address = -1;
static int hf_magic_command_subnet_mask = -1;
static int hf_magic_command_gateway = -1;

static int hf_magic_reply_ip_address = -1;
static int hf_magic_reply_subnet_mask = -1;
static int hf_magic_reply_gateway = -1;
static int hf_magic_reply_tftp = -1;

static int hf_magic_reply_version = -1;
static int hf_magic_reply_device_type_name = -1;
static int hf_magic_reply_default_name = -1;
static int hf_magic_reply_user_name = -1;
static int hf_magic_reply_cid = -1;
static int hf_magic_reply_dcid = -1;

static expert_field ei_magic_reply_invalid_type = EI_INIT;


static int proto_rdmnet = -1;
static gint ett_rdmnet = -1;

/* Register fields */
static int hf_rdmnet_cid = -1;
static int hf_rdmnet_packet_identifier = -1;
static int hf_rdmnet_pdu = -1;
static int hf_rdmnet_pdu_flag_d = -1;
static int hf_rdmnet_pdu_flag_h = -1;
static int hf_rdmnet_pdu_flag_l = -1;
static int hf_rdmnet_pdu_flag_v = -1;
static int hf_rdmnet_pdu_flags = -1;
static int hf_rdmnet_pdu_length = -1;
static int hf_rdmnet_postamble_size = -1;
static int hf_rdmnet_preamble_size = -1;
static int hf_rdmnet_protocol_id = -1;
static int hf_rdmnet_tcp_length = -1;

static int hf_rdmnet_llrp_vector = -1;
static int hf_rdmnet_llrp_destination_cid = -1;
static int hf_rdmnet_llrp_transaction_number = -1;
static int hf_rdmnet_llrp_probe_request_vector = -1;
static int hf_rdmnet_llrp_probe_request_pdu_length = -1;
static int hf_rdmnet_llrp_probe_request_lower_uid = -1;
static int hf_rdmnet_llrp_probe_request_upper_uid = -1;
static int hf_rdmnet_llrp_probe_request_filter = -1;
static int hf_rdmnet_llrp_probe_request_filter_client_tcp_inactive = -1;
static int hf_rdmnet_llrp_probe_request_filter_brokers_only = -1;
static int hf_rdmnet_llrp_probe_request_known_uid = -1;

static int hf_rdmnet_llrp_probe_reply_vector = -1;
static int hf_rdmnet_llrp_probe_reply_uid = -1;
static int hf_rdmnet_llrp_probe_reply_hardware_address = -1;
static int hf_rdmnet_llrp_probe_reply_component_type = -1;
static int hf_rdmnet_llrp_rdm_command_start_code = -1;

static int hf_rdmnet_rpt_vector = -1;
static int hf_rdmnet_rpt_source_uid = -1;
static int hf_rdmnet_rpt_source_endpoint_id = -1;
static int hf_rdmnet_rpt_destination_uid = -1;
static int hf_rdmnet_rpt_destination_endpoint_id = -1;
static int hf_rdmnet_rpt_sequence_number = -1;
static int hf_rdmnet_rpt_reserved = -1;
static int hf_rdmnet_rpt_request_vector = -1;
static int hf_rdmnet_rpt_request_rdm_command = -1;
static int hf_rdmnet_rpt_status_vector = -1;
static int hf_rdmnet_rpt_status_unknown_rpt_uid_string = -1;
static int hf_rdmnet_rpt_status_rdm_timeout_string = -1;
static int hf_rdmnet_rpt_status_rdm_invalid_response_string = -1;
static int hf_rdmnet_rpt_status_unknown_rdm_uid_string = -1;
static int hf_rdmnet_rpt_status_unknown_endpoint_string = -1;
static int hf_rdmnet_rpt_status_broadcast_complete_string = -1;
static int hf_rdmnet_rpt_status_unknown_vector_string = -1;
static int hf_rdmnet_rpt_notification_vector = -1;
static int hf_rdmnet_rpt_notification_rdm_command = -1;

static int hf_rdmnet_broker_vector = -1;
static int hf_rdmnet_broker_client_protocol_vector = -1;
static int hf_rdmnet_broker_client_protocol_cid = -1;
static int hf_rdmnet_broker_client_rpt_client_uid = -1;
static int hf_rdmnet_broker_client_rpt_client_type = -1;
static int hf_rdmnet_broker_client_rpt_binding_cid = -1;
static int hf_rdmnet_broker_client_ept_protocol_vector = -1;
static int hf_rdmnet_broker_client_ept_protocol_manufacturer_id = -1;
static int hf_rdmnet_broker_client_ept_protocol_protocol_id = -1;
static int hf_rdmnet_broker_client_ept_protocol_string = -1;
static int hf_rdmnet_broker_connect_client_scope = -1;
static int hf_rdmnet_broker_connect_e133_version = -1;
static int hf_rdmnet_broker_connect_search_domain = -1;
static int hf_rdmnet_broker_connect_connection_flags = -1;
static int hf_rdmnet_broker_connect_connection_flags_incremental_updates = -1;
static int hf_rdmnet_broker_connect_reply_connection_code = -1;
static int hf_rdmnet_broker_connect_reply_e133_version = -1;
static int hf_rdmnet_broker_connect_reply_broker_uid = -1;
static int hf_rdmnet_broker_connect_reply_client_uid = -1;
static int hf_rdmnet_broker_client_entry_update_connection_flags = -1;
static int hf_rdmnet_broker_client_entry_update_connection_flags_incremental_updates = -1;
static int hf_rdmnet_broker_redirect_ipv4_address = -1;
static int hf_rdmnet_broker_redirect_ipv4_tcp_port = -1;
static int hf_rdmnet_broker_redirect_ipv6_address = -1;
static int hf_rdmnet_broker_redirect_ipv6_tcp_port = -1;
static int hf_rdmnet_broker_disconnect_reason = -1;
static int hf_rdmnet_broker_dynamic_uid_request = -1;
static int hf_rdmnet_broker_rid = -1;
static int hf_rdmnet_broker_assigned_dynamic_uid = -1;
static int hf_rdmnet_broker_assigned_rid = -1;
static int hf_rdmnet_broker_assigned_status_code = -1;
static int hf_rdmnet_broker_fetch_dynamic_uid = -1;

static int hf_rdmnet_ept_vector = -1;
static int hf_rdmnet_ept_destination_cid = -1;
static int hf_rdmnet_ept_data_pdu_length = -1;
static int hf_rdmnet_ept_data_vector = -1;
static int hf_rdmnet_ept_data_vector_manfacturer_id = -1;
static int hf_rdmnet_ept_data_vector_protocol_id = -1;
static int hf_rdmnet_ept_data_opaque_data = -1;
static int hf_rdmnet_ept_status_pdu_length = -1;
static int hf_rdmnet_ept_status_vector = -1;
static int hf_rdmnet_ept_status_unknown_cid = -1;
static int hf_rdmnet_ept_status_status_string = -1;
static int hf_rdmnet_ept_status_unknown_vector = -1;
static int hf_rdmnet_ept_status_vector_string = -1;

static const value_string acn_protocol_id_vals[] = {
  { ACN_PROTOCOL_ID_SDT,    "SDT Protocol" },
  { ACN_PROTOCOL_ID_DMP,    "DMP Protocol" },
  { ACN_PROTOCOL_ID_DMX,    "DMX Protocol" },
  { ACN_PROTOCOL_ID_DMX_2,  "Ratified DMX Protocol" },
  { ACN_PROTOCOL_ID_RPT,    "RDM Packet Transport Protocol" },
  { ACN_PROTOCOL_ID_BROKER, "Broker Protocol" },
  { ACN_PROTOCOL_ID_LLRP,   "Low Level Recovery Protocol" },
  { ACN_PROTOCOL_ID_EPT,    "Etensible Packet Transport Protocol" },
  { 0,       NULL },
};

static const value_string acn_dmp_adt_r_vals[] = {
  { ACN_DMP_ADT_R_RELATIVE, "Relative" },
  { ACN_DMP_ADT_R_ABSOLUTE, "Absolute" },
  { 0,       NULL },
};

static const value_string acn_dmp_adt_v_vals[] = {
  { ACN_DMP_ADT_V_ACTUAL,  "Actual" },
  { ACN_DMP_ADT_V_VIRTUAL, "Virtual" },
  { 0,       NULL },
};

static const value_string acn_dmp_adt_d_vals[] = {
  { ACN_DMP_ADT_D_NS, "Non-range, single data item" },
  { ACN_DMP_ADT_D_RS, "Range, single data item" },
  { ACN_DMP_ADT_D_RE, "Range, array of equal size data items" },
  { ACN_DMP_ADT_D_RM, "Range, series of mixed size data items" },
  { 0,       NULL },
};

static const value_string acn_dmp_adt_a_vals[] = {
  { ACN_DMP_ADT_A_1, "1 octet" },
  { ACN_DMP_ADT_A_2, "2 octets" },
  { ACN_DMP_ADT_A_4, "4 octets" },
  { ACN_DMP_ADT_A_R, "reserved" },
  { 0,       NULL },
};


static const value_string acn_sdt_vector_vals[] = {
  { ACN_SDT_VECTOR_UNKNOWN,        "Unknown"},
  { ACN_SDT_VECTOR_REL_WRAP,       "Reliable Wrapper"},
  { ACN_SDT_VECTOR_UNREL_WRAP,     "Unreliable Wrapper"},
  { ACN_SDT_VECTOR_CHANNEL_PARAMS, "Channel Parameters"},
  { ACN_SDT_VECTOR_JOIN,           "Join"},
  { ACN_SDT_VECTOR_JOIN_REFUSE,    "Join Refuse"},
  { ACN_SDT_VECTOR_JOIN_ACCEPT,    "Join Accept"},
  { ACN_SDT_VECTOR_LEAVE,          "Leave"},
  { ACN_SDT_VECTOR_LEAVING,        "Leaving"},
  { ACN_SDT_VECTOR_CONNECT,        "Connect"},
  { ACN_SDT_VECTOR_CONNECT_ACCEPT, "Connect Accept"},
  { ACN_SDT_VECTOR_CONNECT_REFUSE, "Connect Refuse"},
  { ACN_SDT_VECTOR_DISCONNECT,     "Disconnect"},
  { ACN_SDT_VECTOR_DISCONNECTING,  "Disconnecting"},
  { ACN_SDT_VECTOR_ACK,            "Ack"},
  { ACN_SDT_VECTOR_NAK,            "Nak"},
  { ACN_SDT_VECTOR_GET_SESSION,    "Get Session"},
  { ACN_SDT_VECTOR_SESSIONS,       "Sessions"},
  { 0,       NULL },
};

static const value_string acn_dmx_vector_vals[] = {
  { ACN_DMX_VECTOR,  "Streaming DMX"},
  { 0,       NULL },
};

static const value_string acn_blob_advanced_features_operation_field_name[] = {
  { 1, "Operation Type" },
  { 2, "Use Controlled Loads" },
  { 3, "Start Dimmer Address" },
  { 4, "End Dimmer Address" },
  { 5, "Space" },
  { 0, NULL }
};

static const value_string acn_blob_dimmer_load_properties2_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  { 9, "Space" },
  { 10, "UDN" },
  { 11, "Reserved" },
  { 12, "Is Load Recorded" },
  { 13, "Output Voltage Step 1" },
  { 14, "Output Voltage Step 2" },
  { 15, "Output Voltage Step 3" },
  { 16, "Output Voltage Step 4" },
  { 17, "Output Voltage Step 5" },
  { 18, "Output Voltage Step 6" },
  { 19, "Output Voltage Step 7" },
  { 20, "Output Voltage Step 8" },
  { 21, "Output Voltage Step 9" },
  { 22, "Output Voltage Step 10" },
  { 23, "Output Voltage Step 11" },
  { 24, "Output Voltage Step 12" },
  { 25, "Output Voltage Step 13" },
  { 26, "Output Voltage Step 14" },
  { 27, "Output Voltage Step 15" },
  { 28, "Output Voltage Step 16" },
  { 29, "Output Voltage Step 17" },
  { 30, "Output Voltage Step 18" },
  { 31, "Output Voltage Step 19" },
  { 32, "Output Voltage Step 20" },
  { 33, "Amperage Step 1" },
  { 34, "Amperage Step 2" },
  { 35, "Amperage Step 3" },
  { 36, "Amperage Step 4" },
  { 37, "Amperage Step 5" },
  { 38, "Amperage Step 6" },
  { 39, "Amperage Step 7" },
  { 40, "Amperage Step 8" },
  { 41, "Amperage Step 9" },
  { 42, "Amperage Step 10" },
  { 43, "Amperage Step 11" },
  { 44, "Amperage Step 12" },
  { 45, "Amperage Step 13" },
  { 46, "Amperage Step 14" },
  { 47, "Amperage Step 15" },
  { 48, "Amperage Step 16" },
  { 49, "Amperage Step 17" },
  { 50, "Amperage Step 18" },
  { 51, "Amperage Step 19" },
  { 52, "Amperage Step 20" },
  { 53, "Voltage Time Step 1" },
  { 54, "Voltage Time Step 2" },
  { 55, "Voltage Time Step 3" },
  { 56, "Voltage Time Step 4" },
  { 57, "Voltage Time Step 5" },
  { 58, "Voltage Time Step 6" },
  { 59, "Voltage Time Step 7" },
  { 60, "Voltage Time Step 8" },
  { 61, "Voltage Time Step 9" },
  { 62, "Voltage Time Step 10" },
  { 63, "Voltage Time Step 11" },
  { 64, "Voltage Time Step 12" },
  { 65, "Voltage Time Step 13" },
  { 66, "Voltage Time Step 14" },
  { 67, "Voltage Time Step 15" },
  { 68, "Voltage Time Step 16" },
  { 69, "Voltage Time Step 17" },
  { 70, "Voltage Time Step 18" },
  { 71, "Voltage Time Step 19" },
  { 72, "Voltage Time Step 20" },
  { 73, "Is Rig Check Recorded" },
  { 74, "Recorded Level" },
  { 75, "Recorded Current" },
  { 0, NULL }
};
static value_string_ext acn_blob_dimmer_load_properties2_field_name_ext = VALUE_STRING_EXT_INIT(acn_blob_dimmer_load_properties2_field_name);

static const value_string acn_blob_dimmer_properties2_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  { 9, "Space" },
  { 10, "UDN" },
  { 11, "Reserved" },
  { 12, "Dimmer Name" },
  { 13, "Dimmer Module" },
  { 14, "Dimmer Mode" },
  { 15, "Dimmer Control" },
  { 16, "Dimmer Curve" },
  { 17, "Off Level Percent" },
  { 18, "On Level Percent" },
  { 19, "On Time(sec)" },
  { 20, "Off Time(sec)" },
  { 21, "Dimmer AF Enabled" },
  { 22, "Threshold" },
  { 23, "Min Scale" },
  { 24, "Unregulated Min Scale" },
  { 25, "Max Scale" },
  { 26, "Unregulated Max Scale" },
  { 27, "Voltage Regulation" },
  { 28, "Preheat Enable" },
  { 29, "Preheat Time" },
  { 30, "DC Output Prevent" },
  { 31, "Inrush Protect" },
  { 32, "AF Sensitivity" },
  { 33, "AF Reaction Time" },
  { 34, "Scale Load" },
  { 35, "PTIO" },
  { 36, "Allow In Preset" },
  { 37, "Allow In Panic" },
  { 38, "Allow In Panic DD" },
  { 39, "Report No Loads" },
  { 40, "Loads Error Reporting Enabled" },
  { 41, "New Dimmer Space Number" },
  { 42, "New Dimmer Number" },
  { 43, "DMX A Patch" },
  { 44, "DMX B Patch" },
  { 45, "sACN Patch" },
  { 46, "DMX A Patch DD" },
  { 47, "DMX B Patch DD" },
  { 48, "sACN Patch DD" },
  { 49, "DMX A 16-bit Enable" },
  { 40, "DMX B 16-bit Enable" },
  { 51, "sACN 16-bit Enable" },
  { 52, "Dimmer Zone" },
  { 0, NULL }
};
static value_string_ext acn_blob_dimmer_properties2_field_name_ext = VALUE_STRING_EXT_INIT(acn_blob_dimmer_properties2_field_name);

static const value_string acn_blob_dimmer_rack_properties2_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  { 9, "Space" },
  { 10, "UDN" },
  { 11, "Reserved" },
  { 12, "Rack CID" },
  { 13, "Rack Number" },
  { 14, "Rack Name" },
  { 15, "Rack Model" },
  { 16, "Rack AF Enable" },
  { 17, "Temperature Format" },
  { 18, "Data Loss Behavior DMX A" },
  { 19, "Data Loss Behavior DMX B" },
  { 20, "Data Loss Behavior sACN" },
  { 21, "Data Loss Cross/Wait Time DMX A" },
  { 22, "Data Loss Cross/Wait Time DMX B" },
  { 23, "Data Loss Wait Time sACN" },
  { 24, "Data Loss Fade Time DMX A" },
  { 25, "Data Loss Fade Time DMX B" },
  { 26, "Data Loss Fade Time sACN" },
  { 27, "Data Loss Preset DMX A" },
  { 28, "Data Loss Preset DMX B" },
  { 29, "Data Loss Preset sACN" },
  { 20, "Data Port Priority DMX A" },
  { 31, "Data Port Priority DMX B" },
  { 32, "Data Port Enabled DMX A" },
  { 33, "Data Port Enabled DMX B" },
  { 34, "Data Port Enabled sACN" },
  { 35, "16 Bit Enabled DMX A" },
  { 36, "16 Bit Enabled DMX B" },
  { 37, "16 Bit Enabled sACN" },
  { 38, "Patch From Home Screen" },
  { 39, "SCR Off Time" },
  { 30, "Time Mode" },
  { 41, "Offset from UTC" },
  { 42, "Universal Hold Last Look Time" },
  { 43, "Reactivate Presets On Boot" },
  { 44, "Voltage High Warning Level" },
  { 45, "Temperature High Warning Level" },
  { 46, "Fan Operation Timing" },
  { 47, "Allow Backplane Communication Errors" },
  { 48, "Activate Presets on Boot" },
  { 49, "SmartLink2 Power Supply Enable" },
  { 40, "Remote Record Enable" },
  { 51, "System Number" },
  { 52, "Architectural Priority" },
  { 53, "Data Loss Preset Space DMX A" },
  { 54, "Data Loss Preset Space DMX B" },
  { 55, "Arch. Off Behavior" },
  { 0, NULL }
};
static value_string_ext acn_blob_dimmer_rack_properties2_field_name_ext = VALUE_STRING_EXT_INIT(acn_blob_dimmer_rack_properties2_field_name);

static const value_string acn_blob_dimmer_rack_status_properties2_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  { 9, "Space" },
  { 10, "UDN" },
  { 11, "Reserved" },
  { 12, "CPU Tempeture" },
  { 13, "Time of Last Reboot" },
  { 14, "Time Now" },
  { 15, "Rack Phasing" },
  { 16, "Power Frequency" },
  { 17, "Phase A Voltage" },
  { 18, "Phase B Voltage" },
  { 19, "Phase C Voltage" },
  { 20, "DMX A Port Status" },
  { 21, "DMX B Port Status" },
  { 22, "Active Preset Group IDs" },
  { 23, "Active Preset Group ID[0]" },
  { 24, "Active Preset Group ID[1]" },
  { 25, "Active Preset Group ID[2]" },
  { 26, "Active Preset Group ID[3]" },
  { 27, "Active Preset Group ID[4]" },
  { 28, "Active Preset Group ID[5]" },
  { 29, "Active Preset Group ID[6]" },
  { 30, "Active Preset Group ID[7]" },
  { 31, "Active Preset Group ID[8]" },
  { 32, "Active Preset Group ID[9]" },
  { 33, "Active Preset Group ID[10]" },
  { 34, "Active Preset Group ID[11]" },
  { 35, "Active Preset Group ID[12]" },
  { 36, "Active Preset Group ID[13]" },
  { 37, "Active Preset Group ID[14]" },
  { 38, "Active Preset Group ID[15]" },
  { 39, "Active Preset Group ID[16]" },
  { 40, "Active Preset Group ID[17]" },
  { 41, "Active Preset Group ID[18]" },
  { 42, "Active Preset Group ID[19]" },
  { 43, "Active Preset Group ID[20]" },
  { 44, "Active Preset Group ID[21]" },
  { 45, "Active Preset Group ID[22]" },
  { 46, "Active Preset Group ID[23]" },
  { 47, "Active Preset Group ID[24]" },
  { 48, "Active Preset Group ID[25]" },
  { 49, "Active Preset Group ID[26]" },
  { 50, "Active Preset Group ID[27]" },
  { 51, "Active Preset Group ID[28]" },
  { 52, "Active Preset Group ID[29]" },
  { 53, "Active Preset Group ID[30]" },
  { 54, "Active Preset Group ID[31]" },
  { 55, "Active Preset Group ID[32]" },
  { 56, "Active Preset Group ID[33]" },
  { 57, "Active Preset Group ID[34]" },
  { 58, "Active Preset Group ID[35]" },
  { 59, "Active Preset Group ID[36]" },
  { 60, "Active Preset Group ID[37]" },
  { 61, "Active Preset Group ID[38]" },
  { 62, "Active Preset Group ID[39]" },
  { 63, "Active Preset Group ID[40]" },
  { 64, "Active Preset Group ID[41]" },
  { 65, "Active Preset Group ID[42]" },
  { 66, "Active Preset Group ID[43]" },
  { 67, "Active Preset Group ID[44]" },
  { 68, "Active Preset Group ID[45]" },
  { 69, "Active Preset Group ID[46]" },
  { 70, "Active Preset Group ID[47]" },
  { 71, "Active Preset Group ID[48]" },
  { 72, "Active Preset Group ID[49]" },
  { 73, "Active Preset Group ID[50]" },
  { 74, "Active Preset Group ID[51]" },
  { 75, "Active Preset Group ID[52]" },
  { 76, "Active Preset Group ID[53]" },
  { 77, "Active Preset Group ID[54]" },
  { 78, "Active Preset Group ID[55]" },
  { 79, "Active Preset Group ID[56]" },
  { 80, "Active Preset Group ID[57]" },
  { 81, "Active Preset Group ID[58]" },
  { 82, "Active Preset Group ID[59]" },
  { 83, "Active Preset Group ID[60]" },
  { 84, "Active Preset Group ID[61]" },
  { 85, "Active Preset Group ID[62]" },
  { 86, "Active Preset Group ID[63]" },
  { 87, "Rack AF State" },
  { 88, "Number of Stored Presets for This Rack" },
  { 89, "Number of Lugs in This Rack" },
  { 90, "DSP Version" },
  { 91, "AF Card Version Slot 1" },
  { 92, "AF Card Version Slot 2" },
  { 93, "AF Card Version Slot 3" },
  { 94, "AF Card Version Slot 4" },
  { 95, "HCS08 Version" },
  { 96, "FPGA Version" },
  { 97, "Upload Progress AF Card 1" },
  { 98, "Upload Progress AF Card 2" },
  { 99, "Upload Progress AF Card 3" },
  { 100, "Upload Progress AF Card 4" },
  { 0, NULL }
};
static value_string_ext acn_blob_dimmer_rack_status_properties2_field_name_ext = VALUE_STRING_EXT_INIT(acn_blob_dimmer_rack_status_properties2_field_name);

static const value_string acn_blob_dimmer_status_properties2_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  { 9, "Space" },
  { 10, "UDN" },
  { 11, "Reserved" },
  { 12, "Source Winning Control" },
  { 13, "Priority of Winning Source" },
  { 14, "Winning Level" },
  { 15, "Winning DMX A Level" },
  { 16, "Winning DMX B Level" },
  { 17, "Winning sACN Level" },
  { 18, "Source Winning Control DD" },
  { 19, "Priority of Winning Source DD" },
  { 20, "Winning Level DD" },
  { 21, "Winning DMX A Level DD" },
  { 22, "Winning DMX B Level DD" },
  { 23, "Winning DMX sACN Level DD" },
  { 24, "Actual Load" },
  { 25, "Load Status" },
  { 0, NULL }
};
static value_string_ext acn_blob_dimmer_status_properties2_field_name_ext = VALUE_STRING_EXT_INIT(acn_blob_dimmer_status_properties2_field_name);


static const value_string acn_blob_direct_control_operation_field_name[] = {
  { 1, "Space" },
  { 2, "Dimmer Number" },
  { 3, "DD Side" },
  { 4, "Level" },
  { 5, "Priority" },
  { 0, NULL }
};

static const value_string acn_blob_error3_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  { 9, "Space" },
  { 10, "UDN" },
  { 11, "sACN Address" },
  { 12, "Error Type" },
  { 13, "Severity" },
  { 14, "Timestamp" },
  { 15, "Error Text" },
  { 0, NULL }
};

static const value_string acn_blob_field_type_vals[] = {
  { ACN_BLOB_FIELD_TYPE1, "1 Byte Signed Integer" },
  { ACN_BLOB_FIELD_TYPE2, "2 Bytes Signed Integer" },
  { ACN_BLOB_FIELD_TYPE3, "4 Bytes Signed Integer" },
  { ACN_BLOB_FIELD_TYPE4, "8 Bytes Signed Integer" },
  { ACN_BLOB_FIELD_TYPE5, "1 Byte Unsigned Integer" },
  { ACN_BLOB_FIELD_TYPE6, "2 Bytes Unsigned Integer" },
  { ACN_BLOB_FIELD_TYPE7, "4 Bytes Unsigned Integer" },
  { ACN_BLOB_FIELD_TYPE8, "8 Bytes Unsigned Integer" },
  { ACN_BLOB_FIELD_TYPE9, "Float" },
  { ACN_BLOB_FIELD_TYPE10, "Double" },
  { ACN_BLOB_FIELD_TYPE11, "Variblob" },
  { ACN_BLOB_FIELD_TYPE12, "Ignore" },
  { 0, NULL }
};

static const value_string acn_blob_generate_config_operation_field_name[] = {
  { 1, "First Dimmer" },
  { 2, "Numbering Style" },
  { 3, "Use Dimmer Doubling" },
  { 4, "Default Module Type" },
  { 0, NULL }
};

static const value_string acn_blob_ip_field_name[] = {
  { 1, "IP Address" },
  { 2, "Subnet Mask" },
  { 3, "Gateway" },
  { 0, NULL }
};

static const value_string acn_blob_error1_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  /*{9,  "Space"}, */
  { 9, "UDN" },
  { 10, "sACN Address" },
  { 11, "Error Type" },
  { 12, "Severity" },
  { 13, "Timestamp" },
  { 14, "Error Text" },
  { 0, NULL }
};

static const value_string acn_blob_error2_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  { 9, "Space" },
  { 10, "UDN" },
  { 11, "sACN Address" },
  { 12, "Error Type" },
  { 13, "Severity" },
  { 14, "Timestamp" },
  { 15, "Error Text" },
  { 0, NULL }
};

static const value_string acn_blob_metadata_devices_field_name[] = {
  { 1, "Device Type" },
  { 2, "Identifier Name 1" },
  { 3, "Identifier Name 2" },
  { 4, "Identifier Name 3" },
  { 5, "Identifier Name 4" },
  { 0, NULL }
};

static const value_string acn_blob_metadata_field_name[] = {
  { 1, "Device Type" },
  { 2, "Metadata Type" },
  { 3, "Identifier Name 1" },
  { 4, "Identifier Name 2" },
  { 5, "Identifier Name 3" },
  { 6, "Identifier Name 4" },
  { 7, "Metadata 1" },
  { 8, "Metadata 2" },
  { 9, "Metadata 3" },
  { 10, "Metadata 4" },
  { 11, "Metadata 5" },
  { 12, "Metadata 6" },
  { 13, "Metadata 7" },
  { 14, "Metadata 8" },
  { 15, "Device CID" },
  { 0, NULL }
};

static const value_string acn_blob_metadata_types_field_name[] = {
  { 1, "Metadata Type" },
  { 2, "Identifier Name 1" },
  { 3, "Identifier Name 2" },
  { 4, "Identifier Name 3" },
  { 5, "Identifier Name 4" },
  { 6, "Identifier Name 5" },
  { 7, "Identifier Name 6" },
  { 8, "Identifier Name 7" },
  { 9, "Identifier Name 8" },
  { 0, NULL }
};

static const value_string acn_blob_time1_field_name[] = {
  { 1, "Time" },
  { 2, "Time Zone Name" },
  { 3, "Time Zone Offset Hour" },
  { 4, "Time Zone Offset Min" },
  { 5, "Time Zone Offset Sec" },
  { 6, "DST Name" },
  { 7, "Start Month" },
  { 8, "Start Week" },
  { 9, "Start Day" },
  { 10, "End Month" },
  { 11, "End Week" },
  { 12, "End Day" },
  { 13, "Timed Event Update" },
  { 0, NULL }
};

static const value_string acn_blob_dimmer_properties1_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  { 9, "Space" },
  { 10, "UDN" },
  { 11, "Reserved" },
  { 12, "Dimmer Name" },
  { 13, "Dimmer Module" },
  { 14, "Dimmer Mode" },
  { 15, "Dimmer Control" },
  { 16, "Dimmer Curve" },
  { 17, "On Level Percent" },
  { 18, "Off Level Percent" },
  { 19, "On Time(sec)" },
  { 20, "Off Time(sec)" },
  { 21, "Dimmer AF Enabled" },
  { 22, "Threshold" },
  { 23, "Min Scale" },
  { 24, "Unregulated Min Scale" },
  { 25, "Max Scale" },
  { 26, "Unregulated Max Scale" },
  { 27, "Voltage Regulation" },
  { 28, "Preheat Enable" },
  { 29, "Preheat Time" },
  { 30, "DC Output Prevent" },
  { 31, "Inrush Protect" },
  { 32, "AF Sensitivity" },
  { 33, "AF Reaction Time" },
  { 34, "Scale Load" },
  { 35, "PTIO" },
  { 36, "Allow In Preset" },
  { 37, "Allow In Panic" },
  { 38, "Allow In Panic DD" },
  /*{39, "Loads Reporting Mode"},
  {40, "New Dimmer Space Number"}, */
  { 39, "Report No Loads Enable" },
  { 40, "Loads Error Reporting Enable" },
  { 41, "Dimmer Space" },
  { 42, "New Dimmer Number" },
  { 43, "DMX A Patch" },
  { 44, "DMX B Patch" },
  { 45, "sACN Patch" },
  { 46, "DMX A Patch DD" },
  { 47, "DMX B Patch DD" },
  { 48, "sACN Patch DD" },
  { 0, NULL }
};
static value_string_ext acn_blob_dimmer_properties1_field_name_ext = VALUE_STRING_EXT_INIT(acn_blob_dimmer_properties1_field_name);

static const value_string acn_blob_dimmer_load_properties1_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  { 9, "Space" },
  { 10, "UDN" },
  { 11, "Reserved" },
  { 12, "Is Load Recorded" },
  { 13, "Output Voltage Step 1" },
  { 14, "Output Voltage Step 2" },
  { 15, "Output Voltage Step 3" },
  { 16, "Output Voltage Step 4" },
  { 17, "Output Voltage Step 5" },
  { 18, "Output Voltage Step 6" },
  { 19, "Output Voltage Step 7" },
  { 20, "Output Voltage Step 8" },
  { 21, "Output Voltage Step 9" },
  { 22, "Output Voltage Step 10" },
  { 23, "Output Voltage Step 11" },
  { 24, "Output Voltage Step 12" },
  { 25, "Output Voltage Step 13" },
  { 26, "Output Voltage Step 14" },
  { 27, "Output Voltage Step 15" },
  { 28, "Output Voltage Step 16" },
  { 29, "Output Voltage Step 17" },
  { 30, "Output Voltage Step 18" },
  { 31, "Output Voltage Step 19" },
  { 32, "Output Voltage Step 20" },
  { 33, "Amperage Step 1" },
  { 34, "Amperage Step 2" },
  { 35, "Amperage Step 3" },
  { 36, "Amperage Step 4" },
  { 37, "Amperage Step 5" },
  { 38, "Amperage Step 6" },
  { 39, "Amperage Step 7" },
  { 40, "Amperage Step 8" },
  { 41, "Amperage Step 9" },
  { 42, "Amperage Step 10" },
  { 43, "Amperage Step 11" },
  { 44, "Amperage Step 12" },
  { 45, "Amperage Step 13" },
  { 46, "Amperage Step 14" },
  { 47, "Amperage Step 15" },
  { 48, "Amperage Step 16" },
  { 49, "Amperage Step 17" },
  { 50, "Amperage Step 18" },
  { 51, "Amperage Step 19" },
  { 52, "Amperage Step 20" },
  { 53, "Voltage Time Step 1" },
  { 54, "Voltage Time Step 2" },
  { 55, "Voltage Time Step 3" },
  { 56, "Voltage Time Step 4" },
  { 57, "Voltage Time Step 5" },
  { 58, "Voltage Time Step 6" },
  { 59, "Voltage Time Step 7" },
  { 60, "Voltage Time Step 8" },
  { 61, "Voltage Time Step 9" },
  { 62, "Voltage Time Step 10" },
  { 63, "Voltage Time Step 11" },
  { 64, "Voltage Time Step 12" },
  { 65, "Voltage Time Step 13" },
  { 66, "Voltage Time Step 14" },
  { 67, "Voltage Time Step 15" },
  { 68, "Voltage Time Step 16" },
  { 69, "Voltage Time Step 17" },
  { 70, "Voltage Time Step 18" },
  { 71, "Voltage Time Step 19" },
  { 72, "Voltage Time Step 20" },
  { 0, NULL }
};
static value_string_ext acn_blob_dimmer_load_properties1_field_name_ext = VALUE_STRING_EXT_INIT(acn_blob_dimmer_load_properties1_field_name);

static const value_string acn_blob_dimmer_rack_properties1_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  { 9, "Space" },
  { 10, "UDN" },
  { 11, "Reserved" },
  { 12, "Rack CID" },
  { 13, "Rack Number" },
  { 14, "Rack Name" },
  { 15, "Rack Model" },
  { 16, "Rack AF Enable" },
  { 17, "Temperature Format" },
  { 18, "Data Loss Behavior DMX A" },
  { 19, "Data Loss Behavior DMX B" },
  { 20, "Data Loss Behavior sACN" },
  { 21, "Data Loss Cross/Wait Time DMX A" },
  { 22, "Data Loss Cross/Wait Time DMX B" },
  { 23, "Data Loss Wait Time sACN" },
  { 24, "Data Loss Fade Time DMX A" },
  { 25, "Data Loss Fade Time DMX B" },
  { 26, "Data Loss Fade Time sACN" },
  { 27, "Data Loss Preset DMX A" },
  { 28, "Data Loss Preset DMX B" },
  { 29, "Data Port Priority DMX A" },
  { 30, "Data Port Priority DMX B" },
  { 31, "Data Port Enabled DMX A" },
  { 32, "Data Port Enabled DMX B" },
  { 33, "Data Port Enabled sACN" },
  { 34, "16 Bit Enabled DMX A" },
  { 35, "16 Bit Enabled DMX B" },
  { 36, "16 Bit Enabled sACN" },
  { 37, "Patch From Home Screen" },
  { 38, "SCR Off Time" },
  { 39, "Time Mode" },
  { 40, "Offset from UTC" },
  { 41, "Universal Hold Last Look Time" },
  { 42, "Reactivate Presets On Boot" },
  { 43, "Voltage High Warning Level" },
  { 44, "Temperature High Warning Level" },
  { 45, "Fan Operation Timing" },
  { 46, "Allow Backplane Communication Errors" },
  { 0, NULL }
};
static value_string_ext acn_blob_dimmer_rack_properties1_field_name_ext = VALUE_STRING_EXT_INIT(acn_blob_dimmer_rack_properties1_field_name);


static const value_string acn_blob_dimmer_rack_status_properties1_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  { 9, "Space" },
  { 10, "UDN" },
  { 11, "Reserved" },
  { 12, "CPU Tempeture" },
  { 13, "Time of Last Reboot" },
  { 14, "Time Now" },
  { 15, "Rack Phasing" },
  { 16, "Power Frequency" },
  { 17, "Phase A Voltage" },
  { 18, "Phase B Voltage" },
  { 19, "Phase C Voltage" },
  { 20, "DMX A Port Status" },
  { 21, "DMX B Port Status" },
  { 22, "Rack AF State" },
  { 23, "Number of Stored Presets for This Rack" },
  { 24, "Number of Lugs in This Rack" },
  { 25, "DSP Version" },
  { 26, "AF Card Version Slot 1" },
  { 27, "AF Card Version Slot 2" },
  { 28, "AF Card Version Slot 3" },
  { 29, "AF Card Version Slot 4" },
  { 30, "HCS08 Version" },
  { 31, "FPGA Version" },
  { 32, "Upload Progress AF Card 1" },
  { 33, "Upload Progress AF Card 2" },
  { 34, "Upload Progress AF Card 3" },
  { 35, "Upload Progress AF Card 4" },
  { 0, NULL }
};
static value_string_ext acn_blob_dimmer_rack_status_properties1_field_name_ext = VALUE_STRING_EXT_INIT(acn_blob_dimmer_rack_status_properties1_field_name);

static const value_string acn_blob_dimmer_status_properties1_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  { 9, "Space" },
  { 10, "UDN" },
  { 11, "Reserved" },
  { 12, "Source Winning Control" },
  { 13, "Priority of Winning Source" },
  { 14, "Winning Level" },
  { 15, "Winning DMX A Level" },
  { 16, "Winning DMX B Level" },
  { 17, "Winning sACN Level" },
  { 18, "Source Winning Control DD" },
  { 19, "Priority of Winning Source DD" },
  { 20, "Winning Level DD" },
  { 21, "Winning DMX A Level DD" },
  { 22, "Winning DMX B Level DD" },
  { 23, "Winning DMX sACN Level DD" },
  { 24, "Actual Load" },
  { 0, NULL }
};
static value_string_ext acn_blob_dimmer_status_properties1_field_name_ext = VALUE_STRING_EXT_INIT(acn_blob_dimmer_status_properties1_field_name);

static const value_string acn_blob_preset_operation_field_name[] = {
  { 1, "Operation Type" },
  { 2, "Preset Number" },
  { 3, "Space" },
  { 0, NULL }
};

static const value_string acn_blob_preset_properties_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  { 9, "Space" },
  { 10, "UDN" },
  { 11, "Reserved" },
  { 12, "Preset Number" },
  { 13, "Preset Name" },
  { 14, "Fade In Time" },
  { 15, "Fade Out Time" },
  { 16, "Priority" },
  { 17, "Levels" },
  { 18, "Level[0]" },
  { 19, "Level[1]" },
  { 20, "Level[2]" },
  { 21, "Level[3]" },
  { 22, "Level[4]" },
  { 23, "Level[5]" },
  { 24, "Level[6]" },
  { 25, "Level[7]" },
  { 26, "Level[8]" },
  { 27, "Level[9]" },
  { 28, "Level[10]" },
  { 29, "Level[11]" },
  { 30, "Level[12]" },
  { 31, "Level[13]" },
  { 32, "Level[14]" },
  { 33, "Level[15]" },
  { 34, "Level[16]" },
  { 35, "Level[17]" },
  { 36, "Level[18]" },
  { 37, "Level[19]" },
  { 38, "Level[20]" },
  { 39, "Level[21]" },
  { 40, "Level[22]" },
  { 41, "Level[23]" },
  { 42, "Level[24]" },
  { 43, "Level[25]" },
  { 44, "Level[26]" },
  { 45, "Level[27]" },
  { 46, "Level[28]" },
  { 47, "Level[29]" },
  { 48, "Level[30]" },
  { 49, "Level[31]" },
  { 50, "Level[32]" },
  { 51, "Level[33]" },
  { 52, "Level[34]" },
  { 53, "Level[35]" },
  { 54, "Level[36]" },
  { 55, "Level[37]" },
  { 56, "Level[38]" },
  { 57, "Level[39]" },
  { 58, "Level[40]" },
  { 59, "Level[41]" },
  { 60, "Level[42]" },
  { 61, "Level[43]" },
  { 62, "Level[44]" },
  { 63, "Level[45]" },
  { 64, "Level[46]" },
  { 65, "Level[47]" },
  { 66, "Level[48]" },
  { 67, "Level[49]" },
  { 68, "Level[50]" },
  { 69, "Level[51]" },
  { 70, "Level[52]" },
  { 71, "Level[53]" },
  { 72, "Level[54]" },
  { 73, "Level[55]" },
  { 74, "Level[56]" },
  { 75, "Level[57]" },
  { 76, "Level[58]" },
  { 77, "Level[59]" },
  { 78, "Level[60]" },
  { 79, "Level[61]" },
  { 80, "Level[62]" },
  { 81, "Level[63]" },
  { 82, "Level[64]" },
  { 83, "Level[65]" },
  { 84, "Level[66]" },
  { 85, "Level[67]" },
  { 86, "Level[68]" },
  { 87, "Level[69]" },
  { 88, "Level[70]" },
  { 89, "Level[71]" },
  { 90, "Level[72]" },
  { 91, "Level[73]" },
  { 92, "Level[74]" },
  { 93, "Level[75]" },
  { 94, "Level[76]" },
  { 95, "Level[77]" },
  { 96, "Level[78]" },
  { 97, "Level[79]" },
  { 98, "Level[80]" },
  { 99, "Level[81]" },
  { 100, "Level[82]" },
  { 101, "Level[83]" },
  { 102, "Level[84]" },
  { 103, "Level[85]" },
  { 104, "Level[86]" },
  { 105, "Level[87]" },
  { 106, "Level[88]" },
  { 107, "Level[89]" },
  { 108, "Level[90]" },
  { 109, "Level[91]" },
  { 110, "Level[92]" },
  { 111, "Level[93]" },
  { 112, "Level[94]" },
  { 113, "Level[95]" },
  { 114, "Level[96]" },
  { 115, "Level[97]" },
  { 116, "Level[98]" },
  { 117, "Level[99]" },
  { 118, "Level[100]" },
  { 119, "Level[101]" },
  { 120, "Level[102]" },
  { 121, "Level[103]" },
  { 122, "Level[104]" },
  { 123, "Level[105]" },
  { 124, "Level[106]" },
  { 125, "Level[107]" },
  { 126, "Level[108]" },
  { 127, "Level[109]" },
  { 128, "Level[110]" },
  { 129, "Level[111]" },
  { 130, "Level[112]" },
  { 131, "Level[113]" },
  { 132, "Level[114]" },
  { 133, "Level[115]" },
  { 134, "Level[116]" },
  { 135, "Level[117]" },
  { 136, "Level[118]" },
  { 137, "Level[119]" },
  { 138, "Level[120]" },
  { 139, "Level[121]" },
  { 140, "Level[122]" },
  { 141, "Level[123]" },
  { 142, "Level[124]" },
  { 143, "Level[125]" },
  { 144, "Level[126]" },
  { 145, "Level[127]" },
  { 146, "Level[128]" },
  { 147, "Level[129]" },
  { 148, "Level[130]" },
  { 149, "Level[131]" },
  { 150, "Level[132]" },
  { 151, "Level[133]" },
  { 152, "Level[134]" },
  { 153, "Level[135]" },
  { 154, "Level[136]" },
  { 155, "Level[137]" },
  { 156, "Level[138]" },
  { 157, "Level[139]" },
  { 158, "Level[140]" },
  { 159, "Level[141]" },
  { 160, "Level[142]" },
  { 161, "Level[143]" },
  { 162, "Level[144]" },
  { 163, "Level[145]" },
  { 164, "Level[146]" },
  { 165, "Level[147]" },
  { 166, "Level[148]" },
  { 167, "Level[149]" },
  { 168, "Level[150]" },
  { 169, "Level[151]" },
  { 170, "Level[152]" },
  { 171, "Level[153]" },
  { 172, "Level[154]" },
  { 173, "Level[155]" },
  { 174, "Level[156]" },
  { 175, "Level[157]" },
  { 176, "Level[158]" },
  { 177, "Level[159]" },
  { 178, "Level[160]" },
  { 179, "Level[161]" },
  { 180, "Level[162]" },
  { 181, "Level[163]" },
  { 182, "Level[164]" },
  { 183, "Level[165]" },
  { 184, "Level[166]" },
  { 185, "Level[167]" },
  { 186, "Level[168]" },
  { 187, "Level[169]" },
  { 188, "Level[170]" },
  { 189, "Level[171]" },
  { 190, "Level[172]" },
  { 191, "Level[173]" },
  { 192, "Level[174]" },
  { 193, "Level[175]" },
  { 194, "Level[176]" },
  { 195, "Level[177]" },
  { 196, "Level[178]" },
  { 197, "Level[179]" },
  { 198, "Level[180]" },
  { 199, "Level[181]" },
  { 200, "Level[182]" },
  { 201, "Level[183]" },
  { 202, "Level[184]" },
  { 203, "Level[185]" },
  { 204, "Level[186]" },
  { 205, "Level[187]" },
  { 206, "Level[188]" },
  { 207, "Level[189]" },
  { 208, "Level[190]" },
  { 209, "Level[191]" },
  { 0, NULL }
};
static value_string_ext acn_blob_preset_properties_field_name_ext = VALUE_STRING_EXT_INIT(acn_blob_preset_properties_field_name);

static const value_string acn_blob_range_type_vals[] = {
  { ACN_BLOB_RANGE_MID, "Middle range Blob" },
  { ACN_BLOB_RANGE_START, "Start range Blob" },
  { ACN_BLOB_RANGE_END, "End Range Blob" },
  { ACN_BLOB_RANGE_SINGLE, "Single Blob" },
  { 0, NULL }
};

static const value_string acn_blob_set_levels_operation_field_name[] = {
  { 1, "Start Dimmer Address" },
  { 2, "End Dimmer Address" },
  { 3, "DD Side" },
  { 4, "Space" },
  { 5, "Level" },
  { 0, NULL }
};

static const value_string acn_blob_time2_field_name[] = {
  { 1, "Time" },
  { 2, "Time Zone Name" },
  { 3, "Time Zone Offset Hour" },
  { 4, "Time Zone Offset Min" },
  { 5, "Time Zone Offset Sec" },
  { 6, "DST Name" },
  { 7, "Start Month" },
  { 8, "Start Week" },
  { 9, "Start Day" },
  { 10, "End Month" },
  { 11, "End Week" },
  { 12, "End Day" },
  { 13, "Timed Event Update" },
  { 14, "Unix Time Zone Environment-compatible Name" },
  { 0, NULL }
};

static const value_string acn_blob_rpc_field_name[] = {
  { 1, "Command" },
  { 2, "Transaction ID" },
  { 3, "Number of Arguments" },
  { 4, "Argument" },
  { 0, NULL }
};

static const value_string acn_blob_dhcp_config_subnet_field_name[] = {
  { 1, "Command" },
  { 2, "Subnet" },
  { 3, "Netmask" },
  { 4, "Given Next Server" },
  { 5, "Given Router" },
  { 6, "Given Netmask" },
  { 7, "Default Lease Time" },
  { 8, "Max Lease Time" },
  { 9, "Given Domain Name" },
  { 10, "Given DNS Servers" },
  { 11, "Given NTP Server" },
  { 12, "Given Time Zone Offset Hour" },
  { 13, "Given Time Zone Offset Minute" },
  { 14, "Given Time Zone Offset Second" },
  { 15, "Given Time Zone DST Name" },
  { 16, "Given Time Zone Start Month" },
  { 17, "Given Time Zone Start Week" },
  { 18, "Given Time Zone Start Day" },
  { 19, "Given Time Zone End Month" },
  { 20, "Given Time Zone End Week" },
  { 21, "Given Time Zone End Day" },
  { 22, "Given UNIX Timezone Name" },
  { 0, NULL }
};

static const value_string acn_blob_dhcp_config_static_route_field_name[] = {
  { 1, "Command" },
  { 2, "Subnet" },
  { 3, "Netmask" },
  { 4, "MAC Address" },
  { 5, "Host Name" },
  { 6, "Address" },
  { 0, NULL }
};

static const value_string acn_blob_energy_management_field_name[] = {
  { 1, "Project ID" },
  { 2, "Space" },
  { 3, "Circuit Power Count" },
  { 4, "Circuit" },
  { 5, "Power" },
  { 6, "Shed Actual" },
  { 7, "Shed Potential" },
  { 0, NULL }
};

static const value_string acn_blob_time3_field_name[] = {
  { 1, "Time" },
  { 2, "Time Zone Index" },
  { 3, "City" },
  { 4, "Country" },
  { 5, "Longitude" },
  { 6, "Latitude" },
  { 7, "UTC Offset Hours" },
  { 8, "UTC Offset Minutes" },
  { 9, "Time Zone Name" },
  { 10, "DST Type" },
  { 11, "DST Start Month" },
  { 12, "DST Start Week" },
  { 13, "DST Start Day" },
  { 14, "DST Start Hours" },
  { 15, "DST Start Minutes" },
  { 16, "DST Start Locality" },
  { 17, "DST Stop Month" },
  { 18, "DST Stop Week" },
  { 19, "DST Stop Day" },
  { 20, "DST Stop Hours" },
  { 21, "DST Stop Minutes" },
  { 22, "DST Stop Locality" },
  { 23, "Timed Event Update" },
  { 0, NULL }
};

static const value_string acn_blob_time3_time_zone_vals[] = {
  { 0, "Aalborg, Denmark - Central European Standard Time : (UTC+01:00)" },
  { 1, "Aberdeen, United Kingdom - Greenwich Mean Time : (UTC)" },
  { 2, "Abu Dhabi, United Arab Emirates - Gulf Standard Time : (UTC+04:00)" },
  { 3, "Abuja, Nigeria - West Africa Time : (UTC+01:00)" },
  { 4, "Accra, Ghana - Greenwich Mean Time : (UTC)" },
  { 5, "Addis Ababa, Ethiopia - Eastern Africa Standard Time : (UTC+03:00)" },
  { 6, "Adelaide, SA, Australia - Australian Central Standard Time : (UTC+09:30)" },
  { 7, "Agana, GU, Guam - Chamorro Standard Time : (UTC+10:00)" },
  { 8, "Ahmadabad, India - India Standard Time : (UTC+05:30)" },
  { 9, "Akita, Japan - Japan Standard Time : (UTC+09:00)" },
  { 10, "Akron, OH, USA - Eastern Standard Time : (UTC-05:00)" },
  { 11, "Albuquerque, NM, USA - Mountain Standard Time : (UTC-07:00)" },
  { 12, "Alexandria, VA, USA - Eastern Standard Time : (UTC-05:00)" },
  { 13, "Algiers, Algeria - Central European Standard Time : (UTC+01:00)" },
  { 14, "Allentown, PA, USA - Eastern Standard Time : (UTC-05:00)" },
  { 15, "Almaty, Kazakhstan - Alma-Ata Time : (UTC+06:00)" },
  { 16, "Amman, Jordan - Arabia Standard Time : (UTC+03:00)" },
  { 17, "Amsterdam, Netherlands - Central European Standard Time : (UTC+01:00)" },
  { 18, "Anaheim, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 19, "Anchorage, AK, USA - Alaska Standard Time : (UTC-09:00)" },
  { 20, "Andorra la Vella, Andorra - Central European Standard Time : (UTC+01:00)" },
  { 21, "Angers, France - Central European Standard Time : (UTC+01:00)" },
  { 22, "Ankara, Turkey - Eastern European Standard Time : (UTC+02:00)" },
  { 23, "Ann Arbor, MI, USA - Eastern Standard Time : (UTC-05:00)" },
  { 24, "Antananarivo, Madagascar - Eastern Africa Standard Time : (UTC+03:00)" },
  { 25, "Antwerp, Belgium - Central European Standard Time : (UTC+01:00)" },
  { 26, "Apia, Samoa - West Samoa Time : (UTC+14:00)" },
  { 27, "Ashgabat, Turkmenistan - Turkmenistan Time : (UTC+05:00)" },
  { 28, "Asmara, Eritrea - Eastern Africa Standard Time : (UTC+03:00)" },
  { 29, "Athens, Greece - Eastern European Standard Time : (UTC+02:00)" },
  { 30, "Atlanta, GA, USA - Eastern Standard Time : (UTC-05:00)" },
  { 31, "Auckland, New Zealand - New Zealand Standard Time : (UTC+12:00)" },
  { 32, "Austin, TX, USA - Central Standard Time : (UTC-06:00)" },
  { 33, "Badajoz, Spain - Central European Standard Time : (UTC+01:00)" },
  { 34, "Baghdad, Iraq - Arabia Standard Time : (UTC+03:00)" },
  { 35, "Bakersfield, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 36, "Baku, Azerbaijan - Azerbaijan Time : (UTC+04:00)" },
  { 37, "Baltimore, MD, USA - Eastern Standard Time : (UTC-05:00)" },
  { 38, "Bamako, Mali - Greenwich Mean Time : (UTC)" },
  { 39, "Bandar Seri Begawan, Brunei - Brunei Darussalam Time : (UTC+08:00)" },
  { 40, "Bangalore, India - India Standard Time : (UTC+05:30)" },
  { 41, "Bangkok, Thailand - Indochina Time : (UTC+07:00)" },
  { 42, "Bangui, Central African Republic - West Africa Time : (UTC+01:00)" },
  { 43, "Banjul, Gambia - Greenwich Mean Time : (UTC)" },
  { 44, "Barcelona, Spain - Central European Standard Time : (UTC+01:00)" },
  { 45, "Bari, Italy - Central European Standard Time : (UTC+01:00)" },
  { 46, "Baton Rouge, LA, USA - Central Standard Time : (UTC-06:00)" },
  { 47, "Beaumont, TX, USA - Central Standard Time : (UTC-06:00)" },
  { 48, "Beijing, China - China Standard Time : (UTC+08:00)" },
  { 49, "Beirut, Lebanon - Eastern European Standard Time : (UTC+02:00)" },
  { 50, "Belem, Brazil - Brasilia Time : (UTC-03:00)" },
  { 51, "Belfast, United Kingdom - Greenwich Mean Time : (UTC)" },
  { 52, "Belgrade, Serbia - Central European Standard Time : (UTC+01:00)" },
  { 53, "Belmopan, Belize - Central Standard Time : (UTC-06:00)" },
  { 54, "Belo Horizonte, Brazil - Brasilia Time : (UTC-03:00)" },
  { 55, "Bergen, Norway - Central European Standard Time : (UTC+01:00)" },
  { 56, "Berkeley, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 57, "Berlin, Germany - Central European Standard Time : (UTC+01:00)" },
  { 58, "Bern, Switzerland - Central European Standard Time : (UTC+01:00)" },
  { 59, "Birmingham, AL, USA - Central Standard Time : (UTC-06:00)" },
  { 60, "Birmingham, United Kingdom - Greenwich Mean Time : (UTC)" },
  { 61, "Bishkek, Kyrgyzstan - Kyrgyzstan Time : (UTC+06:00)" },
  { 62, "Bissau, Guinea-Bissau - Greenwich Mean Time : (UTC)" },
  { 63, "Boise, ID, USA - Mountain Standard Time : (UTC-07:00)" },
  { 64, "Bologna, Italy - Central European Standard Time : (UTC+01:00)" },
  { 65, "Bonn, Germany - Central European Standard Time : (UTC+01:00)" },
  { 66, "Bordeaux, France - Central European Standard Time : (UTC+01:00)" },
  { 67, "Boston, MA, USA - Eastern Standard Time : (UTC-05:00)" },
  { 68, "Bournemouth, United Kingdom - Greenwich Mean Time : (UTC)" },
  { 69, "Brasilia, Brazil - Brasilia Time : (UTC-03:00)" },
  { 70, "Bratislava, Slovakia - Central European Standard Time : (UTC+01:00)" },
  { 71, "Brazzaville, Republic of the Congo - West Africa Time : (UTC+01:00)" },
  { 72, "Bremen, Germany - Central European Standard Time : (UTC+01:00)" },
  { 73, "Brest, France - Central European Standard Time : (UTC+01:00)" },
  { 74, "Bridgeport, CT, USA - Eastern Standard Time : (UTC-05:00)" },
  { 75, "Bridgetown, Barbados - Atlantic Standard Time : (UTC-04:00)" },
  { 76, "Brisbane, QLD, Australia - Australian Eastern Standard Time : (UTC+10:00)" },
  { 77, "Brno, Czech Republic - Central European Standard Time : (UTC+01:00)" },
  { 78, "Brussels, Belgium - Central European Standard Time : (UTC+01:00)" },
  { 79, "Bucharest, Romania - Eastern European Standard Time : (UTC+02:00)" },
  { 80, "Budapest, Hungary - Central European Standard Time : (UTC+01:00)" },
  { 81, "Buenos Aires, Argentina - Argentina Time : (UTC-03:00)" },
  { 82, "Buffalo, NY, USA - Eastern Standard Time : (UTC-05:00)" },
  { 83, "Bujumbura, Burundi - South Africa Standard Time : (UTC+02:00)" },
  { 84, "Cagliari, Italy - Central European Standard Time : (UTC+01:00)" },
  { 85, "Cairo, Egypt - Eastern European Standard Time : (UTC+02:00)" },
  { 86, "Calgary, AB, Canada - Mountain Standard Time : (UTC-07:00)" },
  { 87, "Cali, Colombia - Colombia Time : (UTC-05:00)" },
  { 88, "Canberra, Australia - Australian Eastern Standard Time : (UTC+10:00)" },
  { 89, "Cape Town, South Africa - South Africa Standard Time : (UTC+02:00)" },
  { 90, "Caracas, Venezuela - Venezuelan Standard Time : (UTC-04:30)" },
  { 91, "Cardiff, United Kingdom - Greenwich Mean Time : (UTC)" },
  { 92, "Cedar Rapids, IA, USA - Central Standard Time : (UTC-06:00)" },
  { 93, "Charlotte, NC, USA - Eastern Standard Time : (UTC-05:00)" },
  { 94, "Charlottetown, PE, Canada - Atlantic Standard Time : (UTC-04:00)" },
  { 95, "Chatham Islands, Chatham Islands, New Zealand - Chatham Island Standard Time : (UTC+12:45)" },
  { 96, "Chengdu, China - China Standard Time : (UTC+08:00)" },
  { 97, "Chennai, India - India Standard Time : (UTC+05:30)" },
  { 98, "Chiba, Japan - Japan Standard Time : (UTC+09:00)" },
  { 99, "Chicago, IL, USA - Central Standard Time : (UTC-06:00)" },
  { 100, "Chisinau, Moldova - Eastern European Standard Time : (UTC+02:00)" },
  { 101, "Chongqing, China - China Standard Time : (UTC+08:00)" },
  { 102, "Cincinnati, OH, USA - Eastern Standard Time : (UTC-05:00)" },
  { 103, "Cleveland, OH, USA - Eastern Standard Time : (UTC-05:00)" },
  { 104, "Colorado Springs, CO, USA - Mountain Standard Time : (UTC-07:00)" },
  { 105, "Columbus, GA, USA - Eastern Standard Time : (UTC-05:00)" },
  { 106, "Columbus, OH, USA - Eastern Standard Time : (UTC-05:00)" },
  { 107, "Conakry, Guinea - Greenwich Mean Time : (UTC)" },
  { 108, "Copenhagen, Denmark - Central European Standard Time : (UTC+01:00)" },
  { 109, "Cork, Ireland - Greenwich Mean Time : (UTC)" },
  { 110, "Corpus Christi, TX, USA - Central Standard Time : (UTC-06:00)" },
  { 111, "Curitiba, Brazil - Brasilia Time : (UTC-03:00)" },
  { 112, "Dakar, Senegal - Greenwich Mean Time : (UTC)" },
  { 113, "Dallas, TX, USA - Central Standard Time : (UTC-06:00)" },
  { 114, "Damascus, Syria - Eastern European Standard Time : (UTC+02:00)" },
  { 115, "Dar es Salaam, Tanzania - Eastern Africa Standard Time : (UTC+03:00)" },
  { 116, "Darwin, NT, Australia - Australian Central Standard Time : (UTC+09:30)" },
  { 117, "Dayton, OH, USA - Eastern Standard Time : (UTC-05:00)" },
  { 118, "Delhi, India - India Standard Time : (UTC+05:30)" },
  { 119, "Denver, CO, USA - Mountain Standard Time : (UTC-07:00)" },
  { 120, "Des Moines, IA, USA - Central Standard Time : (UTC-06:00)" },
  { 121, "Detroit, MI, USA - Eastern Standard Time : (UTC-05:00)" },
  { 122, "Dhaka, Bangladesh - Central Asia Standard Time : (UTC+06:00)" },
  { 123, "Dijon, France - Romance Standard Time : (UTC+01:00)" },
  { 124, "Djibouti, Djibouti - Eastern Africa Standard Time : (UTC+03:00)" },
  { 125, "Doha, Qatar - Arabia Standard Time : (UTC+03:00)" },
  { 126, "Dortmund, Germany - Central European Standard Time : (UTC+01:00)" },
  { 127, "Dresden, Germany - Central European Standard Time : (UTC+01:00)" },
  { 128, "Dublin, Ireland - Greenwich Mean Time : (UTC)" },
  { 129, "Dushanbe, Tajikistan - Tajikistan Time : (UTC+05:00)" },
  { 130, "Dusseldorf, Germany - Central European Standard Time : (UTC+01:00)" },
  { 131, "Edinburgh, United Kingdom - Greenwich Mean Time : (UTC)" },
  { 132, "Edmonton, AB, Canada - Mountain Standard Time : (UTC-07:00)" },
  { 133, "El Paso, TX, USA - Mountain Standard Time : (UTC-07:00)" },
  { 134, "Erfurt, Germany - Central European Standard Time : (UTC+01:00)" },
  { 135, "Eucla, WA, Australia - Australian Central Western Standard Time  : (UTC+08:45)" },
  { 136, "Eugene, OR, USA - Pacific Standard Time : (UTC-08:00)" },
  { 137, "Evansville, IN, USA - Eastern Standard Time : (UTC-05:00)" },
  { 138, "Florence, Italy - Central European Standard Time : (UTC+01:00)" },
  { 139, "Fort Defiance, AZ, USA - Mountain Standard Time : (UTC-07:00)" },
  { 140, "Fort Lauderdale, FL, USA - Eastern Standard Time : (UTC-05:00)" },
  { 141, "Fort Wayne, IN, USA - Eastern Standard Time : (UTC-05:00)" },
  { 142, "Fort Worth, TX, USA - Central Standard Time : (UTC-06:00)" },
  { 143, "Fortaleza, Brazil - Brasilia Time : (UTC-03:00)" },
  { 144, "Frankfurt, Germany - Central European Standard Time : (UTC+01:00)" },
  { 145, "Freetown, Sierra Leone - Greenwich Mean Time : (UTC)" },
  { 146, "Freiburg, Germany - Central European Standard Time : (UTC+01:00)" },
  { 147, "Fremont, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 148, "Fresno, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 149, "Fukuoka, Japan - Japan Standard Time : (UTC+09:00)" },
  { 150, "Gaborone, Botswana - Central Africa Time : (UTC+02:00)" },
  { 151, "Galway, Ireland - Greenwich Mean Time : (UTC)" },
  { 152, "Geneva, Switzerland - Central European Standard Time : (UTC+01:00)" },
  { 153, "Genova, Italy - Central European Standard Time : (UTC+01:00)" },
  { 154, "George Town, Cayman Islands - Eastern Standard Time : (UTC-05:00)" },
  { 155, "Georgetown, Guyana - Guyana Time : (UTC-04:00)" },
  { 156, "Glasgow, United Kingdom - Greenwich Mean Time : (UTC)" },
  { 157, "Glendale, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 158, "Granada, Spain - Central European Standard Time : (UTC+01:00)" },
  { 159, "Grand Rapids, MI, USA - Eastern Standard Time : (UTC-05:00)" },
  { 160, "Guadalajara, Mexico - Central Standard Time : (UTC-06:00)" },
  { 161, "Guangzhou, China - China Standard Time : (UTC+08:00)" },
  { 162, "Guatemala City, Guatemala - Central Standard Time : (UTC-06:00)" },
  { 163, "Haikou, China - China Standard Time : (UTC+08:00)" },
  { 164, "Halifax, NS, Canada - Atlantic Standard Time : (UTC-04:00)" },
  { 165, "Hamburg, Germany - Central European Standard Time : (UTC+01:00)" },
  { 166, "Hamilton, Bermuda - Atlantic Standard Time : (UTC-04:00)" },
  { 167, "Hannover, Germany - Central European Standard Time : (UTC+01:00)" },
  { 168, "Hanoi, Vietnam - Indochina Time : (UTC+07:00)" },
  { 169, "Harare, Zimbabwe - Central Africa Time : (UTC+02:00)" },
  { 170, "Harbin, China - China Standard Time : (UTC+08:00)" },
  { 171, "Hartford, CT, USA - Eastern Standard Time : (UTC-05:00)" },
  { 172, "Havana, Cuba - Cuba Standard Time : (UTC-05:00)" },
  { 173, "Helsinki, Finland - Eastern European Standard Time : (UTC+02:00)" },
  { 174, "Hiroshima, Japan - Japan Standard Time : (UTC+09:00)" },
  { 175, "Hobart, TAS, Australia - Australian Eastern Standard Time : (UTC+10:00)" },
  { 176, "Hong Kong SAR, China - China Standard Time : (UTC+08:00)" },
  { 177, "Honiara, Solomon Islands - Solomon Islands Time : (UTC+11:00)" },
  { 178, "Honolulu, HI, USA - Hawaii-Aleutian Standard Time : (UTC-10:00)" },
  { 179, "Houston, TX, USA - Central Standard Time : (UTC-06:00)" },
  { 180, "Hull, PQ, Canada - Eastern Standard Time : (UTC-05:00)" },
  { 181, "Huntsville, AL, USA - Central Standard Time : (UTC-06:00)" },
  { 182, "Indianapolis, IN, USA - Eastern Standard Time : (UTC-05:00)" },
  { 183, "Irkutsk, Russia - Irkutsk Time : (UTC+08:00)" },
  { 184, "Islamabad, Pakistan - Pakistan Standard Time : (UTC+05:00)" },
  { 185, "Istanbul, Turkey - Eastern European Standard Time : (UTC+02:00)" },
  { 186, "Jackson, MS, USA - Central Standard Time : (UTC-06:00)" },
  { 187, "Jacksonville, FL, USA - Eastern Standard Time : (UTC-05:00)" },
  { 188, "Jakarta, Indonesia - Western Indonesian Time : (UTC+07:00)" },
  { 189, "Jerusalem, Israel - Israel Standard Time : (UTC+02:00)" },
  { 190, "Kabul, Afghanistan - Afghanistan Standard Time : (UTC+04:30)" },
  { 191, "Kampala, Uganda - Eastern Africa Standard Time : (UTC+03:00)" },
  { 192, "Kanazawa, Japan - Japan Standard Time : (UTC+09:00)" },
  { 193, "Kansas City, KS, USA - Central Standard Time : (UTC-06:00)" },
  { 194, "Kansas City, MO, USA - Central Standard Time : (UTC-06:00)" },
  { 195, "Karachi, Pakistan - Pakistan Standard Time : (UTC+05:00)" },
  { 196, "Kathmandu, Nepal - Nepal Standard Time : (UTC+05:45)" },
  { 197, "Kelowna, BC, Canada - Pacific Standard Time : (UTC-08:00)" },
  { 198, "Khartoum, Sudan - Eastern Africa Standard Time : (UTC+03:00)" },
  { 199, "Kiev, Ukraine - Eastern European Standard Time : (UTC+02:00)" },
  { 200, "Kigali, Rwanda - Central Africa Time : (UTC+02:00)" },
  { 201, "Kingston, Jamaica - Eastern Standard Time : (UTC-05:00)" },
  { 202, "Kingston, Norfolk Island - Norfolk Time : (UTC+11:30)" },
  { 203, "Kinshasa, Democratic Republic of the Congo - West Africa Time : (UTC+01:00)" },
  { 204, "Kiritimati, Christmas Island, Kiribati - Line Islands Time : (UTC+14:00)" },
  { 205, "Knoxville, TN, USA - Eastern Standard Time : (UTC-05:00)" },
  { 206, "Kobe, Japan - Japan Standard Time : (UTC+09:00)" },
  { 207, "Kochi, Japan - Japan Standard Time : (UTC+09:00)" },
  { 208, "Kolkata (Calcutta), India - India Standard Time : (UTC+05:30)" },
  { 209, "Krasnoyarsk, Russia - Krasnoyarsk Time : (UTC+07:00)" },
  { 210, "Kuala Lumpur, Malaysia - Singapore Standard Time : (UTC+08:00)" },
  { 211, "Kuwait, Kuwait - Arabia Standard Time : (UTC+03:00)" },
  { 212, "Kwangju, Korea - Korea Standard Time : (UTC+09:00)" },
  { 213, "Kyoto, Japan - Japan Standard Time : (UTC+09:00)" },
  { 214, "La Paz, Bolivia - Bolivia Time : (UTC-04:00)" },
  { 215, "Lansing, MI, USA - Eastern Standard Time : (UTC-05:00)" },
  { 216, "Laredo, TX, USA - Central Standard Time : (UTC-06:00)" },
  { 217, "Las Vegas, NV, USA - Pacific Standard Time : (UTC-08:00)" },
  { 218, "Leipzig, Germany - Central European Standard Time : (UTC+01:00)" },
  { 219, "Lexington, KY, USA - Eastern Standard Time : (UTC-05:00)" },
  { 220, "Lhasa, China - China Standard Time : (UTC+08:00)" },
  { 221, "Libreville, Gabon - West Africa Time : (UTC+01:00)" },
  { 222, "Lille, France - Central European Standard Time : (UTC+01:00)" },
  { 223, "Lilongwe, Malawi - Central Africa Time : (UTC+02:00)" },
  { 224, "Lima, Peru - Peru Time : (UTC-05:00)" },
  { 225, "Limerick, Ireland - Greenwich Mean Time : (UTC)" },
  { 226, "Limoges, France - Central European Standard Time : (UTC+01:00)" },
  { 227, "Lincoln, NE, USA - Central Standard Time : (UTC-06:00)" },
  { 228, "Lisbon, Portugal - Greenwich Mean Time : (UTC)" },
  { 229, "Little Rock, AR, USA - Central Standard Time : (UTC-06:00)" },
  { 230, "Liverpool, United Kingdom - Greenwich Mean Time : (UTC)" },
  { 231, "Ljubljana, Slovenia - Central European Standard Time : (UTC+01:00)" },
  { 232, "London, United Kingdom - Greenwich Mean Time : (UTC)" },
  { 233, "Londonderry, United Kingdom - Greenwich Mean Time : (UTC)" },
  { 234, "Long Beach, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 235, "Lord Howe Island, Lord Howe Island, Australia - Lord Howe Standard Time : (UTC+10:30)" },
  { 236, "Los Angeles, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 237, "Louisville, KY, USA - Eastern Standard Time : (UTC-05:00)" },
  { 238, "Luanda, Angola - West Africa Time : (UTC+01:00)" },
  { 239, "Lubbock, TX, USA - Central Standard Time : (UTC-06:00)" },
  { 240, "Lusaka, Zambia - Central Africa Time : (UTC+02:00)" },
  { 241, "Luxembourg, Luxembourg - Central European Standard Time : (UTC+01:00)" },
  { 242, "Lyon, France - Central European Standard Time : (UTC+01:00)" },
  { 243, "Madison, WI, USA - Central Standard Time : (UTC-06:00)" },
  { 244, "Madrid, Spain - Central European Standard Time : (UTC+01:00)" },
  { 245, "Malabo, Equatorial Guinea - West Africa Time : (UTC+01:00)" },
  { 246, "Malaga, Spain - Central European Standard Time : (UTC+01:00)" },
  { 247, "Managua, Nicaragua - Central Standard Time : (UTC-06:00)" },
  { 248, "Manama, Bahrain - Arabia Standard Time : (UTC+03:00)" },
  { 249, "Manaus, Brazil - Amazon Time : (UTC-04:00)" },
  { 250, "Manchester, United Kingdom - Greenwich Mean Time : (UTC)" },
  { 251, "Manila, Philippines - Philippine Time : (UTC+08:00)" },
  { 252, "Maputo, Mozambique - Central Africa Time : (UTC+02:00)" },
  { 253, "Maracaibo, Venezuela - Venezuelan Standard Time : (UTC-04:30)" },
  { 254, "Marseille, France - Central European Standard Time : (UTC+01:00)" },
  { 255, "Maseru, Lesotho - South Africa Standard Time : (UTC+02:00)" },
  { 256, "Masqat, Oman - Gulf Standard Time : (UTC+04:00)" },
  { 257, "Mbabane, Swaziland - South Africa Standard Time : (UTC+02:00)" },
  { 258, "Medellin, Colombia - Colombia Time : (UTC-05:00)" },
  { 259, "Melbourne, VIC, Australia - Australian Eastern Standard Time : (UTC+10:00)" },
  { 260, "Memphis, TN, USA - Central Standard Time : (UTC-06:00)" },
  { 261, "Metz, France - Central European Standard Time : (UTC+01:00)" },
  { 262, "Mexico City, Mexico - Central Standard Time : (UTC-06:00)" },
  { 263, "Miami, FL, USA - Eastern Standard Time : (UTC-05:00)" },
  { 264, "Milan, Italy - Central European Standard Time : (UTC+01:00)" },
  { 265, "Milwaukee, WI, USA - Central Standard Time : (UTC-06:00)" },
  { 266, "Minneapolis, MN, USA - Central Standard Time : (UTC-06:00)" },
  { 267, "Minsk, Belarus - Further-Eastern European Time : (UTC+03:00)" },
  { 268, "Mobile, AL, USA - Central Standard Time : (UTC-06:00)" },
  { 269, "Mogadishu, Somalia - Eastern Africa Standard Time : (UTC+03:00)" },
  { 270, "Monaco, Monaco - Central European Standard Time : (UTC+01:00)" },
  { 271, "Monrovia, Liberia - Greenwich Mean Time : (UTC)" },
  { 272, "Monterrey, Mexico - Central Standard Time : (UTC-06:00)" },
  { 273, "Montevideo, Uruguay - Uruguay Time : (UTC-03:00)" },
  { 274, "Montreal, PQ, Canada - Eastern Standard Time : (UTC-05:00)" },
  { 275, "Morioka, Japan - Japan Standard Time : (UTC+09:00)" },
  { 276, "Moscow, Russia - Moscow Standard Time : (UTC+03:00)" },
  { 277, "Mumbai, India - India Standard Time : (UTC+05:30)" },
  { 278, "Munich, Germany - Central European Standard Time : (UTC+01:00)" },
  { 279, "Murmansk, Russia - Moscow Standard Time : (UTC+03:00)" },
  { 280, "N'Djamena, Chad - West Africa Time : (UTC+01:00)" },
  { 281, "Nagano, Japan - Japan Standard Time : (UTC+09:00)" },
  { 282, "Nagasaki, Japan - Japan Standard Time : (UTC+09:00)" },
  { 283, "Nagoya, Japan - Japan Standard Time : (UTC+09:00)" },
  { 284, "Nairobi, Kenya - Eastern Africa Standard Time : (UTC+03:00)" },
  { 285, "Nanjing, China - China Standard Time : (UTC+08:00)" },
  { 286, "Naples, Italy - Central European Standard Time : (UTC+01:00)" },
  { 287, "Nashville, TN, USA - Central Standard Time : (UTC-06:00)" },
  { 288, "Nassau, Bahamas - Eastern Standard Time : (UTC-05:00)" },
  { 289, "New Orleans, LA, USA - Central Standard Time : (UTC-06:00)" },
  { 290, "New York, NY, USA - Eastern Standard Time : (UTC-05:00)" },
  { 291, "Newark, NJ, USA - Eastern Standard Time : (UTC-05:00)" },
  { 292, "Niamey, Niger - West Africa Time : (UTC+01:00)" },
  { 293, "Nicosia, Cyprus - Eastern European Standard Time : (UTC+02:00)" },
  { 294, "Norwich, United Kingdom - Greenwich Mean Time : (UTC)" },
  { 295, "Nouakchott, Mauritania - Greenwich Mean Time : (UTC)" },
  { 296, "Novosibirsk, Russia - Novosibirsk Time : (UTC+06:00)" },
  { 297, "Nuku'alofa, Tonga - Tonga Standard Time : (UTC+13:00)" },
  { 298, "Nuuk, Greenland - West Greenland Time : (UTC-03;00)" },
  { 299, "Oakland, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 300, "Oklahoma City, OK, USA - Central Standard Time : (UTC-06:00)" },
  { 301, "Omaha, NE, USA - Central Standard Time : (UTC-06:00)" },
  { 302, "Orlando, FL, USA - Eastern Standard Time : (UTC-05:00)" },
  { 303, "Osaka, Japan - Japan Standard Time : (UTC+09:00)" },
  { 304, "Oshawa, ON, Canada - Eastern Standard Time : (UTC-05:00)" },
  { 305, "Oslo, Norway - Central European Standard Time : (UTC+01:00)" },
  { 306, "Ottawa, ON, Canada - Eastern Standard Time : (UTC-05:00)" },
  { 307, "Ouagadougou, Burkina Faso - Greenwich Mean Time : (UTC)" },
  { 308, "Overland Park, KS, USA - Central Standard Time : (UTC-06:00)" },
  { 309, "Oviedo, Spain - Central European Standard Time : (UTC+01:00)" },
  { 310, "Palermo, Italy - Central European Standard Time : (UTC+01:00)" },
  { 311, "Palma de Mallorca, Spain - Central European Standard Time : (UTC+01:00)" },
  { 312, "Panama City, Panama - Eastern Standard Time : (UTC-05:00)" },
  { 313, "Paramaribo, Surinam - Suriname Time : (UTC-03:00)" },
  { 314, "Paris, France - Central European Standard Time : (UTC+01:00)" },
  { 315, "Pasadena, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 316, "Pasadena, TX, USA - Central Standard Time : (UTC-06:00)" },
  { 317, "Peoria, IL, USA - Central Standard Time : (UTC-06:00)" },
  { 318, "Perth, WA, Australia - Australia Western Standard Time : (UTC+08:00)" },
  { 319, "Perugia, Italy - Central European Standard Time : (UTC+01:00)" },
  { 320, "Philadelphia, PA, USA - Eastern Standard Time : (UTC-05:00)" },
  { 321, "Phnom Penh, Cambodia - Indochina Time : (UTC+07:00)" },
  { 322, "Phoenix, AZ, USA - Mountain Standard Time : (UTC-07:00)" },
  { 323, "Pisa, Italy - Central European Standard Time : (UTC+01:00)" },
  { 324, "Pittsburgh, PA, USA - Eastern Standard Time : (UTC-05:00)" },
  { 325, "Plymouth, United Kingdom - Greenwich Mean Time : (UTC)" },
  { 326, "Port Louis, Mauritius - Mauritius Time : (UTC+04:00)" },
  { 327, "Port Moresby, Papua New Guinea - Papua New Guinea Time : (UTC+10:00)" },
  { 328, "Port-au-Prince, Haiti - Eastern Standard Time : (UTC-05:00)" },
  { 329, "Port-of-Spain, Trinidad and Tobago - Atlantic Standard Time : (UTC-04:00)" },
  { 330, "Portland, OR, USA - Pacific Standard Time : (UTC-08:00)" },
  { 331, "Porto Alegre, Brazil - Brasilia Time : (UTC-03:00)" },
  { 332, "Porto, Portugal - Western European Time : (UTC)" },
  { 333, "Porto-Novo, Benin - West Africa Time : (UTC+01:00)" },
  { 334, "Prague, Czech Republic - Central European Standard Time : (UTC+01:00)" },
  { 335, "Praia, Cape Verde - Cape Verde Time : (UTC-01:00)" },
  { 336, "Pretoria, South Africa - South Africa Standard Time : (UTC+02:00)" },
  { 337, "Providence, RI, USA - Eastern Standard Time : (UTC-05:00)" },
  { 338, "Puebla de Zaragoza, Mexico - Eastern Standard Time : (UTC-05:00)" },
  { 339, "Pusan, Korea - Korea Standard Time : (UTC+09:00)" },
  { 340, "Pyongyang, North Korea - Korea Standard Time : (UTC+09:00)" },
  { 341, "Quebec City, PQ, Canada - Eastern Standard Time : (UTC-05:00)" },
  { 342, "Quito, Ecuador - Ecuador Time : (UTC-05:00)" },
  { 343, "Rabat, Morocco - Western European Time : (UTC)" },
  { 344, "Raleigh, NC, USA - Eastern Standard Time : (UTC-05:00)" },
  { 345, "Recife, Brazil - Brasilia Time : (UTC-03:00)" },
  { 346, "Redmond, WA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 347, "Reggio Calabria, Italy - Central European Standard Time : (UTC+01:00)" },
  { 348, "Regina, SK, Canada - Central Standard Time : (UTC-06:00)" },
  { 349, "Richmond, VA, USA - Eastern Standard Time : (UTC-05:00)" },
  { 350, "Riga, Latvia - Eastern European Standard Time : (UTC+02:00)" },
  { 351, "Rio de Janeiro, Brazil - Brasilia Time : (UTC-03:00)" },
  { 352, "Riyadh, Saudi Arabia - Arabia Standard Time : (UTC+03:00)" },
  { 353, "Rockford, IL, USA - Central Standard Time : (UTC-06:00)" },
  { 354, "Rome, Italy - Central European Standard Time : (UTC+01:00)" },
  { 355, "Roseau, Dominica - Atlantic Standard Time : (UTC-04:00)" },
  { 356, "Roswell, NM, USA - Mountain Standard Time : (UTC-07:00)" },
  { 357, "Rouen, France - Central European Standard Time : (UTC+01:00)" },
  { 358, "Sacramento, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 359, "Saint John, NB, Canada - Atlantic Standard Time : (UTC-04:00)" },
  { 360, "Saint Louis, MO, USA - Central Standard Time : (UTC-06:00)" },
  { 361, "Saint Paul, MN, USA - Central Standard Time : (UTC-06:00)" },
  { 362, "Salt Lake City, UT, USA - Mountain Standard Time : (UTC-07:00)" },
  { 363, "Salvador, Brazil - Brasilia Time : (UTC-03:00)" },
  { 364, "Salzburg, Austria - Central European Standard Time : (UTC+01:00)" },
  { 365, "San Antonio, TX, USA - Central Standard Time : (UTC-06:00)" },
  { 366, "San Bernardino, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 367, "San Diego, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 368, "San Francisco, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 369, "San Jose, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 370, "San Salvador, El Salvador - Central Standard Time : (UTC-06:00)" },
  { 371, "Sana'a, Yemen - Arabia Standard Time : (UTC+03:00)" },
  { 372, "Santa Ana, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 373, "Santa Rosa, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 374, "Santander, Spain - Central European Standard Time : (UTC+01:00)" },
  { 375, "Santiago, Chile - Chile Standard Time : (UTC-04:00)" },
  { 376, "Santo Domingo, Dominican Republic - Atlantic Standard Time : (UTC-04:00)" },
  { 377, "Sao Paulo, Brazil - Brasilia Time : (UTC-03:00)" },
  { 378, "Sapporo, Japan - Japan Standard Time : (UTC+09:00)" },
  { 379, "Sarajevo, Bosnia and Herzegovina - Central European Standard Time : (UTC+01:00)" },
  { 380, "Saskatoon, SK, Canada - Central Standard Time : (UTC-06:00)" },
  { 381, "Savannah, GA, USA - Eastern Standard Time : (UTC-05:00)" },
  { 382, "Seattle, WA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 383, "Sendai, Japan - Japan Standard Time : (UTC+09:00)" },
  { 384, "Seoul, Korea - Korea Standard Time : (UTC+09:00)" },
  { 385, "Sevilla, Spain - Central European Standard Time : (UTC+01:00)" },
  { 386, "Shanghai, China - China Standard Time : (UTC+08:00)" },
  { 387, "Shreveport, LA, USA - Central Standard Time : (UTC-06:00)" },
  { 388, "Simi Valley, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 389, "Singapore, Singapore - Singapore Standard Time : (UTC+08:00)" },
  { 390, "Sioux Falls, SD, USA - Central Standard Time : (UTC-06:00)" },
  { 391, "Skopje, F.Y.R.O. Macedonia - Central European Standard Time : (UTC+01:00)" },
  { 392, "Sofia, Bulgaria - Eastern European Standard Time : (UTC+02:00)" },
  { 393, "South Bend, IN, USA - Eastern Standard Time : (UTC-05:00)" },
  { 394, "Spokane, WA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 395, "Springfield, IL, USA - Central Standard Time : (UTC-06:00)" },
  { 396, "Springfield, MA, USA - Eastern Standard Time : (UTC-05:00)" },
  { 397, "Springfield, MO, USA - Central Standard Time : (UTC-06:00)" },
  { 398, "Sri Jayawardenepura, Sri Lanka - India Standard Time : (UTC+05:30)" },
  { 399, "St. Catharines, ON, Canada - Eastern Standard Time : (UTC-05:00)" },
  { 400, "St. John's, NF, Canada - Newfoundland Standard Time : (UTC-03:30)" },
  { 401, "St. Petersburg, FL, USA - Eastern Standard Time : (UTC-05:00)" },
  { 402, "St. Petersburg, Russia - Moscow Standard Time : (UTC+03:00)" },
  { 403, "Stockholm, Sweden - Central European Standard Time : (UTC+01:00)" },
  { 404, "Stockton, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 405, "Strasbourg, France - Central European Standard Time : (UTC+01:00)" },
  { 406, "Stuttgart, Germany - Central European Standard Time : (UTC+01:00)" },
  { 407, "Sucre, Bolivia - Bolivia Time : (UTC-04:00)" },
  { 408, "Sunnyvale, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 409, "Suva, Fiji Islands - Fiji Standard Time : (UTC+12:00)" },
  { 410, "Sydney, NSW, Australia - Australian Eastern Standard Time : (UTC+10:00)" },
  { 411, "Syracuse, NY, USA - Eastern Standard Time : (UTC-05:00)" },
  { 412, "T'bilisi, Georgia - Georgia Standard Time : (UTC+04:00)" },
  { 413, "Taejon, Korea - Korea Standard Time : (UTC+09:00)" },
  { 414, "Taiohae, Marquesas Islands,  French Polynesia - Marquesas Time : (UTC-9:30)" },
  { 415, "Taipei, Taiwan - China Standard Time : (UTC+08:00)" },
  { 416, "Tallinn, Estonia - Eastern European Standard Time : (UTC+02:00)" },
  { 417, "Tampa, FL, USA - Eastern Standard Time : (UTC-05:00)" },
  { 418, "Taranto, Italy - Central European Standard Time : (UTC+01:00)" },
  { 419, "Tashkent, Uzbekistan - Uzbekistan Time : (UTC+05:00)" },
  { 420, "Tegucigalpa, Honduras - Central Standard Time : (UTC-06:00)" },
  { 421, "Tehran, Iran - Iran Standard Time : (UTC+03:30)" },
  { 422, "Tel Aviv, Israel - Israel Standard Time : (UTC+02:00)" },
  { 423, "The Hague, Netherlands - Central European Standard Time : (UTC+01:00)" },
  { 424, "Thimphu, Bhutan - Bhutan Time : (UTC+06:00)" },
  { 425, "Thunder Bay, ON, Canada - Eastern Standard Time : (UTC-05:00)" },
  { 426, "Tirana, Albania - Central European Standard Time : (UTC+01:00)" },
  { 427, "Tokyo, Japan - Japan Standard Time : (UTC+09:00)" },
  { 428, "Toledo, OH, USA - Eastern Standard Time : (UTC-05:00)" },
  { 429, "Torino, Italy - Central European Standard Time : (UTC+01:00)" },
  { 430, "Toronto, ON, Canada - Eastern Standard Time : (UTC-05:00)" },
  { 431, "Torrance, CA, USA - Pacific Standard Time : (UTC-08:00)" },
  { 432, "Toulouse, France - Central European Standard Time : (UTC+01:00)" },
  { 433, "Tripoli, Libya - Eastern European Standard Time : (UTC+02:00)" },
  { 434, "Tucson, AZ, USA - Mountain Standard Time : (UTC-07:00)" },
  { 435, "Tulsa, OK, USA - Central Standard Time : (UTC-06:00)" },
  { 436, "Tunis, Tunisia - West Africa Time : (UTC+01:00)" },
  { 437, "Ulaanbaatar, Mongolia - Ulaanbaatar Time : (UTC+08:00)" },
  { 438, "Urumqi, China - China Standard Time : (UTC+08:00)" },
  { 439, "Vaduz, Liechtenstein - Central European Standard Time : (UTC+01:00)" },
  { 440, "Valencia, Spain - Central European Standard Time : (UTC+01:00)" },
  { 441, "Valletta, Malta - Central European Standard Time : (UTC+01:00)" },
  { 442, "Vancouver, BC, Canada - Pacific Standard Time : (UTC-08:00)" },
  { 443, "Vatican City, Vatican City - Central European Standard Time : (UTC+01:00)" },
  { 444, "Venice, Italy - Central European Standard Time : (UTC+01:00)" },
  { 445, "Veracruz, Mexico - Central Standard Time : (UTC-06:00)" },
  { 446, "Victoria, Seychelles - Seychelles Time : (UTC+04:00)" },
  { 447, "Vienna, Austria - Central European Standard Time : (UTC+01:00)" },
  { 448, "Vientiane, Laos - Indochina Time : (UTC+07:00)" },
  { 449, "Vilnius, Lithuania - Eastern European Standard Time : (UTC+02:00)" },
  { 450, "Vladivostok, Russia - Vladivostok Standard Time : (UTC+10:00)" },
  { 451, "Volgograd, Russia - Moscow Standard Time : (UTC+03:00)" },
  { 452, "Waco, TX, USA - Central Standard Time : (UTC-06:00)" },
  { 453, "Warsaw, Poland - Central European Standard Time : (UTC+01:00)" },
  { 454, "Washington, DC, USA - Eastern Standard Time : (UTC-05:00)" },
  { 455, "Wellington, New Zealand - New Zealand Standard Time : (UTC+12:00)" },
  { 456, "Whitehorse, YT, Canada - Pacific Standard Time : (UTC-08:00)" },
  { 457, "Windhoek, Namibia - West Africa Time : (UTC+01:00)" },
  { 458, "Winnipeg, MB, Canada - Central Standard Time : (UTC-06:00)" },
  { 459, "Wuhan, China - China Standard Time : (UTC+08:00)" },
  { 460, "Xian, China - China Standard Time : (UTC+08:00)" },
  { 461, "Yakutsk, Russia - Yakutsk Standard Time : (UTC+09:00)" },
  { 462, "Yangon, Myanmar - Myanmar Standard Time : (UTC+06:30)" },
  { 463, "Yekaterinburg, Russia - Yekaterinburg Standard Time : (UTC+05:00)" },
  { 464, "Yellowknife, NT, Canada - Mountain Standard Time : (UTC-07:00)" },
  { 465, "Yerevan, Armenia - Armenia Time : (UTC+04:00)" },
  { 466, "Yokohama, Japan - Japan Standard Time : (UTC+09:00)" },
  { 467, "Zagreb, Croatia - Central European Standard Time : (UTC+01:00)" },
  { 468, "Zaragoza, Spain - Central European Standard Time : (UTC+01:00)" },
  { 469, "Zurich, Switzerland - Central European Standard Time : (UTC+01:00)" },
  { 0, NULL }
};

static const value_string acn_blob_time3_dst_vals[] = {
  { 0, "DST US" },
  { 1, "DST Europe" },
  { 2, "DST Funky" },
  { 3, "DST None" },
  { 0, NULL }
};

static const value_string acn_blob_time3_month_vals[] = {
  { 0, "None" },
  { 1, "January" },
  { 2, "February" },
  { 3, "March" },
  { 4, "April" },
  { 5, "May" },
  { 6, "June" },
  { 7, "July" },
  { 8, "August" },
  { 9, "September" },
  { 10, "October" },
  { 11, "November" },
  { 12, "December" },
  { 0, NULL }
};

static const value_string acn_blob_time3_week_vals[] = {
  { 0, "None" },
  { 1, "First" },
  { 2, "Second" },
  { 3, "Third" },
  { 4, "Fourth" },
  { 5, "Last" },
  { 0, NULL }
};

static const value_string acn_blob_time3_day_vals[] = {
  { 0, "Sunday" },
  { 1, "Monday" },
  { 2, "Tuesday" },
  { 3, "Wednesday" },
  { 4, "Thursday" },
  { 5, "Friday" },
  { 6, "Saturday" },
  { 0, NULL }
};

static const value_string acn_blob_time3_locality_vals[] = {
  { 0, "LOCAL" },
  { 1, "UTC" },
  { 0, NULL }
};

static const value_string acn_blob_energy_cost_field_name[] = {
  { 1, "Month" },
  { 2, "Day" },
  { 3, "Cost per Hour" },
  { 0, NULL }
};

static const value_string acn_blob_sequence_operation_field_name[] = {
  { 1, "Operation Type" },
  { 2, "Space" },
  { 3, "Sequence Number" },
  { 3, "Step Number" },
  { 0, NULL }
};

static const value_string acn_blob_sequence_step_properties_field_name[] = {
  { 1, "System" },
  { 2, "Processor" },
  { 3, "Rack" },
  { 4, "Lug" },
  { 5, "Module" },
  { 6, "Station" },
  { 7, "Port" },
  { 8, "Subdevice" },
  { 9, "Space" },
  { 10, "UDN" },
  { 11, "Reserved" },
  { 12, "Sequence Number" },
  { 13, "Step Number" },
  { 14, "Fade Time" },
  { 15, "Hold Time" },
  { 16, "Level[0]" },
  { 17, "Level[1]" },
  { 18, "Level[2]" },
  { 19, "Level[3]" },
  { 20, "Level[4]" },
  { 21, "Level[5]" },
  { 22, "Level[6]" },
  { 23, "Level[7]" },
  { 24, "Level[8]" },
  { 25, "Level[9]" },
  { 26, "Level[10]" },
  { 27, "Level[11]" },
  { 28, "Level[12]" },
  { 29, "Level[13]" },
  { 30, "Level[14]" },
  { 31, "Level[15]" },
  { 32, "Level[16]" },
  { 33, "Level[17]" },
  { 34, "Level[18]" },
  { 35, "Level[19]" },
  { 36, "Level[20]" },
  { 37, "Level[21]" },
  { 38, "Level[22]" },
  { 39, "Level[23]" },
  { 40, "Level[24]" },
  { 41, "Level[25]" },
  { 42, "Level[26]" },
  { 43, "Level[27]" },
  { 44, "Level[28]" },
  { 45, "Level[29]" },
  { 46, "Level[30]" },
  { 47, "Level[31]" },
  { 48, "Level[32]" },
  { 49, "Level[33]" },
  { 50, "Level[34]" },
  { 51, "Level[35]" },
  { 52, "Level[36]" },
  { 53, "Level[37]" },
  { 54, "Level[38]" },
  { 55, "Level[39]" },
  { 56, "Level[40]" },
  { 57, "Level[41]" },
  { 58, "Level[42]" },
  { 59, "Level[43]" },
  { 60, "Level[44]" },
  { 61, "Level[45]" },
  { 62, "Level[46]" },
  { 63, "Level[47]" },
  { 64, "Level[48]" },
  { 65, "Level[49]" },
  { 66, "Level[50]" },
  { 67, "Level[51]" },
  { 68, "Level[52]" },
  { 69, "Level[53]" },
  { 70, "Level[54]" },
  { 71, "Level[55]" },
  { 72, "Level[56]" },
  { 73, "Level[57]" },
  { 74, "Level[58]" },
  { 75, "Level[59]" },
  { 76, "Level[60]" },
  { 77, "Level[61]" },
  { 78, "Level[62]" },
  { 79, "Level[63]" },
  { 80, "Level[64]" },
  { 81, "Level[65]" },
  { 82, "Level[66]" },
  { 83, "Level[67]" },
  { 84, "Level[68]" },
  { 85, "Level[69]" },
  { 86, "Level[70]" },
  { 87, "Level[71]" },
  { 88, "Level[72]" },
  { 89, "Level[73]" },
  { 90, "Level[74]" },
  { 91, "Level[75]" },
  { 92, "Level[76]" },
  { 93, "Level[77]" },
  { 94, "Level[78]" },
  { 95, "Level[79]" },
  { 96, "Level[80]" },
  { 97, "Level[81]" },
  { 98, "Level[82]" },
  { 99, "Level[83]" },
  { 100, "Level[84]" },
  { 101, "Level[85]" },
  { 102, "Level[86]" },
  { 103, "Level[87]" },
  { 104, "Level[88]" },
  { 105, "Level[89]" },
  { 106, "Level[90]" },
  { 107, "Level[91]" },
  { 108, "Level[92]" },
  { 109, "Level[93]" },
  { 110, "Level[94]" },
  { 111, "Level[95]" },
  { 112, "Level[96]" },
  { 113, "Level[97]" },
  { 114, "Level[98]" },
  { 115, "Level[99]" },
  { 116, "Level[100]" },
  { 117, "Level[101]" },
  { 118, "Level[102]" },
  { 119, "Level[103]" },
  { 120, "Level[104]" },
  { 121, "Level[105]" },
  { 122, "Level[106]" },
  { 123, "Level[107]" },
  { 124, "Level[108]" },
  { 125, "Level[109]" },
  { 126, "Level[110]" },
  { 127, "Level[111]" },
  { 128, "Level[112]" },
  { 129, "Level[113]" },
  { 130, "Level[114]" },
  { 131, "Level[115]" },
  { 132, "Level[116]" },
  { 133, "Level[117]" },
  { 134, "Level[118]" },
  { 135, "Level[119]" },
  { 136, "Level[120]" },
  { 137, "Level[121]" },
  { 138, "Level[122]" },
  { 139, "Level[123]" },
  { 140, "Level[124]" },
  { 141, "Level[125]" },
  { 142, "Level[126]" },
  { 143, "Level[127]" },
  { 144, "Level[128]" },
  { 145, "Level[129]" },
  { 146, "Level[130]" },
  { 147, "Level[131]" },
  { 148, "Level[132]" },
  { 149, "Level[133]" },
  { 150, "Level[134]" },
  { 151, "Level[135]" },
  { 152, "Level[136]" },
  { 153, "Level[137]" },
  { 154, "Level[138]" },
  { 155, "Level[139]" },
  { 156, "Level[140]" },
  { 157, "Level[141]" },
  { 158, "Level[142]" },
  { 159, "Level[143]" },
  { 160, "Level[144]" },
  { 161, "Level[145]" },
  { 162, "Level[146]" },
  { 163, "Level[147]" },
  { 164, "Level[148]" },
  { 165, "Level[149]" },
  { 166, "Level[150]" },
  { 167, "Level[151]" },
  { 168, "Level[152]" },
  { 169, "Level[153]" },
  { 170, "Level[154]" },
  { 171, "Level[155]" },
  { 172, "Level[156]" },
  { 173, "Level[157]" },
  { 174, "Level[158]" },
  { 175, "Level[159]" },
  { 176, "Level[160]" },
  { 177, "Level[161]" },
  { 178, "Level[162]" },
  { 179, "Level[163]" },
  { 180, "Level[164]" },
  { 181, "Level[165]" },
  { 182, "Level[166]" },
  { 183, "Level[167]" },
  { 184, "Level[168]" },
  { 185, "Level[169]" },
  { 186, "Level[170]" },
  { 187, "Level[171]" },
  { 188, "Level[172]" },
  { 189, "Level[173]" },
  { 190, "Level[174]" },
  { 191, "Level[175]" },
  { 192, "Level[176]" },
  { 193, "Level[177]" },
  { 194, "Level[178]" },
  { 195, "Level[179]" },
  { 196, "Level[180]" },
  { 197, "Level[181]" },
  { 198, "Level[182]" },
  { 199, "Level[183]" },
  { 200, "Level[184]" },
  { 201, "Level[185]" },
  { 202, "Level[186]" },
  { 203, "Level[187]" },
  { 204, "Level[188]" },
  { 205, "Level[189]" },
  { 206, "Level[190]" },
  { 207, "Level[191]" },
  { 0, NULL }
};
static value_string_ext acn_blob_sequence_step_properties_field_name_ext = VALUE_STRING_EXT_INIT(acn_blob_sequence_step_properties_field_name);

static const value_string acn_blob_type_vals[] = {
  { ACN_BLOB_IPV4,                           "IPv4 Blob" },
  { ACN_BLOB_IPV6,                           "IPv6 Blob" },
  { ACN_BLOB_ERROR1,                         "Error Blob v1" },
  { ACN_BLOB_ERROR2,                         "Error Blob v2" },
  { ACN_BLOB_METADATA,                       "Metadata" },
  { ACN_BLOB_METADATA_DEVICES,               "Metadata Devices" },
  { ACN_BLOB_METADATA_TYPES,                 "Metadata Types" },
  { ACN_BLOB_TIME1,                          "Time Blob (deprecated 1)" },
  { ACN_BLOB_DIMMER_PROPERTIES,              "Dimmer Properties Blob v1" },
  { ACN_BLOB_DIMMER_LOAD_PROPERTIES,         "Dimmer Load Properties Blob v1" },
  { ACN_BLOB_DIMMING_RACK_PROPERTIES,        "Dimming Rack Properties Blob v1" },
  { ACN_BLOB_DIMMING_RACK_STATUS_PROPERTIES, "Dimming Rack Status Properties Blob v1" },
  { ACN_BLOB_DIMMER_STATUS_PROPERTIES,       "Dimmer Status Properties Blob v1" },
  { ACN_BLOB_SET_LEVELS_OPERATION,           "Set Levels Operation Blob" },
  { ACN_BLOB_PRESET_OPERATION,               "Preset Operation Blob" },
  { ACN_BLOB_ADVANCED_FEATURES_OPERATION,    "Advanced Features Operation Blob" },
  { ACN_BLOB_DIRECT_CONTROL_OPERATION,       "Direct Control Operation Blob" },
  { ACN_BLOB_GENERATE_CONFIG_OPERATION,      "Generate Config Operation Blob" },
  { ACN_BLOB_ERROR3,                         "Error Blob v3" },
  { ACN_BLOB_DIMMER_PROPERTIES2,             "Dimmer Properties Blob v2" },
  { ACN_BLOB_DIMMER_LOAD_PROPERTIES2,        "Dimmer Load Properties Blob v2" },
  { ACN_BLOB_DIMMER_RACK_PROPERTIES2,        "Dimming Rack Properties Blob v2" },
  { ACN_BLOB_DIMMER_RACK_STATUS_PROPERTIES2, "Dimming Rack Status Properties Blob v2" },
  { ACN_BLOB_DIMMER_STATUS_PROPERTIES2,      "Dimmer Status Properties Blob v2" },
  { ACN_BLOB_TIME2,                          "Time Blob (deprecated 2)" },
  { ACN_BLOB_RPC,                            "RPC Blob" },
  { ACN_BLOB_DHCP_CONFIG_SUBNET,             "DHCP Config Subnet Blob" },
  { ACN_BLOB_DHCP_CONFIG_STATIC_ROUTE,       "DHCP Config Static Route Blob" },
  { ACN_BLOB_ENERGY_MANAGEMENT,              "Energy Management Blob" },
  { ACN_BLOB_PRESET_PROPERTIES,              "Preset Properties Blob" },
  { ACN_BLOB_TIME3,                          "Time Blob v2" },
  { ACN_BLOB_ENERGY_COST,                    "Energy Cost Blob" },
  { ACN_BLOB_SEQUENCE_OPERATIONS,            "Sequence Operations Blob" },
  { ACN_BLOB_SEQUENCE_STEP_PROPERTIES,       "Sequence Step Properties Blob" },
  { 0, NULL }
};

static const value_string acn_dmp_vector_vals[] = {
  { ACN_DMP_VECTOR_UNKNOWN,            "Unknown"},
  { ACN_DMP_VECTOR_GET_PROPERTY,       "Get Property"},
  { ACN_DMP_VECTOR_SET_PROPERTY,       "Set Property"},
  { ACN_DMP_VECTOR_GET_PROPERTY_REPLY, "Get property reply"},
  { ACN_DMP_VECTOR_EVENT,              "Event"},
  { ACN_DMP_VECTOR_MAP_PROPERTY,       "Map Property"},
  { ACN_DMP_VECTOR_UNMAP_PROPERTY,     "Unmap Property"},
  { ACN_DMP_VECTOR_SUBSCRIBE,          "Subscribe"},
  { ACN_DMP_VECTOR_UNSUBSCRIBE,        "Unsubscribe"},
  { ACN_DMP_VECTOR_GET_PROPERTY_FAIL,  "Get Property Fail"},
  { ACN_DMP_VECTOR_SET_PROPERTY_FAIL,  "Set Property Fail"},
  { ACN_DMP_VECTOR_MAP_PROPERTY_FAIL,  "Map Property Fail"},
  { ACN_DMP_VECTOR_SUBSCRIBE_ACCEPT,   "Subscribe Accept"},
  { ACN_DMP_VECTOR_SUBSCRIBE_REJECT,   "Subscribe Reject"},
  { ACN_DMP_VECTOR_ALLOCATE_MAP,       "Allocate Map"},
  { ACN_DMP_VECTOR_ALLOCATE_MAP_REPLY, "Allocate Map Reply"},
  { ACN_DMP_VECTOR_DEALLOCATE_MAP,     "Deallocate Map" },
  { ACN_DMP_VECTOR_SYNC_EVENT,         "Sync Event" },
  { 0,       NULL },
};

static const value_string acn_ip_address_type_vals[] = {
  { ACN_ADDR_NULL,   "Null"},
  { ACN_ADDR_IPV4,   "IPv4"},
  { ACN_ADDR_IPV6,   "IPv6"},
  { ACN_ADDR_IPPORT, "Port"},
  { 0,       NULL },
};

static const value_string acn_refuse_code_vals[] = {
  { ACN_REFUSE_CODE_NONSPECIFIC,    "Nonspecific" },
  { ACN_REFUSE_CODE_ILLEGAL_PARAMS, "Illegal Parameters" },
  { ACN_REFUSE_CODE_LOW_RESOURCES,  "Low Resources" },
  { ACN_REFUSE_CODE_ALREADY_MEMBER, "Already Member" },
  { ACN_REFUSE_CODE_BAD_ADDR_TYPE,  "Bad Address Type" },
  { ACN_REFUSE_CODE_NO_RECIP_CHAN,  "No Reciprocal Channel" },
  { 0,       NULL },
};

static const value_string acn_reason_code_vals[] = {
  { ACN_REASON_CODE_NONSPECIFIC,         "Nonspecific" },
  { ACN_REASON_CODE_NO_RECIP_CHAN,       "No Reciprocal Channel" },
  { ACN_REASON_CODE_CHANNEL_EXPIRED,     "Channel Expired" },
  { ACN_REASON_CODE_LOST_SEQUENCE,       "Lost Sequence" },
  { ACN_REASON_CODE_SATURATED,           "Saturated" },
  { ACN_REASON_CODE_TRANS_ADDR_CHANGING, "Transport Address Changing" },
  { ACN_REASON_CODE_ASKED_TO_LEAVE,      "Asked to Leave" },
  { ACN_REASON_CODE_NO_RECIPIENT,        "No Recipient"},
  { 0,       NULL },
};

static const value_string acn_dmp_reason_code_vals[] = {
  { ACN_DMP_REASON_CODE_NONSPECIFIC,                "Nonspecific" },
  { ACN_DMP_REASON_CODE_NOT_A_PROPERTY,             "Not a Property" },
  { ACN_DMP_REASON_CODE_WRITE_ONLY,                 "Write Only" },
  { ACN_DMP_REASON_CODE_NOT_WRITABLE,               "Not Writable" },
  { ACN_DMP_REASON_CODE_DATA_ERROR,                 "Data Error" },
  { ACN_DMP_REASON_CODE_MAPS_NOT_SUPPORTED,         "Maps not Supported" },
  { ACN_DMP_REASON_CODE_SPACE_NOT_AVAILABLE,        "Space not Available" },
  { ACN_DMP_REASON_CODE_PROP_NOT_MAPPABLE,          "Property not Mappable"},
  { ACN_DMP_REASON_CODE_MAP_NOT_ALLOCATED,          "Map not Allocated"},
  { ACN_DMP_REASON_CODE_SUBSCRIPTION_NOT_SUPPORTED, "Subscription not Supported"},
  { ACN_DMP_REASON_CODE_NO_SUBSCRIPTIONS_SUPPORTED, "No Subscriptions Supported"},
  { 0,       NULL },
};

static const enum_val_t dmx_display_view[] = {
  { "hex"    , "Hex    ",     ACN_PREF_DMX_DISPLAY_HEX  },
  { "decimal", "Decimal",     ACN_PREF_DMX_DISPLAY_DEC  },
  { "percent", "Percent",     ACN_PREF_DMX_DISPLAY_PER  },
  { NULL, NULL, 0 }
};

static const enum_val_t dmx_display_line_format[] = {
  { "20 per line", "20 per line",     ACN_PREF_DMX_DISPLAY_20PL  },
  { "16 per line", "16 per line",     ACN_PREF_DMX_DISPLAY_16PL  },
  { NULL, NULL, 0 }
};


static const value_string magic_pdu_subtypes[] = {
  { MAGIC_V1,           "V1" },
  { MAGIC_COMMAND,      "V2 Command" },
  { MAGIC_REPLY,        "V2 Reply" },
  { MAGIC_REPLY_TYPE_3, "V2 Reply Type 3" },
  { 0, NULL }
};

static const value_string magic_v1command_vals[] = {
  { V1_SWITCH_TO_NET1, "Switch to Net1" },
  { V1_SWITCH_TO_NET2, "Switch to Net2" },
  { V1_BOOTP,          "bootp" },
  { 0, NULL }
};

static const value_string magic_command_vals[] = {
  { V2_CMD_SWITCH_TO_NET1,          "Switch to Net1 mode" },
  { V2_CMD_SWITCH_TO_NET2,          "Switch to Net2 mode" },
  { V2_CMD_DOWNLOAD,                "Code download" },
  { V2_CMD_SOFTBOOT,                "Soft reboot" },
  { V2_CMD_PHYSICAL_BEACON,         "Physical beacon" },
  { V2_CMD_NETWORK_BEACON,          "Network beacon" },
  { V2_CMD_SWITCH_TO_ACN,           "Switch to ACN mode" },
  { V2_CMD_SWITCH_TO_DYNAMIC_IP,    "Switch to dynamic IP address configuration" },
  { V2_CMD_EXTENDED_NETWORK_BEACON, "Extended network beacon" },
  { V2_CMD_IP_CONFIGURATION,        "IP configuration" },
  { V2_CMD_RESTORE_FACTORY_DEFAULT, "Restore factory default" },
  { V2_CMD_PHYSICAL_BEACON_BY_CID,  "Physical beacon by CID" },
  { V2_CMD_NET2_DOWNLOAD,           "NET2 code download and reboot" },
  { 0, NULL }
};

static const value_string magic_reset_lease_vals[] = {
  { MAGIC_SWITCH_TO_DYNAMIC_MAINTAIN_LEASE, "Maintain lease" },
  { MAGIC_SWITCH_TO_DYNAMIC_RESET_LEASE,    "Reset lease" },
  { 0, NULL }
};

static const value_string magic_ip_configuration_vals[] = {
  { MAGIC_DYNAMIC_IP_MAINTAIN_LEASE, "Dynamic IP, maintain lease" },
  { MAGIC_DYNAMIC_IP_RESET_LEASE,    "Dynamic IP, reset lease" },
  { MAGIC_STATIC_IP,                 "Static IP" },
  { 0, NULL }
};

static const value_string rdmnet_llrp_vector_vals[] = {
  { RDMNET_LLRP_VECTOR_PROBE_REQUEST, "LLRP probe request" },
  { RDMNET_LLRP_VECTOR_PROBE_REPLY,   "LLRP probe reply" },
  { RDMNET_LLRP_VECTOR_RDM_CMD,       "LLRP RDM command" },
  { 0, NULL }
};

static const value_string rdmnet_llrp_probe_request_vals[] = {
  { VECTOR_PROBE_REQUEST_DATA, "Vector probe request data" },
  { 0, NULL }
};

static const value_string rdmnet_llrp_probe_reply_vals[] = {
  { VECTOR_PROBE_REPLY_DATA, "Vector probe reply data" },
  { 0, NULL }
};

static const value_string rdmnet_llrp_probe_reply_component_type_vals[] = {
  { RDMNET_LLRP_COMPONENT_TYPE_RPT_DEVICE,      "Device target" },
  { RDMNET_LLRP_COMPONENT_TYPE_RPT_CONTROLLER,  "Controller target" },
  { RDMNET_LLRP_COMPONENT_TYPE_BROKER,          "Broker target" },
  { RDMNET_LLRP_COMPONENT_TYPE_NON_RDMNET,      "Non RDMnet target" },
  { 0, NULL }
};

static const value_string rdmnet_llrp_rdm_command_start_code_vals[] = {
  { RDMNET_LLRP_VECTOR_RDM_CMD_START_CODE,  "RDM Start Code" },
  { 0, NULL }
};

static const value_string rdmnet_broker_disconnect_reason_vals[] = {
  { RDMNET_RPT_DISCONNECT_SHUTDOWN,               "Component shut down" },
  { RDMNET_RPT_DISCONNECT_CAPACITY_EXHAUSTED,     "Component capacity exhausted" },
  { RDMNET_RPT_DISCONNECT_HARDWARE_FAULT,         "Component hardware fault" },
  { RDMNET_RPT_DISCONNECT_SOFTWARE_FAULT,         "Component software fault" },
  { RDMNET_RPT_DISCONNECT_SOFTWARE_RESET,         "Component software reset" },
  { RDMNET_RPT_DISCONNECT_INCORRECT_SCOPE,        "Broker incorrect scope" },
  { RDMNET_RPT_DISCONNECT_LLRP_RECONFIGURE,       "Component reconfigured by LLRP" },
  { RDMNET_RPT_DISCONNECT_RPT_RECONFIGURE,        "Component reconfigured by RPT" },
  { RDMNET_RPT_DISCONNECT_USER_RECONFIGURE,       "Component reconfigured by user" },
  { 0, NULL }
};

static const value_string rdmnet_rpt_vector_vals[] = {
  { RDMNET_RPT_VECTOR_REQUEST,       "Request" },
  { RDMNET_RPT_VECTOR_STATUS,        "Status" },
  { RDMNET_RPT_VECTOR_NOTIFICATION,  "Notification" },
  { 0, NULL }
};

static const value_string rdmnet_rpt_request_vals[] = {
  { RDMNET_RPT_VECTOR_REQUEST_RDM_CMD,  "RDM Command" },
  { 0, NULL }
};

static const value_string rdmnet_rpt_status_vector_vals[] = {
  { RDMNET_RPT_VECTOR_STATUS_UNKNOWN_RPT_UID,        "Unknown RPT UID" },
  { RDMNET_RPT_VECTOR_STATUS_RDM_TIMEOUT,            "RDM Timeout" },
  { RDMNET_RPT_VECTOR_STATUS_RDM_INVALID_RESPONSE,   "Invalid RDM Response" },
  { RDMNET_RPT_VECTOR_STATUS_UNKNOWN_RDM_UID,        "Unknown RDM UID" },
  { RDMNET_RPT_VECTOR_STATUS_UNKNOWN_ENDPOINT,       "Unknown Endpoint" },
  { RDMNET_RPT_VECTOR_STATUS_BROADCAST_COMPLETE,     "Broadcast Complete" },
  { RDMNET_RPT_VECTOR_STATUS_UNKNOWN_VECTOR,         "Unknown Vector" },
  { RDMNET_RPT_VECTOR_STATUS_INVALID_MESSAGE,        "Invalid Message" },
  { RDMNET_RPT_VECTOR_STATUS_INVALID_COMMAND_CLASS,  "Invalid Command Class" },
  { 0, NULL }
};

static const value_string rdmnet_rpt_notification_vals[] = {
  { RDMNET_RPT_VECTOR_NOTIFICATION_RDM_CMD,  "RDM Command" },
  { 0, NULL }
};

static const value_string rdmnet_rpt_request_rdm_command_start_code_vals[] = {
  { RDMNET_RPT_VECTOR_RDM_CMD_RD_DATA,  "RDM Start Code" },
  { 0, NULL }
};

static const value_string rdmnet_broker_vector_vals[] = {
  { RDMNET_BROKER_VECTOR_FETCH_CLIENT_LIST,       "Fetch client list" },
  { RDMNET_BROKER_VECTOR_CONNECTED_CLIENT_LIST,   "Connected client list" },
  { RDMNET_BROKER_VECTOR_CLIENT_ADD,              "Add client" },
  { RDMNET_BROKER_VECTOR_CLIENT_REMOVE,           "Remove client" },
  { RDMNET_BROKER_VECTOR_CLIENT_ENTRY_CHANGE,     "Change client entry" },
  { RDMNET_BROKER_VECTOR_CONNECT,                 "Connect" },
  { RDMNET_BROKER_VECTOR_CONNECT_REPLY,           "Connect reply" },
  { RDMNET_BROKER_VECTOR_CLIENT_ENTRY_UPDATE,     "Update client entry" },
  { RDMNET_BROKER_VECTOR_REDIRECT_V4,             "Redirect IP v4" },
  { RDMNET_BROKER_VECTOR_REDIRECT_V6,             "Redirect IP v6" },
  { RDMNET_BROKER_VECTOR_DISCONNECT,              "Disconnect" },
  { RDMNET_BROKER_VECTOR_NULL,                    "Null" },
  { RDMNET_BROKER_VECTOR_REQUEST_DYNAMIC_UIDS,    "Request Dynamic UIDs" },
  { RDMNET_BROKER_VECTOR_ASSIGNED_DYNAMIC_UIDS,   "Assigned Dynamic UIDs" },
  { RDMNET_BROKER_VECTOR_FETCH_DYNAMIC_UID_LIST,  "Fetch dynamic UID List" },
  { 0, NULL }
};

static const value_string rdmnet_broker_status_code_vals[] = {
  { RDMNET_BROKER_CONNECT_OK,                    "Ok" },
  { RDMNET_BROKER_CONNECT_SCOPE_MISMATCH,        "Scope mismatch" },
  { RDMNET_BROKER_CONNECT_CAPACITY_EXCEEDED,     "Capacity exceeded" },
  { RDMNET_BROKER_CONNECT_DUPLICATE_UID,         "Duplicate UID" },
  { RDMNET_BROKER_CONNECT_INVALID_CLIENT_ENTRY,  "Invalid client entry" },
  { RDMNET_BROKER_CONNECT_INVALID_UID,           "Invalid UID" },
  { 0, NULL }
};

static const value_string dynamic_uid_mapping_status_code_vals[] = {
  { RDMNET_DYNAMIC_UID_STATUS_OK,                 "Dynamic UID Status Ok" },
  { RDMNET_DYNAMIC_UID_STATUS_INVALID_REQUEST,    "Dynamic UID Status Invalid Request" },
  { RDMNET_DYNAMIC_UID_STATUS_UID_NOT_FOUND,      "Dynamic UID Status UID Not Found" },
  { RDMNET_DYNAMIC_UID_STATUS_DUPLICATE_RID,      "Dynamic UID Status Duplicate RID" },
  { RDMNET_DYNAMIC_UID_STATUS_CAPACITY_EXHAUSTED, "Dynamic UID Status Capacity Exhausted" },
  { 0, NULL }
};

static const value_string broker_client_protocol_vals[] = {
  { RDMNET_CLIENT_PROTOCOL_RPT,  "Client Protocol RPT" },
  { RDMNET_CLIENT_PROTOCOL_EPT,  "Client Protocol EPT" },
  { 0, NULL }
};

static const value_string broker_client_rpt_client_type_vals[] = {
  { RDMNET_RPT_CLIENT_TYPE_DEVICE,      "Device" },
  { RDMNET_RPT_CLIENT_TYPE_CONTROLLER,  "Controller" },
  { 0, NULL }
};

static const value_string rdmnet_ept_vector_vals[] = {
  { RDMNET_EPT_VECTOR_DATA,    "Data" },
  { RDMNET_EPT_VECTOR_STATUS,  "Status" },
  { 0, NULL }
};

static dissector_handle_t rdm_handle;

/******************************************************************************/
/* Test to see if it is a Magic Bullet Packet                                 */
static gboolean
is_magic(tvbuff_t *tvb)
{
  static const guint8 magic_protocol_id = 15;

  if (tvb_get_guint8(tvb, 0) == magic_protocol_id)
    return TRUE;

  return FALSE;
}

/******************************************************************************/
/* Dissect Magic Bullet                                                       */
static int
dissect_magic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8 pdu_subtype;
  gint offset = 0;
  const char *pdu_subtype_string;
  proto_tree *ti, *subtype_item;
  proto_tree *magic_tree;
  guint32 command;
  gint32 str_len;
  guint32 major, minor, patch, aud, crit, build;
  gchar *buffer;

  /* Set the protocol column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAGIC");

  /* Create our tree */
  ti = proto_tree_add_item(tree, proto_magic, tvb, offset, -1, ENC_NA);
  magic_tree = proto_item_add_subtree(ti, ett_magic);

  /* Protocol ID */
  proto_tree_add_item(magic_tree, hf_magic_protocol_id, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  /* PDU Type */
  pdu_subtype = tvb_get_guint8(tvb, offset);
  pdu_subtype_string = val_to_str(pdu_subtype, magic_pdu_subtypes, "Unknown (0x%02x)");

  /* Adjust info column */
  col_clear(pinfo->cinfo, COL_INFO);
  col_add_fstr(pinfo->cinfo, COL_INFO, "MAGIC - %s", pdu_subtype_string);

  /* Append subtype description */
  proto_item_append_text(ti, ": %s", pdu_subtype_string);

  subtype_item = proto_tree_add_item(magic_tree, hf_magic_pdu_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  proto_tree_add_item(magic_tree, hf_magic_major_version, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  proto_tree_add_item(magic_tree, hf_magic_minor_version, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  switch (pdu_subtype) {
    case MAGIC_V1:
      proto_tree_add_item(magic_tree, hf_magic_v1command_vals, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      offset += 4;
      break;

    case MAGIC_COMMAND:
      /* note, v2 is big-endian */
      proto_tree_add_item_ret_uint(magic_tree, hf_magic_command_vals, tvb, offset, 4, ENC_BIG_ENDIAN, &command);
      offset += 4;
      /* deal with variable parameter */
      switch (command) {
        case V2_CMD_DOWNLOAD:
          proto_tree_add_item(magic_tree, hf_magic_command_tftp, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          break;
        case V2_CMD_PHYSICAL_BEACON:
          proto_tree_add_item(magic_tree, hf_magic_command_beacon_duration, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          break;
        case V2_CMD_NETWORK_BEACON:
          proto_tree_add_item(magic_tree, hf_magic_command_beacon_duration, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          break;
        case V2_CMD_SWITCH_TO_DYNAMIC_IP:
          proto_tree_add_item(magic_tree, hf_magic_command_reset_lease, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          break;
        case V2_CMD_EXTENDED_NETWORK_BEACON:
          proto_tree_add_item(magic_tree, hf_magic_command_beacon_duration, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          break;
        case V2_CMD_IP_CONFIGURATION:
          proto_tree_add_item(magic_tree, hf_magic_command_cid, tvb, offset, 16, ENC_BIG_ENDIAN);
          offset += 16;
          proto_tree_add_item(magic_tree, hf_magic_command_ip_configuration, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          proto_tree_add_item(magic_tree, hf_magic_command_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          proto_tree_add_item(magic_tree, hf_magic_command_subnet_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          proto_tree_add_item(magic_tree, hf_magic_command_gateway, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          break;
        case V2_CMD_RESTORE_FACTORY_DEFAULT:
          proto_tree_add_item(magic_tree, hf_magic_command_cid, tvb, offset, 16, ENC_BIG_ENDIAN);
          offset += 16;
          break;
        case V2_CMD_PHYSICAL_BEACON_BY_CID:
          proto_tree_add_item(magic_tree, hf_magic_command_cid, tvb, offset, 16, ENC_BIG_ENDIAN);
          offset += 16;
          proto_tree_add_item(magic_tree, hf_magic_command_beacon_duration, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          break;
        /* case V2_CMD_SOFTBOOT:       */
        /* case V2_CMD_SWITCH_TO_NET1: */
        /* case V2_CMD_SWITCH_TO_NET2: */
        /* case V2_CMD_SWITCH_TO_ACN:  */
        /* case V2_CMD_NET2_DOWNLOAD:  */
      }
      break;

    case MAGIC_REPLY:
      /* note, v2 is big-endian */
      proto_tree_add_item(magic_tree, hf_magic_reply_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(magic_tree, hf_magic_reply_subnet_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(magic_tree, hf_magic_reply_gateway, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(magic_tree, hf_magic_reply_tftp, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;

      /* encoded and display version */
      major = tvb_get_guint8(tvb, offset++);
      minor = tvb_get_guint8(tvb, offset++);
      patch = tvb_get_guint8(tvb, offset++);
      aud = tvb_get_guint8(tvb, offset++);
      crit = tvb_get_guint8(tvb, offset++);
      build = tvb_get_ntohs(tvb, offset);
      offset += 2;

      offset -= 7;
      buffer = wmem_strdup_printf(wmem_packet_scope(), "%d.%d.%d.%d.%d.%d", major, minor, patch, aud, crit, build);
      proto_tree_add_string(magic_tree, hf_magic_reply_version, tvb, offset, 7, buffer);
      offset += 7;

      /* Device Type Name string */
      proto_tree_add_item_ret_length(magic_tree, hf_magic_reply_device_type_name, tvb, offset, 1, ENC_NA|ENC_ASCII, &str_len);
      offset += str_len;

      /* Default Name string */
      proto_tree_add_item_ret_length(magic_tree, hf_magic_reply_default_name, tvb, offset, 1, ENC_NA|ENC_ASCII, &str_len);
      offset += str_len;

      /* User Name string */
      proto_tree_add_item_ret_length(magic_tree, hf_magic_reply_user_name, tvb, offset, 1, ENC_NA|ENC_ASCII, &str_len);
      offset += str_len;
      break;

    case MAGIC_REPLY_TYPE_3:
      command = tvb_get_ntohl(tvb, offset);
      proto_tree_add_item(magic_tree, hf_magic_command_vals, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(magic_tree, hf_magic_reply_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(magic_tree, hf_magic_reply_subnet_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(magic_tree, hf_magic_reply_gateway, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(magic_tree, hf_magic_reply_tftp, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(magic_tree, hf_magic_reply_cid, tvb, offset, 16, ENC_BIG_ENDIAN);
      offset += 16;
      proto_tree_add_item(magic_tree, hf_magic_reply_dcid, tvb, offset, 16, ENC_BIG_ENDIAN);
      offset += 16;

      /* encoded and display version */
      major = tvb_get_guint8(tvb, offset++);
      minor = tvb_get_guint8(tvb, offset++);
      patch = tvb_get_guint8(tvb, offset++);
      aud = tvb_get_guint8(tvb, offset++);
      crit = tvb_get_guint8(tvb, offset++);
      build = tvb_get_ntohs(tvb, offset);
      offset += 2;

      offset -= 7;
      buffer = wmem_strdup_printf(wmem_packet_scope(), "%d.%d.%d.%d.%d.%d", major, minor, patch, aud, crit, build);
      proto_tree_add_string(magic_tree, hf_magic_reply_version, tvb, offset, 7, buffer);
      offset += 7;

      /* Device Type Name string */
      proto_tree_add_item_ret_length(magic_tree, hf_magic_reply_device_type_name, tvb, offset, 1, ENC_NA|ENC_ASCII, &str_len);
      offset += str_len;

      /* Default Name string */
      proto_tree_add_item_ret_length(magic_tree, hf_magic_reply_default_name, tvb, offset, 1, ENC_NA|ENC_ASCII, &str_len);
      offset += str_len;

      /* User Name string */
      proto_tree_add_item_ret_length(magic_tree, hf_magic_reply_user_name, tvb, offset, 1, ENC_NA|ENC_ASCII, &str_len);
      offset += str_len;
      break;

    default:
      expert_add_info(pinfo, subtype_item, &ei_magic_reply_invalid_type);
      offset = tvb_captured_length(tvb);
  }
  return offset;
}

/******************************************************************************/
/* Test to see if it is an ACN or an RDMnet Packet over UDP                   */
static gboolean
is_acn_or_rdmnet_over_udp(tvbuff_t *tvb, guint32 *protocol_id)
{
  static const char acn_packet_id[] = "ASC-E1.17\0\0\0";  /* must be 12 bytes */
  guint32  offset;
  guint8   pdu_flags;

  if (tvb_captured_length(tvb) < (4+sizeof(acn_packet_id) + 6))
    return FALSE;

  /* Check the bytes in octets 4 - 16 */
  if (tvb_memeql(tvb, 4, (const guint8*)acn_packet_id, sizeof(acn_packet_id)-1) != 0)
    return FALSE;

  offset = 16;
  pdu_flags = tvb_get_guint8(tvb, offset) & 0xf0;
  if (pdu_flags & ACN_PDU_FLAG_L) {
    /* length bit is set: there are three length bytes */
    offset += 3;
  }
  else {
    /* length bit is clear: there are two length bytes */
    offset += 2;
  }

  *protocol_id = tvb_get_ntohl(tvb, offset);
  return TRUE;
}

/******************************************************************************/
/* Test to see if it is an RDMnet Packet over TCP                             */
static gboolean
is_rdmnet_over_tcp(tvbuff_t *tvb)
{
  static const char acn_packet_id[] = "ASC-E1.17\0\0\0";  /* must be 12 bytes */
  guint32  offset;
  guint32  protocol_id;
  guint8   pdu_flags;

  if (tvb_captured_length(tvb) < (4+sizeof(acn_packet_id))) {
    return FALSE;
  }

  /* Check the bytes in octets 0 - 12 */
  if (tvb_memeql(tvb, 0, (const guint8*)acn_packet_id, sizeof(acn_packet_id)-1) != 0) {
    return FALSE;
  }

  offset = 16;
  pdu_flags = tvb_get_guint8(tvb, offset) & 0xf0;
  if (pdu_flags & ACN_PDU_FLAG_L) {
    /* length bit is set: there are three length bytes */
    offset += 3;
  } else {
    /* length bit is clear: there are two length bytes */
    offset += 2;
  }

  protocol_id = tvb_get_ntohl(tvb, offset);
  if ((protocol_id == ACN_PROTOCOL_ID_BROKER) ||
      (protocol_id == ACN_PROTOCOL_ID_RPT) ||
      (protocol_id == ACN_PROTOCOL_ID_EPT)) {
    return TRUE;
  }

  return FALSE;
}

/******************************************************************************/
/* Test to see if it is an ACN Packet                                         */
static gboolean
is_acn(tvbuff_t *tvb)
{
  guint32  protocol_id;

  if (is_acn_or_rdmnet_over_udp(tvb, &protocol_id)) {
    if ((protocol_id == ACN_PROTOCOL_ID_DMX) ||
        (protocol_id == ACN_PROTOCOL_ID_DMX_2) ||
        (protocol_id == ACN_PROTOCOL_ID_SDT))
      return TRUE;
  }

  return FALSE;
}

/******************************************************************************/
/* Test to see if it is an ACN Packet                                         */
static gboolean
is_rdmnet_over_udp(tvbuff_t *tvb)
{
  guint32  protocol_id;

  if (is_acn_or_rdmnet_over_udp(tvb, &protocol_id) && (protocol_id == ACN_PROTOCOL_ID_LLRP)) {
      return TRUE;
  }

  return FALSE;
}


/******************************************************************************/
/* Heuristic dissector                                                        */
static gboolean
dissect_acn_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  /* This is a heuristic dissector, which means we get all the UDP
   * traffic not sent to a known dissector and not claimed by
   * a heuristic dissector called before us!
   */

  if (is_acn(tvb)) {
    dissect_acn(tvb, pinfo, tree);
    return TRUE;
  }

  if (is_magic(tvb)) {
    dissect_magic(tvb, pinfo, tree);
    return TRUE;
  }

  /* abort if it is NOT an ACN or Magic Bullet packet */
  return FALSE;
}


/******************************************************************************/
/* Heuristic dissector                                                        */
static gboolean
dissect_rdmnet_over_udp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  if (!is_rdmnet_over_udp(tvb)) {
    return FALSE;
  }

  dissect_rdmnet(tvb, pinfo, tree, 0, 1);
  return TRUE;
}

#define RDMNET_TCP_FRAME_HEADER_LENGTH  16

static int
dissect_one_rdmnet_over_tcp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  if (!is_rdmnet_over_tcp(tvb)) {
    return 0;
  }

  dissect_rdmnet(tvb, pinfo, tree, 0, 0);
  return tvb_captured_length(tvb);
}


static guint
get_rdmnet_tcp_message_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  return (guint)tvb_get_ntohl(tvb, offset + 12) + 16;
}

static int
dissect_rdmnet_over_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, RDMNET_TCP_FRAME_HEADER_LENGTH,
                   get_rdmnet_tcp_message_length, dissect_one_rdmnet_over_tcp_message, data);
  return tvb_captured_length(tvb);
}


/******************************************************************************/
/* Heuristic dissector                                                        */
static gboolean
dissect_rdmnet_over_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  dissect_rdmnet_over_tcp(tvb, pinfo, tree, data);
  return TRUE;
}


/******************************************************************************/
/*  Adds tree branch for channel owner info block                             */
static guint32
acn_add_channel_owner_info_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_item *pi;
  proto_tree *this_tree;
  guint32     session_count;
  guint32     x;

  this_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_acn_channel_owner_info_block, NULL,
                                    "Channel Owner Info Block");

  proto_tree_add_item(this_tree, hf_acn_member_id, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(this_tree, hf_acn_channel_number, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  offset = acn_add_address(tvb, pinfo, this_tree, offset, "Destination Address:");
  offset = acn_add_address(tvb, pinfo, this_tree, offset, "Source Address:");

  session_count = tvb_get_ntohs(tvb, offset);
  for (x=0; x<session_count; x++) {
    pi = proto_tree_add_item(this_tree, hf_acn_protocol_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(pi, " #%d",  x+1);
    offset += 4;
  }
  return offset;
}

/******************************************************************************/
/*  Adds tree branch for channel member info block                            */
static guint32
acn_add_channel_member_info_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_item *pi;
  proto_tree *this_tree;
  guint32     session_count;
  guint32     x;

  this_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_acn_channel_member_info_block,
                                NULL, "Channel Member Info Block");

  proto_tree_add_item(this_tree, hf_acn_member_id, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(this_tree, hf_acn_cid, tvb, offset, 16, ENC_BIG_ENDIAN);
  offset += 16;
  proto_tree_add_item(this_tree, hf_acn_channel_number, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  offset = acn_add_address(tvb, pinfo, this_tree, offset, "Destination Address:");
  offset = acn_add_address(tvb, pinfo, this_tree, offset, "Source Address:");
  proto_tree_add_item(this_tree, hf_acn_reciprocal_channel, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  session_count = tvb_get_ntohs(tvb, offset);
  for (x=0; x<session_count; x++) {
    pi = proto_tree_add_item(this_tree, hf_acn_protocol_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(pi, " #%d",  x+1);
    offset += 4;
  }
  return offset;
}


/******************************************************************************/
/* Add labeled expiry                                                         */
static guint32
acn_add_expiry(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, int hf)
{
  proto_tree_add_item(tree, hf, tvb, offset, 1, ENC_NA);
  offset += 1;
  return offset;
}


/******************************************************************************/
/*  Adds tree branch for channel parameters                                   */
static guint32
acn_add_channel_parameter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *param_tree;

  param_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_acn_channel_parameter,
                            NULL, "Channel Parameter Block");
  proto_tree_add_item(param_tree, hf_acn_expiry, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(param_tree, hf_acn_nak_outbound_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(param_tree, hf_acn_nak_holdoff, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(param_tree, hf_acn_nak_modulus, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(param_tree, hf_acn_nak_max_wait, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  return offset; /* bytes used */
}


/******************************************************************************/
/* Add an address tree                                                        */
static guint32
acn_add_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, const char *label)
{
  proto_item *pi;
  proto_tree *addr_tree = NULL;
  guint8      ip_address_type;
  guint32     port;

  /* Get type */
  ip_address_type = tvb_get_guint8(tvb, offset);

  switch (ip_address_type) {
    case ACN_ADDR_NULL:
      proto_tree_add_item(tree, hf_acn_ip_address_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset    += 1;
      break;
    case ACN_ADDR_IPV4:
      /* Build tree and add type*/
      addr_tree = proto_tree_add_subtree(tree, tvb, offset, 7, ett_acn_address, &pi, label);
      proto_tree_add_item(addr_tree, hf_acn_ip_address_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset    += 1;
      /* Add port */
      port       = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(addr_tree, hf_acn_port, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset    += 2;
      /* Add Address */
      proto_tree_add_item(addr_tree, hf_acn_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
      /* Append port and address to tree item */
      proto_item_append_text(pi, " %s, Port %d", tvb_address_to_str(wmem_packet_scope(), tvb, AT_IPv4, offset), port);
      offset    += 4;
      break;
    case ACN_ADDR_IPV6:
      /* Build tree and add type*/
      addr_tree = proto_tree_add_subtree(tree, tvb, offset, 19, ett_acn_address, &pi, label);
      proto_tree_add_item(addr_tree, hf_acn_ip_address_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset    += 1;
      /* Add port */
      port       = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(addr_tree, hf_acn_port, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset    += 2;
      /* Add Address */
      proto_tree_add_item(addr_tree, hf_acn_ipv6, tvb, offset, 16, ENC_NA);
      /* Append port and address to tree item */
      proto_item_append_text(pi, " %s, Port %d", tvb_address_to_str(wmem_packet_scope(), tvb, AT_IPv6, offset), port);
      offset    += 16;
      break;
    case ACN_ADDR_IPPORT:
      /* Build tree and add type*/
      addr_tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_acn_address, &pi, label);
      proto_tree_add_item(addr_tree, hf_acn_ip_address_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset    += 1;
      /* Add port */
      port       = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(addr_tree, hf_acn_port, tvb, offset, 2, ENC_BIG_ENDIAN);
      /* Append port to tree item */
      proto_item_append_text(pi, " Port %d", port);
      offset    += 2;
      break;
  }
  return offset;
}

/******************************************************************************/
/*  Adds tree branch for address type                             */
static guint32
acn_add_dmp_address_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, acn_dmp_adt_type *adt)
{
  proto_tree  *this_tree;
  guint8       D;
  const gchar *name;

  /* header contains address and data type */
  adt->flags = tvb_get_guint8(tvb, offset);

  D = ACN_DMP_ADT_EXTRACT_D(adt->flags);
  name = val_to_str(D, acn_dmp_adt_d_vals, "not valid (%d)");
  this_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1, ett_acn_address_type,
                                NULL, "Address and Data Type: %s", name);

  proto_tree_add_uint(this_tree, hf_acn_dmp_adt_v, tvb, offset, 1, adt->flags);
  proto_tree_add_uint(this_tree, hf_acn_dmp_adt_r, tvb, offset, 1, adt->flags);
  proto_tree_add_uint(this_tree, hf_acn_dmp_adt_d, tvb, offset, 1, adt->flags);
  proto_tree_add_uint(this_tree, hf_acn_dmp_adt_x, tvb, offset, 1, adt->flags);
  proto_tree_add_uint(this_tree, hf_acn_dmp_adt_a, tvb, offset, 1, adt->flags);
  offset += 1;

  return offset; /* bytes used */
}

/******************************************************************************/
/* Add an dmp address                                                         */
static guint32
acn_add_dmp_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, acn_dmp_adt_type *adt)
{
  gint32 start_offset;
  gint32 bytes_used;
  guint8 D, A;

  start_offset = offset;

  D = ACN_DMP_ADT_EXTRACT_D(adt->flags);
  A = ACN_DMP_ADT_EXTRACT_A(adt->flags);

  switch (D) {
    case ACN_DMP_ADT_D_NS:      /* Non-range address, Single data item */
      adt->increment    = 1;
      adt->count        = 1;
      switch (A) {              /* address */
        case ACN_DMP_ADT_A_1:   /* One octet address, (range: one octet address, increment, and count). */
          adt->address  = tvb_get_guint8(tvb, offset);
          offset       += 1;
          bytes_used    = 1;
          break;
        case ACN_DMP_ADT_A_2:   /* Two octet address, (range: two octet address, increment, and count). */
          adt->address  = tvb_get_ntohs(tvb, offset);
          offset       += 2;
          bytes_used    = 2;
          break;
        case ACN_DMP_ADT_A_4:   /* Four octet address, (range: one octet address, increment, and count). */
          adt->address  = tvb_get_ntohl(tvb, offset);
          offset       += 4;
          bytes_used    = 4;
          break;
        default:                /* and ACN_DMP_ADT_A_R (Four octet address, (range: four octet address, increment, and count)*/
          return offset;
      }                         /* of switch (A)  */

      if (adt->flags & ACN_DMP_ADT_FLAG_V) {
        proto_tree_add_uint(tree, hf_acn_dmp_virtual_address, tvb, start_offset, bytes_used, adt->address);
      } else {
        proto_tree_add_uint(tree, hf_acn_dmp_actual_address, tvb, start_offset, bytes_used, adt->address);
      }
      break;

    case ACN_DMP_ADT_D_RS:      /* Range address, Single data item */
      switch (A) {
        case ACN_DMP_ADT_A_1:   /* One octet address, (range: one octet address, increment, and count). */
          adt->address    = tvb_get_guint8(tvb, offset);
          offset         += 1;
          adt->increment  = tvb_get_guint8(tvb, offset);
          offset         += 1;
          adt->count      = tvb_get_guint8(tvb, offset);
          offset         += 1;
          bytes_used      = 3;
          break;
        case ACN_DMP_ADT_A_2:   /* Two octet address, (range: two octet address, increment, and count). */
          adt->address    = tvb_get_ntohs(tvb, offset);
          offset         += 2;
          adt->increment  = tvb_get_ntohs(tvb, offset);
          offset         += 2;
          adt->count      = tvb_get_ntohs(tvb, offset);
          offset         += 2;
          bytes_used      = 6;
          break;
        case ACN_DMP_ADT_A_4:   /* Four octet address, (range: four octet address, increment, and count). */
          adt->address    = tvb_get_ntohl(tvb, offset);
          offset         += 4;
          adt->increment  = tvb_get_ntohl(tvb, offset);
          offset         += 4;
          adt->count      = tvb_get_ntohl(tvb, offset);
          offset         += 4;
          bytes_used      = 12;
          break;
        default:                /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
          return offset;
      }                         /* of switch (A)  */

      if (adt->flags & ACN_DMP_ADT_FLAG_V) {
        proto_tree_add_uint_format_value(tree, hf_acn_dmp_virtual_address_first, tvb, start_offset, bytes_used,
                            adt->address, "0x%X, inc: %d, count: %d",
                            adt->address, adt->increment, adt->count);
      } else {
        proto_tree_add_uint_format_value(tree, hf_acn_dmp_actual_address_first, tvb, start_offset, bytes_used,
                            adt->address, "0x%X, inc: %d, count: %d",
                            adt->address, adt->increment, adt->count);
      }
      break;

    case ACN_DMP_ADT_D_RE:      /* Range address, Array of equal size data items */
      switch (A) {
        case ACN_DMP_ADT_A_1:   /* One octet address, (range: one octet address, increment, and count). */
          adt->address    = tvb_get_guint8(tvb, offset);
          offset         += 1;
          adt->increment  = tvb_get_guint8(tvb, offset);
          offset         += 1;
          adt->count      = tvb_get_guint8(tvb, offset);
          offset         += 1;
          bytes_used      = 3;
          break;
        case ACN_DMP_ADT_A_2:   /* Two octet address, (range: two octet address, increment, and count). */
          adt->address    = tvb_get_ntohs(tvb, offset);
          offset         += 2;
          adt->increment  = tvb_get_ntohs(tvb, offset);
          offset         += 2;
          adt->count      = tvb_get_ntohs(tvb, offset);
          offset         += 2;
          bytes_used      = 6;
          break;
        case ACN_DMP_ADT_A_4:   /* Four octet address, (range: four octet address, increment, and count). */
          adt->address    = tvb_get_ntohl(tvb, offset);
          offset         += 4;
          adt->increment  = tvb_get_ntohl(tvb, offset);
          offset         += 4;
          adt->count      = tvb_get_ntohl(tvb, offset);
          offset         += 4;
          bytes_used      = 12;
          break;
        default:                /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
          return offset;
      }                         /* of switch (A)  */

      if (adt->flags & ACN_DMP_ADT_FLAG_V) {
        proto_tree_add_uint_format_value(tree, hf_acn_dmp_virtual_address_first, tvb, start_offset, bytes_used,
                            adt->address, "0x%X, inc: %d, count: %d",
                            adt->address, adt->increment, adt->count);
      } else {
        proto_tree_add_uint_format_value(tree, hf_acn_dmp_actual_address_first, tvb, start_offset, bytes_used,
                            adt->address, "0x%X, inc: %d, count: %d",
                            adt->address, adt->increment, adt->count);
      }
      break;

    case ACN_DMP_ADT_D_RM: /* Range address, Series of mixed size data items */
      switch (A) {
        case ACN_DMP_ADT_A_1: /* One octet address, (range: one octet address, increment, and count). */
          adt->address =   tvb_get_guint8(tvb, offset);
          offset += 1;
          adt->increment =   tvb_get_guint8(tvb, offset);
          offset += 1;
          adt->count =   tvb_get_guint8(tvb, offset);
          offset += 1;
          bytes_used = 3;
          break;
        case ACN_DMP_ADT_A_2: /* Two octet address, (range: two octet address, increment, and count). */
          adt->address =   tvb_get_ntohs(tvb, offset);
          offset += 2;
          adt->increment =   tvb_get_ntohs(tvb, offset);
          offset += 2;
          adt->count =   tvb_get_ntohs(tvb, offset);
          offset += 2;
          bytes_used = 6;
          break;
        case ACN_DMP_ADT_A_4: /* Four octet address, (range: four octet address, increment, and count). */
          adt->address =   tvb_get_ntohl(tvb, offset);
          offset += 4;
          adt->increment =   tvb_get_ntohl(tvb, offset);
          offset += 4;
          adt->count =   tvb_get_ntohl(tvb, offset);
          offset += 4;
          bytes_used = 12;
          break;
        default: /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
          return offset;
      } /* of switch (A)  */

      if (adt->flags & ACN_DMP_ADT_FLAG_V) {
        proto_tree_add_uint_format_value(tree, hf_acn_dmp_virtual_address_first, tvb, start_offset, bytes_used,
                            adt->address, "0x%X, inc: %d, count: %d",
                            adt->address, adt->increment, adt->count);
      } else {
        proto_tree_add_uint_format_value(tree, hf_acn_dmp_actual_address_first, tvb, start_offset, bytes_used,
                            adt->address, "0x%X, inc: %d, count: %d",
                            adt->address, adt->increment, adt->count);
      }
      break;
  } /* of switch (D) */

  return offset;
}


/*******************************************************************************/
/* Display DMP Data                                                            */
static guint32
acn_add_dmp_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, acn_dmp_adt_type *adt)
{
  guint8      D, A;
  guint32     data_size;
  guint32     data_value;
  guint32     data_address;
  guint32     x,y;
  gchar      *buffer;
  wmem_strbuf_t *default_buffer;
  proto_item *ti;
  guint32     ok_to_process = FALSE;

  /* We would like to rip through Property Address-Data pairs                 */
  /* but since we don't now how many there are nor how big the data size is,  */
  /* it not possible. So, we just show the whole thing as a block of date!    */
  /*                                                                          */
  /* There are a few exceptions however                                       */
  /* 1) if the address type is ACN_DMP_ADT_D_NS or ACN_DMP_ADT_D_RS and       */
  /*    or ACN_DMP_ADT_D_RE                                                   */
  /*    then number of bytes is <= count + 4. Each value is at least one byte */
  /*    and another address/data pair is at least 4 bytes so if the remaining */
  /*    bytes is less than the count plus 4 then the remaining data           */
  /*    must be all data                                                      */
  /*                                                                          */
  /* 2) if the address type is ACN_DMP_ADT_D_RE and the number of bytes       */
  /*    equals the number of bytes in remaining in the pdu then there is      */
  /*    a 1 to one match                                                      */

  D = ACN_DMP_ADT_EXTRACT_D(adt->flags);
  switch (D) {
    case ACN_DMP_ADT_D_NS:
    case ACN_DMP_ADT_D_RS:
      if (adt->data_length <= adt->count + 4) {
        ok_to_process = TRUE;
      }
      break;
    case ACN_DMP_ADT_D_RE:
      if (adt->count == 0) {
        break;
      }
      if (adt->data_length <= adt->count + 4) {
        ok_to_process = TRUE;
      }
      break;
  }

  if (!ok_to_process) {
    data_size  = adt->data_length;
    ti         = proto_tree_add_item(tree, hf_acn_data, tvb, offset, data_size, ENC_NA);
    offset    += data_size;
    proto_item_set_text(ti, "Data and more Address-Data Pairs (further dissection not possible)");
    return offset;
  }

  A = ACN_DMP_ADT_EXTRACT_A(adt->flags);

  switch (D) {
    case ACN_DMP_ADT_D_NS:      /* Non-range address, Single data item */
      /* calculate data size */
      data_size    = adt->data_length;
      data_address = adt->address;

      switch (A) {
        case ACN_DMP_ADT_A_1: /* One octet address, (range: one octet address, increment, and count). */
          buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%2.2X ->", data_address);
          break;
        case ACN_DMP_ADT_A_2: /* Two octet address, (range: two octet address, increment, and count). */
          buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%4.4X ->", data_address);
          break;
        case ACN_DMP_ADT_A_4: /* Four octet address, (range: four octet address, increment, and count). */
          buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%8.8X ->", data_address);
          break;
        default: /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
          offset += data_size;
          return offset;
      }

      switch (data_size) {
        case 1:
          data_value = tvb_get_guint8(tvb, offset);
          proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 1, data_value, "%s %2.2X", buffer, data_value);
          break;
        case 2:
          data_value = tvb_get_ntohs(tvb, offset);
          proto_tree_add_uint_format(tree, hf_acn_data16, tvb, offset, 2, data_value, "%s %4.4X", buffer, data_value);
          break;
        case 3:
          data_value = tvb_get_ntoh24(tvb, offset);
          proto_tree_add_uint_format(tree, hf_acn_data24, tvb, offset, 3, data_value, "%s %6.6X", buffer, data_value);
          break;
        case 4:
          data_value = tvb_get_ntohl(tvb, offset);
          proto_tree_add_uint_format(tree, hf_acn_data32, tvb, offset, 4, data_value, "%s %8.8X", buffer, data_value);
          break;
        default:
          default_buffer = wmem_strbuf_new(wmem_packet_scope(), "");
          /* build string of values */
          for (y=0; y<20 && y<data_size; y++) {
            data_value = tvb_get_guint8(tvb, offset+y);
            wmem_strbuf_append_printf(default_buffer, " %2.2X", data_value);
          }
          /* add the item */
          ti = proto_tree_add_item(tree, hf_acn_data, tvb, offset, data_size, ENC_NA);
          offset += data_size;
          /* change the text */
          proto_item_set_text(ti, "%s", wmem_strbuf_get_str(default_buffer));
          break;
      } /* of switch (data_size) */
      offset += data_size;
      break;

    case ACN_DMP_ADT_D_RS: /* Range address, Single data item */
      /* calculate data size */
      data_size = adt->data_length;
      data_address = adt->address;

      for (x=0; x<adt->count; x++) {
        switch (A) {
          case ACN_DMP_ADT_A_1: /* One octet address, (range: one octet address, increment, and count). */
            buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%2.2X ->", data_address);
            break;
          case ACN_DMP_ADT_A_2: /* Two octet address, (range: two octet address, increment, and count). */
            buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%4.4X ->", data_address);
            break;
          case ACN_DMP_ADT_A_4: /* Four octet address, (range: four octet address, increment, and count). */
            buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%8.8X ->", data_address);
            break;
          default: /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
            return offset;
        }

        switch (data_size) {
          case 1:
            data_value = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 1, data_value, "%s %2.2X", buffer, data_value);
            break;
          case 2:
            data_value = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 2, data_value, "%s %4.4X", buffer, data_value);
            break;
          case 3:
            data_value = tvb_get_ntoh24(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 3, data_value, "%s %6.6X", buffer, data_value);
            break;
          case 4:
            data_value = tvb_get_ntohl(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 4, data_value, "%s %8.8X", buffer, data_value);
            break;
          default:
            /* build string of values */
            default_buffer = wmem_strbuf_new(wmem_packet_scope(), "");
            for (y=0; y<20 && y<data_size; y++) {
              data_value = tvb_get_guint8(tvb, offset+y);
              wmem_strbuf_append_printf(default_buffer, " %2.2X", data_value);
            }
            /* add the item */
            ti = proto_tree_add_item(tree, hf_acn_data, tvb, offset, data_size, ENC_NA);
            /* change the text */
            proto_item_set_text(ti, "%s", wmem_strbuf_get_str(default_buffer));
            break;
        } /* of switch (data_size) */
        data_address += adt->increment;
      } /* of (x=0;x<adt->count;x++) */
      offset += data_size;
      break;

    case ACN_DMP_ADT_D_RE: /* Range address, Array of equal size data items */
      /* calculate data size */
      data_size = adt->data_length / adt->count;
      data_address = adt->address;

      for (x=0; x<adt->count; x++) {
        switch (A) {
          case ACN_DMP_ADT_A_1: /* One octet address, (range: one octet address, increment, and count). */
            buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%2.2X ->", data_address);
            break;
          case ACN_DMP_ADT_A_2: /* Two octet address, (range: two octet address, increment, and count). */
            buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%4.4X ->", data_address);
            break;
          case ACN_DMP_ADT_A_4: /* Four octet address, (range: four octet address, increment, and count). */
            buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%8.8X ->", data_address);
            break;
          default: /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
            return offset;
        }

        switch (data_size) {
          case 1:
            data_value = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 1, data_value, "%s %2.2X", buffer, data_value);
            break;
          case 2:
            data_value = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 2, data_value, "%s %4.4X", buffer, data_value);
            break;
          case 3:
            data_value = tvb_get_ntoh24(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 3, data_value, "%s %6.6X", buffer, data_value);
            break;
          case 4:
            data_value = tvb_get_ntohl(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 4, data_value, "%s %8.8X", buffer, data_value);
            break;
          default:
            /* build string of values */
            default_buffer = wmem_strbuf_new(wmem_packet_scope(), "");
            for (y=0; y<20 && y<data_size; y++) {
              data_value = tvb_get_guint8(tvb, offset+y);
              wmem_strbuf_append_printf(default_buffer, " %2.2X", data_value);
            }
            /* add the item */
            ti = proto_tree_add_item(tree, hf_acn_data, tvb, offset, data_size, ENC_NA);
            /* change the text */
            proto_item_set_text(ti, "%s", wmem_strbuf_get_str(default_buffer));
            break;
        } /* of switch (data_size) */

        offset += data_size;
        data_address += adt->increment;
      } /* of (x=0;x<adt->count;x++) */
      break;

    case ACN_DMP_ADT_D_RM: /* Range address, Series of mixed size data items */
      data_size = adt->data_length;
      ti = proto_tree_add_item(tree, hf_acn_data, tvb, offset, data_size, ENC_NA);
      offset += data_size;
      /* change the text */
      proto_item_set_text(ti, "Mixed size data items");
      break;
  } /* of switch (D) */
  return offset;
}

/*******************************************************************************/
/* Display DMP Reason codes                                                    */
static guint32
acn_add_dmp_reason_codes(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, acn_dmp_adt_type *adt)
{
  guint8       D, A;
  guint32      data_value;
  guint32      data_address;
  guint32      x;

  gchar       *buffer;
  const gchar *name;

  D = ACN_DMP_ADT_EXTRACT_D(adt->flags);
  A = ACN_DMP_ADT_EXTRACT_A(adt->flags);
  switch (D) {
    case ACN_DMP_ADT_D_NS: /* Non-range address, Single data item */
      data_address = adt->address;
      switch (A) {
        case ACN_DMP_ADT_A_1: /* One octet address, (range: one octet address, increment, and count). */
          buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%2.2X ->", data_address);
          break;
        case ACN_DMP_ADT_A_2: /* Two octet address, (range: two octet address, increment, and count). */
          buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%4.4X ->", data_address);
          break;
        case ACN_DMP_ADT_A_4: /* Four octet address, (range: four octet address, increment, and count). */
          buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%8.8X ->", data_address);
          break;
        default: /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
          return offset;
      }

      /* Get reason */
      data_value  = tvb_get_guint8(tvb, offset);
      name        = val_to_str(data_value, acn_dmp_reason_code_vals, "reason not valid (%d)");
      proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 1, data_value, "%s %s", buffer, name);
      offset     += 1;
      break;

    case ACN_DMP_ADT_D_RS: /* Range address, Single data item */
      data_address = adt->address;
      for (x=0; x<adt->count; x++) {
        switch (A) {
          case ACN_DMP_ADT_A_1: /* One octet address, (range: one octet address, increment, and count). */
            buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%2.2X ->", data_address);
            break;
          case ACN_DMP_ADT_A_2: /* Two octet address, (range: two octet address, increment, and count). */
            buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%4.4X ->", data_address);
            break;
          case ACN_DMP_ADT_A_4: /* Four octet address, (range: four octet address, increment, and count). */
            buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%8.8X ->", data_address);
            break;
          default: /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
            return offset;
        }

        /* Get reason */
        data_value = tvb_get_guint8(tvb, offset);
        name       = val_to_str(data_value, acn_dmp_reason_code_vals, "reason not valid (%d)");
        proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 1, data_value, "%s %s", buffer, name);

        data_address += adt->increment;
      } /* of (x=0;x<adt->count;x++) */
      offset += 1;
      break;

    case ACN_DMP_ADT_D_RE: /* Range address, Array of equal size data items */
    case ACN_DMP_ADT_D_RM: /* Range address, Series of mixed size data items */
      data_address = adt->address;
      for (x=0; x<adt->count; x++) {
        switch (A) {
          case ACN_DMP_ADT_A_1: /* One octet address, (range: one octet address, increment, and count). */
            buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%2.2X ->", data_address);
            break;
          case ACN_DMP_ADT_A_2: /* Two octet address, (range: two octet address, increment, and count). */
            buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%4.4X ->", data_address);
            break;
          case ACN_DMP_ADT_A_4: /* Four octet address, (range: four octet address, increment, and count). */
            buffer = wmem_strdup_printf(wmem_packet_scope(), "Addr 0x%8.8X ->", data_address);
            break;
          default: /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
            return offset;
        }
        /* Get reason */
        data_value    = tvb_get_guint8(tvb, offset);
        name          = val_to_str(data_value, acn_dmp_reason_code_vals, "reason not valid (%d)");
        proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 1, data_value, "%s %s", buffer, name);
        data_address += adt->increment;
        offset       += 1;
      } /* of (x=0;x<adt->count;x++) */
      break;
  } /* of switch (D) */
  return offset;
}

/******************************************************************************/
/* Get Field Type Parameters */
static void
get_field_type_parameters(tvbuff_t *tvb, int blob_offset, guint8 field_type, guint8 *field_length, guint8 *blob_offset1, guint8 *blob_offset2, guint8 *blob_offset3)
{
  /* Switch Over Field Type to Determine Data */
  switch (field_type) {
    case ACN_BLOB_FIELD_TYPE1:
    case ACN_BLOB_FIELD_TYPE5:
      /* Set field length and blob_offsets to use */
      *field_length = 1;
      *blob_offset1 = 0;
      *blob_offset2 = 1;
      *blob_offset3 = *field_length;
      break;
    case ACN_BLOB_FIELD_TYPE2:
    case ACN_BLOB_FIELD_TYPE6:
      /* Set field length and blob_offsets to use */
      *field_length = 2;
      *blob_offset1 = 0;
      *blob_offset2 = 1;
      *blob_offset3 = *field_length;
      break;
    case ACN_BLOB_FIELD_TYPE3:
    case ACN_BLOB_FIELD_TYPE7:
      /* Set field length and blob_offsets to use */
      *field_length = 4;
      *blob_offset1 = 0;
      *blob_offset2 = 1;
      *blob_offset3 = *field_length;
      break;
    case ACN_BLOB_FIELD_TYPE4:
    case ACN_BLOB_FIELD_TYPE8:
      /* Set field length and blob_offsets to use */
      *field_length = 8;
      *blob_offset1 = 0;
      *blob_offset2 = 1;
      *blob_offset3 = *field_length;
      break;
    case ACN_BLOB_FIELD_TYPE9:
      /* float */
      /* Set field length and blob_offsets to use */
      *field_length = 4;
      *blob_offset1 = 0;
      *blob_offset2 = 1;
      *blob_offset3 = *field_length;
      break;
    case ACN_BLOB_FIELD_TYPE10:
      /* double */
      /* Set field length and blob_offsets to use */
      *field_length = 8;
      *blob_offset1 = 0;
      *blob_offset2 = 1;
      *blob_offset3 = *field_length;
      break;
    case ACN_BLOB_FIELD_TYPE11:
      /* Set field length and blob_offsets to use */
      *field_length = tvb_get_guint8(tvb, blob_offset + 2);
      *blob_offset1 = 2;
      *blob_offset2 = 1;
      *blob_offset3 = (*field_length) - 2;
      break;
    case ACN_BLOB_FIELD_TYPE12:
      /* Set field length and blob_offsets to use for ignores */
      *field_length = 0;
      *blob_offset1 = 0;
      *blob_offset2 = 0;
      *blob_offset3 = 1;
      break;
    default:
      /* Set field length and blob_offsets to use for unknowns */
      *field_length = 0;
      *blob_offset1 = 0;
      *blob_offset2 = 0;
      *blob_offset3 = 1;
  }
}

/******************************************************************************/
/* Get Field Name */
static const gchar *
get_field_name(guint8 blob_type, guint16 field_number)
{
  guint16 temp_field_number;
  const gchar *field_name;

  /*Find the field sub tree name depending on the blob type.*/
  switch (blob_type) {
    case ACN_BLOB_IPV4:
    case ACN_BLOB_IPV6:
      field_name = val_to_str(field_number, acn_blob_ip_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_ERROR1:
      field_name = val_to_str(field_number, acn_blob_error1_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_ERROR2:
      field_name = val_to_str(field_number, acn_blob_error2_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_METADATA:
      field_name = val_to_str(field_number, acn_blob_metadata_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_METADATA_DEVICES:
      field_name = val_to_str(field_number, acn_blob_metadata_devices_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_METADATA_TYPES:
      field_name = val_to_str(field_number, acn_blob_metadata_types_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_TIME1:
      field_name = val_to_str(field_number, acn_blob_time1_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_DIMMER_PROPERTIES:
      field_name = val_to_str_ext(field_number, &acn_blob_dimmer_properties1_field_name_ext, "not valid (%d)");
      break;
    case ACN_BLOB_DIMMER_LOAD_PROPERTIES:
      field_name = val_to_str_ext(field_number, &acn_blob_dimmer_load_properties1_field_name_ext, "not valid (%d)");
      break;
    case ACN_BLOB_DIMMING_RACK_PROPERTIES:
      field_name = val_to_str_ext(field_number, &acn_blob_dimmer_rack_properties1_field_name_ext, "not valid (%d)");
      break;
    case ACN_BLOB_DIMMING_RACK_STATUS_PROPERTIES:
      field_name = val_to_str_ext(field_number, &acn_blob_dimmer_rack_status_properties1_field_name_ext, "not valid (%d)");
      break;
    case ACN_BLOB_DIMMER_STATUS_PROPERTIES:
      field_name = val_to_str_ext(field_number, &acn_blob_dimmer_status_properties1_field_name_ext, "not valid (%d)");
      break;
    case ACN_BLOB_SET_LEVELS_OPERATION:
      field_name = val_to_str(field_number, acn_blob_set_levels_operation_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_PRESET_OPERATION:
      field_name = val_to_str(field_number, acn_blob_preset_operation_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_ADVANCED_FEATURES_OPERATION:
      field_name = val_to_str(field_number, acn_blob_advanced_features_operation_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_DIRECT_CONTROL_OPERATION:
      field_name = val_to_str(field_number, acn_blob_direct_control_operation_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_GENERATE_CONFIG_OPERATION:
      field_name = val_to_str(field_number, acn_blob_generate_config_operation_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_ERROR3:
      field_name = val_to_str(field_number, acn_blob_error3_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_DIMMER_PROPERTIES2:
      field_name = val_to_str_ext(field_number, &acn_blob_dimmer_properties2_field_name_ext, "not valid (%d)");
      break;
    case ACN_BLOB_DIMMER_LOAD_PROPERTIES2:
      field_name = val_to_str_ext(field_number, &acn_blob_dimmer_load_properties2_field_name_ext, "not valid (%d)");
      break;
    case ACN_BLOB_DIMMER_RACK_PROPERTIES2:
      field_name = val_to_str_ext(field_number, &acn_blob_dimmer_rack_properties2_field_name_ext, "not valid (%d)");
      break;
    case ACN_BLOB_DIMMER_RACK_STATUS_PROPERTIES2:
      field_name = val_to_str_ext(field_number, &acn_blob_dimmer_rack_status_properties2_field_name_ext, "not valid (%d)");
      break;
    case ACN_BLOB_DIMMER_STATUS_PROPERTIES2:
      field_name = val_to_str_ext(field_number, &acn_blob_dimmer_status_properties2_field_name_ext, "not valid (%d)");
      break;
    case ACN_BLOB_TIME2:
      field_name = val_to_str(field_number, acn_blob_time2_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_RPC:
      {
        temp_field_number = field_number;
        /* field names 4 repeats: 1, 2, 3, 4, 4, 4, ... */
        if (temp_field_number > 3)
          temp_field_number = 4;
        field_name = val_to_str(temp_field_number, acn_blob_rpc_field_name, "not valid (%d)");
      }
      break;
    case ACN_BLOB_DHCP_CONFIG_SUBNET:
      field_name = val_to_str(field_number, acn_blob_dhcp_config_subnet_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_DHCP_CONFIG_STATIC_ROUTE:
      field_name = val_to_str(field_number, acn_blob_dhcp_config_static_route_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_ENERGY_MANAGEMENT:
      {
        temp_field_number = field_number;
        /* field names 4 through 7 repeat: 1, 2, 3, 4, 5, 6, 7, 4, 5, 6, 7, ... */
        if (temp_field_number > 3)
          temp_field_number = (field_number % 4) + 4;
        field_name = val_to_str(temp_field_number, acn_blob_energy_management_field_name, "not valid (%d)");
      }
      break;
    case ACN_BLOB_PRESET_PROPERTIES:
      field_name = val_to_str_ext(field_number, &acn_blob_preset_properties_field_name_ext, "not valid (%d)");
      break;
    case ACN_BLOB_TIME3:
      field_name = val_to_str(field_number, acn_blob_time3_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_ENERGY_COST:
      field_name = val_to_str(field_number, acn_blob_energy_cost_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_SEQUENCE_OPERATIONS:
      field_name = val_to_str(field_number, acn_blob_sequence_operation_field_name, "not valid (%d)");
      break;
    case ACN_BLOB_SEQUENCE_STEP_PROPERTIES:
      field_name = val_to_str_ext(field_number, &acn_blob_sequence_step_properties_field_name_ext, "not valid (%d)");
      break;
    default:
      field_name = "Unknown field";
      break;
  }

  return field_name;
}

/******************************************************************************/
/* Display Blob Field Value */
static void
display_blob_field_value(tvbuff_t *tvb, proto_tree *field_tree, guint16 field_number, guint8 blob_type, guint8 field_type, guint8 field_length, int blob_offset, guint8 blob_offset3, int display_variblob_as_CID)
{
  gint8             field_value8;
  gint32            field_value32;
  const gchar      *field_string;
  proto_item       *ti;

  /* Add field value to field sub tree */
  if (field_type == ACN_BLOB_FIELD_TYPE12) {
    /* "ignore" always takes priority */
    proto_tree_add_string(field_tree, hf_acn_blob_field_value_string, tvb, blob_offset, field_length, "Ignore");
  }
  else if (blob_type == ACN_BLOB_IPV4) {
    proto_tree_add_item(field_tree, hf_acn_blob_field_value_ipv4, tvb, blob_offset, field_length-2, ENC_BIG_ENDIAN);
  }
  else if (blob_type == ACN_BLOB_IPV6) {
    proto_tree_add_item(field_tree, hf_acn_blob_field_value_ipv6, tvb, blob_offset, field_length-2, ENC_NA);
  }
  else if ((blob_type == ACN_BLOB_TIME3) && (field_number == 2)) {
    /* time zone index */
    field_value32 = (gint32)(tvb_get_ntohl(tvb, blob_offset));
    if (field_value32 == -1) {
      field_string = "Field Value: Custom";
    }
    else {
      field_string = val_to_str(field_value32, acn_blob_time3_time_zone_vals, "not valid (%d)");
    }
    proto_tree_add_int_format(field_tree, hf_acn_blob_time_zone, tvb, blob_offset, 4, field_value32, "%s", field_string);
  }
  else if ((blob_type == ACN_BLOB_TIME3) && (field_number == 10)) {
    /* DST type */
    field_value8 = tvb_get_guint8(tvb, blob_offset);
    field_string = val_to_str(field_value8, acn_blob_time3_dst_vals, "not valid (%d)");
    proto_tree_add_uint_format(field_tree, hf_acn_blob_dst_type, tvb, blob_offset, 1, field_value8, "%s", field_string);
  }
  else if ((blob_type == ACN_BLOB_TIME3) && (field_number == 11)) {
    /* DST on month */
    field_value8 = tvb_get_guint8(tvb, blob_offset);
    field_string = val_to_str(field_value8, acn_blob_time3_month_vals, "not valid (%d)");
    proto_tree_add_uint_format(field_tree, hf_acn_blob_dst_type, tvb, blob_offset, 1, field_value8, "%s", field_string);
  }
  else if ((blob_type == ACN_BLOB_TIME3) && (field_number == 12)) {
    /* DST on week */
    field_value8 = tvb_get_guint8(tvb, blob_offset);
    field_string = val_to_str(field_value8, acn_blob_time3_week_vals, "not valid (%d)");
    proto_tree_add_uint_format(field_tree, hf_acn_blob_dst_type, tvb, blob_offset, 1, field_value8, "%s", field_string);
  }
  else if ((blob_type == ACN_BLOB_TIME3) && (field_number == 13)) {
    /* DST start day */
    field_value8 = tvb_get_guint8(tvb, blob_offset);
    field_string = val_to_str(field_value8, acn_blob_time3_day_vals, "not valid (%d)");
    proto_tree_add_uint_format(field_tree, hf_acn_blob_dst_start_day, tvb, blob_offset, 1, field_value8, "%s", field_string);
  }
  else if ((blob_type == ACN_BLOB_TIME3) && (field_number == 16)) {
    /* DST start locality */
    field_value8 = tvb_get_guint8(tvb, blob_offset);
    field_string = val_to_str(field_value8, acn_blob_time3_locality_vals, "not valid (%d)");
    proto_tree_add_uint_format(field_tree, hf_acn_blob_dst_start_locality, tvb, blob_offset, 1, field_value8, "%s", field_string);
  }
  else if ((blob_type == ACN_BLOB_TIME3) && (field_number == 17)) {
    /* DST off month */
    field_value8 = tvb_get_guint8(tvb, blob_offset);
    field_string = val_to_str(field_value8, acn_blob_time3_month_vals, "not valid (%d)");
    proto_tree_add_uint_format(field_tree, hf_acn_blob_dst_type, tvb, blob_offset, 1, field_value8, "%s", field_string);
  }
  else if ((blob_type == ACN_BLOB_TIME3) && (field_number == 18)) {
    /* DST off week */
    field_value8 = tvb_get_guint8(tvb, blob_offset);
    field_string = val_to_str(field_value8, acn_blob_time3_week_vals, "not valid (%d)");
    proto_tree_add_uint_format(field_tree, hf_acn_blob_dst_type, tvb, blob_offset, 1, field_value8, "%s", field_string);
  }
  else if ((blob_type == ACN_BLOB_TIME3) && (field_number == 19)) {
    /* DST stop day */
    field_value8 = tvb_get_guint8(tvb, blob_offset);
    field_string = val_to_str(field_value8, acn_blob_time3_day_vals, "not valid (%d)");
    proto_tree_add_uint_format(field_tree, hf_acn_blob_dst_stop_day, tvb, blob_offset, 1, field_value8, "%s", field_string);
  }
  else if ((blob_type == ACN_BLOB_TIME3) && (field_number == 22)) {
    /* DST stop locality */
    field_value8 = tvb_get_guint8(tvb, blob_offset);
    field_string = val_to_str(field_value8, acn_blob_time3_locality_vals, "not valid (%d)");
    proto_tree_add_uint_format(field_tree, hf_acn_blob_dst_stop_locality, tvb, blob_offset, 1, field_value8, "%s", field_string);
  }
  else {
    switch (field_type) {
      case ACN_BLOB_FIELD_TYPE1:
        /* Need special code to display signed data */
        ti = proto_tree_add_item(field_tree, hf_acn_blob_field_value_number, tvb, blob_offset, 1, ENC_BIG_ENDIAN);
        proto_item_set_len(ti, blob_offset3);
        break;
      case ACN_BLOB_FIELD_TYPE2:
        /* Need special code to display signed data */
        ti = proto_tree_add_item(field_tree, hf_acn_blob_field_value_number, tvb, blob_offset, 2, ENC_BIG_ENDIAN);
        proto_item_set_len(ti, blob_offset3);
        break;
      case ACN_BLOB_FIELD_TYPE3:
        /* Need special code to display signed data */
        ti = proto_tree_add_item(field_tree, hf_acn_blob_field_value_number, tvb, blob_offset, 3, ENC_BIG_ENDIAN);
        proto_item_set_len(ti, blob_offset3);
        break;
      case ACN_BLOB_FIELD_TYPE4:
        /* Need special code to display signed data */
        ti = proto_tree_add_item(field_tree, hf_acn_blob_field_value_number64, tvb, blob_offset, 8, ENC_BIG_ENDIAN);
        proto_item_set_len(ti, blob_offset3);
        break;
      case ACN_BLOB_FIELD_TYPE9:
        /* float */
        proto_tree_add_item(field_tree, hf_acn_blob_field_value_float, tvb, blob_offset, field_length, ENC_BIG_ENDIAN);
        break;
      case ACN_BLOB_FIELD_TYPE10:
        /* double */
        proto_tree_add_item(field_tree, hf_acn_blob_field_value_double, tvb, blob_offset, field_length, ENC_BIG_ENDIAN);
        break;
      case ACN_BLOB_FIELD_TYPE11:
        if (blob_offset3 == 0) {
          proto_tree_add_string(field_tree, hf_acn_blob_field_value_string, tvb, blob_offset, 0, "<none>");
        }
        else if (display_variblob_as_CID) {
          proto_tree_add_item(field_tree, hf_acn_blob_field_value_guid, tvb, blob_offset, field_length, ENC_BIG_ENDIAN);
        }
        else {
          proto_tree_add_item(field_tree, hf_acn_blob_field_value_string, tvb, blob_offset, blob_offset3, ENC_UTF_8 | ENC_NA);
        }
        break;
      /* "ignore", handled above */
      /* case ACN_BLOB_FIELD_TYPE12: */
      /*   proto_tree_add_string(field_tree, hf_acn_blob_field_value_string, tvb, blob_offset, field_length, "Field Value: Ignore"); */
      /*   break; */
      default:
        proto_tree_add_item(field_tree, hf_acn_blob_field_value_number, tvb, blob_offset, blob_offset3, ENC_BIG_ENDIAN);
        break;
    }
  }
}

/******************************************************************************/
/* Display Blob Field */
static void
display_blob_field(tvbuff_t *tvb, proto_tree *blob_tree, guint8 blob_type, int *blob_offset, guint16 *field_number, int display_variblob_as_CID)
{
  guint8            field_type;
  guint8            field_length;
  guint8            blob_offset1;
  guint8            blob_offset2;
  guint8            blob_offset3;
  guint16           temp_field_number;

  proto_item       *fi;
  proto_tree       *field_tree = NULL;
  proto_item       *ti;

  const gchar      *field_name;

  if ((blob_type == ACN_BLOB_ENERGY_MANAGEMENT) && (*field_number > 3)) {
    /* an exception to blob field rules: no "type" subfield, no "length" subfield */

    /* field names 4 through 7 repeat: 1, 2, 3, 4, 5, 6, 7, 4, 5, 6, 7, ... */
    temp_field_number = (*field_number % 4) + 4;

    switch (temp_field_number) {
      case 4:
        /* uint2 */
        field_length = 2;
        blob_offset3 = 2;
        field_name = get_field_name(blob_type, temp_field_number);

        /* Create Sub Tree for Field Type*/
        fi = proto_tree_add_item(blob_tree, hf_acn_blob_tree_field_type, tvb, *blob_offset, field_length, ENC_NA);
        field_tree = proto_item_add_subtree(fi, ett_acn_blob);

        /* Add the Field Name Found to Sub Tree */
        proto_item_append_text(fi, ": %s", field_name);

        ti = proto_tree_add_item(field_tree, hf_acn_blob_field_value_number, tvb, *blob_offset, 2, ENC_BIG_ENDIAN);
        proto_item_set_len(ti, blob_offset3);
        break;
      case 5:
      case 6:
      case 7:
        /* uint4 */
        field_length = 4;
        blob_offset3 = 4;
        field_name = get_field_name(blob_type, temp_field_number);

        /* Create Sub Tree for Field Type*/
        fi = proto_tree_add_item(blob_tree, hf_acn_blob_tree_field_type, tvb, *blob_offset, field_length, ENC_NA);
        field_tree = proto_item_add_subtree(fi, ett_acn_blob);

        /* Add the Field Name Found to Sub Tree */
        proto_item_append_text(fi, ": %s", field_name);
        ti = proto_tree_add_item(field_tree, hf_acn_blob_field_value_number, tvb, *blob_offset, 4, ENC_BIG_ENDIAN);
        proto_item_set_len(ti, blob_offset3);
        break;
    }
  }
  else {
    /* Get field type*/
    field_type = tvb_get_guint8(tvb, *blob_offset);
    get_field_type_parameters(tvb, *blob_offset, field_type, &field_length, &blob_offset1, &blob_offset2, &blob_offset3);
    field_name = get_field_name(blob_type, *field_number);

    /* Create Sub Tree for Field Type*/
    fi = proto_tree_add_item(blob_tree, hf_acn_blob_tree_field_type, tvb, *blob_offset, field_length + 1, ENC_NA);
    field_tree = proto_item_add_subtree(fi, ett_acn_blob);

    /* Add the Field Name Found to Sub Tree */
    proto_item_append_text(fi, ": %s", field_name);

    /* Add field type to field sub tree */
    proto_tree_add_uint(field_tree, hf_acn_blob_field_type, tvb, *blob_offset, 1, field_type);
    *blob_offset += blob_offset1;

    /* Add field length to field sub tree */
    proto_tree_add_uint(field_tree, hf_acn_blob_field_length, tvb, *blob_offset, 1, field_length);
    *blob_offset += blob_offset2;

    display_blob_field_value(tvb, field_tree, *field_number, blob_type, field_type, field_length, *blob_offset, blob_offset3, display_variblob_as_CID);
  }

  *blob_offset += blob_offset3;
  *field_number += 1;
}

/******************************************************************************/
/* Dissect Blob Metadata */
static guint32
dissect_acn_blob_metadata(tvbuff_t *tvb, proto_tree *blob_tree, int blob_offset, int end_offset)
{
  guint8   blob_type = ACN_BLOB_METADATA;
  guint16  field_number = 1;
  gboolean display_variblob_as_CID;

  /* Loop though dissecting fields until the end is reached */
  while (blob_offset < end_offset) {
    if (field_number == 15) {

      display_variblob_as_CID = 1;
    }
    else {
      display_variblob_as_CID = 0;

    }

    display_blob_field(tvb, blob_tree, blob_type, &blob_offset, &field_number, display_variblob_as_CID);
  }
  return 0;
}

/******************************************************************************/
/* Dissect Blob Preset Properties */
static guint32
dissect_acn_blob_preset_properties(tvbuff_t *tvb, proto_tree *blob_tree, int blob_offset, int end_offset)
{
  guint8       blob_type = ACN_BLOB_PRESET_PROPERTIES;
  guint8       field_type;
  guint8       field_length;
  guint8       blob_offset1;
  guint8       blob_offset2;
  guint8       blob_offset3;
  guint8       sub_blob_index;
  guint16      field_number = 1;
  guint8       max_sub_blobs = 192;
  proto_item  *fi;
  proto_tree  *sub_blob_tree = NULL;
  const gchar *field_name;

  /* Loop though dissecting fields until the end is reached */
  while (blob_offset < end_offset) {
    if (field_number == 17) {
      /* Create subtree for "Levels" */
      field_type = tvb_get_guint8(tvb, blob_offset);
      get_field_type_parameters(tvb, blob_offset, field_type, &field_length, &blob_offset1, &blob_offset2, &blob_offset3);

      field_name = get_field_name(blob_type, field_number);
      field_number += 1;

      /* Create Sub Tree for Field Type */
      fi = proto_tree_add_item(blob_tree, hf_acn_blob_tree_field_type, tvb, blob_offset, (field_length + 1) * max_sub_blobs, ENC_NA);
      sub_blob_tree = proto_item_add_subtree(fi, ett_acn_blob);

      proto_item_append_text(fi, ": %s", field_name);
      sub_blob_index = 0;

      while ((sub_blob_index < max_sub_blobs) && (blob_offset < end_offset)) {
        display_blob_field(tvb, sub_blob_tree, blob_type, &blob_offset, &field_number, 0);

        sub_blob_index += 1;
      }

    }

    else {
      display_blob_field(tvb, blob_tree, blob_type, &blob_offset, &field_number, 0);
    }

  }
  return 0;
}

/******************************************************************************/
/* Dissect Blob Dimming Rack Properties v2 */
static guint32
dissect_acn_blob_dimming_rack_properties_v2(tvbuff_t *tvb, proto_tree *blob_tree, int blob_offset, int end_offset)
{
  guint8       blob_type = ACN_BLOB_DIMMER_RACK_PROPERTIES2;
  guint16      field_number = 1;
  gboolean     display_variblob_as_CID;

  /* Loop though dissecting fields until the end is reached */
  while (blob_offset < end_offset) {
    if (field_number == 12) {

      display_variblob_as_CID = 1;

    }
    else {

      display_variblob_as_CID = 0;

    }

    display_blob_field(tvb, blob_tree, blob_type, &blob_offset, &field_number, display_variblob_as_CID);
  }
  return 0;
}

/******************************************************************************/
/* Dissect Blob Dimming Rack Status Properties v2 */
static guint32
dissect_acn_blob_dimming_rack_status_properties_v2(tvbuff_t *tvb, proto_tree *blob_tree, int blob_offset, int end_offset)
{
  guint8       blob_type;
  guint8       field_type;
  guint8       field_length;
  guint8       blob_offset1;
  guint8       blob_offset2;
  guint8       blob_offset3;
  guint8       sub_blob_index;
  guint16      field_number;

  int          number_of_sub_blobs;

  proto_item  *fi;
  proto_tree  *sub_blob_tree = NULL;

  const gchar *field_name;

  /*First Assignments*/
  blob_type = ACN_BLOB_DIMMER_RACK_STATUS_PROPERTIES2;
  field_number = 1;
  number_of_sub_blobs = 64;

  /* Loop though dissecting fields until the end is reached */
  while (blob_offset < end_offset) {
    if (field_number == 22) {
      /* Create subtree for "Active Preset Group IDs" */
      field_type = tvb_get_guint8(tvb, blob_offset);
      get_field_type_parameters(tvb, blob_offset, field_type, &field_length, &blob_offset1, &blob_offset2, &blob_offset3);

      field_name = get_field_name(blob_type, field_number);
      field_number += 1;

      /* Create Sub Tree for Field Type */
      fi = proto_tree_add_item(blob_tree, hf_acn_blob_tree_field_type, tvb, blob_offset, (field_length + 1) * number_of_sub_blobs, ENC_NA);
      sub_blob_tree = proto_item_add_subtree(fi, ett_acn_blob);

      proto_item_append_text(fi, ": %s", field_name);

      sub_blob_index = 0;

      while ((sub_blob_index < number_of_sub_blobs) && (blob_offset < end_offset)) {
        display_blob_field(tvb, sub_blob_tree, blob_type, &blob_offset, &field_number, 0);

        sub_blob_index += 1;

      }

    }

    else {
      display_blob_field(tvb, blob_tree, blob_type, &blob_offset, &field_number, 0);
    }

  }
  return 0;
}

/******************************************************************************/
/* Get Blob Type From Fields
Both "Dimmer Properties v2" and "Preset Properties" ended up with blob type 20 */
static guint8
get_blob_type_from_fields(tvbuff_t *tvb, int blob_offset, int end_offset)
{
  guint8  field_type;
  guint8  field_length;
  guint8  blob_offset1;
  guint8  blob_offset2;
  guint8  blob_offset3;
  guint16 field_number = 1;

  while (blob_offset < end_offset) {
    field_type = tvb_get_guint8(tvb, blob_offset);
    if (field_number == 12) {
      if (field_type == ACN_BLOB_FIELD_TYPE11) {
        /* string: dimmer name field */
        return ACN_BLOB_DIMMER_PROPERTIES2;
      }
      /* number: preset number field */
      return ACN_BLOB_PRESET_PROPERTIES;
    }
    get_field_type_parameters(tvb, blob_offset, field_type, &field_length, &blob_offset1, &blob_offset2, &blob_offset3);
    blob_offset += blob_offset2 + blob_offset3;
    field_number += 1;
  }

  return ACN_BLOB_DIMMER_PROPERTIES2;
}

/******************************************************************************/
/* Dissect Blob */
static guint32
dissect_acn_blob(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *pdu_tree, int blob_offset, int end_offset)
{
  /* Declarations for blobs*/
  guint8     version;
  guint8     range;
  guint8     blob_type;
  guint8     range_number;
  guint16    field_number = 1;
  proto_item *bi;
  proto_tree *blob_tree = NULL;
  const gchar *blob_name;
  /* const gchar *range_type; */

  /* Add blob to tree */
  bi = proto_tree_add_item(pdu_tree, hf_acn_blob, tvb, blob_offset, end_offset, ENC_NA);
  blob_tree = proto_item_add_subtree(bi, 0);
  end_offset = blob_offset + end_offset;
  blob_offset += 4;

  /* Add Blob version item to tree */
  version = tvb_get_guint8(tvb, blob_offset);
  proto_tree_add_item(blob_tree, hf_acn_blob_version, tvb, blob_offset, 1, version);
  blob_offset += 1;

  /* Add Blob Start and End Range Info */
  range = tvb_get_guint8(tvb, blob_offset);
  proto_tree_add_item(blob_tree, hf_acn_blob_range_type, tvb, blob_offset, 1, range);
  /* range_type = val_to_str(range, acn_blob_range_type_vals, "not valid (%d)"); */
  blob_offset += 1;

  /* Add Blob Range Number */
  range_number = tvb_get_guint8(tvb, blob_offset);
  proto_tree_add_item(blob_tree, hf_acn_blob_range_number, tvb, blob_offset, 1, range_number);
  blob_offset += 1;

  /* Add Blob Meta-Type */
  blob_type = tvb_get_guint8(tvb, blob_offset);
  if (blob_type == ACN_BLOB_DIMMER_PROPERTIES2) {
    /* Dimmer  Properties v2 and Preset Properties have the same 'type' value (20) */
    blob_type = get_blob_type_from_fields(tvb, blob_offset + 1, end_offset);
  }

  proto_tree_add_item(blob_tree, hf_acn_blob_type, tvb, blob_offset, 1, blob_type);

  blob_name = val_to_str(blob_type, acn_blob_type_vals, "not valid (%d)");
  proto_item_append_text(bi, ": %s", blob_name);
  blob_offset += 1;

  if (blob_type == ACN_BLOB_METADATA) {
    return dissect_acn_blob_metadata(tvb, blob_tree, blob_offset, end_offset);
  }
  if (blob_type == ACN_BLOB_PRESET_PROPERTIES) {
    return dissect_acn_blob_preset_properties(tvb, blob_tree, blob_offset, end_offset);
  }
  if (blob_type == ACN_BLOB_DIMMER_RACK_PROPERTIES2) {
    return dissect_acn_blob_dimming_rack_properties_v2(tvb, blob_tree, blob_offset, end_offset);
  }
  if (blob_type == ACN_BLOB_DIMMER_RACK_STATUS_PROPERTIES2) {
    return dissect_acn_blob_dimming_rack_status_properties_v2(tvb, blob_tree, blob_offset, end_offset);
  }

  /* Loop though dissecting fields until the end is reached */
  while (blob_offset < end_offset) {
    display_blob_field(tvb, blob_tree, blob_type, &blob_offset, &field_number, 0);
  }
  return 0;
}

/******************************************************************************/
/* Dissect PDU L bit flag                                                     */
static void
dissect_pdu_bit_flag_l(tvbuff_t *tvb, int *offset, guint8 *pdu_flags, guint32 *pdu_length, guint32 *pdu_flvh_length)
{
  guint8  octet;
  guint32 length1;
  guint32 length2;
  guint32 length3;

  /* get PDU flags and length flag */
  octet      = tvb_get_guint8(tvb, (*offset)++);
  *pdu_flags = octet & 0xf0;
  length1    = octet & 0x0f;     /* bottom 4 bits only */
  length2    = tvb_get_guint8(tvb, (*offset)++);

  /* if length flag is set, then we have a 20 bit length else we have a 12 bit */
  /* flvh = flags, length, vector, header */
  if (*pdu_flags & ACN_PDU_FLAG_L) {
    length3 = tvb_get_guint8(tvb, *offset);
    *offset += 1;
    *pdu_length = length3 | (length2 << 8) | (length1 << 16);
    *pdu_flvh_length = 3;
  } else {
    *pdu_length = length2 | (length1 << 8);
    *pdu_flvh_length = 2;
  }
}

/******************************************************************************/
/* Dissect PDU V bit flag                                                     */
static void
dissect_pdu_bit_flag_v(int *offset, guint8 pdu_flags, guint32 *vector_offset, acn_pdu_offsets *last_pdu_offsets, guint32 *pdu_flvh_length, guint8 increment)
{
  /* Set vector offset */
  if (pdu_flags & ACN_PDU_FLAG_V) {
    /* use new values */
    *vector_offset            = *offset;
    last_pdu_offsets->vector  = *offset;
    *offset                   += increment;
    *pdu_flvh_length          += increment;
  } else {
    /* use last values */
    *vector_offset            = last_pdu_offsets->vector;
  }
}

/******************************************************************************/
/* Dissect PDU H bit flag                                                     */
static void
dissect_pdu_bit_flag_h(int *offset, guint8 pdu_flags, guint32 *header_offset, acn_pdu_offsets *last_pdu_offsets, guint32 *pdu_flvh_length, guint8 increment)
{
  /* Set header offset */
  if (pdu_flags & ACN_PDU_FLAG_H) {
    /* use new values */
    *header_offset            = *offset;
    last_pdu_offsets->header  = *offset;
    *offset                   += increment;
    *pdu_flvh_length          += increment;
  } else {
    /* use last values */
    *header_offset            = last_pdu_offsets->header;
  }
}

/******************************************************************************/
/* Dissect PDU D bit flag                                                     */
static void
dissect_pdu_bit_flag_d(int offset, guint8 pdu_flags, guint32 pdu_length, guint32 *data_offset, guint32 *data_length, acn_pdu_offsets *last_pdu_offsets, guint32 pdu_flvh_length, gboolean set_last_value_length)
{
  /* Adjust data */
  if (pdu_flags & ACN_PDU_FLAG_D) {
    /* use new values */
    *data_offset                  = offset;
    *data_length                  = pdu_length - pdu_flvh_length;
    last_pdu_offsets->data        = offset;
    last_pdu_offsets->data_length = *data_length;
  } else {
    /* use last values */
    *data_offset                  = last_pdu_offsets->data;
    if (set_last_value_length) {
      *data_length                = last_pdu_offsets->data_length;
    }
  }
}

/******************************************************************************/
/* Add flag and flag tree                                                     */
static void
begin_dissect_acn_pdu(proto_tree **pdu_tree, tvbuff_t *tvb, proto_item **ti, proto_tree *tree, guint32 *pdu_start, int *offset, guint8 *pdu_flags, guint32 *pdu_length, guint32 *pdu_flvh_length, gint ett_base_pdu, gboolean is_acn)
{
  proto_item  *pi;
  proto_tree  *flag_tree;

  /* save start of pdu block */
  *pdu_start        = *offset;

  dissect_pdu_bit_flag_l(tvb, offset, pdu_flags, pdu_length, pdu_flvh_length);
  /* offset should now be pointing to vector (if one exists) */

  /* add pdu item and tree */
  if (is_acn) {
    *ti = proto_tree_add_item(tree, hf_acn_pdu, tvb, *pdu_start, *pdu_length, ENC_NA);
  } else {
    *ti = proto_tree_add_item(tree, hf_rdmnet_pdu, tvb, *pdu_start, *pdu_length, ENC_NA);
  }
  *pdu_tree = proto_item_add_subtree(*ti, ett_base_pdu);

  /* add flag item and tree */
  if (is_acn) {
    pi        = proto_tree_add_uint(*pdu_tree, hf_acn_pdu_flags, tvb, *pdu_start, 1, *pdu_flags);
    flag_tree = proto_item_add_subtree(pi, ett_acn_pdu_flags);
    proto_tree_add_item(flag_tree, hf_acn_pdu_flag_l, tvb, *pdu_start, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_acn_pdu_flag_v, tvb, *pdu_start, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_acn_pdu_flag_h, tvb, *pdu_start, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_acn_pdu_flag_d, tvb, *pdu_start, 1, ENC_BIG_ENDIAN);
  }
  else {
    pi        = proto_tree_add_uint(*pdu_tree, hf_rdmnet_pdu_flags, tvb, *pdu_start, 1, *pdu_flags);
    flag_tree = proto_item_add_subtree(pi, ett_rdmnet_pdu_flags);
    proto_tree_add_item(flag_tree, hf_rdmnet_pdu_flag_l, tvb, *pdu_start, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_rdmnet_pdu_flag_v, tvb, *pdu_start, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_rdmnet_pdu_flag_h, tvb, *pdu_start, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_rdmnet_pdu_flag_d, tvb, *pdu_start, 1, ENC_BIG_ENDIAN);
  }
}

/******************************************************************************/
/* Dissect wrapped SDT PDU                                                    */
static guint32
dissect_acn_dmp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  gboolean          blob_exists = 0;
  guint8            pdu_flags;
  guint32           pdu_start;
  guint32           pdu_length;
  guint32           pdu_flvh_length; /* flags, length, vector, header */
  guint8            D;
  guint32           vector_offset;
  guint32           header_offset;
  guint32           data_offset;
  guint32           old_offset;
  guint32           end_offset;
  guint32           data_length;
  guint32           address_count;
  guint32           blob_offset;
  guint32           blob_end_offset = 0;

  proto_item       *ti;
  proto_tree       *pdu_tree  = NULL;

  /* this pdu */
  const gchar      *name;
  acn_dmp_adt_type  adt       = {0,0,0,0,0,0};
  acn_dmp_adt_type  adt2      = {0,0,0,0,0,0};
  guint32           vector;

  begin_dissect_acn_pdu(&pdu_tree, tvb, &ti, tree, &pdu_start, &offset, &pdu_flags, &pdu_length, &pdu_flvh_length, ett_acn_dmp_pdu, 1);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_acn_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  dissect_pdu_bit_flag_v(&offset, pdu_flags, &vector_offset, last_pdu_offsets, &pdu_flvh_length, 1);
  /* offset should now be pointing to header (if one exists) */

  /* Add Vector item */
  vector = tvb_get_guint8(tvb, vector_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_dmp_vector, tvb, vector_offset, 1, vector);

  /* Add Vector item to tree*/
  name = val_to_str(vector, acn_dmp_vector_vals, "not valid (%d)");
  proto_item_append_text(ti, ": ");
  proto_item_append_text(ti, "%s", name);

  dissect_pdu_bit_flag_h(&offset, pdu_flags, &header_offset, last_pdu_offsets, &pdu_flvh_length, 1);
  /* offset should now be pointing to data (if one exists) */

  /* header contains address and data type */
  acn_add_dmp_address_type(tvb, pinfo, pdu_tree, header_offset, &adt);

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 1);
  end_offset = data_offset + data_length;

  /* Check if blob exists, find beginning offset */
  blob_offset = data_offset;
  blob_exists = 0;
  while ((blob_offset < (end_offset - 4)) && (blob_exists != 1)) {
    if (tvb_get_ntohl(tvb, blob_offset) == 0x426c6f62) {
      /* 0x426c6f62 == "Blob" */
      blob_exists = 1;
      break;
    }
    blob_offset += 1;
  }

  /* Fix the end_offset for finding Address-Data pair if blob exists*/
  if (blob_exists == 1) {
    blob_end_offset = end_offset - blob_offset;
    end_offset = blob_offset;
    data_length = blob_offset - data_offset;
  }

  switch (vector) {
    case ACN_DMP_VECTOR_UNKNOWN:
      break;
    case ACN_DMP_VECTOR_GET_PROPERTY:
      /* Rip through property address */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_SET_PROPERTY:
      /* Rip through Property Address-Data pairs                                 */
      /* But, in reality, this generally won't work as we have know way of       */
      /* calculating the next Address-Data pair                                  */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;

        adt.data_length = data_length - (data_offset - old_offset);
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_data(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_GET_PROPERTY_REPLY:
      /* Rip through Property Address-Data pairs */
      /* But, in reality, this generally won't work as we have know way of       */
      /* calculating the next Address-Data pair                                  */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;

        adt.data_length = data_length - (data_offset - old_offset);
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_data(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_EVENT:
    case ACN_DMP_VECTOR_SYNC_EVENT:
      /* Rip through Property Address-Data pairs */
      /* But, in reality, this generally won't work as we have know way of       */
      /* calculating the next Address-Data pair                                  */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;

        adt.data_length = data_length - (data_offset - old_offset);
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_data(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_MAP_PROPERTY:
      /* Virtual Address type */
      data_offset = acn_add_dmp_address_type(tvb, pinfo, pdu_tree, data_offset, &adt2);
      /* Rip through Actual-Virtual Address Pairs */
      while (data_offset < end_offset) {
        /* actual */
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
        D = ACN_DMP_ADT_EXTRACT_D(adt.flags);
        switch (D) {
          case ACN_DMP_ADT_D_NS:
            address_count = 1;
            break;
          case ACN_DMP_ADT_D_RS:
            address_count = 1;
            break;
          case ACN_DMP_ADT_D_RE:
            address_count = adt.count;
            break;
            /*case ACN_DMP_ADT_D_RM: */
          default:
            /* OUCH */
            return pdu_start + pdu_length;
            break;
        }

        /* virtual */
        while (address_count > 0) {
          data_offset = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt2);
          address_count--;
        }
      }
      break;
    case ACN_DMP_VECTOR_UNMAP_PROPERTY:
      /* Rip through Actual Property Address */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_SUBSCRIBE:
      /* Rip through Property Address */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_UNSUBSCRIBE:
      /* Rip through Property Address */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_GET_PROPERTY_FAIL:
      /* Rip through Address-Reason Code Pairs */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;

        adt.data_length = data_length - (data_offset - old_offset);
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_reason_codes(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_SET_PROPERTY_FAIL:
      /* Rip through Address-Reason Code Pairs */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;

        adt.data_length = data_length - (data_offset - old_offset);
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_reason_codes(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_MAP_PROPERTY_FAIL:
      /* Rip through Address-Reason Code Pairs */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;

        adt.data_length = data_length - (data_offset - old_offset);
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_reason_codes(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_SUBSCRIBE_ACCEPT:
      /* Rip through Property Addresses */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_SUBSCRIBE_REJECT:
      /* Rip through Address-Reason Code Pairs */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;

        adt.data_length = data_length - (data_offset - old_offset);
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_reason_codes(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_ALLOCATE_MAP:
      /* No data for this */
      break;
    case ACN_DMP_VECTOR_ALLOCATE_MAP_REPLY:
      /* Single reason code  */
      proto_tree_add_item(pdu_tree, hf_acn_dmp_reason_code, tvb, data_offset, 1, ENC_BIG_ENDIAN);
      /* data_offset += 1; */
    case ACN_DMP_VECTOR_DEALLOCATE_MAP:
      /* No data for this */
      break;
  }

  /* If blob exists, call function to dissect blob*/
  if (blob_exists == 1) {
    dissect_acn_blob(tvb, pinfo, pdu_tree, blob_offset, blob_end_offset);
  }

  return pdu_start + pdu_length;
}


/******************************************************************************/
/* Dissect wrapped SDT PDU                                                    */
static guint32
dissect_acn_sdt_wrapped_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  guint32          vector_offset;
  guint32          data_offset;
  guint32          data_length;

  proto_item  *ti;
  proto_tree  *pdu_tree  = NULL;

  /* this pdu */
  const gchar *name;
  guint32      vector;

  begin_dissect_acn_pdu(&pdu_tree, tvb, &ti, tree, &pdu_start, &offset, &pdu_flags, &pdu_length, &pdu_flvh_length, ett_acn_sdt_pdu, 1);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_acn_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  dissect_pdu_bit_flag_v(&offset, pdu_flags, &vector_offset, last_pdu_offsets, &pdu_flvh_length, 1);
  /* offset should now be pointing to header (if one exists) */

  /* Add Vector item */
  vector = tvb_get_guint8(tvb, vector_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_sdt_vector, tvb, vector_offset, 1, vector);

  /* Add Vector item to tree*/
  name = val_to_str(vector, acn_sdt_vector_vals, "not valid (%d)");
  proto_item_append_text(ti, ": ");
  proto_item_append_text(ti, "%s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 0);

  switch (vector) {
    case ACN_SDT_VECTOR_ACK:
      proto_tree_add_item(pdu_tree, hf_acn_reliable_sequence_number, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      /*data_offset += 4;*/
      break;
    case ACN_SDT_VECTOR_CHANNEL_PARAMS:
      data_offset = acn_add_channel_parameter(tvb, pinfo, pdu_tree, data_offset);
      data_offset = acn_add_address(tvb, pinfo, pdu_tree, data_offset, "Ad-hoc Address:");
      /*data_offset =*/ acn_add_expiry(tvb, pinfo, pdu_tree, data_offset, hf_acn_adhoc_expiry);
      break;
    case ACN_SDT_VECTOR_LEAVE:
      /* nothing more */
      break;
    case ACN_SDT_VECTOR_CONNECT:
      /* Protocol ID item */
      proto_tree_add_item(pdu_tree, hf_acn_protocol_id, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      /*data_offset += 4;*/
      break;
    case ACN_SDT_VECTOR_CONNECT_ACCEPT:
      /* Protocol ID item */
      proto_tree_add_item(pdu_tree, hf_acn_protocol_id, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      /*data_offset += 4;*/
      break;
    case ACN_SDT_VECTOR_CONNECT_REFUSE:
      /* Protocol ID item */
      proto_tree_add_item(pdu_tree, hf_acn_protocol_id, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_refuse_code, tvb, data_offset, 1, ENC_BIG_ENDIAN);
      /*data_offset += 1;*/
      break;
    case ACN_SDT_VECTOR_DISCONNECT:
      /* Protocol ID item */
      proto_tree_add_item(pdu_tree, hf_acn_protocol_id, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      /*data_offset += 4;*/
      break;
    case ACN_SDT_VECTOR_DISCONNECTING:
      /* Protocol ID item */
      proto_tree_add_item(pdu_tree, hf_acn_protocol_id, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_reason_code, tvb, data_offset, 1, ENC_BIG_ENDIAN);
      /*data_offset += 1;*/
      break;

  }

  return pdu_start + pdu_length;
}


/******************************************************************************/
/* Dissect SDT Client PDU                                                     */
static guint32
dissect_acn_sdt_client_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};
  guint32          vector_offset;
  guint32          header_offset;
  guint32          data_offset;
  guint32          data_length;
  guint32          old_offset;
  guint32          end_offset;

  proto_item      *ti;
  proto_tree      *pdu_tree    = NULL;

  /* this pdu */
  const gchar     *name;
  guint32          member_id;
  guint32          protocol_id;
  guint16          association;

  begin_dissect_acn_pdu(&pdu_tree, tvb, &ti, tree, &pdu_start, &offset, &pdu_flags, &pdu_length, &pdu_flvh_length, ett_acn_sdt_client_pdu, 1);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_acn_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  dissect_pdu_bit_flag_v(&offset, pdu_flags, &vector_offset, last_pdu_offsets, &pdu_flvh_length, 2);
  /* offset should now be pointing to header (if one exists) */

  /* add Member ID item  */
  member_id = tvb_get_ntohs(tvb, vector_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_member_id, tvb, vector_offset, 2, member_id);

  dissect_pdu_bit_flag_h(&offset, pdu_flags, &header_offset, last_pdu_offsets, &pdu_flvh_length, 6);
  /* offset should now be pointing to data (if one exists) */

  /* add Protocol ID item (Header)*/
  protocol_id = tvb_get_ntohl(tvb, header_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_protocol_id, tvb, header_offset, 4, protocol_id);
  header_offset += 4;

  /* Add protocol to tree*/
  name = val_to_str(protocol_id, acn_protocol_id_vals, "id not valid (%d)");
  proto_item_append_text(ti, ": ");
  proto_item_append_text(ti, "%s", name);

  /* add association item */
  association = tvb_get_ntohs(tvb, header_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_association, tvb, header_offset, 2, association);
  /*header_offset += 2;*/

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 1);
  end_offset = data_offset + data_length;

  switch (protocol_id) {
    case ACN_PROTOCOL_ID_SDT:
      while (data_offset < end_offset) {
        old_offset  = data_offset;
        data_offset = dissect_acn_sdt_wrapped_pdu(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_PROTOCOL_ID_DMP:
      while (data_offset < end_offset) {
        old_offset  = data_offset;
        data_offset = dissect_acn_dmp_pdu(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
        if (data_offset == old_offset) break;
      }
      break;
  }
  return pdu_start + pdu_length;
}


/******************************************************************************/
/* level to string (ascii)                                                    */
/*  level    : 8 bit value                                                    */
/*  string   : pointer to buffer to fill                                      */
/*  leading_char: character to buffer left of digits                          */
/*  min_char : minimum number of characters (for filling, not including space)*/
/*  show_zero: show zeros or dots                                             */
/* also adds a space to right end                                             */
/*                                                                            */
/*  returns end of string                                                     */
/*  faster than printf()                                                      */
static char *
ltos(guint8 level, gchar *string, guint8 base, gchar leading_char, guint8 min_chars, gboolean show_zero)
{
  guint8 i;
  /* verify base */
  if (base < 2 || base > 16) {
    *string = '\0';
    return(string);
  }
  /* deal with zeros */
  if ((level == 0) && (!show_zero)) {
    for (i=0; i<min_chars; i++) {
      string[i] = '.';
    }
    string[i++] = ' ';
    string[i] = '\0';
    return(string + i);
  }

  i = 0;
  /* do our convert, comes out backwards! */
  do {
    string[i++] = "0123456789ABCDEF"[level % base];
  } while ((level /= base) > 0);

  /* expand to needed character */
  for (; i<min_chars; i++) {
    string[i] = leading_char;
  }
  /* terminate */
  string[i] = '\0';

  /* now reverse (and correct) the order */
  g_strreverse(string);

  /* add a space at the end (ok it's at the start but it will be at the end)*/
  string[i++] = ' ';
  string[i] = '\0';
  return(string + i);
}


/******************************************************************************/
/* Dissect DMX data PDU                                                       */
#define BUFFER_SIZE 128
static guint32
dissect_acn_dmx_data_pdu(guint32 protocol_id, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8            pdu_flags;
  guint32           pdu_start;
  guint32           pdu_length;
  guint32           pdu_flvh_length; /* flags, length, vector, header */
  guint32           vector_offset;
  guint32           data_offset;
  guint32           end_offset;
  guint32           data_length;
  guint32           header_offset;
  guint32           total_cnt;
  guint32           item_cnt;

  proto_item       *ti;
  proto_tree       *pdu_tree;

/* this pdu */
  acn_dmp_adt_type  adt       = {0,0,0,0,0,0};
  const gchar      *name;
  guint32           vector;
  gchar            *buffer;
  char             *buf_ptr;
  guint             x;
  guint8            level;
  guint8            min_char;
  guint8            base;
  gchar             leading_char;
  guint             perline;
  guint             halfline;
  guint16           dmx_count;
  guint16           dmx_start_code;
  guint16           info_start_code;
  guint8            dmx_2_start_code;

  buffer = (gchar*)wmem_alloc(wmem_packet_scope(), BUFFER_SIZE);
  buffer[0] = '\0';

  begin_dissect_acn_pdu(&pdu_tree, tvb, &ti, tree, &pdu_start, &offset, &pdu_flags, &pdu_length, &pdu_flvh_length, ett_acn_dmx_data_pdu, 1);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_acn_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  dissect_pdu_bit_flag_v(&offset, pdu_flags, &vector_offset, last_pdu_offsets, &pdu_flvh_length, 1);
  /* offset should now be pointing to header (if one exists) */

  /* Add Vector item */
  vector = tvb_get_guint8(tvb, vector_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_dmp_vector, tvb, vector_offset, 1, vector);

  /* Add Vector item to tree*/
  name = val_to_str(vector, acn_dmp_vector_vals, "not valid (%d)");
  proto_item_append_text(ti, ": ");
  proto_item_append_text(ti, "%s", name);

  dissect_pdu_bit_flag_h(&offset, pdu_flags, &header_offset, last_pdu_offsets, &pdu_flvh_length, 1);
  /* offset should now be pointing to data (if one exists) */

  /* process based on vector */
  acn_add_dmp_address_type(tvb, pinfo, pdu_tree, header_offset, &adt);

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 1);
  end_offset = data_offset + data_length;

  switch (vector) {
    case ACN_DMP_VECTOR_SET_PROPERTY:
      dmx_start_code = tvb_get_ntohs(tvb, data_offset);
      if (protocol_id == ACN_PROTOCOL_ID_DMX_2) {
        proto_tree_add_item(pdu_tree, hf_acn_dmx_2_first_property_address, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      } else {
        proto_tree_add_item(pdu_tree, hf_acn_dmx_start_code, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      }
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_dmx_increment, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      dmx_count    = tvb_get_ntohs(tvb, data_offset);
      proto_tree_add_item(pdu_tree, hf_acn_dmx_count, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;

      if (protocol_id == ACN_PROTOCOL_ID_DMX_2) {
        dmx_2_start_code = (guint8)tvb_get_ntohs(tvb, data_offset - 1);
        proto_tree_add_item(pdu_tree, hf_acn_dmx_2_start_code, tvb, data_offset, 1, ENC_BIG_ENDIAN);
        data_offset += 1;
        dmx_count   -= 1;
      }

      buf_ptr = buffer;

      switch (global_acn_dmx_display_line_format) {
        case ACN_PREF_DMX_DISPLAY_16PL:
          perline  = 16;
          halfline = 8;
          break;
        default:
          perline  = 20;
          halfline = 10;
      }

      /* values base on display mode */
      switch ((guint)global_acn_dmx_display_view) {
        case ACN_PREF_DMX_DISPLAY_HEX:
          min_char = 2;
          base     = 16;
          break;
/*      case ACN_PREF_DMX_DISPLAY_PER: */
        default:
          min_char = 3;
          base     = 10;
      }

      /* do we display leading zeros */
      if (global_acn_dmx_display_leading_zeros) {
        leading_char = '0';
      } else {
        leading_char = ' ';
      }
      /* add a snippet to info (this may be slow) */
      if (protocol_id == ACN_PROTOCOL_ID_DMX_2) {
        info_start_code = dmx_2_start_code;
      }
      else {
        info_start_code = dmx_start_code;
      }
      col_append_fstr(pinfo->cinfo,COL_INFO, ", Sc %02x, [%02x %02x %02x %02x %02x %02x...]",
        info_start_code,
        tvb_get_guint8(tvb, data_offset),
        tvb_get_guint8(tvb, data_offset+1),
        tvb_get_guint8(tvb, data_offset+2),
        tvb_get_guint8(tvb, data_offset+3),
        tvb_get_guint8(tvb, data_offset+4),
        tvb_get_guint8(tvb, data_offset+5));

      /* add a header line */
      *buf_ptr++ =  ' ';
      *buf_ptr++ =  ' ';
      *buf_ptr++ =  ' ';
      for (x=0; x<perline; x++) {
        buf_ptr = ltos((guint8)(x+1), buf_ptr, 10, ' ', min_char, FALSE);
        if ((x+1)==halfline) {
          *buf_ptr++ =  '|';
          *buf_ptr++ =  ' ';
        }
      }
      *buf_ptr = '\0';
      proto_tree_add_string(pdu_tree, hf_acn_dmx_data, tvb, data_offset, dmx_count, buffer);

      /* start our line */
      g_snprintf(buffer, BUFFER_SIZE, "001-%03d: ", perline);
      buf_ptr = buffer + 9;

      total_cnt = 0;
      item_cnt = 0;
      for (x=data_offset; x<end_offset; x++) {
        level = tvb_get_guint8(tvb, x);
        if (global_acn_dmx_display_view == ACN_PREF_DMX_DISPLAY_PER) {
          if ((level > 0) && (level < 3)) {
            level = 1;
          } else {
            level = level * 100 / 255;
          }
        }
        buf_ptr = ltos(level, buf_ptr, base, leading_char, min_char, global_acn_dmx_display_zeros);
        total_cnt++;
        item_cnt++;

        if (item_cnt == perline || x == (end_offset-1)) {
          /* add leader... */
          proto_tree_add_string_format(pdu_tree, hf_acn_dmx_data, tvb, data_offset, item_cnt, buffer, "%s", buffer);
          data_offset += perline;
          g_snprintf(buffer, BUFFER_SIZE, "%03d-%03d: ",total_cnt, total_cnt+perline);
          buf_ptr = buffer + 9;
          item_cnt = 0;
        } else {
          /* add separator character */
          if (item_cnt == halfline) {
            *buf_ptr++ = '|';
            *buf_ptr++ = ' ';
            *buf_ptr   = '\0';
          }
        }
      }
      /* NOTE:
      address data type                   (fixed at 0xA2)
      start code - 1 byte, reserved       (should be 0)
                 - 1 byte, start code     (0x255)
                 - 2 bytes, packet offset (should be 0000)
      address increment - 4 bytes         (ignore)
      number of dmx values - 4 bytes      (0-512)
      dmx values 0-512 bytes              (data)
      */

      break;
  }
  return pdu_start + pdu_length;
}

/******************************************************************************/
/* Dissect Common Base PDU                                                    */
static void
dissect_acn_common_base_pdu(tvbuff_t *tvb, proto_tree *tree, int *offset, acn_pdu_offsets *last_pdu_offsets, guint8 *pdu_flags, guint32 *pdu_start, guint32 *pdu_length, guint32 *pdu_flvh_length, guint32 *vector_offset, proto_item **ti, proto_tree **pdu_tree, gint ett_base_pdu, guint8 v_flag_increment, gboolean is_acn)
{
  begin_dissect_acn_pdu(pdu_tree, tvb, ti, tree, pdu_start, offset, pdu_flags, pdu_length, pdu_flvh_length, ett_base_pdu, is_acn);

  /* Add PDU Length item */
  if (is_acn) {
    proto_tree_add_uint(*pdu_tree, hf_acn_pdu_length, tvb, *pdu_start, *pdu_flvh_length, *pdu_length);
  } else {
    proto_tree_add_uint(*pdu_tree, hf_rdmnet_pdu_length, tvb, *pdu_start, *pdu_flvh_length, *pdu_length);
  }

  dissect_pdu_bit_flag_v(offset, *pdu_flags, vector_offset, last_pdu_offsets, pdu_flvh_length, v_flag_increment);
  /* offset should now be pointing to header (if one exists) */
}

/******************************************************************************/
/* Dissect DMX Base PDU                                                       */
static guint32
dissect_acn_dmx_base_pdu(guint32 protocol_id, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};
  guint8           option_flags;
  guint32          vector_offset;
  guint32          data_offset;
  guint32          data_length;

  proto_item      *ti, *pi;
  proto_tree      *pdu_tree;
  proto_tree      *flag_tree;

  /* this pdu */
  const char      *name;
  guint32          vector;

  guint32          universe;
  guint32          priority;
  guint32          sequence;

  dissect_acn_common_base_pdu(tvb, tree, &offset, last_pdu_offsets, &pdu_flags, &pdu_start, &pdu_length, &pdu_flvh_length, &vector_offset, &ti, &pdu_tree, ett_acn_dmx_pdu, 4, 1);

  /* Add Vector item */
  vector = tvb_get_ntohl(tvb, vector_offset);
  proto_tree_add_item(pdu_tree, hf_acn_dmx_vector, tvb, vector_offset, 4, ENC_BIG_ENDIAN);
  /* vector_offset +=4; */

  /* Add Vector item to tree*/
  name = val_to_str(vector, acn_dmx_vector_vals, "not valid (%d)");
  proto_item_append_text(ti, ": %s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 0);

  /* process based on vector */
  switch (vector) {
    case ACN_DMP_VECTOR_SET_PROPERTY:
      if (protocol_id == ACN_PROTOCOL_ID_DMX_2) {
        proto_tree_add_item(pdu_tree, hf_acn_dmx_source_name, tvb, data_offset, 64, ENC_UTF_8|ENC_NA);
        data_offset += 64;
      } else {
        proto_tree_add_item(pdu_tree, hf_acn_dmx_source_name, tvb, data_offset, 32, ENC_UTF_8|ENC_NA);
        data_offset += 32;
      }

      priority = tvb_get_guint8(tvb, data_offset);
      proto_tree_add_item(pdu_tree, hf_acn_dmx_priority, tvb, data_offset, 1, ENC_BIG_ENDIAN);
      data_offset += 1;

      if (protocol_id == ACN_PROTOCOL_ID_DMX_2) {
        proto_tree_add_item(pdu_tree, hf_acn_dmx_2_reserved, tvb, data_offset, 2, ENC_BIG_ENDIAN);
        data_offset += 2;
      }

      sequence = tvb_get_guint8(tvb, data_offset);
      proto_tree_add_item(pdu_tree, hf_acn_dmx_sequence_number, tvb, data_offset, 1, ENC_BIG_ENDIAN);
      data_offset += 1;

      if (protocol_id == ACN_PROTOCOL_ID_DMX_2) {
        option_flags = tvb_get_guint8(tvb, data_offset);
        pi = proto_tree_add_uint(pdu_tree, hf_acn_dmx_2_options, tvb, data_offset, 1, option_flags);
        flag_tree = proto_item_add_subtree(pi, ett_acn_dmx_2_options);
        proto_tree_add_item(flag_tree, hf_acn_dmx_2_option_p, tvb, data_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_acn_dmx_2_option_s, tvb, data_offset, 1, ENC_BIG_ENDIAN);
        data_offset += 1;
      }

      universe = tvb_get_ntohs(tvb, data_offset);
      proto_tree_add_item(pdu_tree, hf_acn_dmx_universe, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;

      /* add universe to info */
      col_append_fstr(pinfo->cinfo,COL_INFO, ", Universe %d, Seq %3d", universe, sequence );
      proto_item_append_text(ti, ", Universe: %d, Priority: %d", universe, priority);

      /*data_offset =*/ dissect_acn_dmx_data_pdu(protocol_id, tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);

      break;
  }
  return pdu_start + pdu_length;
}

/******************************************************************************/
/* Dissect SDT Base PDU                                                       */
static guint32
dissect_acn_sdt_base_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};
  guint32          vector_offset;
  guint32          data_offset;
  guint32          end_offset;
  guint32          old_offset;
  guint32          data_length;

  proto_item      *ti, *pi;
  proto_tree      *pdu_tree;

  /* this pdu */
  const gchar     *name;
  guint32          vector;
  guint32          member_id;

  dissect_acn_common_base_pdu(tvb, tree, &offset, last_pdu_offsets, &pdu_flags, &pdu_start, &pdu_length, &pdu_flvh_length, &vector_offset, &ti, &pdu_tree, ett_acn_sdt_base_pdu, 1, 1);

  /* Add Vector item */
  vector = tvb_get_guint8(tvb, vector_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_sdt_vector, tvb, vector_offset, 1, vector);

  /* Add Vector item to tree*/
  name = val_to_str(vector, acn_sdt_vector_vals, "not valid (%d)");
  proto_item_append_text(ti, ": %s", name);
  /* proto_item_append_text(ti, "%s", name); */

  /* NO HEADER DATA ON THESE* (at least so far) */

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 1);
  end_offset = data_offset + data_length;

  /* process based on vector */
  switch (vector) {
    case ACN_SDT_VECTOR_UNKNOWN:
      break;
    case ACN_SDT_VECTOR_REL_WRAP:
    case ACN_SDT_VECTOR_UNREL_WRAP:
      proto_tree_add_item(pdu_tree, hf_acn_channel_number,           tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_total_sequence_number,    tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_reliable_sequence_number, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_oldest_available_wrapper, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_first_member_to_ack,      tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_last_member_to_ack,       tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_mak_threshold,            tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;

      while (data_offset < end_offset) {
        old_offset = data_offset;
        data_offset = dissect_acn_sdt_client_pdu(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
        if (data_offset == old_offset) break;
      }
      break;
    case ACN_SDT_VECTOR_CHANNEL_PARAMS:
      break;
    case ACN_SDT_VECTOR_JOIN:
      proto_tree_add_item(pdu_tree, hf_acn_cid,                      tvb, data_offset, 16, ENC_BIG_ENDIAN);
      data_offset += 16;
      proto_tree_add_item(pdu_tree, hf_acn_member_id,                tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_channel_number,           tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_reciprocal_channel,       tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_total_sequence_number,    tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_reliable_sequence_number, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      data_offset = acn_add_address(tvb, pinfo, pdu_tree, data_offset, "Destination Address:");
      data_offset = acn_add_channel_parameter(tvb, pinfo, pdu_tree, data_offset);
      /*data_offset =*/ acn_add_expiry(tvb, pinfo, pdu_tree, data_offset, hf_acn_adhoc_expiry);
      break;
    case ACN_SDT_VECTOR_JOIN_REFUSE:
      pi = proto_tree_add_item(pdu_tree, hf_acn_cid,                  tvb, data_offset, 16, ENC_BIG_ENDIAN);
      data_offset += 16;
      proto_item_append_text(pi, "(Leader)");
      proto_tree_add_item(pdu_tree, hf_acn_channel_number,            tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_member_id,                 tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_reliable_sequence_number,  tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_refuse_code,               tvb, data_offset, 1, ENC_BIG_ENDIAN);
      /*data_offset ++;*/
      break;
    case ACN_SDT_VECTOR_JOIN_ACCEPT:
      pi = proto_tree_add_item(pdu_tree, hf_acn_cid, tvb, data_offset, 16, ENC_BIG_ENDIAN);
      data_offset += 16;
      proto_item_append_text(pi, "(Leader)");
      proto_tree_add_item(pdu_tree, hf_acn_channel_number, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_member_id, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_reliable_sequence_number, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_reciprocal_channel, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      /*data_offset += 2;*/
      break;
    case ACN_SDT_VECTOR_LEAVE:
      break;
    case ACN_SDT_VECTOR_LEAVING:
      pi = proto_tree_add_item(pdu_tree, hf_acn_cid,                 tvb, data_offset, 16, ENC_BIG_ENDIAN);
      data_offset += 16;
      proto_item_append_text(pi, "(Leader)");
      proto_tree_add_item(pdu_tree, hf_acn_channel_number,           tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_member_id,                tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_reliable_sequence_number, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_reason_code,              tvb, data_offset, 1, ENC_BIG_ENDIAN);
      /* offset += 1; */
      break;
    case ACN_SDT_VECTOR_CONNECT:
      break;
    case ACN_SDT_VECTOR_CONNECT_ACCEPT:
      break;
    case ACN_SDT_VECTOR_CONNECT_REFUSE:
      break;
    case ACN_SDT_VECTOR_DISCONNECT:
      break;
    case ACN_SDT_VECTOR_DISCONNECTING:
      break;
    case ACN_SDT_VECTOR_ACK:
      break;
    case ACN_SDT_VECTOR_NAK:
      pi = proto_tree_add_item(pdu_tree, hf_acn_cid,                 tvb, data_offset, 16, ENC_BIG_ENDIAN);
      data_offset += 16;
      proto_item_append_text(pi, "(Leader)");
      proto_tree_add_item(pdu_tree, hf_acn_channel_number,           tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_member_id,                tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_reliable_sequence_number, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_first_missed_sequence,    tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_last_missed_sequence,     tvb, data_offset, 4, ENC_BIG_ENDIAN);
      /*data_offset += 4;*/
      break;
    case ACN_SDT_VECTOR_GET_SESSION:
      proto_tree_add_item(pdu_tree, hf_acn_cid, tvb, data_offset, 16, ENC_BIG_ENDIAN);
      /*data_offset += 16;*/
      break;
    case ACN_SDT_VECTOR_SESSIONS:
      member_id = tvb_get_ntohs(tvb, data_offset);
      switch (member_id) {
        case 0:
          /*data_offset =*/ acn_add_channel_owner_info_block(tvb, pinfo, pdu_tree, data_offset);
          break;
        case 1:
          /*data_offset =*/ acn_add_channel_member_info_block(tvb, pinfo, pdu_tree, data_offset);
          break;
      }
      break;
  }

  return pdu_start + pdu_length;
}


/******************************************************************************/
/* Dissect LLRP Probe Request PDU                                             */
static guint32
dissect_llrp_probe_request_pdu(tvbuff_t *tvb, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8           pdu_flags;
  guint8           vector;
  guint8           filter_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  guint32          data_offset;
  guint32          end_offset;

  proto_item      *ti, *pi;
  proto_tree      *flag_tree;
  proto_tree      *pdu_tree;

  begin_dissect_acn_pdu(&pdu_tree, tvb, &ti, tree, &pdu_start, &offset, &pdu_flags, &pdu_length, &pdu_flvh_length, ett_rdmnet_llrp_probe_request_pdu, 0);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_rdmnet_llrp_probe_request_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  dissect_pdu_bit_flag_v(&offset, pdu_flags, &data_offset, last_pdu_offsets, &pdu_flvh_length, 2);
  /* offset should now be pointing to header (if one exists) */

  /* add vector item  */
  vector = tvb_get_guint8(tvb, data_offset);
  proto_tree_add_uint(pdu_tree, hf_rdmnet_llrp_probe_request_vector, tvb, data_offset, 1, vector);

  dissect_pdu_bit_flag_h(&offset, pdu_flags, &data_offset, last_pdu_offsets, &pdu_flvh_length, 6);
  data_offset -= 1;
  /* offset should now be pointing to data (if one exists) */

  /* lower uid */
  proto_tree_add_item(pdu_tree, hf_rdmnet_llrp_probe_request_lower_uid, tvb, data_offset, 6, ENC_NA);
  data_offset += 6;

  /* upper uid */
  proto_tree_add_item(pdu_tree, hf_rdmnet_llrp_probe_request_upper_uid, tvb, data_offset, 6, ENC_NA);
  data_offset += 6;

  /* filter */
  filter_flags = tvb_get_guint8(tvb, data_offset);
  filter_flags = filter_flags & 0x03;
  pi = proto_tree_add_uint(pdu_tree, hf_rdmnet_llrp_probe_request_filter, tvb, data_offset, 1, filter_flags);
  flag_tree = proto_item_add_subtree(pi, ett_rdmnet_llrp_probe_request_filter_flags);
  proto_tree_add_item(flag_tree, hf_rdmnet_llrp_probe_request_filter_brokers_only, tvb, data_offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_rdmnet_llrp_probe_request_filter_client_tcp_inactive, tvb, data_offset, 2, ENC_BIG_ENDIAN);
  data_offset += 2;

  /* known uids */
  end_offset = pdu_start + pdu_length;
  while (data_offset + 6 <= end_offset) {
    proto_tree_add_item(pdu_tree, hf_rdmnet_llrp_probe_request_known_uid, tvb, data_offset, 6, ENC_NA);
    data_offset += 6;
  }

  return pdu_start + pdu_length;
}


/******************************************************************************/
/* Dissect LLRP Probe Reply PDU                                             */
static guint32
dissect_llrp_probe_reply_pdu(tvbuff_t *tvb, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8           pdu_flags;
  guint8           vector;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  guint32          data_offset;

  proto_item      *ti;
  proto_tree      *pdu_tree;

  begin_dissect_acn_pdu(&pdu_tree, tvb, &ti, tree, &pdu_start, &offset, &pdu_flags, &pdu_length, &pdu_flvh_length, ett_rdmnet_llrp_probe_reply_pdu, 0);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_rdmnet_llrp_probe_request_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  dissect_pdu_bit_flag_v(&offset, pdu_flags, &data_offset, last_pdu_offsets, &pdu_flvh_length, 2);
  /* offset should now be pointing to header (if one exists) */

  /* add vector item  */
  vector = tvb_get_guint8(tvb, data_offset);
  proto_tree_add_uint(pdu_tree, hf_rdmnet_llrp_probe_reply_vector, tvb, data_offset, 1, vector);

  dissect_pdu_bit_flag_h(&offset, pdu_flags, &data_offset, last_pdu_offsets, &pdu_flvh_length, 6);
  data_offset -= 1;
  /* offset should now be pointing to data (if one exists) */

  /* uid */
  proto_tree_add_item(pdu_tree, hf_rdmnet_llrp_probe_reply_uid, tvb, data_offset, 6, ENC_NA);
  data_offset += 6;

  /* hardware address */
  proto_tree_add_item(pdu_tree, hf_rdmnet_llrp_probe_reply_hardware_address, tvb, data_offset, 6, ENC_NA);
  data_offset += 6;

  /* component type */
  proto_tree_add_item(pdu_tree, hf_rdmnet_llrp_probe_reply_component_type, tvb, data_offset, 1, ENC_BIG_ENDIAN);

  return pdu_start + pdu_length;
}


/******************************************************************************/
/* Dissect RDM Command                                                        */
static guint32
dissect_rdm_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdu_tree, guint32 data_offset, guint32 length)
{
  gboolean         save_info;
  gboolean         save_protocol;
  guint32          data_end;
  tvbuff_t        *next_tvb;

  save_info     = col_get_writable(pinfo->cinfo, COL_INFO);
  save_protocol = col_get_writable(pinfo->cinfo, COL_PROTOCOL);
  col_set_writable(pinfo->cinfo, COL_INFO, FALSE);
  col_set_writable(pinfo->cinfo, COL_PROTOCOL, FALSE);

  data_end = data_offset + length;
  next_tvb = tvb_new_subset_length(tvb, data_offset, length);
  call_dissector(rdm_handle, next_tvb, pinfo, pdu_tree);

  col_set_writable(pinfo->cinfo, COL_INFO, save_info);
  col_set_writable(pinfo->cinfo, COL_PROTOCOL, save_protocol);

  return data_end;
}


/******************************************************************************/
/* Dissect LLRP RDM Command PDU                                               */
static guint32
dissect_llrp_rdm_command_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8           pdu_flags;
  guint8           vector;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_end;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  guint32          data_offset;

  proto_item      *ti;
  proto_tree      *pdu_tree;

  /* this pdu */
  const gchar     *name;

  begin_dissect_acn_pdu(&pdu_tree, tvb, &ti, tree, &pdu_start, &offset, &pdu_flags, &pdu_length, &pdu_flvh_length, ett_rdmnet_llrp_rdm_command_pdu, 0);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_rdmnet_llrp_probe_request_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  dissect_pdu_bit_flag_v(&offset, pdu_flags, &data_offset, last_pdu_offsets, &pdu_flvh_length, 2);
  /* offset should now be pointing to header (if one exists) */

  /* add vector item  */
  vector = tvb_get_guint8(tvb, data_offset);
  proto_tree_add_uint(pdu_tree, hf_rdmnet_llrp_rdm_command_start_code, tvb, data_offset, 1, vector);

  /* Add Vector item to tree */
  name = val_to_str(vector, rdmnet_llrp_rdm_command_start_code_vals, "unknown (%d)");
  proto_item_append_text(ti, ": %s", name);

  dissect_pdu_bit_flag_h(&offset, pdu_flags, &data_offset, last_pdu_offsets, &pdu_flvh_length, 6);
  data_offset -= 1;
  /* offset should now be pointing to data (if one exists) */

  pdu_end = pdu_start + pdu_length;
  dissect_rdm_command(tvb, pinfo, pdu_tree, data_offset, (pdu_length-4));

  return pdu_end;
}


/******************************************************************************/
/* Dissect LLRP Base PDU                                                      */
static guint32
dissect_acn_llrp_base_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};
  guint32          vector_offset;
  guint32          data_offset;
  guint32          data_length;
  e_guid_t         guid;

  proto_item      *ti;
  proto_tree      *pdu_tree;

  /* this pdu */
  const gchar     *name;
  guint32          vector;

  dissect_acn_common_base_pdu(tvb, tree, &offset, last_pdu_offsets, &pdu_flags, &pdu_start, &pdu_length, &pdu_flvh_length, &vector_offset, &ti, &pdu_tree, ett_rdmnet_llrp_base_pdu, 1, 0);

  /* Add Vector item */
  vector = tvb_get_ntohl(tvb, vector_offset);
  proto_tree_add_item(pdu_tree, hf_rdmnet_llrp_vector, tvb, vector_offset, 4, ENC_BIG_ENDIAN);

  /* Add Vector item to tree */
  name = val_to_str(vector, rdmnet_llrp_vector_vals, "unknown (%d)");
  proto_item_append_text(ti, ": %s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 0);
  data_offset += 3;

  /* get destination (CID) 16 bytes */
  proto_tree_add_item(pdu_tree, hf_rdmnet_llrp_destination_cid, tvb, data_offset, 16, ENC_BIG_ENDIAN);
  tvb_get_guid(tvb, data_offset, &guid, ENC_BIG_ENDIAN);
  proto_item_append_text(ti, ", Dest: %s", guid_to_str(wmem_packet_scope(), &guid));
  data_offset += 16;

  /* transaction number (4 bytes) */
  proto_tree_add_item(pdu_tree, hf_rdmnet_llrp_transaction_number, tvb, data_offset, 4, ENC_BIG_ENDIAN);
  data_offset += 4;

  /* process based on vector */
  switch (vector) {
    case RDMNET_LLRP_VECTOR_PROBE_REQUEST:
      dissect_llrp_probe_request_pdu(tvb, pdu_tree, data_offset, &pdu_offsets);
      break;
    case RDMNET_LLRP_VECTOR_PROBE_REPLY:
      dissect_llrp_probe_reply_pdu(tvb, pdu_tree, data_offset, &pdu_offsets);
      break;
    case RDMNET_LLRP_VECTOR_RDM_CMD:
      dissect_llrp_rdm_command_pdu(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
      break;
  }

  return pdu_start + pdu_length;
}


/******************************************************************************/
/* Dissect Broker Client Entry PDU                                            */
static guint32
dissect_broker_client_entry_pdu(tvbuff_t *tvb, proto_tree *tree, guint32 offset, acn_pdu_offsets *last_pdu_offsets)
{
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_end;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  guint32          vector_offset;
  guint32          data_offset;
  guint32          data_length;

  proto_item      *ti;
  proto_item      *ti2;
  proto_tree      *pdu_tree;
  proto_tree      *pdu_tree2;

  /* this pdu */
  const gchar     *name;
  guint32          vector;

  dissect_acn_common_base_pdu(tvb, tree, &offset, last_pdu_offsets, &pdu_flags, &pdu_start, &pdu_length, &pdu_flvh_length, &vector_offset, &ti, &pdu_tree, ett_rdmnet_broker_client_entry_pdu, 1, 0);
  pdu_end = pdu_start + pdu_length;

  /* Add Vector item */
  vector = tvb_get_ntohl(tvb, vector_offset);
  proto_tree_add_item(pdu_tree, hf_rdmnet_broker_client_protocol_vector, tvb, vector_offset, 4, ENC_BIG_ENDIAN);

  /* Add Vector item to tree */
  name = val_to_str(vector, broker_client_protocol_vals, "unknown (%d)");
  proto_item_append_text(ti, ": %s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 0);
  data_offset += 3;

  /* client protocol cid */
  proto_tree_add_item(pdu_tree, hf_rdmnet_broker_client_protocol_cid, tvb, data_offset, 16, ENC_NA);
  data_offset += 16;

  /* process based on vector */
  switch (vector) {
  case RDMNET_CLIENT_PROTOCOL_RPT:
    /* client uid */
    proto_tree_add_item(pdu_tree, hf_rdmnet_broker_client_rpt_client_uid, tvb, data_offset, 6, ENC_NA);
    data_offset += 6;

    /* client type */
    proto_tree_add_item(pdu_tree, hf_rdmnet_broker_client_rpt_client_type, tvb, data_offset, 1, ENC_BIG_ENDIAN);
    data_offset += 1;

    /* binding cid */
    proto_tree_add_item(pdu_tree, hf_rdmnet_broker_client_rpt_binding_cid, tvb, data_offset, 16, ENC_NA);
    data_offset += 16;
    break;
  case RDMNET_CLIENT_PROTOCOL_EPT:
    while (offset + 36 < pdu_end) {
      /* protocol vector (manufacturer id + protocol id) */
      ti2 = proto_tree_add_item(pdu_tree, hf_rdmnet_broker_client_ept_protocol_vector, tvb, data_offset, 4, ENC_NA);
      pdu_tree2 = proto_item_add_subtree(ti2, ett_rdmnet_broker_client_entry_manufacturer_protocol_ids);
      proto_tree_add_item(pdu_tree2, hf_rdmnet_broker_client_ept_protocol_manufacturer_id, tvb, 0, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(pdu_tree2, hf_rdmnet_broker_client_ept_protocol_protocol_id, tvb, 2, 2, ENC_BIG_ENDIAN);
      offset += 4;

      /* protocol string */
      proto_tree_add_item(pdu_tree, hf_rdmnet_broker_client_ept_protocol_string, tvb, data_offset, 32, ENC_ASCII|ENC_NA);
      data_offset += 32;
    }
    break;
  }

  return pdu_end;
}


/******************************************************************************/
/* Dissect Broker Connect                                                     */
static guint32
dissect_broker_connect(tvbuff_t *tvb, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets, guint32 pdu_end)
{
  guint8           connection_flags;
  proto_item      *pi;
  proto_tree      *flag_tree;

  /* client scope */
  proto_tree_add_item(tree, hf_rdmnet_broker_connect_client_scope, tvb, offset, 63, ENC_ASCII|ENC_NA);
  offset += 63;

  /* e133 version */
  proto_tree_add_item(tree, hf_rdmnet_broker_connect_e133_version, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* search domain */
  proto_tree_add_item(tree, hf_rdmnet_broker_connect_search_domain, tvb, offset, 231, ENC_ASCII|ENC_NA);
  offset += 231;

  /* connection flags */
  connection_flags = tvb_get_guint8(tvb, offset);
  connection_flags = connection_flags & 0x01;
  pi = proto_tree_add_uint(tree, hf_rdmnet_broker_connect_connection_flags, tvb, offset, 1, connection_flags);
  flag_tree = proto_item_add_subtree(pi, ett_rdmnet_broker_connect_connection_flags);
  proto_tree_add_item(flag_tree, hf_rdmnet_broker_connect_connection_flags_incremental_updates, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  /* client_entry_pdu */
  dissect_broker_client_entry_pdu(tvb, tree, offset, last_pdu_offsets);

  return pdu_end;
}


/******************************************************************************/
/* Dissect Broker Connect Reply                                               */
static guint32
dissect_broker_connect_reply(tvbuff_t *tvb, proto_tree *tree, int offset)
{
  /* connection code */
  proto_tree_add_item(tree, hf_rdmnet_broker_connect_reply_connection_code, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* e133 version */
  proto_tree_add_item(tree, hf_rdmnet_broker_connect_reply_e133_version, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* broker uid */
  proto_tree_add_item(tree, hf_rdmnet_broker_connect_reply_broker_uid, tvb, offset, 6, ENC_NA);
  offset += 6;

  /* client uid */
  proto_tree_add_item(tree, hf_rdmnet_broker_connect_reply_client_uid, tvb, offset, 6, ENC_NA);

  return 0;
}


/******************************************************************************/
/* Dissect Broker Client Entry Update                                         */
static guint32
dissect_broker_client_entry_update(tvbuff_t *tvb, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets, guint32 pdu_end)
{
  guint8           connection_flags;

  proto_item      *pi;
  proto_tree      *flag_tree;

  /* connection flags */
  connection_flags = tvb_get_guint8(tvb, offset);
  connection_flags = connection_flags & 0x01;
  pi = proto_tree_add_uint(tree, hf_rdmnet_broker_client_entry_update_connection_flags, tvb, offset, 1, connection_flags);
  flag_tree = proto_item_add_subtree(pi, ett_rdmnet_broker_client_entry_update_connection_flags);
  proto_tree_add_item(flag_tree, hf_rdmnet_broker_client_entry_update_connection_flags_incremental_updates, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  /* client_entry_pdu */
  dissect_broker_client_entry_pdu(tvb, tree, offset, last_pdu_offsets);

  return pdu_end;
}


/******************************************************************************/
/* Dissect Broker Redirect V4                                                 */
static guint32
dissect_broker_redirect_v4(tvbuff_t *tvb, proto_tree *tree, int offset)
{
  /* ipv4 address */
  proto_tree_add_item(tree, hf_rdmnet_broker_redirect_ipv4_address, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* tcp port */
  proto_tree_add_item(tree, hf_rdmnet_broker_redirect_ipv4_tcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);

  return 0;
}


/******************************************************************************/
/* Dissect Broker Redirect V6                                                 */
static guint32
dissect_broker_redirect_v6(tvbuff_t *tvb, proto_tree *tree, int offset)
{
  /* ipv4 address */
  proto_tree_add_item(tree, hf_rdmnet_broker_redirect_ipv6_address, tvb, offset, 16, ENC_NA);
  offset += 16;

  /* tcp port */
  proto_tree_add_item(tree, hf_rdmnet_broker_redirect_ipv6_tcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);

  return 0;
}


/******************************************************************************/
/* Dissect Broker Disconnect                                                  */
static guint32
dissect_broker_disconnect(tvbuff_t *tvb, proto_tree *tree, int offset)
{
  /* disconnect reason */
  proto_tree_add_item(tree, hf_rdmnet_broker_disconnect_reason, tvb, offset, 2, ENC_BIG_ENDIAN);

  return 0;
}


/******************************************************************************/
/* Dissect Broker Request Dynamic UIDs                                        */
static guint32
dissect_broker_request_dynamic_uids(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint32 pdu_end)
{
  /* packed list of dynamic uid request (6 bytes) and rid (16 bytes) */
  while (offset + 22 < pdu_end) {
    /* dynamic uid request (6 bytes) */
    proto_tree_add_item(tree, hf_rdmnet_broker_dynamic_uid_request, tvb, offset, 6, ENC_NA);
    offset += 6;

    /* rid (16 bytes) */
    proto_tree_add_item(tree, hf_rdmnet_broker_rid, tvb, offset, 16, ENC_NA);
    offset += 16;
  }

  return 0;
}


/******************************************************************************/
/* Dissect Broker Assigned Dynamic UIDs                                       */
static guint32
dissect_broker_assigned_dynamic_uids(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint32 pdu_end)
{
  /* packed list of dynamic uid request (6 bytes), rid (16 bytes), and status_code (2 bytes) */
  while (offset + 24 < pdu_end) {
    /* dynamic uid request (6 bytes) */
    proto_tree_add_item(tree, hf_rdmnet_broker_assigned_dynamic_uid, tvb, offset, 6, ENC_NA);
    offset += 6;

    /* rid (16 bytes) */
    proto_tree_add_item(tree, hf_rdmnet_broker_assigned_rid, tvb, offset, 16, ENC_NA);
    offset += 16;

    /* status code (2 bytes) */
    proto_tree_add_item(tree, hf_rdmnet_broker_assigned_status_code, tvb, offset, 2, ENC_NA);
    offset += 2;
  }

  return 0;
}


/******************************************************************************/
/* Dissect Broker Fetch Dynamic UIDs                                       */
static guint32
dissect_broker_fetch_dynamic_uids(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint32 pdu_end)
{
  /* packed list of dynamic uid request (6 bytes) */
  while (offset + 6 < pdu_end) {
    /* dynamic uid request (6 bytes) */
    proto_tree_add_item(tree, hf_rdmnet_broker_fetch_dynamic_uid, tvb, offset, 6, ENC_NA);
    offset += 6;
  }

  return 0;
}


/******************************************************************************/
/* Dissect Broker Base PDU                                                    */
static guint32
dissect_acn_broker_base_pdu(tvbuff_t *tvb, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_end;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};
  guint32          vector_offset;
  guint32          data_offset;
  guint32          old_offset;
  guint32          end_offset;
  guint32          data_length;

  proto_item      *ti;
  proto_tree      *pdu_tree;

  /* this pdu */
  const gchar     *name;
  guint16          vector;

  dissect_acn_common_base_pdu(tvb, tree, &offset, last_pdu_offsets, &pdu_flags, &pdu_start, &pdu_length, &pdu_flvh_length, &vector_offset, &ti, &pdu_tree, ett_rdmnet_broker_base_pdu, 1, 0);
  pdu_end = pdu_start + pdu_length;

  /* Add Vector item */
  vector = tvb_get_ntohs(tvb, vector_offset);
  proto_tree_add_item(pdu_tree, hf_rdmnet_broker_vector, tvb, vector_offset, 2, ENC_BIG_ENDIAN);

  /* Add Vector item to tree */
  name = val_to_str(vector, rdmnet_broker_vector_vals, "unknown (%d)");
  proto_item_append_text(ti, ": %s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 0);
  data_offset += 1;

  /* process based on vector */
  switch (vector) {
  case RDMNET_BROKER_VECTOR_FETCH_CLIENT_LIST:
  case RDMNET_BROKER_VECTOR_NULL:
    /* no data */
    break;
  case RDMNET_BROKER_VECTOR_CONNECTED_CLIENT_LIST:
  case RDMNET_BROKER_VECTOR_CLIENT_ADD:
  case RDMNET_BROKER_VECTOR_CLIENT_REMOVE:
  case RDMNET_BROKER_VECTOR_CLIENT_ENTRY_CHANGE:
    end_offset = pdu_start + pdu_length;
    while (data_offset < end_offset) {
      old_offset = data_offset;
      data_offset = dissect_broker_client_entry_pdu(tvb, pdu_tree, data_offset, &pdu_offsets);
      if (data_offset == old_offset) break;
    }
    break;
  case RDMNET_BROKER_VECTOR_CONNECT:
    dissect_broker_connect(tvb, pdu_tree, data_offset, &pdu_offsets, pdu_end);
    break;
  case RDMNET_BROKER_VECTOR_CONNECT_REPLY:
    dissect_broker_connect_reply(tvb, pdu_tree, data_offset);
    break;
  case RDMNET_BROKER_VECTOR_CLIENT_ENTRY_UPDATE:
    dissect_broker_client_entry_update(tvb, pdu_tree, data_offset, &pdu_offsets, pdu_end);
    break;
  case RDMNET_BROKER_VECTOR_REDIRECT_V4:
    dissect_broker_redirect_v4(tvb, pdu_tree, data_offset);
    break;
  case RDMNET_BROKER_VECTOR_REDIRECT_V6:
    dissect_broker_redirect_v6(tvb, pdu_tree, data_offset);
    break;
  case RDMNET_BROKER_VECTOR_DISCONNECT:
    dissect_broker_disconnect(tvb, pdu_tree, data_offset);
    break;
  case RDMNET_BROKER_VECTOR_REQUEST_DYNAMIC_UIDS:
    dissect_broker_request_dynamic_uids(tvb, pdu_tree, data_offset, pdu_end);
    break;
  case RDMNET_BROKER_VECTOR_ASSIGNED_DYNAMIC_UIDS:
    dissect_broker_assigned_dynamic_uids(tvb, pdu_tree, data_offset, pdu_end);
    break;
  case RDMNET_BROKER_VECTOR_FETCH_DYNAMIC_UID_LIST:
    dissect_broker_fetch_dynamic_uids(tvb, pdu_tree, data_offset, pdu_end);
    break;
  }

  return pdu_start + pdu_length;
}


/******************************************************************************/
/* Dissect RPT Request RDM Command                                            */
static guint32
dissect_rpt_request_rdm_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_end;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  guint32          vector_offset;
  guint32          data_offset;
  guint32          data_length;

  proto_item      *ti;
  proto_tree      *pdu_tree;

  /* this pdu */
  const gchar     *name;
  guint8           vector;

  dissect_acn_common_base_pdu(tvb, tree, &offset, last_pdu_offsets, &pdu_flags, &pdu_start, &pdu_length, &pdu_flvh_length, &vector_offset, &ti, &pdu_tree, ett_rdmnet_rpt_request_pdu, 1, 0);

  /* Add Vector item */
  vector = tvb_get_guint8(tvb, vector_offset);
  proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_request_rdm_command, tvb, vector_offset, 1, ENC_BIG_ENDIAN);

  /* Add Vector item to tree */
  name = val_to_str(vector, rdmnet_rpt_request_rdm_command_start_code_vals, "unknown (%d)");
  proto_item_append_text(ti, ": %s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 0);
  /* data_offset += 3; */

  pdu_end = pdu_start + pdu_length;
  dissect_rdm_command(tvb, pinfo, pdu_tree, data_offset, (pdu_length-4));

  return pdu_end;
}


/******************************************************************************/
/* Dissect RPT Request                                                        */
static guint32
dissect_rpt_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};
  guint32          vector_offset;
  guint32          data_offset;
  guint32          data_length;

  proto_item      *ti;
  proto_tree      *pdu_tree;

  /* this pdu */
  const gchar     *name;
  guint32          vector;

  dissect_acn_common_base_pdu(tvb, tree, &offset, last_pdu_offsets, &pdu_flags, &pdu_start, &pdu_length, &pdu_flvh_length, &vector_offset, &ti, &pdu_tree, ett_rdmnet_rpt_request_pdu, 1, 0);

  /* Add Vector item */
  vector = tvb_get_ntohl(tvb, vector_offset);
  proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_request_vector, tvb, vector_offset, 4, ENC_BIG_ENDIAN);

  /* Add Vector item to tree */
  name = val_to_str(vector, rdmnet_rpt_request_vals, "unknown (%d)");
  proto_item_append_text(ti, ": %s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 0);
  data_offset += 3;

  /* rdm command */
  dissect_rpt_request_rdm_command(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);

  return 0;
}


/******************************************************************************/
/* Dissect RPT Status                                                         */
static guint32
dissect_rpt_status(tvbuff_t *tvb, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_end;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  guint32          vector_offset;
  guint32          data_offset;
  guint32          data_length;

  proto_item      *ti;
  proto_tree      *pdu_tree;

  /* this pdu */
  const gchar     *name;
  guint16          vector;

  dissect_acn_common_base_pdu(tvb, tree, &offset, last_pdu_offsets, &pdu_flags, &pdu_start, &pdu_length, &pdu_flvh_length, &vector_offset, &ti, &pdu_tree, ett_rdmnet_rpt_status_pdu, 1, 0);

  /* Add Vector item */
  vector = tvb_get_ntohs(tvb, vector_offset);
  proto_item_append_text(ti, ", vector = %u", vector);
  proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_status_vector, tvb, vector_offset, 2, ENC_BIG_ENDIAN);

  /* Add Vector item to tree */
  name = val_to_str(vector, rdmnet_rpt_status_vector_vals, "unknown (%d)");
  proto_item_append_text(ti, ": %s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 0);
  data_offset += 3;

  pdu_end = pdu_start + pdu_length;
  switch (vector) {
  case RDMNET_RPT_VECTOR_STATUS_UNKNOWN_RPT_UID:
    if (pdu_end > data_offset) {
      proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_status_unknown_rpt_uid_string, tvb, data_offset, (pdu_end - data_offset), ENC_ASCII|ENC_NA);
    }
    break;
  case RDMNET_RPT_VECTOR_STATUS_RDM_TIMEOUT:
    if (pdu_end > data_offset) {
      proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_status_rdm_timeout_string, tvb, data_offset, (pdu_end - data_offset), ENC_ASCII|ENC_NA);
    }
    break;
  case RDMNET_RPT_VECTOR_STATUS_RDM_INVALID_RESPONSE:
    if (pdu_end > data_offset) {
      proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_status_rdm_invalid_response_string, tvb, data_offset, (pdu_end - data_offset), ENC_ASCII|ENC_NA);
    }
    break;
  case RDMNET_RPT_VECTOR_STATUS_UNKNOWN_RDM_UID:
    if (pdu_end > data_offset) {
      proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_status_unknown_rdm_uid_string, tvb, data_offset, (pdu_end - data_offset), ENC_ASCII|ENC_NA);
    }
    break;
  case RDMNET_RPT_VECTOR_STATUS_UNKNOWN_ENDPOINT:
    if (pdu_end > data_offset) {
      proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_status_unknown_endpoint_string, tvb, data_offset, (pdu_end - data_offset), ENC_ASCII|ENC_NA);
    }
    break;
  case RDMNET_RPT_VECTOR_STATUS_BROADCAST_COMPLETE:
    if (pdu_end > data_offset) {
      proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_status_broadcast_complete_string, tvb, data_offset, (pdu_end - data_offset), ENC_ASCII|ENC_NA);
    }
    break;
  case RDMNET_RPT_VECTOR_STATUS_UNKNOWN_VECTOR:
    if (pdu_end > data_offset) {
      proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_status_unknown_vector_string, tvb, data_offset, (pdu_end - data_offset), ENC_ASCII|ENC_NA);
    }
    break;
  case RDMNET_RPT_VECTOR_STATUS_INVALID_MESSAGE:
  case RDMNET_RPT_VECTOR_STATUS_INVALID_COMMAND_CLASS:
    /* no data */
    break;
  }

  return pdu_start + pdu_length;
}


/******************************************************************************/
/* Dissect RPT Notification RDM Command                                       */
static guint32
dissect_rpt_notification_rdm_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_end;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  guint32          vector_offset;
  guint32          data_offset;
  guint32          data_length;

  proto_item      *ti;
  proto_tree      *pdu_tree;

  /* this pdu */
  const gchar     *name;
  guint8           vector;

  dissect_acn_common_base_pdu(tvb, tree, &offset, last_pdu_offsets, &pdu_flags, &pdu_start, &pdu_length, &pdu_flvh_length, &vector_offset, &ti, &pdu_tree, ett_rdmnet_rpt_request_pdu, 1, 0);

  /* Add Vector item */
  vector = tvb_get_guint8(tvb, vector_offset);
  proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_notification_rdm_command, tvb, vector_offset, 1, ENC_BIG_ENDIAN);

  /* Add Vector item to tree */
  name = val_to_str(vector, rdmnet_rpt_request_rdm_command_start_code_vals, "unknown (%d)");
  proto_item_append_text(ti, ": %s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 0);
  /* data_offset += 3; */

  pdu_end = pdu_start + pdu_length;
  dissect_rdm_command(tvb, pinfo, pdu_tree, data_offset, (pdu_length-4));

  return pdu_end;
}


/******************************************************************************/
/* Dissect RPT Notification                                                   */
static guint32
dissect_rpt_notification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_end;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};
  guint32          vector_offset;
  guint32          data_offset;
  guint32          data_length;
  guint32          old_offset;

  proto_item      *ti;
  proto_tree      *pdu_tree;

  /* this pdu */
  const gchar     *name;
  guint32          vector;

  dissect_acn_common_base_pdu(tvb, tree, &offset, last_pdu_offsets, &pdu_flags, &pdu_start, &pdu_length, &pdu_flvh_length, &vector_offset, &ti, &pdu_tree, ett_rdmnet_rpt_notification_pdu, 1, 0);

  /* Add Vector item */
  vector = tvb_get_ntohl(tvb, vector_offset);
  proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_notification_vector, tvb, vector_offset, 4, ENC_BIG_ENDIAN);

  /* Add Vector item to tree  "RDM Command" */
  name = val_to_str(vector, rdmnet_rpt_notification_vals, "unknown (%d)");
  proto_item_append_text(ti, ": %s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 0);
  data_offset += 3;

  /* rdm command */
  pdu_end = pdu_start + pdu_length;
  while (data_offset < pdu_end) {
    old_offset = data_offset;
    data_offset = dissect_rpt_notification_rdm_command(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
    if (data_offset == old_offset) break;
  }

  return pdu_end;
}


/******************************************************************************/
/* Dissect RPT Base PDU                                                       */
static guint32
dissect_acn_rpt_base_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};
  guint32          vector_offset;
  guint32          data_offset;
  guint32          data_length;

  proto_item      *ti;
  proto_tree      *pdu_tree;

  /* this pdu */
  const gchar     *name;
  guint32          vector;

  dissect_acn_common_base_pdu(tvb, tree, &offset, last_pdu_offsets, &pdu_flags, &pdu_start, &pdu_length, &pdu_flvh_length, &vector_offset, &ti, &pdu_tree, ett_rdmnet_rpt_base_pdu, 1, 0);

  /* Add Vector item */
  vector = tvb_get_ntohl(tvb, vector_offset);
  proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_vector, tvb, vector_offset, 4, ENC_BIG_ENDIAN);

  /* Add Vector item to tree */
  name = val_to_str(vector, rdmnet_rpt_vector_vals, "unknown (%d)");
  proto_item_append_text(ti, ": %s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 0);
  data_offset += 3;

  /* source uid (6 bytes) */
  proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_source_uid, tvb, data_offset, 6, ENC_NA);
  data_offset += 6;

  /* source endpoint id (2 bytes) */
  proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_source_endpoint_id, tvb, data_offset, 2, ENC_BIG_ENDIAN);
  data_offset += 2;

  /* destination uid (6 bytes) */
  proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_destination_uid, tvb, data_offset, 6, ENC_NA);
  data_offset += 6;

  /* destination endpoint id (2 bytes) */
  proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_destination_endpoint_id, tvb, data_offset, 2, ENC_BIG_ENDIAN);
  data_offset += 2;

  /* sequence number (4 bytes) */
  proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_sequence_number, tvb, data_offset, 4, ENC_BIG_ENDIAN);
  data_offset += 4;

  /* reserved (1 byte) */
  proto_tree_add_item(pdu_tree, hf_rdmnet_rpt_reserved, tvb, data_offset, 1, ENC_BIG_ENDIAN);
  data_offset += 1;

  /* process based on vector */
  switch (vector) {
  case RDMNET_RPT_VECTOR_REQUEST:
    dissect_rpt_request(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
    break;
  case RDMNET_RPT_VECTOR_STATUS:
    dissect_rpt_status(tvb, pdu_tree, data_offset, &pdu_offsets);
    break;
  case RDMNET_RPT_VECTOR_NOTIFICATION:
    dissect_rpt_notification(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
    break;
  }

  return pdu_start + pdu_length;
}


/******************************************************************************/
/* Dissect EPT Data                                                           */
static guint32
dissect_ept_data(tvbuff_t *tvb, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_end;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  guint32          vector_offset;
  guint32          data_offset;

  proto_item      *ti;
  proto_item      *ti2;
  proto_tree      *pdu_tree;
  proto_tree      *pdu_tree2;

  dissect_acn_common_base_pdu(tvb, tree, &offset, last_pdu_offsets, &pdu_flags, &pdu_start, &pdu_length, &pdu_flvh_length, &vector_offset, &ti, &pdu_tree, ett_rdmnet_ept_data_pdu, 1, 0);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_rdmnet_ept_data_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  dissect_pdu_bit_flag_v(&offset, pdu_flags, &data_offset, last_pdu_offsets, &pdu_flvh_length, 2);
  /* offset should now be pointing to header (if one exists) */

  /* esta manufacturer id + protocol id (4 bytes) */
  ti2 = proto_tree_add_item(pdu_tree, hf_rdmnet_ept_data_vector, tvb, data_offset, 4, ENC_BIG_ENDIAN);
  pdu_tree2 = proto_item_add_subtree(ti2, ett_rdmnet_ept_data_vector_pdu);
  proto_tree_add_item(pdu_tree2, hf_rdmnet_ept_data_vector_manfacturer_id, tvb, 0, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(pdu_tree2, hf_rdmnet_ept_data_vector_protocol_id, tvb, 2, 2, ENC_BIG_ENDIAN);
  data_offset += 4;

  /* opaque data */
  pdu_end = pdu_start + pdu_length;
  proto_tree_add_item(pdu_tree, hf_rdmnet_ept_data_opaque_data, tvb, data_offset, (pdu_end - data_offset), ENC_NA);

  return pdu_start + pdu_length;
}


/******************************************************************************/
/* Dissect EPT Status                                                         */
static guint32
dissect_ept_status(tvbuff_t *tvb, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  guint8           pdu_flags;
  guint16          vector;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_end;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  guint32          vector_offset;
  guint32          data_offset;

  proto_item      *ti;
  proto_tree      *pdu_tree;

  dissect_acn_common_base_pdu(tvb, tree, &offset, last_pdu_offsets, &pdu_flags, &pdu_start, &pdu_length, &pdu_flvh_length, &vector_offset, &ti, &pdu_tree, ett_rdmnet_ept_status_pdu, 1, 0);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_rdmnet_ept_status_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  dissect_pdu_bit_flag_v(&offset, pdu_flags, &data_offset, last_pdu_offsets, &pdu_flvh_length, 2);
  /* offset should now be pointing to header (if one exists) */

  vector = tvb_get_ntohs(tvb, data_offset);
  proto_tree_add_item(pdu_tree, hf_rdmnet_ept_status_vector, tvb, data_offset, 2, ENC_NA);
  data_offset += 2;

  /* process based on vector */
  switch (vector) {
  case RDMNET_EPT_VECTOR_UNKNOWN_CID:
      /* unknown cid (16 bytes) */
      proto_tree_add_item(pdu_tree, hf_rdmnet_ept_status_unknown_cid, tvb, data_offset, 16, ENC_NA);
      data_offset += 16;

      /* status string */
      pdu_end = pdu_start + pdu_length;
      proto_tree_add_item(pdu_tree, hf_rdmnet_ept_status_status_string, tvb, data_offset, (pdu_end - data_offset), ENC_ASCII|ENC_NA);
      break;
  case RDMNET_EPT_VECTOR_UNKNOWN_VECTOR:
      /* unknown cid (4 bytes) */
      proto_tree_add_item(pdu_tree, hf_rdmnet_ept_status_unknown_vector, tvb, data_offset, 4, ENC_NA);
      data_offset += 4;

      /* vector string */
      pdu_end = pdu_start + pdu_length;
      proto_tree_add_item(pdu_tree, hf_rdmnet_ept_status_vector_string, tvb, data_offset, (pdu_end - data_offset), ENC_ASCII|ENC_NA);
      break;
  }

  return pdu_start + pdu_length;
}


/******************************************************************************/
/* Dissect EPT Base PDU                                                       */
static guint32
dissect_acn_ept_base_pdu(tvbuff_t *tvb, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};
  guint32          vector_offset;
  guint32          data_offset;
  guint32          data_length;

  proto_item      *ti;
  proto_tree      *pdu_tree;

  /* this pdu */
  const gchar     *name;
  guint32          vector;

  dissect_acn_common_base_pdu(tvb, tree, &offset, last_pdu_offsets, &pdu_flags, &pdu_start, &pdu_length, &pdu_flvh_length, &vector_offset, &ti, &pdu_tree, ett_rdmnet_ept_base_pdu, 1, 0);

  /* Add Vector item */
  vector = tvb_get_ntohl(tvb, vector_offset);
  proto_tree_add_item(pdu_tree, hf_rdmnet_ept_vector, tvb, vector_offset, 4, ENC_BIG_ENDIAN);

  /* Add Vector item to tree */
  name = val_to_str(vector, rdmnet_ept_vector_vals, "unknown (%d)");
  proto_item_append_text(ti, ": %s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  dissect_pdu_bit_flag_d(offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, pdu_flvh_length, 0);
  data_offset += 3;

  /* destination cid (16 bytes) */
  proto_tree_add_item(pdu_tree, hf_rdmnet_ept_destination_cid, tvb, data_offset, 16, ENC_NA);
  data_offset += 16;

  /* process based on vector */
  switch (vector) {
  case RDMNET_EPT_VECTOR_DATA:
      dissect_ept_data(tvb, pdu_tree, data_offset, &pdu_offsets);
      break;
  case RDMNET_EPT_VECTOR_STATUS:
      dissect_ept_status(tvb, pdu_tree, data_offset, &pdu_offsets);
      break;
  }

  return pdu_start + pdu_length;
}

/******************************************************************************/
/* Dissect Root PDU                                                           */
static guint32
dissect_acn_root_pdu_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdu_tree, proto_item *ti, const char *title, int *offset, guint8 pdu_flags, guint32 pdu_length, guint32 *data_offset, guint32 *data_length, acn_pdu_offsets *last_pdu_offsets, gboolean add_cid_to_info, guint32 *pdu_flvh_length, gboolean is_acn)
{
  guint32   header_offset;
  e_guid_t  guid;

  /* Adjust header */
  proto_item_append_text(ti, "%s", title);

  dissect_pdu_bit_flag_h(offset, pdu_flags, &header_offset, last_pdu_offsets, pdu_flvh_length, 16);
  /* offset should now be pointing to data (if one exists) */

  /* get Header (CID) 16 bytes */
  tvb_get_guid(tvb, header_offset, &guid, ENC_BIG_ENDIAN);
  proto_item_append_text(ti, ", Src: %s", guid_to_str(wmem_packet_scope(), &guid));

  if (add_cid_to_info) {
    /* add cid to info */
    col_add_fstr(pinfo->cinfo, COL_INFO, "CID %s", guid_to_str(wmem_packet_scope(), &guid));
  }

  if (is_acn) {
    proto_tree_add_item(pdu_tree, hf_acn_cid, tvb, header_offset, 16, ENC_BIG_ENDIAN);
  } else {
    proto_tree_add_item(pdu_tree, hf_rdmnet_cid, tvb, header_offset, 16, ENC_BIG_ENDIAN);
  }
  /* header_offset += 16; */

  dissect_pdu_bit_flag_d(*offset, pdu_flags, pdu_length, data_offset, data_length, last_pdu_offsets, *pdu_flvh_length, 1);

  return (*data_offset) + (*data_length);
}

/******************************************************************************/
/* Dissect Root PDU                                                           */
static guint32
dissect_acn_root_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets, gboolean is_acn)
{
  /* common to all pdu */
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};
  guint32          vector_offset;
  guint32          data_offset;
  guint32          end_offset;
  guint32          old_offset;
  guint32          data_length;

  proto_item      *ti;
  proto_tree      *pdu_tree;

  /* this pdu */
  guint32          protocol_id;

  begin_dissect_acn_pdu(&pdu_tree, tvb, &ti, tree, &pdu_start, &offset, &pdu_flags, &pdu_length, &pdu_flvh_length, ett_acn_root_pdu, is_acn);

  /* Add PDU Length item */
  if (is_acn) {
    proto_tree_add_uint(pdu_tree, hf_acn_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);
  } else {
    proto_tree_add_uint(pdu_tree, hf_rdmnet_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);
  }

  dissect_pdu_bit_flag_v(&offset, pdu_flags, &vector_offset, last_pdu_offsets, &pdu_flvh_length, 4);
  /* offset should now be pointing to header (if one exists) */

  /* Get Protocol ID (vector) */
  protocol_id = tvb_get_ntohl(tvb, vector_offset);
  if (is_acn) {
    proto_tree_add_uint(pdu_tree, hf_acn_protocol_id, tvb, vector_offset, 4, protocol_id);
  } else {
    proto_tree_add_uint(pdu_tree, hf_rdmnet_protocol_id, tvb, vector_offset, 4, protocol_id);
  }

  /* process based on protocol_id */
  switch (protocol_id) {
    case ACN_PROTOCOL_ID_DMX:
    case ACN_PROTOCOL_ID_DMX_2:
      if (global_acn_dmx_enable) {
        end_offset = dissect_acn_root_pdu_header(tvb, pinfo, pdu_tree, ti, ": Root DMX", &offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, 1, &pdu_flvh_length, 1);

        /* adjust for what we used */
        while (data_offset < end_offset) {
          old_offset = data_offset;
          data_offset = dissect_acn_dmx_base_pdu(protocol_id, tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
          if (data_offset == old_offset) break;
        }
      }
      break;
    case ACN_PROTOCOL_ID_SDT:
      end_offset = dissect_acn_root_pdu_header(tvb, pinfo, pdu_tree, ti, ": Root SDT", &offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, 0, &pdu_flvh_length, 1);

      /* adjust for what we used */
      while (data_offset < end_offset) {
        old_offset = data_offset;
        data_offset = dissect_acn_sdt_base_pdu(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
        if (data_offset == old_offset) break;
      }
      break;
    case ACN_PROTOCOL_ID_RPT:
      end_offset = dissect_acn_root_pdu_header(tvb, pinfo, pdu_tree, ti, ": Root RPT", &offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, 0, &pdu_flvh_length, 0);

      /* adjust for what we used */
      while (data_offset < end_offset) {
        old_offset = data_offset;
        data_offset = dissect_acn_rpt_base_pdu(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
        if (data_offset == old_offset) break;
      }
      break;
    case ACN_PROTOCOL_ID_BROKER:
      end_offset = dissect_acn_root_pdu_header(tvb, pinfo, pdu_tree, ti, ": Root Broker", &offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, 0, &pdu_flvh_length, 0);

      /* adjust for what we used */
      while (data_offset < end_offset) {
        old_offset = data_offset;
        data_offset = dissect_acn_broker_base_pdu(tvb, pdu_tree, data_offset, &pdu_offsets);
        if (data_offset == old_offset) break;
      }
      break;
    case ACN_PROTOCOL_ID_LLRP:
      end_offset = dissect_acn_root_pdu_header(tvb, pinfo, pdu_tree, ti, ": Root LLRP", &offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, 0, &pdu_flvh_length, 0);

      /* adjust for what we used */
      while (data_offset < end_offset) {
        old_offset = data_offset;
        data_offset = dissect_acn_llrp_base_pdu(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
        if (data_offset == old_offset) break;
      }
      break;
    case ACN_PROTOCOL_ID_EPT:
      end_offset = dissect_acn_root_pdu_header(tvb, pinfo, pdu_tree, ti, ": Root EPT", &offset, pdu_flags, pdu_length, &data_offset, &data_length, last_pdu_offsets, 0, &pdu_flvh_length, 0);

      /* adjust for what we used */
      while (data_offset < end_offset) {
        old_offset = data_offset;
        data_offset = dissect_acn_ept_base_pdu(tvb, pdu_tree, data_offset, &pdu_offsets);
        if (data_offset == old_offset) break;
      }
      break;
  }

  return pdu_start + pdu_length;
}

/******************************************************************************/
/* Dissect ACN                                                                */
static int
dissect_acn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item      *ti;
  proto_tree      *acn_tree;
  guint32          data_offset = 0;
  guint32          old_offset;
  guint32          end_offset;
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};

/*   if (!is_acn(tvb)) { */
/*     return 0;         */
/*   }                   */

  /* Set the protocol column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ACN");
  col_add_fstr(pinfo->cinfo, COL_INFO, "ACN [Src Port: %d, Dst Port: %d]", pinfo->srcport, pinfo->destport );

  ti = proto_tree_add_item(tree, proto_acn, tvb, 0, -1, ENC_NA);
  acn_tree = proto_item_add_subtree(ti, ett_acn);

  /* add preamble, postamble and ACN Packet ID */
  proto_tree_add_item(acn_tree, hf_acn_preamble_size, tvb, data_offset, 2, ENC_BIG_ENDIAN);
  data_offset += 2;
  proto_tree_add_item(acn_tree, hf_acn_postamble_size, tvb, data_offset, 2, ENC_BIG_ENDIAN);
  data_offset += 2;
  proto_tree_add_item(acn_tree, hf_acn_packet_identifier, tvb, data_offset, 12, ENC_UTF_8 | ENC_NA);
  data_offset += 12;

  /* one past the last byte */
  end_offset = data_offset + tvb_reported_length_remaining(tvb, data_offset);
  while (data_offset < end_offset) {
    old_offset = data_offset;
    data_offset = dissect_acn_root_pdu(tvb, pinfo, acn_tree, data_offset, &pdu_offsets, 1);
    if (data_offset == old_offset) break;
  }
  return tvb_reported_length(tvb);
}

/******************************************************************************/
/* Dissect RDMnet                                                             */
static int
dissect_rdmnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 data_offset, gboolean is_udp)
{
  proto_item      *ti;
  proto_tree      *rdmnet_tree;
  /* guint32          data_offset = 0; */
  guint32          old_offset;
  guint32          end_offset;
  guint32          pdu_length;
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};

  /* Set the protocol column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDMnet");
  col_add_fstr(pinfo->cinfo, COL_INFO, "RDMnet [Src Port: %d, Dst Port: %d]", pinfo->srcport, pinfo->destport );

  if (is_udp) {
    ti = proto_tree_add_item(tree, proto_rdmnet, tvb, data_offset, -1, ENC_NA);
  } else {
    pdu_length = tvb_get_ntohl(tvb, 12) + 16;
    ti = proto_tree_add_item(tree, proto_rdmnet, tvb, data_offset, pdu_length, ENC_NA);
  }
  rdmnet_tree = proto_item_add_subtree(ti, ett_rdmnet);

  if (is_udp) {
    /* UDP only: preamble and postamble */
    proto_tree_add_item(rdmnet_tree, hf_rdmnet_preamble_size, tvb, data_offset, 2, ENC_BIG_ENDIAN);
    data_offset += 2;
    proto_tree_add_item(rdmnet_tree, hf_rdmnet_postamble_size, tvb, data_offset, 2, ENC_BIG_ENDIAN);
    data_offset += 2;
  }
  /* add ACN Packet ID */
  proto_tree_add_item(rdmnet_tree, hf_rdmnet_packet_identifier, tvb, data_offset, 12, ENC_UTF_8 | ENC_NA);
  data_offset += 12;

  pdu_length = 0;
  if (!is_udp) {
    /* TCP only: data length (may be less than packet length) */
    proto_tree_add_item(rdmnet_tree, hf_rdmnet_tcp_length, tvb, data_offset, 4, ENC_BIG_ENDIAN);
    pdu_length = tvb_get_ntohl(tvb, data_offset);
    data_offset += 4;
  }

  /* one past the last byte */
  if (is_udp) {
    end_offset = data_offset + tvb_reported_length_remaining(tvb, data_offset);
  } else {
    end_offset = data_offset + pdu_length;
  }
  while (data_offset < end_offset) {
    old_offset = data_offset;
    data_offset = dissect_acn_root_pdu(tvb, pinfo, rdmnet_tree, data_offset, &pdu_offsets, 0);
    if (data_offset == old_offset) break;
  }

  return end_offset;
}

/******************************************************************************/
/* Register protocol                                                          */
void
proto_register_acn(void)
{
  static hf_register_info hf[] = {
    /**************************************************************************/
    /* In alphabetical order */
    /* Address Type */
    /* PDU flags*/
    { &hf_acn_ip_address_type,
      { "Addr Type", "acn.ip_address_type",
        FT_UINT8, BASE_DEC, VALS(acn_ip_address_type_vals), 0x0,
        NULL, HFILL }
    },
    /* Association */
    { &hf_acn_association,
      { "Association", "acn.association",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* Blob */
    { &hf_acn_blob,
      { "Blob", "acn.blob",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
#if 0
    /* Blob Dimmer Load Properties 2 Type */
    { &hf_acn_blob_dimmer_load_properties2_type,
      { "Blob Field", "acn.blob_dimmer_load_properties2_type",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
#endif
    /* Blob Field Length */
    { &hf_acn_blob_field_length,
      { "Field Length", "acn.blob_field_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    /* Blob Field Type */
    { &hf_acn_blob_field_type,
      { "Field Type", "acn.blob_field_type",
        FT_UINT8, BASE_DEC, VALS(acn_blob_field_type_vals), 0x0,
        NULL, HFILL }
    },
    /* Blob Field Value Number */
    { &hf_acn_blob_field_value_number,
      { "Field Value", "acn.blob_field_value_number",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_acn_blob_field_value_number64,
      { "Field Value", "acn.blob_field_value_number64",
        FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_acn_blob_field_value_float,
      { "Field Value", "acn.blob_field_value_float",
        FT_FLOAT, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_acn_blob_field_value_double,
      { "Field Value", "acn.blob_field_value_double",
        FT_DOUBLE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_acn_blob_field_value_guid,
      { "Field Value", "acn.blob_field_value_guid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    /* Blob Field Value String*/
    { &hf_acn_blob_field_value_string,
      { "Field Value", "acn.blob_field_value_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Blob Field Value IPV4 */
    { &hf_acn_blob_field_value_ipv4,
      { "Field Value", "acn.blob_field_value_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Blob Field Value IPV6 */
    { &hf_acn_blob_field_value_ipv6,
      { "Field Value", "acn.blob_field_value_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Blob Metadata Device Type */
    { &hf_acn_blob_tree_field_type,
      { "Blob Field", "acn.blob_tree_field_type",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
#if 0
    /* Blob Metadata Types Type */
    { &hf_acn_blob_metadata_types_type,
      { "Blob Field", "acn.blob_metadata_types_type",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
#endif
    /* Blob Range Number */
    { &hf_acn_blob_range_number,
      { "Blob Range Number", "acn.blob_range_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    /* Blob Range Type */
    { &hf_acn_blob_range_type,
      { "Blob Range Type", "acn.blob_range_type",
        FT_UINT8, BASE_HEX, VALS(acn_blob_range_type_vals), 0x0,
        NULL, HFILL }
    },
#if 0
    /* Blob Range Start */
    { &hf_acn_blob_range_start,
      { "Blob Range Start", "acn.blob_range_start",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
#endif
    /* Blob Type */
    { &hf_acn_blob_type,
      { "Blob Type", "acn.blob_type",
        FT_UINT8, BASE_DEC, VALS(acn_blob_type_vals), 0x0,
        NULL, HFILL }
    },
    /* Blob Version */
    { &hf_acn_blob_version,
      { "Blob Version", "acn.blob_version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_acn_blob_time_zone,
      { "Time Zone", "acn.blob_time_zone",
        FT_INT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_acn_blob_dst_type,
      { "DST Type", "acn.blob_dst_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_acn_blob_dst_start_day,
      { "DST Start Day", "acn.blob_dst_start_day",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_acn_blob_dst_stop_day,
      { "DST Stop Day", "acn.blob_dst_stop_day",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_acn_blob_dst_start_locality,
      { "DST Start Locality", "acn.blob_dst_start_locality",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_acn_blob_dst_stop_locality,
      { "DST Stop Locality", "acn.blob_dst_stop_locality",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    /* Channel Number */
    { &hf_acn_channel_number,
      { "Channel Number", "acn.channel_number",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* CID */
    { &hf_acn_cid,
      { "CID", "acn.cid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Client Protocol ID */
#if 0
    { &hf_acn_client_protocol_id,
      { "Client Protocol ID", "acn.client_protocol_id",
        FT_UINT32, BASE_DEC, VALS(acn_protocol_id_vals), 0x0,
        NULL, HFILL }
    },
#endif
    /* DMP data */
    { &hf_acn_data,
      { "Data", "acn.dmp_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_acn_data8,
      { "Addr", "acn.dmp_data8",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        "Data8", HFILL }
    },
    { &hf_acn_data16,
      { "Addr", "acn.dmp_data16",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        "Data16", HFILL }
    },
    { &hf_acn_data24,
      { "Addr", "acn.dmp_data24",
        FT_UINT24, BASE_DEC_HEX, NULL, 0x0,
        "Data24", HFILL }
    },
    { &hf_acn_data32,
      { "Addr", "acn.dmp_data32",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        "Data32", HFILL }
    },

    /* DMP Address type*/
#if 0
    { &hf_acn_dmp_adt,
      { "Address and Data Type", "acn.dmp_adt",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
#endif
    { &hf_acn_dmp_adt_a,
      { "Size", "acn.dmp_adt_a",
        FT_UINT8, BASE_DEC, VALS(acn_dmp_adt_a_vals), 0x03,
        NULL, HFILL }
    },
    { &hf_acn_dmp_adt_d,
      { "Data Type", "acn.dmp_adt_d",
        FT_UINT8, BASE_DEC, VALS(acn_dmp_adt_d_vals), 0x30,
        NULL, HFILL }
    },
    { &hf_acn_dmp_adt_r,
      { "Relative", "acn.dmp_adt_r",
        FT_UINT8, BASE_DEC, VALS(acn_dmp_adt_r_vals), 0x40,
        NULL, HFILL }
    },
    { &hf_acn_dmp_adt_v,
      { "Virtual", "acn.dmp_adt_v",
        FT_UINT8, BASE_DEC, VALS(acn_dmp_adt_v_vals), 0x80,
        NULL, HFILL }
    },
    { &hf_acn_dmp_adt_x,
      { "Reserved", "acn.dmp_adt_x",
        FT_UINT8, BASE_DEC, NULL, 0x0c,
        NULL, HFILL }
    },

    /* DMP Reason Code */
    { &hf_acn_dmp_reason_code,
      { "Reason Code", "acn.dmp_reason_code",
        FT_UINT8, BASE_DEC, VALS(acn_dmp_reason_code_vals), 0x0,
        NULL, HFILL }
    },

    /* DMP Vector */
    { &hf_acn_dmp_vector,
      { "DMP Vector", "acn.dmp_vector",
        FT_UINT8, BASE_DEC, VALS(acn_dmp_vector_vals), 0x0,
        NULL, HFILL }
    },

    { &hf_acn_dmp_actual_address,
      { "Actual Address", "acn.dmp_actual_address",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_acn_dmp_virtual_address,
      { "Virtual Address", "acn.dmp_virtual_address",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_acn_dmp_actual_address_first,
      { "Actual Address First", "acn.dmp_actual_address_first",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_acn_dmp_virtual_address_first,
      { "Virtual Address First", "acn.dmp_virtual_address_first",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    /* Expiry */
    { &hf_acn_expiry,
      { "Expiry", "acn.expiry",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* First Member to ACK */
    { &hf_acn_first_member_to_ack,
      { "First Member to ACK", "acn.first_member_to_ack",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* First Missed Sequence */
    { &hf_acn_first_missed_sequence,
      { "First Missed Sequence", "acn.first_missed_sequence",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* IPV4 */
    { &hf_acn_ipv4,
      { "IPV4", "acn.ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* IPV6 */
    { &hf_acn_ipv6,
      { "IPV6", "acn.ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Last Member to ACK */
    { &hf_acn_last_member_to_ack,
      { "Last Member to ACK", "acn.last_member_to_ack",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* Last Missed Sequence */
    { &hf_acn_last_missed_sequence,
      { "Last Missed Sequence", "acn.last_missed_sequence",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* MAK threshold */
    { &hf_acn_mak_threshold,
      { "MAK Threshold", "acn.mak_threshold",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* Member ID */
    { &hf_acn_member_id,
      { "Member ID", "acn.member_id",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* NAK Holdoff */
    { &hf_acn_nak_holdoff,
      { "NAK holdoff (ms)", "acn.nak_holdoff",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* NAK Max Wait */
    { &hf_acn_nak_max_wait,
      { "NAK Max Wait (ms)", "acn.nak_max_wait",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* NAK Modulus */
    { &hf_acn_nak_modulus,
      { "NAK Modulus", "acn.nak_modulus",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* NAK Outbound Flag */
    { &hf_acn_nak_outbound_flag,
      { "NAK Outbound Flag", "acn.nak_outbound_flag",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }
    },
    /* Oldest Available Wrapper */
    { &hf_acn_oldest_available_wrapper,
      { "Oldest Available Wrapper", "acn.oldest_available_wrapper",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* Preamble Size */
    { &hf_acn_preamble_size,
      { "Size of preamble", "acn.preamble_size",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Preamble size in bytes", HFILL }
    },
    /* Packet Identifier */
    { &hf_acn_packet_identifier,
      { "Packet Identifier", "acn.packet_identifier",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* PDU */
    { &hf_acn_pdu,
      { "PDU", "acn.pdu",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* PDU flags*/
    { &hf_acn_pdu_flags,
      { "Flags", "acn.pdu.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "PDU Flags", HFILL }
    },
    { &hf_acn_pdu_flag_d,
      { "Data", "acn.pdu.flag_d",
        FT_BOOLEAN, 8, NULL, ACN_PDU_FLAG_D,
        "Data flag", HFILL }
    },
    { &hf_acn_pdu_flag_h,
      { "Header", "acn.pdu.flag_h",
        FT_BOOLEAN, 8, NULL, ACN_PDU_FLAG_H,
        "Header flag", HFILL }
    },
    { &hf_acn_pdu_flag_l,
      { "Length", "acn.pdu.flag_l",
        FT_BOOLEAN, 8, NULL, ACN_PDU_FLAG_L,
        "Length flag", HFILL }
    },
    { &hf_acn_pdu_flag_v,
      { "Vector", "acn.pdu.flag_v",
        FT_BOOLEAN, 8, NULL, ACN_PDU_FLAG_V,
        "Vector flag", HFILL }
    },
    /* PDU Length */
    { &hf_acn_pdu_length,
      { "Length", "acn.pdu.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "PDU Length", HFILL }
    },
    /* Port */
    { &hf_acn_port,
      { "Port", "acn.port",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* Postamble Size */
    { &hf_acn_postamble_size,
      { "Size of postamble", "acn.postamble_size",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Postamble size in bytes", HFILL }
    },
    /* Protocol ID */
    { &hf_acn_protocol_id,
      { "Protocol ID", "acn.protocol_id",
        FT_UINT32, BASE_DEC, VALS(acn_protocol_id_vals), 0x0,
        NULL, HFILL }
    },
    /* Reason Code */
    { &hf_acn_reason_code,
      { "Reason Code", "acn.reason_code",
        FT_UINT8, BASE_DEC, VALS(acn_reason_code_vals), 0x0,
        NULL, HFILL }
    },
    /* Reciprocal Channel */
    { &hf_acn_reciprocal_channel,
      { "Reciprocal Channel Number", "acn.reciprocal_channel",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        "Reciprocal Channel", HFILL }
    },
    /* Refuse Code */
    { &hf_acn_refuse_code,
      { "Refuse Code", "acn.refuse_code",
        FT_UINT8, BASE_DEC, VALS(acn_refuse_code_vals), 0x0,
        NULL, HFILL }
    },
    /* Reliable Sequence Number */
    { &hf_acn_reliable_sequence_number,
      { "Reliable Sequence Number", "acn.reliable_sequence_number",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* Ad-hoc Expiry */
    { &hf_acn_adhoc_expiry,
      { "Ad-hoc Expiry", "acn.adhoc_expiry",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    /* SDT Vector */
    { &hf_acn_sdt_vector,
      { "SDT Vector", "acn.sdt_vector",
        FT_UINT8, BASE_DEC, VALS(acn_sdt_vector_vals), 0x0,
        NULL, HFILL }
    },

    /* DMX Vector */
    { &hf_acn_dmx_vector,
      { "Vector", "acn.dmx_vector",
        FT_UINT32, BASE_DEC, VALS(acn_dmx_vector_vals), 0x0,
        "DMX Vector", HFILL }
    },
    /* DMX Source Name */
    { &hf_acn_dmx_source_name,
      { "Source", "acn.dmx.source_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "DMX Source Name", HFILL }
    },

    /* DMX priority */
    { &hf_acn_dmx_priority,
      { "Priority", "acn.dmx.priority",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "DMX Priority", HFILL }
    },

    /* DMX 2 reserved */
    { &hf_acn_dmx_2_reserved,
      { "Reserved", "acn.dmx.reserved",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "DMX Reserved", HFILL }
    },

    /* DMX Sequence number */
    { &hf_acn_dmx_sequence_number,
      { "Seq No", "acn.dmx.seq_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "DMX Sequence Number", HFILL }
    },

    /* DMX 2 options */
    { &hf_acn_dmx_2_options,
      { "Options", "acn.dmx.options",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "DMX Options", HFILL }
    },

    { &hf_acn_dmx_2_option_p,
      { "Preview Data", "acn.dmx.option_p",
        FT_BOOLEAN, 8, NULL, ACN_DMX_OPTION_P,
        "Preview Data flag", HFILL }
    },

    { &hf_acn_dmx_2_option_s,
      { "Stream Terminated", "acn.dmx.option_s",
        FT_BOOLEAN, 8, NULL, ACN_DMX_OPTION_S,
        "Stream Terminated flag", HFILL }
    },

    /* DMX Universe */
    { &hf_acn_dmx_universe,
      { "Universe", "acn.dmx.universe",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "DMX Universe", HFILL }
    },

    /* DMX Start Code */
    { &hf_acn_dmx_start_code,
      { "Start Code", "acn.dmx.start_code",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        "DMX Start Code", HFILL }
    },

    /* DMX 2 First Property Address */
    { &hf_acn_dmx_2_first_property_address,
      { "First Property Address", "acn.dmx.start_code",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        "DMX First Property Address", HFILL }
    },

    /* DMX Address Increment */
    { &hf_acn_dmx_increment,
      { "Increment", "acn.dmx.increment",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "DMX Increment", HFILL }
    },

    /* DMX Packet Count */
    { &hf_acn_dmx_count,
      { "Count", "acn.dmx.count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "DMX Count", HFILL }
    },

    /* DMX 2 Start Code */
    { &hf_acn_dmx_2_start_code,
      { "Start Code", "acn.dmx.start_code2",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        "DMX Start Code", HFILL }
    },

    /*
     * If you want the pretty-printed data in the field, for filtering
     * purposes, you have to make it an FT_STRING.
     *
     * If you want the raw data in the field, for filtering purposes,
     * you have to make it an FT_BYTES *AND* use "proto_tree_add_bytes_format()"
     * to put the pretty-printed data into the display but not the field.
     */
    { &hf_acn_dmx_data,
      { "Data", "acn.dmx.data",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    /* Session Count */
#if 0
    { &hf_acn_session_count,
      { "Session Count", "acn.session_count",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
#endif
    /* Total Sequence Number */
    { &hf_acn_total_sequence_number,
      { "Total Sequence Number", "acn.total_sequence_number",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    }
  };

  static hf_register_info magic_hf[] = {
    /* Protocol ID */
    { &hf_magic_protocol_id,
      { "Protocol ID", "magic.protocol_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    /* PDU Type */
    { &hf_magic_pdu_subtype,
      { "PDU type", "magic.type",
        FT_UINT8, BASE_DEC, VALS(magic_pdu_subtypes), 0x0,
        NULL, HFILL },
    },

    /* Major Version */
    { &hf_magic_major_version,
      { "Major Version", "magic.major_version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    /* Minor Version */
    { &hf_magic_minor_version,
      { "Minor Version", "magic.minor_version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    /* V1 Command */
    { &hf_magic_v1command_vals,
      { "Command", "magic.v1_command",
        FT_UINT32, BASE_DEC, VALS(magic_v1command_vals), 0x0,
        NULL, HFILL }
    },

    /* V2 Command */
    { &hf_magic_command_vals,
      { "Command", "magic.command",
        FT_UINT32, BASE_DEC, VALS(magic_command_vals), 0x0,
        NULL, HFILL }
    },

    /* Beacon Duration */
    { &hf_magic_command_beacon_duration,
      { "Duration", "magic.beacon_duration",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Beacon Duration", HFILL }
    },

    /* TFTP */
    { &hf_magic_command_tftp,
      { "TFTP IP", "magic.tftp",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "IP of TFTP server", HFILL }
    },

    /* Reset Lease */
    { &hf_magic_command_reset_lease,
      { "Reset Lease", "magic.reset_lease",
        FT_UINT32, BASE_DEC, VALS(magic_reset_lease_vals), 0x0,
        NULL, HFILL }
    },

    /* CID */
    { &hf_magic_command_cid,
      { "CID", "magic.cid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    /* Command IP Configuration */
    { &hf_magic_command_ip_configuration,
      { "IP Configuration", "magic.ip_configuration",
        FT_UINT32, BASE_DEC, VALS(magic_ip_configuration_vals), 0x0,
        NULL, HFILL }
    },

    /* Command IP Address */
    { &hf_magic_command_ip_address,
      { "IP Address", "magic.ip_address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    /* Command Subnet Mask */
    { &hf_magic_command_subnet_mask,
      { "Subnet Mask", "magic.subnet_mask",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    /* Command Gateway */
    { &hf_magic_command_gateway,
      { "Gateway", "magic.gateway",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    /* Reply IP Address */
    { &hf_magic_reply_ip_address,
      { "IP", "magic.reply.ip_address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "Local IP Address", HFILL }
    },

    /* Reply Subnet Mask */
    { &hf_magic_reply_subnet_mask,
      { "Subnet Mask", "magic.reply.subnet_mask",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "Local Subnet Mask", HFILL }
    },

    /* Reply Gateway */
    { &hf_magic_reply_gateway,
      { "Gateway", "magic.reply.gateway",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "Local Gateway", HFILL }
    },

    /* Reply TFTP */
    { &hf_magic_reply_tftp,
      { "TFTP IP", "magic.reply.tftp",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "IP of TFTP server", HFILL }
    },

    /* Reply Version */
    { &hf_magic_reply_version,
      { "Reply Version", "magic.reply.version",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    /* Reply Device Type Name */
    { &hf_magic_reply_device_type_name,
      { "Device Type Name", "magic.reply.device_type_name",
        FT_UINT_STRING, BASE_NONE, NULL, 0x0,
        "Reply Device Type Name", HFILL }
    },

    /* Reply Default Name */
    { &hf_magic_reply_default_name,
      { "Default Name", "magic.reply.default_name",
        FT_UINT_STRING, BASE_NONE, NULL, 0x0,
        "Reply Default Name", HFILL }
    },

    /* Reply User Name */
    { &hf_magic_reply_user_name,
      { "User Name", "magic.reply.user_name",
        FT_UINT_STRING, BASE_NONE, NULL, 0x0,
        "Reply User Name", HFILL }
    },

    /* CID */
    { &hf_magic_reply_cid,
      { "CID", "magic.reply.cid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        "Reply CID", HFILL }
    },

    /* DCID */
    { &hf_magic_reply_dcid,
      { "DCID", "magic.reply.dcid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        "Reply DCID", HFILL }
    },
  };

  static hf_register_info rdmnet_hf[] = {
    /* CID */
    { &hf_rdmnet_cid,
      { "CID", "rdmnet.cid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Packet Identifier */
    { &hf_rdmnet_packet_identifier,
      { "Packet Identifier", "rdmnet.packet_identifier",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* PDU */
    { &hf_rdmnet_pdu,
      { "PDU", "rdmnet.pdu",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* PDU flags*/
    { &hf_rdmnet_pdu_flags,
      { "Flags", "rdmnet.pdu.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "PDU Flags", HFILL }
    },
    { &hf_rdmnet_pdu_flag_d,
      { "Data", "rdmnet.pdu.flag_d",
        FT_BOOLEAN, 8, NULL, ACN_PDU_FLAG_D,
        "Data flag", HFILL }
    },
    { &hf_rdmnet_pdu_flag_h,
      { "Header", "rdmnet.pdu.flag_h",
        FT_BOOLEAN, 8, NULL, ACN_PDU_FLAG_H,
        "Header flag", HFILL }
    },
    { &hf_rdmnet_pdu_flag_l,
      { "Length", "rdmnet.pdu.flag_l",
        FT_BOOLEAN, 8, NULL, ACN_PDU_FLAG_L,
        "Length flag", HFILL }
    },
    { &hf_rdmnet_pdu_flag_v,
      { "Vector", "rdmnet.pdu.flag_v",
        FT_BOOLEAN, 8, NULL, ACN_PDU_FLAG_V,
        "Vector flag", HFILL }
    },
    /* PDU Length */
    { &hf_rdmnet_pdu_length,
      { "Length", "rdmnet.pdu.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "PDU Length", HFILL }
    },
    /* Postamble Size */
    { &hf_rdmnet_postamble_size,
      { "Size of postamble", "rdmnet.postamble_size",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Postamble size in bytes", HFILL }
    },
    /* Preamble Size */
    { &hf_rdmnet_preamble_size,
      { "Size of preamble", "rdmnet.preamble_size",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Preamble size in bytes", HFILL }
    },
    /* Protocol ID */
    { &hf_rdmnet_protocol_id,
      { "Protocol ID", "rdmnet.protocol_id",
        FT_UINT32, BASE_DEC, VALS(acn_protocol_id_vals), 0x0,
        NULL, HFILL }
    },
    /* Postamble Size */
    { &hf_rdmnet_tcp_length,
      { "Data length", "rdmnet.tcp_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "TCP data size in bytes", HFILL }
    },
    /* LLRP Vector */
    { &hf_rdmnet_llrp_vector,
      { "LLRP Vector", "rdmnet.llrp_vector",
        FT_UINT32, BASE_DEC, VALS(rdmnet_llrp_vector_vals), 0x0,
        NULL, HFILL }
    },
    /* LLRP Destination CID */
    { &hf_rdmnet_llrp_destination_cid,
      { "CID", "rdmnet.llrp.destination_cid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* LLRP Transaction Number */
    { &hf_rdmnet_llrp_transaction_number,
      { "Transaction Number", "rdmnet.llrp.transaction_number",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* LLRP Probe Request PDU Length */
    { &hf_rdmnet_llrp_probe_request_pdu_length,
      { "Length", "rdmnet.llrp.probe_request.pdu.length",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        "PDU Length", HFILL }
    },
    /* LLRP Probe Request Vector */
    { &hf_rdmnet_llrp_probe_request_vector,
      { "LLRP Vector", "rdmnet.llrp.probe_request_vector",
        FT_UINT8, BASE_DEC, VALS(rdmnet_llrp_probe_request_vals), 0x0,
        NULL, HFILL }
    },
    /* LLRP Probe Request Lower UID */
    { &hf_rdmnet_llrp_probe_request_lower_uid,
      { "Lower UID", "rdmnet.llrp.probe_request.lower_uid",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* LLRP Probe Request Upper UID */
    { &hf_rdmnet_llrp_probe_request_upper_uid,
      { "Upper UID", "rdmnet.llrp.probe_request.upper_uid",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* LLRP Probe Request Filter */
    { &hf_rdmnet_llrp_probe_request_filter,
      { "Filter", "rdmnet.llrp.probe_request.filter",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_rdmnet_llrp_probe_request_filter_brokers_only,
      { "Brokers Only", "rdmnet.llrp.probe_request.filter_brokers_only",
        FT_BOOLEAN, 8, NULL, RDMNET_LLRP_VECTOR_PROBE_REQUEST_BROKERS_ONLY,
        "Brokers only flag", HFILL }
    },
    { &hf_rdmnet_llrp_probe_request_filter_client_tcp_inactive,
      { "Client TCP Inactive", "rdmnet.llrp.probe_request.filter_client_tcp_inactive",
        FT_BOOLEAN, 8, NULL, RDMNET_LLRP_VECTOR_PROBE_REQUEST_CLIENT_TCP_INACTIVE,
        "Client TCP inactive flag", HFILL }
    },
    /* LLRP Probe Request Unknown UID */
    { &hf_rdmnet_llrp_probe_request_known_uid,
      { "Known UID", "rdmnet.llrp.probe_request.known_uid",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* LLRP Probe Reply Vector */
    { &hf_rdmnet_llrp_probe_reply_vector,
      { "LLRP Vector", "rdmnet.llrp.probe_reply_vector",
        FT_UINT8, BASE_DEC, VALS(rdmnet_llrp_probe_reply_vals), 0x0,
        NULL, HFILL }
    },
    /* LLRP Probe Reply UID */
    { &hf_rdmnet_llrp_probe_reply_uid,
      { "UID", "rdmnet.llrp.probe_reply.uid",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* LLRP Probe Reply Hardware Address */
    { &hf_rdmnet_llrp_probe_reply_hardware_address,
      { "Hardware Address", "rdmnet.llrp.probe_reply.hardware_address",
        FT_BYTES, SEP_COLON, NULL, 0x0,
        NULL, HFILL }
    },
    /* LLRP Probe Reply Component Type */
    { &hf_rdmnet_llrp_probe_reply_component_type,
      { "Component Type", "rdmnet.llrp.probe_reply.component_type",
        FT_UINT8, BASE_DEC, VALS(rdmnet_llrp_probe_reply_component_type_vals), 0x0,
        NULL, HFILL }
    },
    /* LLRP RDM Command Start Code */
    { &hf_rdmnet_llrp_rdm_command_start_code,
      { "RDM Command", "rdmnet.llrp.rdm_command.start_code",
        FT_UINT8, BASE_DEC, VALS(rdmnet_llrp_rdm_command_start_code_vals), 0x0,
        NULL, HFILL }
    },
    /* RPT Vector */
    { &hf_rdmnet_rpt_vector,
      { "RPT Vector", "rdmnet.rpt_vector",
        FT_UINT8, BASE_DEC, VALS(rdmnet_rpt_vector_vals), 0x0,
        NULL, HFILL }
    },
    /* RPT Source UID */
    { &hf_rdmnet_rpt_source_uid,
      { "Source UID", "rdmnet.rpt.source_uid",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* RPT Source Endpoint ID */
    { &hf_rdmnet_rpt_source_endpoint_id,
      { "Source Endpoint ID", "rdmnet.rpt.source_endpoint_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    /* RPT Destination UID */
    { &hf_rdmnet_rpt_destination_uid,
      { "Destination UID", "rdmnet.rpt.destination_uid",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* RPT Destination Endpoint ID */
    { &hf_rdmnet_rpt_destination_endpoint_id,
      { "Destination Endpoint ID", "rdmnet.rpt.destination_endpoint_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    /* RPT Sequence Number */
    { &hf_rdmnet_rpt_sequence_number,
      { "Sequence Number", "rdmnet.rpt.sequence_number",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    /* RPT Reserved */
    { &hf_rdmnet_rpt_reserved,
      { "Reserved", "rdmnet.rpt.reserved",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    /* RPT Request Vector */
    { &hf_rdmnet_rpt_request_vector,
      { "RPT Request Vector", "rdmnet.rpt.request_vector",
        FT_UINT32, BASE_DEC, VALS(rdmnet_rpt_request_vals), 0x0,
        NULL, HFILL }
    },
    /* RPT Request RDM Command */
    { &hf_rdmnet_rpt_request_rdm_command,
      { "RDM Command", "rdmnet.rpt.request.rdm_command",
        FT_UINT8, BASE_DEC, VALS(rdmnet_rpt_request_rdm_command_start_code_vals), 0x0,
        NULL, HFILL }
    },
    /* RPT Status Vector */
    { &hf_rdmnet_rpt_status_vector,
      { "Status Vector", "rdmnet.rpt.status.vector",
        FT_UINT16, BASE_DEC, VALS(rdmnet_rpt_status_vector_vals), 0x0,
        NULL, HFILL }
    },
    /* RPT Status Unknown RPT UID String */
    { &hf_rdmnet_rpt_status_unknown_rpt_uid_string,
      { "Status", "rdmnet.rpt.status.unknown_rpt_uid_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* RPT Status RDM Timeout String */
    { &hf_rdmnet_rpt_status_rdm_timeout_string,
      { "Status", "rdmnet.rpt.status.rdm_timeout_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* RPT Status Invalid RDM Response String */
    { &hf_rdmnet_rpt_status_rdm_invalid_response_string,
      { "Status", "rdmnet.rpt.status.invalid_rdm_response_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* RPT Status Unknown RDM UID String */
    { &hf_rdmnet_rpt_status_unknown_rdm_uid_string,
      { "Status", "rdmnet.rpt.status.unknown_rdm_uid_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* RPT Status Unknown Endpoint String */
    { &hf_rdmnet_rpt_status_unknown_endpoint_string,
      { "Status", "rdmnet.rpt.status.unknown_endpoint_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* RPT Status Broadcast Complete String */
    { &hf_rdmnet_rpt_status_broadcast_complete_string,
      { "Status", "rdmnet.rpt.status.broadcast_complete_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* RPT Status Unknown Vector String */
    { &hf_rdmnet_rpt_status_unknown_vector_string,
      { "Status", "rdmnet.rpt.status.unknown_vector_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* RPT Notification Vector */
    { &hf_rdmnet_rpt_notification_vector,
      { "RPT Notification Vector", "rdmnet.rpt.notification_vector",
        FT_UINT32, BASE_DEC, VALS(rdmnet_rpt_notification_vals), 0x0,
        NULL, HFILL }
    },
    /* RPT Notification RDM Command */
    { &hf_rdmnet_rpt_notification_rdm_command,
      { "RDM Command", "rdmnet.rpt.notification.rdm_command",
        FT_UINT8, BASE_DEC, VALS(rdmnet_rpt_request_rdm_command_start_code_vals), 0x0,
        NULL, HFILL }
    },
    /* Broker Vector */
    { &hf_rdmnet_broker_vector,
      { "Broker Vector", "rdmnet.broker_vector",
        FT_UINT8, BASE_DEC, VALS(rdmnet_broker_vector_vals), 0x0,
        NULL, HFILL }
    },
    /* Broker Client Protocol Vector */
    { &hf_rdmnet_broker_client_protocol_vector,
      { "Client Protocol", "rdmnet.broker_client_protocol_vector",
        FT_UINT32, BASE_DEC, VALS(broker_client_protocol_vals), 0x0,
        NULL, HFILL }
    },
    /* Broker Client Protocol CID */
    { &hf_rdmnet_broker_client_protocol_cid,
      { "Client CID", "rdmnet.broker_client_cid",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Client RPT Client UID */
    { &hf_rdmnet_broker_client_rpt_client_uid,
      { "Client UID", "rdmnet.broker_client_rpt_client_uid",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Client RPT Client Type */
    { &hf_rdmnet_broker_client_rpt_client_type,
      { "RPT client type", "rdmnet.broker_client_rpt_client_type",
        FT_UINT8, BASE_DEC, VALS(broker_client_rpt_client_type_vals), 0x0,
        NULL, HFILL }
    },
    /* Broker Client RPT Binding CID */
    { &hf_rdmnet_broker_client_rpt_binding_cid,
      { "Binding CID", "rdmnet.broker_client_rpt_binding_cid",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Client EPT Protocol Vector */
    { &hf_rdmnet_broker_client_ept_protocol_vector,
      { "Protocol Vector", "rdmnet.broker_client_ept_vector",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Client EPT Manufacturer ID */
    { &hf_rdmnet_broker_client_ept_protocol_manufacturer_id,
      { "Manufacturer ID", "rdmnet.broker_client_ept_manufacturer_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Client EPT Protocol ID */
    { &hf_rdmnet_broker_client_ept_protocol_protocol_id,
      { "Protocol ID", "rdmnet.broker_client_ept_protocol_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Client EPT Protocol String */
    { &hf_rdmnet_broker_client_ept_protocol_string,
      { "Protocol String", "rdmnet.broker_client_ept_protocol_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Connect Scope */
    { &hf_rdmnet_broker_connect_client_scope,
      { "Client Scope", "rdmnet.broker.connect.client_scope",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Connect E1.33 Version */
    { &hf_rdmnet_broker_connect_e133_version,
      { "E1.33 Version", "rdmnet.broker.connect.e133_version",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Connect Search Domain */
    { &hf_rdmnet_broker_connect_search_domain,
      { "Search Domain", "rdmnet.broker.connect.search_domain",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Connect Connection Flags */
    { &hf_rdmnet_broker_connect_connection_flags,
      { "Flags", "rdmnet.broker.connect.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Connection Flags", HFILL }
    },
    { &hf_rdmnet_broker_connect_connection_flags_incremental_updates,
      { "Incremental Updates", "rdmnet.broker.connect.flags_incremental_updates",
        FT_BOOLEAN, 8, NULL, RDMNET_BROKER_VECTOR_CONNECT_INCREMENTAL_UPDATES,
        "Incremental updates flag", HFILL }
    },
    /* Broker Connect Reply Connection Code */
    { &hf_rdmnet_broker_connect_reply_connection_code,
      { "Connection Code", "rdmnet.broker.connect_reply.connection_code",
        FT_UINT16, BASE_DEC, VALS(rdmnet_broker_status_code_vals), 0x0,
        NULL, HFILL }
    },
    /* Broker Connect Reply E1.33 Version */
    { &hf_rdmnet_broker_connect_reply_e133_version,
      { "E1.33 Version", "rdmnet.broker.connect_reply.e133_version",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Connect Reply Broker UID */
    { &hf_rdmnet_broker_connect_reply_broker_uid,
      { "Broker UID", "rdmnet.broker.connect_reply.broker_uid",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Connect Reply Client UID */
    { &hf_rdmnet_broker_connect_reply_client_uid,
      { "Client UID", "rdmnet.broker.connect_reply.client_uid",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Client Entry Update Connection Flags */
    { &hf_rdmnet_broker_client_entry_update_connection_flags,
      { "Flags", "rdmnet.broker.client_entry_update.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Connection Flags", HFILL }
    },
    { &hf_rdmnet_broker_client_entry_update_connection_flags_incremental_updates,
      { "Incremental Updates", "rdmnet.broker.client_entry_update.flags_incremental_updates",
        FT_BOOLEAN, 8, NULL, RDMNET_BROKER_VECTOR_CONNECT_INCREMENTAL_UPDATES,
        "Incremental updates flag", HFILL }
    },
    /* Broker Redirect IPv4 Address */
    { &hf_rdmnet_broker_redirect_ipv4_address,
      { "IPv4 Address", "rdmnet.broker.redirect_ipv4.ipv4_address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "Redirect IPv4 address", HFILL }
    },
    /* Broker Redirect IPv4 TCP Port */
    { &hf_rdmnet_broker_redirect_ipv4_tcp_port,
      { "IPv4 TCP Port", "rdmnet.broker.redirect_ipv4.tcp_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Redirect IPv4 TCP port", HFILL }
    },
    /* Broker Redirect IPv6 Address */
    { &hf_rdmnet_broker_redirect_ipv6_address,
      { "IPv6 Address", "rdmnet.broker.redirect_ipv6.ipv4_address",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "Redirect IPv6 address", HFILL }
    },
    /* Broker Redirect IPv6 TCP Port */
    { &hf_rdmnet_broker_redirect_ipv6_tcp_port,
      { "TCP Port", "rdmnet.broker.redirect_ipv6.tcp_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Redirect IPv6 TCP port", HFILL }
    },
    /* Broker Disconnect Reason */
    { &hf_rdmnet_broker_disconnect_reason,
      { "Reason", "rdmnet.broker.disconnect.reason",
        FT_UINT16, BASE_DEC, VALS(rdmnet_broker_disconnect_reason_vals), 0x0,
        "Disconnect reason", HFILL }
    },
    /* Broker Dynamic UID Request */
    { &hf_rdmnet_broker_dynamic_uid_request,
      { "Dynamic UID Request", "rdmnet.broker.request_dynamic_uids.dynamic_uid_request",
        FT_BYTES, SEP_DOT, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker RID */
    { &hf_rdmnet_broker_rid,
      { "RID", "rdmnet.broker.request_dynamic_uids.rid",
        FT_BYTES, SEP_DOT, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Assigned Dynamic UID */
    { &hf_rdmnet_broker_assigned_dynamic_uid,
      { "Dynamic UID Request", "rdmnet.broker.assigned_dynamic_uids.dynamic_uid",
        FT_BYTES, SEP_DOT, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker Assigned RID */
    { &hf_rdmnet_broker_assigned_rid,
      { "RID", "rdmnet.broker.assigned_dynamic_uids.rid",
        FT_BYTES, SEP_DOT, NULL, 0x0,
        NULL, HFILL }
    },
    /* Broker_Assigned Status Code */
    { &hf_rdmnet_broker_assigned_status_code,
      { "Status Code", "rdmnet.broker.assigned_dynamic_uids.status_code",
        FT_UINT16, BASE_DEC, VALS(dynamic_uid_mapping_status_code_vals), 0x0,
        NULL, HFILL }
    },
    /* Broker Fetch Dynamic UID */
    { &hf_rdmnet_broker_fetch_dynamic_uid,
      { "Dynamic UID", "rdmnet.broker.fetch_dynamic_uids.dynamic_uid",
        FT_BYTES, SEP_DOT, NULL, 0x0,
        NULL, HFILL }
    },
    /* EPT Vector */
    { &hf_rdmnet_ept_vector,
      { "EPT Vector", "rdmnet.ept_vector",
        FT_UINT8, BASE_DEC, VALS(rdmnet_ept_vector_vals), 0x0,
        NULL, HFILL }
    },
    /* EPT Destination CID */
    { &hf_rdmnet_ept_destination_cid,
      { "Destination CID", "rdmnet.ept.destination_cid",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* EPT Data PDU Length */
    { &hf_rdmnet_ept_data_pdu_length,
      { "Length", "rdmnet.ept.data.pdu.length",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        "PDU Length", HFILL }
    },
    /* EPT Data Vector */
    { &hf_rdmnet_ept_data_vector,
      { "Vector", "rdmnet.ept.data.vector",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "Data vector", HFILL }
    },
    /* EPT Data Vector Manfacturer ID */
    { &hf_rdmnet_ept_data_vector_manfacturer_id,
      { "Manfac. ID", "rdmnet.ept.data.vector.manfacturer_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Manfacturer id", HFILL }
    },
    /* EPT Data Vector Protocol ID */
    { &hf_rdmnet_ept_data_vector_protocol_id,
      { "Protocol", "rdmnet.ept.data.vector.protocol_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Protocol id", HFILL }
    },
    /* EPT Data Opaque Data */
    { &hf_rdmnet_ept_data_opaque_data,
      { "Data", "rdmnet.ept.data.opaque_data",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* EPT Status PDU Length */
    { &hf_rdmnet_ept_status_pdu_length,
      { "Length", "rdmnet.ept.status.pdu.length",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        "PDU Length", HFILL }
    },
    /* EPT Status Unknown CID */
    { &hf_rdmnet_ept_status_unknown_cid,
      { "Unknown CID", "rdmnet.ept.status.unknown_cid",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* EPT Status Status String */
    { &hf_rdmnet_ept_status_status_string,
      { "Status String", "rdmnet.ept.status.status_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* EPT Status Vector */
    { &hf_rdmnet_ept_status_vector,
      { "Unknown Vector", "rdmnet.ept.status.vector",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* EPT Status Unknown Vector */
    { &hf_rdmnet_ept_status_unknown_vector,
      { "Unknown Vector", "rdmnet.ept.status.unknown_vector",
        FT_BYTES, SEP_SPACE, NULL, 0x0,
        NULL, HFILL }
    },
    /* EPT Status Vector String */
    { &hf_rdmnet_ept_status_vector_string,
      { "Vector String", "rdmnet.ept.status.vector_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_acn,
    &ett_acn_channel_owner_info_block,
    &ett_acn_channel_member_info_block,
    &ett_acn_channel_parameter,
    &ett_acn_address,
    &ett_acn_address_type,
    &ett_acn_pdu_flags,
    &ett_acn_dmp_pdu,
    &ett_acn_sdt_pdu,
    &ett_acn_sdt_client_pdu,
    &ett_acn_sdt_base_pdu,
    &ett_acn_root_pdu,
    &ett_acn_dmx_address,
    &ett_acn_dmx_2_options,
    &ett_acn_dmx_data_pdu,
    &ett_acn_dmx_pdu,
    &ett_acn_blob
  };

  /* Setup protocol subtree array */
  static gint *magic_ett[] = {
    &ett_magic
  };

  /* Setup protocol subtree array */
  static gint *rdmnet_ett[] = {
    &ett_rdmnet,
    &ett_rdmnet_pdu_flags,
    &ett_rdmnet_llrp_base_pdu,
    &ett_rdmnet_llrp_probe_request_pdu,
    &ett_rdmnet_llrp_probe_request_filter_flags,
    &ett_rdmnet_llrp_probe_reply_pdu,
    &ett_rdmnet_llrp_rdm_command_pdu,
    &ett_rdmnet_rpt_base_pdu,
    &ett_rdmnet_rpt_request_pdu,
    &ett_rdmnet_rpt_status_pdu,
    &ett_rdmnet_rpt_notification_pdu,
    &ett_rdmnet_broker_base_pdu,
    &ett_rdmnet_broker_client_entry_pdu,
    &ett_rdmnet_broker_client_entry_manufacturer_protocol_ids,
    &ett_rdmnet_broker_connect_connection_flags,
    &ett_rdmnet_broker_client_entry_update_connection_flags,
    &ett_rdmnet_ept_base_pdu,
    &ett_rdmnet_ept_data_pdu,
    &ett_rdmnet_ept_data_vector_pdu,
    &ett_rdmnet_ept_status_pdu
  };

  static ei_register_info ei[] = {
    { &ei_magic_reply_invalid_type, { "magic.reply.invalid_type", PI_PROTOCOL, PI_WARN, "Invalid type", EXPFILL }},
  };

  module_t *acn_module;
  expert_module_t* expert_acn;

  proto_acn = proto_register_protocol (
    "Architecture for Control Networks", /* name */
    "ACN",                               /* short name */
    "acn"                                /* abbrev */
    );

  proto_magic = proto_register_protocol(
    "Magic Bullet",                      /* name */
    "MAGIC",                             /* short name */
    "magic"                              /* abbrev */
    );

  proto_rdmnet = proto_register_protocol(
    "RDMnet",                            /* name */
    "RDMnet",                            /* short name */
    "rdmnet"                             /* abbrev */
    );

  proto_register_field_array(proto_acn, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  acn_module = prefs_register_protocol(proto_acn, NULL);
  prefs_register_obsolete_preference(acn_module, "heuristic_acn");

  prefs_register_bool_preference(acn_module, "dmx_enable",
                                 "Streaming DMX",
                                 "Enable Streaming DMX extension dissector (ANSI BSR E1.31)",
                                 &global_acn_dmx_enable);

  prefs_register_enum_preference(acn_module, "dmx_display_view",
                                 "DMX, display format",
                                 "Display format",
                                 &global_acn_dmx_display_view,
                                 dmx_display_view,
                                 TRUE);

  prefs_register_bool_preference(acn_module, "dmx_display_zeros",
                                 "DMX, display zeros",
                                 "Display zeros instead of dots",
                                 &global_acn_dmx_display_zeros);

  prefs_register_bool_preference(acn_module, "dmx_display_leading_zeros",
                                 "DMX, display leading zeros",
                                 "Display leading zeros on levels",
                                 &global_acn_dmx_display_leading_zeros);

  prefs_register_enum_preference(acn_module, "dmx_display_line_format",
                                 "DMX, display line format",
                                 "Display line format",
                                 &global_acn_dmx_display_line_format,
                                 dmx_display_line_format,
                                 TRUE);

  proto_register_field_array(proto_magic, magic_hf, array_length(magic_hf));
  proto_register_subtree_array(magic_ett, array_length(magic_ett));
  expert_acn = expert_register_protocol(proto_magic);
  expert_register_field_array(expert_acn, ei, array_length(ei));

  proto_register_field_array(proto_rdmnet, rdmnet_hf, array_length(rdmnet_hf));
  proto_register_subtree_array(rdmnet_ett, array_length(rdmnet_ett));
}


/******************************************************************************/
/* Register handoff                                                           */
void
proto_reg_handoff_acn(void)
{
  /* dissector_handle_t acn_handle; */
  /* acn_handle = create_dissector_handle(dissect_acn, proto_acn); */
  /* dissector_add_for_decode_as_with_preference("udp.port", acn_handle);                         */

  rdm_handle      = find_dissector_add_dependency("rdm", proto_acn);

  heur_dissector_add("udp", dissect_acn_heur, "ACN", "acn", proto_acn, HEURISTIC_DISABLE);
  heur_dissector_add("udp", dissect_rdmnet_over_udp_heur, "RDMnet over UDP (LLRP)", "rdmnet_udp", proto_acn, HEURISTIC_DISABLE);
  heur_dissector_add("tcp", dissect_rdmnet_over_tcp_heur, "RDMnet over TCP (Broker, RPT, EPT)", "rdmnet_tcp", proto_acn, HEURISTIC_DISABLE);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
