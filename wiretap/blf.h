/** @file
 *
 * Binary Log File (BLF) file format from Vector Informatik decoder
 * for the Wiretap library.
 *
 * Copyright (c) 2021-2022 by Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*
  * The following was used as a reference for the file format:
  *     https://bitbucket.org/tobylorenz/vector_blf
  * The repo above includes multiple examples files as well.
  */

#ifndef __W_BLF_H__
#define __W_BLF_H__

#include "wtap.h"
#include <epan/value_string.h>

wtap_open_return_val blf_open(wtap *wth, int *err, gchar **err_info);


#define BLF_HEADER_TYPE_DEFAULT                   1
#define BLF_HEADER_TYPE_2                         2
#define BLF_HEADER_TYPE_3                         3


#define BLF_COMPRESSION_NONE                      0
#define BLF_COMPRESSION_ZLIB                      2

#define BLF_TIMESTAMP_RESOLUTION_10US             1
#define BLF_TIMESTAMP_RESOLUTION_1NS              2

typedef struct blf_date {
    guint16 year;
    guint16 month;
    guint16 dayofweek;
    guint16 day;
    guint16 hour;
    guint16 mins;
    guint16 sec;
    guint16 ms;
} blf_date_t;

/* BLF Header */
typedef struct blf_fileheader {
    guint8 magic[4];
    guint32 header_length;

    guint8 applications[4];
    guint8 api[4];

    guint64 len_compressed;
    guint64 len_uncompressed;

    guint32 obj_count;
    guint32 obj_read;

    blf_date_t start_date;
    blf_date_t end_date;

    guint32 length3;
} blf_fileheader_t;

typedef struct blf_blockheader {
    guint8  magic[4];
    guint16 header_length;         /* length of header starting with magic */
    guint16 header_type;           /* header format ? */
    guint32 object_length;         /* complete length including header */
    guint32 object_type;
} blf_blockheader_t;

typedef struct blf_logcontainerheader {
    guint16 compression_method;    /* 0 uncompressed, 2 zlib */
    guint16 res1;
    guint32 res2;
    guint32 uncompressed_size;
    guint32 res4;
} blf_logcontainerheader_t;

typedef struct blf_logobjectheader {
    guint32 flags;
    guint16 client_index;
    guint16 object_version;
    guint64 object_timestamp;
} blf_logobjectheader_t;

#define BLF_TS_STATUS_ORIG_TS_VALID     0x01
#define BLF_TS_STATUS_SW_TS             0x02
#define BLF_TS_STATUS_PROTO_SPECIFIC    0x10

typedef struct blf_logobjectheader2 {
    guint32 flags;
    guint8  timestamp_status;
    guint8  res1;
    guint16 object_version;
    guint64 object_timestamp;
    guint64 original_timestamp;
} blf_logobjectheader2_t;

typedef struct blf_logobjectheader3 {
    guint32 flags;
    guint16 static_size;
    guint16 object_version;
    guint64 object_timestamp;
} blf_logobjectheader3_t;


#define BLF_DIR_RX    0
#define BLF_DIR_TX    1
#define BLF_DIR_TX_RQ 2

typedef struct blf_ethernetframeheader {
    guint8  src_addr[6];
    guint16 channel;
    guint8  dst_addr[6];
    guint16 direction;
    guint16 ethtype;
    guint16 tpid;
    guint16 tci;
    guint16 payloadlength;
    guint64 res;
} blf_ethernetframeheader_t;

typedef struct blf_ethernetframeheader_ex {
    guint16 struct_length;
    guint16 flags;
    guint16 channel;
    guint16 hw_channel;
    guint64 frame_duration;
    guint32 frame_checksum;
    guint16 direction;
    guint16 frame_length;
    guint32 frame_handle;
    guint32 error;
} blf_ethernetframeheader_ex_t;

typedef struct blf_wlanframeheader {
    guint16 channel;
    guint16 flags;
    guint8  direction;
    guint8  radio_channel;
    guint16 signal_strength;
    guint16 signal_quality;
    guint16 frame_length;
    guint32 res;
} blf_wlanframeheader_t;

/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/CanMessage.h */

/* shared for CAN message and CAN message2 and CANFD message */
#define BLF_CANMESSAGE_FLAG_TX                      0x01
#define BLF_CANMESSAGE_FLAG_NERR                    0x20
#define BLF_CANMESSAGE_FLAG_WU                      0x40
#define BLF_CANMESSAGE_FLAG_RTR                     0x80

/* shared for CAN message and CAN message2*/
typedef struct blf_canmessage {
    guint16 channel;
    guint8  flags;
    guint8  dlc;
    guint32 id;
} blf_canmessage_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/CanMessage2.h */

typedef struct blf_canmessage2_trailer {
    guint32 frameLength_in_ns;
    guint8 bitCount;
    guint8 reserved1;
    guint16 reserved2;
} blf_canmessage2_trailer_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/CanFdMessage.h */

/* EDL 0: CAN, 1: CAN-FD*/
#define BLF_CANFDMESSAGE_CANFDFLAG_EDL              0x01
#define BLF_CANFDMESSAGE_CANFDFLAG_BRS              0x02
#define BLF_CANFDMESSAGE_CANFDFLAG_ESI              0x04

typedef struct blf_canfdmessage {
    guint16 channel;
    guint8  flags;
    guint8  dlc;
    guint32 id;
    guint32 frameLength_in_ns;
    guint8  canfdflags;
    guint8  validDataBytes;
    guint8  reservedCanFdMessage1;
    guint32  reservedCanFdMessage2;
    /* DATA */
    /* guint32 reservedCanFdMessage3 */
} blf_canfdmessage_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/CanFdMessage64.h */

#define BLF_CANFDMESSAGE64_FLAG_NERR                0x000004
#define BLF_CANFDMESSAGE64_FLAG_HIGH_VOLT_WAKE_UP   0x000008
#define BLF_CANFDMESSAGE64_FLAG_REMOTE_FRAME        0x000010
#define BLF_CANFDMESSAGE64_FLAG_TX_ACK              0x000040
#define BLF_CANFDMESSAGE64_FLAG_TX_REQ              0x000080
#define BLF_CANFDMESSAGE64_FLAG_SRR                 0x000200
#define BLF_CANFDMESSAGE64_FLAG_R0                  0x000400
#define BLF_CANFDMESSAGE64_FLAG_R1                  0x000800
/* EDL 0: CAN, 1: CAN-FD*/
#define BLF_CANFDMESSAGE64_FLAG_EDL                 0x001000
#define BLF_CANFDMESSAGE64_FLAG_BRS                 0x002000
#define BLF_CANFDMESSAGE64_FLAG_ESI                 0x004000
#define BLF_CANFDMESSAGE64_FLAG_BURST               0x200000

typedef struct blf_canfdmessage64 {
    guint8  channel;
    guint8  dlc;
    guint8  validDataBytes;
    guint8  txCount;
    guint32 id;
    guint32 frameLength_in_ns;
    guint32 flags;
    guint32 btrCfgArb;
    guint32 btrCfgData;
    guint32 timeOffsetBrsNs;
    guint32 timeOffsetCrcDelNs;
    guint16 bitCount;
    guint8  dir;
    guint8  extDataOffset;
    guint32 crc;
} blf_canfdmessage64_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/FlexRayData.h */

#define BLF_FLEXRAYDATA_FRAME                       0x01
#define BLF_FLEXRAYDATA_CHANNEL_B                   0x80

typedef struct blf_flexraydata {
    guint16 channel;
    guint8  mux;
    guint8  len;
    guint16 messageId;
    guint16 crc;
    guint8  dir;
    guint8  reservedFlexRayData1;
    guint16 reservedFlexRayData2;
} blf_flexraydata_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/FlexRayV6Message.h */

#define BLF_FLEXRAYMESSAGE_DIR_RX                   0x01
#define BLF_FLEXRAYMESSAGE_DIR_TX                   0x02
#define BLF_FLEXRAYMESSAGE_DIR_TX_REQ               0x04

#define BLF_FLEXRAYMESSAGE_STATE_PPI                0x01
#define BLF_FLEXRAYMESSAGE_STATE_SFI                0x02
#define BLF_FLEXRAYMESSAGE_STATE_RES_BIT2           0x04
#define BLF_FLEXRAYMESSAGE_STATE_NFI                0x08
#define BLF_FLEXRAYMESSAGE_STATE_STFI               0x10
#define BLF_FLEXRAYMESSAGE_STATE_FORMAT             0xe0

#define BLF_FLEXRAYMESSAGE_HEADER_BIT_NM            0x01
#define BLF_FLEXRAYMESSAGE_HEADER_BIT_SYNC          0x02
#define BLF_FLEXRAYMESSAGE_HEADER_BIT_RES           0x04

#define BLF_DLT_FLEXRAY_STFI                        0x08
#define BLF_DLT_FLEXRAY_SFI                         0x10
#define BLF_DLT_FLEXRAY_NFI                         0x20
#define BLF_DLT_FLEXRAY_PPI                         0x40

typedef struct blf_flexraymessage {
    guint16 channel;
    guint8  dir;            /* Flags: 0 RX, 1 TX, 2 TX Req, 3 internal, 4 internal*/
    guint8  lowTime;
    guint32 fpgaTick;
    guint32 fpgaTickOverflow;
    guint32 clientIndexFlexRayV6Message;
    guint32 clusterTime;
    guint16 frameId;
    guint16 headerCrc;
    guint16 frameState;
    guint8  length;
    guint8  cycle;
    guint8  headerBitMask;
    guint8  reservedFlexRayV6Message1;
    guint16 reservedFlexRayV6Message2;
} blf_flexraymessage_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/FlexRayVFrReceiveMsg.h */

#define BLF_FLEXRAYRCVMSG_DIR_RX                  0x01
#define BLF_FLEXRAYRCVMSG_DIR_TX                  0x02
#define BLF_FLEXRAYRCVMSG_DIR_TX_REQ              0x04

#define BLF_FLEXRAYRCVMSG_CHANNELMASK_RES         0x00
#define BLF_FLEXRAYRCVMSG_CHANNELMASK_A           0x01
#define BLF_FLEXRAYRCVMSG_CHANNELMASK_B           0x02
#define BLF_FLEXRAYRCVMSG_CHANNELMASK_AB          0x03

#define BLF_FLEXRAYRCVMSG_DATA_FLAG_NULL_FRAME    0x00000001
#define BLF_FLEXRAYRCVMSG_DATA_FLAG_VALID_DATA    0x00000002
#define BLF_FLEXRAYRCVMSG_DATA_FLAG_SYNC          0x00000004
#define BLF_FLEXRAYRCVMSG_DATA_FLAG_STARTUP       0x00000008
#define BLF_FLEXRAYRCVMSG_DATA_FLAG_PAYLOAD_PREAM 0x00000010
#define BLF_FLEXRAYRCVMSG_DATA_FLAG_RES_20        0x00000020
#define BLF_FLEXRAYRCVMSG_DATA_FLAG_ERROR         0x00000040
#define BLF_FLEXRAYRCVMSG_DATA_FLAG_RES_80        0x00000080

typedef struct blf_flexrayrcvmessage {
    guint16 channel;
    guint16 version;
    guint16 channelMask;    /* 0 res, 1 A, 2 B, 3 A+B */
    guint16 dir;            /* 0 RX, 1 TX, 2 TX Req, 3 internal, 4 internal*/ /* high byte reserved! */
    guint32 clientIndex;
    guint32 clusterNo;
    guint16 frameId;
    guint16 headerCrc1;
    guint16 headerCrc2;
    guint16 payloadLength;
    guint16 payloadLengthValid;
    guint16 cycle;          /* high byte reserved! */
    guint32 tag;
    guint32 data;
    guint32 frameFlags;
    guint32 appParameter;
    /* if ext, skip 40 bytes */
    /* payload bytes */
    /* guint16 res3 */
    /* guint32 res4 */
} blf_flexrayrcvmessage_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/FlexRayVFrReceiveMsgEx.h */

/* defines see above BLF_FLEXRAYRCVMSG_* */

typedef struct blf_flexrayrcvmessageex {
    guint16 channel;
    guint16 version;
    guint16 channelMask;    /* 0 res, 1 A, 2 B, 3 A+B */
    guint16 dir;            /* 0 RX, 1 TX, 2 TX Req, 3 internal, 4 internal*/
    guint32 clientIndex;
    guint32 clusterNo;
    guint16 frameId;
    guint16 headerCrc1;
    guint16 headerCrc2;
    guint16 payloadLength;
    guint16 payloadLengthValid;
    guint16 cycle;
    guint32 tag;
    guint32 data;
    guint32 frameFlags;
    guint32 appParameter;
    guint32 frameCRC;
    guint32 frameLengthInNs;
    guint16 frameId1;
    guint16 pduOffset;
    guint16 blfLogMask;
    guint16 res1;
    guint32 res2;
    guint32 res3;
    guint32 res4;
    guint32 res5;
    guint32 res6;
    guint32 res7;
    /* payload bytes */
} blf_flexrayrcvmessageex_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/LinMessage.h */

typedef struct blf_linmessage {
    guint16 channel;
    guint8  id;
    guint8  dlc;
} blf_linmessage_t;

typedef struct blf_linmessage_trailer {
    guint8  fsmId;
    guint8  fsmState;
    guint8  headerTime;
    guint8  fullTime;
    guint16 crc;
    guint8  dir;            /* 0 RX, 1 TX Receipt, 2 TX Req */
    guint8  res1;
    guint32 res2;
} blf_linmessage_trailer_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/AppText.h */

typedef struct blf_apptext {
    guint32 source;
    guint32 reservedAppText1;
    guint32 textLength;
    guint32 reservedAppText2;
} blf_apptext_t;

#define BLF_APPTEXT_COMMENT  0x00000000
#define BLF_APPTEXT_CHANNEL  0x00000001
#define BLF_APPTEXT_METADATA 0x00000002

#define BLF_BUSTYPE_CAN 1
#define BLF_BUSTYPE_LIN 5
#define BLF_BUSTYPE_MOST 6
#define BLF_BUSTYPE_FLEXRAY 7
#define BLF_BUSTYPE_J1708 9
#define BLF_BUSTYPE_ETHERNET 11
#define BLF_BUSTYPE_WLAN 13
#define BLF_BUSTYPE_AFDX 14


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/ObjectHeaderBase.h */

#define BLF_OBJTYPE_UNKNOWN                       0
#define BLF_OBJTYPE_CAN_MESSAGE                   1
#define BLF_OBJTYPE_CAN_ERROR                     2
#define BLF_OBJTYPE_CAN_OVERLOAD                  3
#define BLF_OBJTYPE_CAN_STATISTIC                 4
#define BLF_OBJTYPE_APP_TRIGGER                   5
#define BLF_OBJTYPE_ENV_INTEGER                   6
#define BLF_OBJTYPE_ENV_DOUBLE                    7
#define BLF_OBJTYPE_ENV_STRING                    8
#define BLF_OBJTYPE_ENV_DATA                      9
#define BLF_OBJTYPE_LOG_CONTAINER                10
#define BLF_OBJTYPE_LIN_MESSAGE                  11
#define BLF_OBJTYPE_LIN_CRC_ERROR                12
#define BLF_OBJTYPE_LIN_DLC_INFO                 13
#define BLF_OBJTYPE_LIN_RCV_ERROR                14
#define BLF_OBJTYPE_LIN_SND_ERROR                15
#define BLF_OBJTYPE_LIN_SLV_TIMEOUT              16
#define BLF_OBJTYPE_LIN_SCHED_MODCH              17
#define BLF_OBJTYPE_LIN_SYN_ERROR                18
#define BLF_OBJTYPE_LIN_BAUDRATE                 19
#define BLF_OBJTYPE_LIN_SLEEP                    20
#define BLF_OBJTYPE_LIN_WAKEUP                   21
#define BLF_OBJTYPE_MOST_SPY                     22
#define BLF_OBJTYPE_MOST_CTRL                    23
#define BLF_OBJTYPE_MOST_LIGHTLOCK               24
#define BLF_OBJTYPE_MOST_STATISTIC               25
#define BLF_OBJTYPE_FLEXRAY_DATA                 29
#define BLF_OBJTYPE_FLEXRAY_SYNC                 30
#define BLF_OBJTYPE_CAN_DRIVER_ERROR             31
#define BLF_OBJTYPE_MOST_PKT                     32
#define BLF_OBJTYPE_MOST_PKT2                    33
#define BLF_OBJTYPE_MOST_HWMODE                  34
#define BLF_OBJTYPE_MOST_REG                     35
#define BLF_OBJTYPE_MOST_GENREG                  36
#define BLF_OBJTYPE_MOST_NETSTATE                37
#define BLF_OBJTYPE_MOST_DATALOST                38
#define BLF_OBJTYPE_MOST_TRIGGER                 39
#define BLF_OBJTYPE_FLEXRAY_CYCLE                40
#define BLF_OBJTYPE_FLEXRAY_MESSAGE              41
#define BLF_OBJTYPE_LIN_CHECKSUM_INFO            42
#define BLF_OBJTYPE_LIN_SPIKE_EVENT              43
#define BLF_OBJTYPE_CAN_DRIVER_SYNC              44
#define BLF_OBJTYPE_FLEXRAY_STATUS               45
#define BLF_OBJTYPE_GPS_EVENT                    46
#define BLF_OBJTYPE_FLEXRAY_ERROR                47
#define BLF_OBJTYPE_FLEXRAY_STATUS2              48
#define BLF_OBJTYPE_FLEXRAY_STARTCYCLE           49
#define BLF_OBJTYPE_FLEXRAY_RCVMESSAGE           50
#define BLF_OBJTYPE_REALTIMECLOCK                51
#define BLF_OBJTYPE_LIN_STATISTIC                54
#define BLF_OBJTYPE_J1708_MESSAGE                55
#define BLF_OBJTYPE_J1708_VIRTUAL_MSG            56
#define BLF_OBJTYPE_LIN_MESSAGE2                 57
#define BLF_OBJTYPE_LIN_SND_ERROR2               58
#define BLF_OBJTYPE_LIN_SYN_ERROR2               59
#define BLF_OBJTYPE_LIN_CRC_ERROR2               60
#define BLF_OBJTYPE_LIN_RCV_ERROR2               61
#define BLF_OBJTYPE_LIN_WAKEUP2                  62
#define BLF_OBJTYPE_LIN_SPIKE_EVENT2             63
#define BLF_OBJTYPE_LIN_LONG_DOM_SIG             64
#define BLF_OBJTYPE_APP_TEXT                     65
#define BLF_OBJTYPE_FLEXRAY_RCVMESSAGE_EX        66
#define BLF_OBJTYPE_MOST_STATISTICEX             67
#define BLF_OBJTYPE_MOST_TXLIGHT                 68
#define BLF_OBJTYPE_MOST_ALLOCTAB                69
#define BLF_OBJTYPE_MOST_STRESS                  70
#define BLF_OBJTYPE_ETHERNET_FRAME               71
#define BLF_OBJTYPE_SYS_VARIABLE                 72
#define BLF_OBJTYPE_CAN_ERROR_EXT                73
#define BLF_OBJTYPE_CAN_DRIVER_ERROR_EXT         74
#define BLF_OBJTYPE_LIN_LONG_DOM_SIG2            75
#define BLF_OBJTYPE_MOST_150_MESSAGE             76
#define BLF_OBJTYPE_MOST_150_PKT                 77
#define BLF_OBJTYPE_MOST_ETHERNET_PKT            78
#define BLF_OBJTYPE_MOST_150_MESSAGE_FRAGMENT    79
#define BLF_OBJTYPE_MOST_150_PKT_FRAGMENT        80
#define BLF_OBJTYPE_MOST_ETHERNET_PKT_FRAGMENT   81
#define BLF_OBJTYPE_MOST_SYSTEM_EVENT            82
#define BLF_OBJTYPE_MOST_150_ALLOCTAB            83
#define BLF_OBJTYPE_MOST_50_MESSAGE              84
#define BLF_OBJTYPE_MOST_50_PKT                  85
#define BLF_OBJTYPE_CAN_MESSAGE2                 86
#define BLF_OBJTYPE_LIN_UNEXPECTED_WAKEUP        87
#define BLF_OBJTYPE_LIN_SHORT_OR_SLOW_RESPONSE   88
#define BLF_OBJTYPE_LIN_DISTURBANCE_EVENT        89
#define BLF_OBJTYPE_SERIAL_EVENT                 90
#define BLF_OBJTYPE_OVERRUN_ERROR                91
#define BLF_OBJTYPE_EVENT_COMMENT                92
#define BLF_OBJTYPE_WLAN_FRAME                   93
#define BLF_OBJTYPE_WLAN_STATISTIC               94
#define BLF_OBJTYPE_MOST_ECL                     95
#define BLF_OBJTYPE_GLOBAL_MARKER                96
#define BLF_OBJTYPE_AFDX_FRAME                   97
#define BLF_OBJTYPE_AFDX_STATISTIC               98
#define BLF_OBJTYPE_KLINE_STATUSEVENT            99
#define BLF_OBJTYPE_CAN_FD_MESSAGE              100
#define BLF_OBJTYPE_CAN_FD_MESSAGE_64           101
#define BLF_OBJTYPE_ETHERNET_RX_ERROR           102
#define BLF_OBJTYPE_ETHERNET_STATUS             103
#define BLF_OBJTYPE_CAN_FD_ERROR_64             104
#define BLF_OBJTYPE_AFDX_STATUS                 106
#define BLF_OBJTYPE_AFDX_BUS_STATISTIC          107
#define BLF_OBJTYPE_AFDX_ERROR_EVENT            109
#define BLF_OBJTYPE_A429_ERROR                  110
#define BLF_OBJTYPE_A429_STATUS                 111
#define BLF_OBJTYPE_A429_BUS_STATISTIC          112
#define BLF_OBJTYPE_A429_MESSAGE                113
#define BLF_OBJTYPE_ETHERNET_STATISTIC          114
#define BLF_OBJTYPE_TEST_STRUCTURE              118
#define BLF_OBJTYPE_DIAG_REQUEST_INTERPRETATION 119
#define BLF_OBJTYPE_ETHERNET_FRAME_EX           120
#define BLF_OBJTYPE_ETHERNET_FRAME_FORWARDED    121
#define BLF_OBJTYPE_ETHERNET_ERROR_EX           122
#define BLF_OBJTYPE_ETHERNET_ERROR_FORWARDED    123
#define BLF_OBJTYPE_FUNCTION_BUS                124
#define BLF_OBJTYPE_DATA_LOST_BEGIN             125
#define BLF_OBJTYPE_DATA_LOST_END               126
#define BLF_OBJTYPE_WATER_MARK_EVENT            127
#define BLF_OBJTYPE_TRIGGER_CONDITION           128
#define BLF_OBJTYPE_CAN_SETTING_CHANGED         129
#define BLF_OBJTYPE_DISTRIBUTED_OBJECT_MEMBER   130
#define BLF_OBJTYPE_ATTRIBUTE_EVENT             131

#endif

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
