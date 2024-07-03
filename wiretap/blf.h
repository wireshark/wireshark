/** @file
 *
 * Binary Log File (BLF) file format from Vector Informatik decoder
 * for the Wiretap library.
 *
 * Copyright (c) 2021-2024 by Dr. Lars Voelker <lars.voelker@technica-engineering.de>
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

wtap_open_return_val blf_open(wtap *wth, int *err, char **err_info);

/*
 * A BLF file is of the form:
 *
 *    BLF File Header
 *    Sequence of BLF objects
 *
 * A BLF object is of the form:
 *
 *    BLF Block Header
 *    Object header (object type dependent, may be empty)
 *    Object contents
 *
 * As per
 *
 *    https://gitlab.com/wireshark/wireshark/-/issues/19896#note_1967971057
 *
 * the sequence may have one (or more?) metadata objects at the beginning.
 * After those, if present, there are zero or more LOG_CONTAINER objects,
 * containing data for all subsequent objects.  An object may be split
 * between LOG_CONTAINER objects, as per
 *
 *    https://gitlab.com/wireshark/wireshark/-/issues/19377#note_1651998569
 *
 * A LOG_CONTAINER object's contents are of the form:
 *
 *    Log container header
 *    Data for contained objects.
 * 
 * The data in a LOG_CONTAINER object may be compressed using zlib.
 */

#define BLF_HEADER_TYPE_DEFAULT                   1
#define BLF_HEADER_TYPE_2                         2
#define BLF_HEADER_TYPE_3                         3


#define BLF_COMPRESSION_NONE                      0
#define BLF_COMPRESSION_ZLIB                      2

#define BLF_TIMESTAMP_RESOLUTION_10US             1
#define BLF_TIMESTAMP_RESOLUTION_1NS              2

typedef struct blf_date {
    uint16_t year;
    uint16_t month;
    uint16_t dayofweek;
    uint16_t day;
    uint16_t hour;
    uint16_t mins;
    uint16_t sec;
    uint16_t ms;
} blf_date_t;

/* BLF File Header */
typedef struct blf_fileheader {
    uint8_t magic[4];               /* magic number - "LOGG" */
    uint32_t header_length;         /* length of the file header */

    uint8_t applications[4];
    uint8_t api[4];

    uint64_t len_compressed;        /* size of the file before uncompressing */
    uint64_t len_uncompressed;

    uint32_t obj_count;             /* number of objects in the file */
    uint32_t obj_read;

    blf_date_t start_date;
    blf_date_t end_date;

    uint32_t length3;
} blf_fileheader_t;

/* BLF Block Header */
typedef struct blf_blockheader {
    uint8_t  magic[4];              /* magic number = "LOBJ" */
    uint16_t header_length;         /* length of header starting with magic */
    uint16_t header_type;           /* header format ? */
    uint32_t object_length;         /* complete length including header */
    uint32_t object_type;
} blf_blockheader_t;

typedef struct blf_logcontainerheader {
    uint16_t compression_method;    /* 0 uncompressed, 2 zlib */
    uint16_t res1;
    uint32_t res2;
    uint32_t uncompressed_size;
    uint32_t res4;
} blf_logcontainerheader_t;

typedef struct blf_logobjectheader {
    uint32_t flags;
    uint16_t client_index;
    uint16_t object_version;
    uint64_t object_timestamp;
} blf_logobjectheader_t;

#define BLF_TS_STATUS_ORIG_TS_VALID     0x01
#define BLF_TS_STATUS_SW_TS             0x02
#define BLF_TS_STATUS_PROTO_SPECIFIC    0x10

typedef struct blf_logobjectheader2 {
    uint32_t flags;
    uint8_t  timestamp_status;
    uint8_t  res1;
    uint16_t object_version;
    uint64_t object_timestamp;
    uint64_t original_timestamp;
} blf_logobjectheader2_t;

typedef struct blf_logobjectheader3 {
    uint32_t flags;
    uint16_t static_size;
    uint16_t object_version;
    uint64_t object_timestamp;
} blf_logobjectheader3_t;


#define BLF_DIR_RX    0
#define BLF_DIR_TX    1
#define BLF_DIR_TX_RQ 2

typedef struct blf_ethernetframeheader {
    uint8_t  src_addr[6];
    uint16_t channel;
    uint8_t  dst_addr[6];
    uint16_t direction;
    uint16_t ethtype;
    uint16_t tpid;
    uint16_t tci;
    uint16_t payloadlength;
    uint64_t res;
} blf_ethernetframeheader_t;

typedef struct blf_ethernetframeheader_ex {
    uint16_t struct_length;
    uint16_t flags;
    uint16_t channel;
    uint16_t hw_channel;
    uint64_t frame_duration;
    uint32_t frame_checksum;
    uint16_t direction;
    uint16_t frame_length;
    uint32_t frame_handle;
    uint32_t error;
} blf_ethernetframeheader_ex_t;

#define BLF_ETHERNET_EX_RES             0x0001
#define BLF_ETHERNET_EX_HARDWARECHANNEL 0x0002
#define BLF_ETHERNET_EX_FRAMEDURATION   0x0004
#define BLF_ETHERNET_EX_FRAMEHANDLE     0x0008

typedef struct blf_ethernet_rxerror {
    uint16_t struct_length;
    uint16_t channel;
    uint16_t direction;
    uint16_t hw_channel;
    uint32_t frame_checksum;
    uint16_t frame_length;  /* Number of valid raw Ethernet data bytes */
    uint32_t error;
} blf_ethernet_rxerror_t;

typedef struct blf_wlanframeheader {
    uint16_t channel;
    uint16_t flags;
    uint8_t  direction;
    uint8_t  radio_channel;
    uint16_t signal_strength;
    uint16_t signal_quality;
    uint16_t frame_length;
    uint32_t res;
} blf_wlanframeheader_t;

/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/CanMessage.h */

/* shared for CAN message and CAN message2 and CANFD message */
#define BLF_CANMESSAGE_FLAG_TX                      0x01
#define BLF_CANMESSAGE_FLAG_NERR                    0x20
#define BLF_CANMESSAGE_FLAG_WU                      0x40
#define BLF_CANMESSAGE_FLAG_RTR                     0x80

/* shared for CAN message and CAN message2*/
typedef struct blf_canmessage {
    uint16_t channel;
    uint8_t  flags;
    uint8_t  dlc;
    uint32_t id;
} blf_canmessage_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/CanMessage2.h */

typedef struct blf_canmessage2_trailer {
    uint32_t frameLength_in_ns;
    uint8_t bitCount;
    uint8_t reserved1;
    uint16_t reserved2;
} blf_canmessage2_trailer_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/CanFdMessage.h */

/* EDL 0: CAN, 1: CAN-FD*/
#define BLF_CANFDMESSAGE_CANFDFLAG_EDL              0x01
#define BLF_CANFDMESSAGE_CANFDFLAG_BRS              0x02
#define BLF_CANFDMESSAGE_CANFDFLAG_ESI              0x04

typedef struct blf_canfdmessage {
    uint16_t channel;
    uint8_t  flags;
    uint8_t  dlc;
    uint32_t id;
    uint32_t frameLength_in_ns;
    uint8_t  arbitration_bit_count;
    uint8_t  canfdflags;
    uint8_t  validDataBytes;
    uint8_t  reservedCanFdMessage1;
    uint32_t reservedCanFdMessage2;
    /* DATA */
    /* uint32_t reservedCanFdMessage3 */
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
    uint8_t  channel;
    uint8_t  dlc;
    uint8_t  validDataBytes;
    uint8_t  txCount;
    uint32_t id;
    uint32_t frameLength_in_ns;
    uint32_t flags;
    uint32_t btrCfgArb;
    uint32_t btrCfgData;
    uint32_t timeOffsetBrsNs;
    uint32_t timeOffsetCrcDelNs;
    uint16_t bitCount;
    uint8_t  dir;
    uint8_t  extDataOffset;
    uint32_t crc;
} blf_canfdmessage64_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/CanErrorFrame.h */

typedef struct blf_canerror {
    uint16_t channel;
    uint16_t length;
} blf_canerror_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/CanErrorFrameExt.h */

#define BLF_CANERROREXT_FLAG_SJA                   0x01
#define BLF_CANERROREXT_FLAG_CANCORE               0x02
#define BLF_CANERROREXT_EXTECC_TX                  0x1000
#define BLF_CANERROREXT_EXTECC_NOT_ACK             0x2000
#define BLF_CANERROREXT_ECC_MEANING_BIT_ERROR      0x0
#define BLF_CANERROREXT_ECC_MEANING_FORM_ERROR     0x1
#define BLF_CANERROREXT_ECC_MEANING_STUFF_ERROR    0x2
#define BLF_CANERROREXT_ECC_MEANING_OTHER_ERROR    0x3
#define BLF_CANERROREXT_ECC_MEANING_CRC_ERROR      0x4
#define BLF_CANERROREXT_ECC_MEANING_ACKDEL_ERROR   0x5
#define BLF_CANERROREXT_ECC_MEANING_OTHER_ERROR2   0x6
#define BLF_CANERROREXT_ECC_MEANING_NACK_ERROR     0x7
#define BLF_CANERROREXT_ECC_MEANING_OVERLOAD       0x8
#define BLF_CANERROREXT_ECC_FDF_BIT_ERROR          0x9

typedef struct blf_canerrorext {
    uint16_t channel;
    uint16_t length;
    uint32_t flags;
    uint8_t  ecc;
    uint8_t  position;
    uint8_t  dlc;
    uint8_t  reserved1;
    uint32_t frameLength_in_ns;
    uint32_t id;
    uint16_t errorCodeExt;
    uint16_t reserved2;
} blf_canerrorext_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/CanFdErrorFrame64.h */

#define BLF_CANERROR64_FLAG_FDF 0x01
#define BLF_CANERROR65_FLAG_BRS 0x02
#define BLF_CANERROR65_FLAG_ESI 0x04

typedef struct blf_canfderror64 {
    uint8_t  channel;
    uint8_t  dlc;
    uint8_t  validDataBytes;
    uint8_t  ecc;
    uint16_t flags;
    uint16_t errorCodeExt;
    uint16_t extFlags;
    uint8_t  extDataOffset;
    uint8_t  reserved1;
    uint32_t id;
    uint32_t frameLength_in_ns;
    uint32_t btrCfgArb;
    uint32_t btrCfgData;
    uint32_t timeOffsetBrsNs;
    uint32_t timeOffsetCrcDelNs;
    uint32_t crc;
    uint16_t errorPosition;
    uint16_t reserved2;
} blf_canfderror64_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/FlexRayData.h */

#define BLF_FLEXRAYDATA_FRAME                       0x01
#define BLF_FLEXRAYDATA_CHANNEL_B                   0x80

typedef struct blf_flexraydata {
    uint16_t channel;
    uint8_t  mux;
    uint8_t  len;
    uint16_t messageId;
    uint16_t crc;
    uint8_t  dir;
    uint8_t  reservedFlexRayData1;
    uint16_t reservedFlexRayData2;
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
    uint16_t channel;
    uint8_t  dir;            /* Flags: 0 RX, 1 TX, 2 TX Req, 3 internal, 4 internal*/
    uint8_t  lowTime;
    uint32_t fpgaTick;
    uint32_t fpgaTickOverflow;
    uint32_t clientIndexFlexRayV6Message;
    uint32_t clusterTime;
    uint16_t frameId;
    uint16_t headerCrc;
    uint16_t frameState;
    uint8_t  length;
    uint8_t  cycle;
    uint8_t  headerBitMask;
    uint8_t  reservedFlexRayV6Message1;
    uint16_t reservedFlexRayV6Message2;
} blf_flexraymessage_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/FlexRayVFrReceiveMsg.h */

#define BLF_FLEXRAYRCVMSG_DIR_RX                  0x01
#define BLF_FLEXRAYRCVMSG_DIR_TX                  0x02
#define BLF_FLEXRAYRCVMSG_DIR_TX_REQ              0x04

#define BLF_FLEXRAYRCVMSG_CHANNELMASK_RES         0x00
#define BLF_FLEXRAYRCVMSG_CHANNELMASK_A           0x01
#define BLF_FLEXRAYRCVMSG_CHANNELMASK_B           0x02
#define BLF_FLEXRAYRCVMSG_CHANNELMASK_AB          0x03

#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_NULL_FRAME    0x00000001
#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_VALID_DATA    0x00000002
#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_SYNC          0x00000004
#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_STARTUP       0x00000008
#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_PAYLOAD_PREAM 0x00000010
#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_RES_20        0x00000020
#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_ERROR         0x00000040
#define BLF_FLEXRAYRCVMSG_FRAME_FLAG_RES_80        0x00000080

typedef struct blf_flexrayrcvmessage {
    uint16_t channel;
    uint16_t version;
    uint16_t channelMask;    /* 0 res, 1 A, 2 B, 3 A+B */
    uint16_t dir;            /* 0 RX, 1 TX, 2 TX Req, 3 internal, 4 internal*/ /* high byte reserved! */
    uint32_t clientIndex;
    uint32_t clusterNo;
    uint16_t frameId;
    uint16_t headerCrc1;
    uint16_t headerCrc2;
    uint16_t payloadLength;
    uint16_t payloadLengthValid;
    uint16_t cycle;          /* high byte reserved! */
    uint32_t tag;
    uint32_t data;
    uint32_t frameFlags;
    uint32_t appParameter;
    /* if ext, skip 40 bytes */
    /* payload bytes */
    /* uint16_t res3 */
    /* uint32_t res4 */
} blf_flexrayrcvmessage_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/FlexRayVFrReceiveMsgEx.h */

/* defines see above BLF_FLEXRAYRCVMSG_* */

typedef struct blf_flexrayrcvmessageex {
    uint16_t channel;
    uint16_t version;
    uint16_t channelMask;    /* 0 res, 1 A, 2 B, 3 A+B */
    uint16_t dir;            /* 0 RX, 1 TX, 2 TX Req, 3 internal, 4 internal*/
    uint32_t clientIndex;
    uint32_t clusterNo;
    uint16_t frameId;
    uint16_t headerCrc1;
    uint16_t headerCrc2;
    uint16_t payloadLength;
    uint16_t payloadLengthValid;
    uint16_t cycle;
    uint32_t tag;
    uint32_t data;
    uint32_t frameFlags;
    uint32_t appParameter;
    uint32_t frameCRC;
    uint32_t frameLengthInNs;
    uint16_t frameId1;
    uint16_t pduOffset;
    uint16_t blfLogMask;
    uint16_t res1;
    uint32_t res2;
    uint32_t res3;
    uint32_t res4;
    uint32_t res5;
    uint32_t res6;
    uint32_t res7;
    /* payload bytes */
} blf_flexrayrcvmessageex_t;


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/LinMessage.h */

typedef struct blf_linmessage {
    uint16_t channel;
    uint8_t  id;
    uint8_t  dlc;
    uint8_t  data[8];
    uint8_t  fsmId;
    uint8_t  fsmState;
    uint8_t  headerTime;
    uint8_t  fullTime;
    uint16_t crc;
    uint8_t  dir;            /* 0 RX, 1 TX Receipt, 2 TX Req */
    uint8_t  res1;
/*  This field is optional and skipping does not hurt us.
    uint32_t res2;
*/
} blf_linmessage_t;

typedef struct blf_linrcverror {
    uint16_t channel;
    uint8_t  id;
    uint8_t  dlc;
    uint8_t  fsmId;
    uint8_t  fsmState;
    uint8_t  headerTime;
    uint8_t  fullTime;
    uint8_t  stateReason;
    uint8_t  offendingByte;
    uint8_t  shortError;
    uint8_t  timeoutDuringDlcDetection;
} blf_linrcverror_t;

typedef struct blf_linsenderror {
    uint16_t channel;
    uint8_t  id;
    uint8_t  dlc;
    uint8_t  fsmId;
    uint8_t  fsmState;
    uint8_t  headerTime;
    uint8_t  fullTime;
} blf_linsenderror_t;

typedef struct blf_linwakeupevent {
    uint16_t    channel;
    uint8_t     signal;
    uint8_t     external;
} blf_linwakeupevent_t;

typedef struct blf_linbusevent {
    uint64_t sof;
    uint32_t eventBaudrate;
    uint16_t channel;
    uint8_t  res1[2];
} blf_linbusevent_t;

typedef struct blf_linsynchfieldevent {
    blf_linbusevent_t   linBusEvent;
    uint64_t            synchBreakLength;
    uint64_t            synchDelLength;
} blf_linsynchfieldevent_t;

typedef struct blf_linmessagedescriptor {
    blf_linsynchfieldevent_t    linSynchFieldEvent;
    uint16_t                    supplierId;             /* LIN 2.0 or higher */
    uint16_t                    messageId;              /* LIN 2.0: message identifier, LIN 2.1: position index as specified in LDF */
    uint8_t                     configuredNodeAddress;  /* LIN 2.0 or higher */
    uint8_t                     id;
    uint8_t                     dlc;
    uint8_t                     checksumModel;
} blf_linmessagedescriptor_t;

typedef struct blf_lindatabytetimestampevent {
    blf_linmessagedescriptor_t  linMessageDescriptor;
    uint64_t                    databyteTimestamps[9];  /* Byte 0: Timestamp of last header byte, Bytes 1-9: Timestamps of data bytes 1-8 */
} blf_lindatabytetimestampevent_t;

typedef struct blf_linmessage2 {
    blf_lindatabytetimestampevent_t linDataByteTimestampEvent;
    uint8_t                         data[8];
    uint16_t                        crc;
    uint8_t                         dir;        /* 0 RX, 1 TX Receipt, 2 TX Req */
    uint8_t                         simulated;  /* 0 Real frame, 1 Simulated frame */
    uint8_t                         isEtf;      /* 0 Not event triggered frame, 1 Event triggered frame */
    uint8_t                         eftAssocIndex;
    uint8_t                         eftAssocEftId;
    uint8_t                         fsmId;      /* Obsolete */
    uint8_t                         fsmState;   /* Obsolete */
    uint8_t                         res1[3];
/*  These fields are optional and skipping does not hurt us.
    uint32_t                        respBaudrate;
    double                          exactHeaderBaudrate;
    uint32_t                        earlyStopBitOffset;
    uint32_t                        earlyStopBitOffsetResponse;
*/
} blf_linmessage2_t;

typedef struct blf_lincrcerror2 {
    blf_lindatabytetimestampevent_t linDataByteTimestampEvent;
    uint8_t                         data[8];
    uint16_t                        crc;
    uint8_t                         dir;        /* 0 RX, 1 TX Receipt, 2 TX Req */
    uint8_t                         fsmId;      /* Obsolete */
    uint8_t                         fsmState;   /* Obsolete */
    uint8_t                         simulated;  /* 0 Real frame, 1 Simulated frame */
    uint8_t                         res1[2];
/*  These fields are optional and skipping does not hurt us.
    uint32_t                        respBaudrate;
    uint8_t                         res2[4];
    double                          exactHeaderBaudrate;
    uint32_t                        earlyStopBitOffset;
    uint32_t                        earlyStopBitOffsetResponse;
*/
} blf_lincrcerror2_t;

typedef struct blf_linrcverror2 {
    blf_lindatabytetimestampevent_t linDataByteTimestampEvent;
    uint8_t                         data[8];
    uint8_t                         fsmId;      /* Obsolete */
    uint8_t                         fsmState;   /* Obsolete */
    uint8_t                         stateReason;
    uint8_t                         offendingByte;
    uint8_t                         shortError;
    uint8_t                         timeoutDuringDlcDetection;
    uint8_t                         isEtf;
    uint8_t                         hasDataBytes;
/*  These fields are optional and skipping does not hurt us.
    uint32_t                        respBaudrate;
    uint8_t                         res[4];
    double                          exactHeaderBaudrate;
    uint32_t                        earlyStopBitOffset;
    uint32_t                        earlyStopBitOffsetResponse;
*/
} blf_linrcverror2_t;

typedef struct blf_linsenderror2 {
    blf_linmessagedescriptor_t  linMessageDescriptor;
    uint64_t                    eoh;
    uint8_t                     isEtf;
    uint8_t                     fsmId;      /* Obsolete */
    uint8_t                     fsmState;   /* Obsolete */
    uint8_t                     res1;
/*  These fields are optional and skipping does not hurt us.
    uint8_t                     res2[4];
    double                      exactHeaderBaudrate;
    uint32_t                    earlyStopBitOffset;
*/
} blf_linsenderror2_t;

typedef struct blf_linwakeupevent2 {
    blf_linbusevent_t   linBusEvent;
    uint8_t             lengthInfo; /* Wake-up lenght: 0 = OK; 1 = Too short; 2 = Too long. */
    uint8_t             signal;
    uint8_t             external;
    uint8_t             res;
} blf_linwakeupevent2_t;

typedef struct blf_linsleepmodeevent {
    uint16_t    channel;
    uint8_t     reason;
    uint8_t     flags;
} blf_linsleepmodeevent_t;

#define BLF_LIN_WU_SLEEP_REASON_START_STATE         0   /* Initial state of the interface */
#define BLF_LIN_SLEEP_REASON_GO_TO_SLEEP_FRAME      1
#define BLF_LIN_SLEEP_REASON_BUS_IDLE_TIMEOUT       2
#define BLF_LIN_SLEEP_REASON_SILENT_SLEEPMODE_CMD   3   /* Command to shorten bus idle timeout */
#define BLF_LIN_WU_REASON_EXTERNAL_WAKEUP_SIG       9
#define BLF_LIN_WU_REASON_INTERNAL_WAKEUP_SIG       10
#define BLF_LIN_WU_REASON_BUS_TRAFFIC               11
#define BLF_LIN_NO_SLEEP_REASON_BUS_TRAFFIC         18  /* LIN hardware does not go into Sleep mode in spite of request to do so */


/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/AppText.h */

typedef struct blf_apptext {
    uint32_t source;
    uint32_t reservedAppText1;
    uint32_t textLength;
    uint32_t reservedAppText2;
} blf_apptext_t;

#define BLF_APPTEXT_COMMENT     0x00000000
#define BLF_APPTEXT_CHANNEL     0x00000001
#define BLF_APPTEXT_METADATA    0x00000002
#define BLF_APPTEXT_ATTACHMENT  0x00000003
#define BLF_APPTEXT_TRACELINE   0x00000004
#define BLF_APPTEXT_CONT        0x000000FE
#define BLF_APPTEXT_FAILED      0x000000FF

#define BLF_APPTEXT_XML_GENERAL     0x01
#define BLF_APPTEXT_XML_CHANNELS    0x02
#define BLF_APPTEXT_XML_IDENTITY    0x03

#define BLF_BUSTYPE_CAN 1
#define BLF_BUSTYPE_LIN 5
#define BLF_BUSTYPE_MOST 6
#define BLF_BUSTYPE_FLEXRAY 7
#define BLF_BUSTYPE_J1708 9
#define BLF_BUSTYPE_ETHERNET 11
#define BLF_BUSTYPE_WLAN 13
#define BLF_BUSTYPE_AFDX 14

/* see https://bitbucket.org/tobylorenz/vector_blf/src/master/src/Vector/BLF/EthernetStatus.h */
typedef struct blf_ethernet_status {
    uint16_t channel;
    uint16_t flags;
    uint8_t  linkStatus;
    uint8_t  ethernetPhy;
    uint8_t  duplex;
    uint8_t  mdi;
    uint8_t  connector;
    uint8_t  clockMode;
    uint8_t  pairs;
    uint8_t  hardwareChannel;
    uint32_t bitrate;
/* Starting from version 1
    uint64_t linkUpDuration;    // In nanoseconds
*/
} blf_ethernet_status_t;

#define BLF_ETH_STATUS_LINKSTATUS       0x0001
#define BLF_ETH_STATUS_BITRATE          0x0002
#define BLF_ETH_STATUS_ETHERNETPHY      0x0004
#define BLF_ETH_STATUS_DUPLEX           0x0008
#define BLF_ETH_STATUS_MDITYPE          0x0010
#define BLF_ETH_STATUS_CONNECTOR        0x0020
#define BLF_ETH_STATUS_CLOCKMODE        0x0040
#define BLF_ETH_STATUS_BRPAIR           0x0080
#define BLF_ETH_STATUS_HARDWARECHANNEL  0x0100
#define BLF_ETH_STATUS_LINKUPDURATION   0x0200

typedef struct blf_ethernet_phystate {
    uint16_t    channel;
    uint16_t    flags;
    uint8_t     phyState;
    uint8_t     phyEvent;
    uint8_t     hardwareChannel;
    uint8_t     res1;
} blf_ethernet_phystate_t;

#define BLF_PHY_STATE_PHYSTATE          0x0001
#define BLF_PHY_STATE_PHYEVENT          0x0002
#define BLF_PHY_STATE_HARDWARECHANNEL   0x0004


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
#define BLF_OBJTYPE_RESERVED5                   115
#define BLF_OBJTYPE_RESERVED6                   116
#define BLF_OBJTYPE_RESERVED7                   117
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
#define BLF_OBJTYPE_DISTRIBUTED_OBJECT_CHANGE   132
#define BLF_OBJTYPE_ETHERNET_PHY_STATE          133

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
