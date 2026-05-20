/* packet-ecatmb.h
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef _PACKET_ECATMAILBOX_H_
#define _PACKET_ECATMAILBOX_H_

#include <ws_diag_control.h>
DIAG_OFF_PEDANTIC

/* Ensure the same data layout for all platforms */

/**
 * @brief IEEE 802.3 Ethernet MAC address (6 octets).
 */
typedef struct TETHERNET_ADDRESS
{
    uint8_t b[6]; /**< Six octets of the MAC address in network byte order. */
} ETHERNET_ADDRESS, *PETHERNET_ADDRESS;

/** @brief Wire-size of #ETHERNET_ADDRESS in bytes. */
#define ETHERNET_ADDRESS_LEN ((int) sizeof(ETHERNET_ADDRESS))


/* EtherCAT mailbox protocol type identifiers */
#define ETHERCAT_MBOX_TYPE_ADS  1  /**< Mailbox type: AMS/ADS — #AmsHead follows. */
#define ETHERCAT_MBOX_TYPE_EOE  2  /**< Mailbox type: Ethernet over EtherCAT — #ETHERCAT_EOE_HEADER follows. */
#define ETHERCAT_MBOX_TYPE_COE  3  /**< Mailbox type: CANopen over EtherCAT — #ETHERCAT_COE_HEADER follows. */
#define ETHERCAT_MBOX_TYPE_FOE  4  /**< Mailbox type: File Access over EtherCAT — #ETHERCAT_FOE_HEADER follows. */
#define ETHERCAT_MBOX_TYPE_SOE  5  /**< Mailbox type: Servo Drive Profile over EtherCAT — #ETHERCAT_SOE_HEADER follows. */
#define ETHERCAT_MBOX_TYPE_VOE  15 /**< Mailbox type: Vendor-specific over EtherCAT — #ETHERCAT_VOE_HEADER follows. */


/**
 * @brief Union providing bit-field and raw access to the EtherCAT mailbox control word.
 */
typedef union tMbxHeaderControlUnion
{
    uint16_t Control; /**< Raw 16-bit mailbox control word. */
    struct
    {
        uint16_t Channel     : 6; /**< Optional communication channel index (default = 0). */
        uint16_t Priority    : 2; /**< Optional communication priority (default = 0; higher = more urgent). */
        uint16_t Type        : 4; /**< Mailbox protocol type; see @c ETHERCAT_MBOX_TYPE_* values. */
        uint16_t Counter     : 3; /**< Sequence counter for duplicate detection (0 = counter not used). */
        uint16_t Unsupported : 1; /**< Set by the slave when the requested protocol is not supported. */
    } v;                          /**< Structured bit-field access. */
} MbxHeaderControlUnion;


/**
 * @brief EtherCAT mailbox header, common to all mailbox protocol frames.
 */
typedef struct TETHERCAT_MBOX_HEADER
{
    uint16_t              Length;       /**< Number of bytes of mailbox data following this header. */
    uint16_t              Address;      /**< Slave→Master: physical address of the destination station;
                                         *   Master→Slave: physical address of the source station (0 = master). */
    MbxHeaderControlUnion aControlUnion; /**< Channel, priority, type, counter, and unsupported-protocol flag. */
} ETHERCAT_MBOX_HEADER, *PETHERCAT_MBOX_HEADER;

#define ETHERCAT_MBOX_HEADER_LEN ((int) sizeof(ETHERCAT_MBOX_HEADER))

/* EoE*/
#define ETHERNET_FRAMENO_MASK         0x0000000F

#define EOE_TYPE_FRAME_FRAG    0 /* ETHERCAT_EOE_HEADER followed by frame fragment (ETHERCAT_EOE_TIMESTAMP may included) */
#define EOE_TYPE_TIMESTAMP_RES 1 /* ETHERCAT_EOE_HEADER followed by ETHERCAT_EOE_TIMESTAMP */
#define EOE_TYPE_INIT_REQ      2 /* ETHERCAT_EOE_HEADER followed by ETHERCAT_EOE_INIT */
#define EOE_TYPE_INIT_RES      3 /* ETHERCAT_EOE_HEADER */
#define EOE_TYPE_MACFILTER_REQ 4 /* ETHERCAT_EOE_HEADER followed by ETHERCAT_EOE_MACFILTER */
#define EOE_TYPE_MACFILTER_RES 5 /* ETHERCAT_EOE_HEADER */

#define EOE_RESULT_NOERROR                  0x0000
#define EOE_RESULT_UNSPECIFIED_ERROR        0x0001
#define EOE_RESULT_UNSUPPORTED_TYPE         0x0002
#define EOE_RESULT_NO_IP_SUPPORT            0x0201
#define EOE_RESULT_NO_MACFILTERMASK_SUPPORT 0x0401


/*typedef struct TETHERCAT_EOE_INIT
{
   uint32_t         ContainsMacAddr        :1;
   uint32_t         ContainsIpAddr         :1;
   uint32_t         ContainsSubnetMask     :1;
   uint32_t         ContainsDefaultGateway :1;
   uint32_t         ContainsDnsServer      :1;
   uint32_t         ContainsDnsName        :1;
   uint32_t         Reserved               :26;
   ETHERNET_ADDRESS MacAddr;
   uint32_t         IpAddr;
   uint32_t         SubnetMask;
   uint32_t         DefaultGateway;
   uint32_t         DnsServer;
   char             DnsName[32];
} ETHERCAT_EOE_INIT, *PETHERCAT_EOE_INIT;*/
#define ETHERCAT_EOE_INIT_LEN 58 /*sizeof(ETHERCAT_EOE_INIT)*/

/**
 * @brief Union providing bit-field and raw access to EoE MAC filter options.
 */
typedef union tEoeMacFilterOptionsUnion
{
    struct
    {
        uint16_t MacFilterCount     : 4; /**< Number of valid MAC address filter entries (0–15). */
        uint16_t MacFilterMaskCount : 2; /**< Number of valid MAC address filter mask entries (0–3). */
        uint16_t Reserved1          : 1; /**< Reserved; must be zero. */
        uint16_t NoBroadcasts       : 1; /**< Non-zero to suppress forwarding of broadcast frames. */
        uint16_t Reserved2          : 8; /**< Reserved; must be zero. */
    } v;                                 /**< Structured bit-field access. */
    uint16_t Options;                    /**< Raw 16-bit options word. */
} EoeMacFilterOptionsUnion;


/**
 * @brief EtherCAT EoE (Ethernet over EtherCAT) MAC filter configuration.
 */
typedef struct TETHERCAT_EOE_MACFILTER
{
    EoeMacFilterOptionsUnion anEoeMacFilterOptionsUnion; /**< Filter count, mask count, and option flags. */
    ETHERNET_ADDRESS MacFilter[16];                      /**< Array of up to 16 MAC address filter entries. */
    ETHERNET_ADDRESS MacFilterMask[4];                   /**< Array of up to 4 MAC address masks applied to @c MacFilter entries. */
} ETHERCAT_EOE_MACFILTER;

/** @brief Wire-size of #ETHERCAT_EOE_MACFILTER in bytes. */
#define ETHERCAT_EOE_MACFILTER_LEN ((int) sizeof(ETHERCAT_EOE_MACFILTER))


/**
 * @brief EtherCAT EoE timestamp record.
 */
typedef struct TETHERCAT_EOE_TIMESTAMP
{
    uint32_t TimeStamp; /**< 32-bit EoE timestamp value in nanoseconds. */
} ETHERCAT_EOE_TIMESTAMP;

/** @brief Wire-size of #ETHERCAT_EOE_TIMESTAMP in bytes. */
#define ETHERCAT_EOE_TIMESTAMP_LEN ((int) sizeof(ETHERCAT_EOE_TIMESTAMP))


/**
 * @brief Union providing typed access to the EoE header data word, interpreted by message type.
 */
typedef union tEoeHeaderDataUnion
{
    struct
    {                                /**< Valid for @c EOE_TYPE_FRAME_FRAG and @c EOE_TYPE_TIMESTAMP_RES. */
        uint16_t Fragment     : 6;   /**< Fragment sequence number within the current Ethernet frame (FRAME_FRAG only). */
        uint16_t OffsetBuffer : 6;   /**< If @c Fragment != 0: byte offset of this fragment × 32.
                                      *   If @c Fragment == 0: total buffer size × 32 (FRAME_FRAG only). */
        uint16_t FrameNo      : 4;   /**< Frame number correlating fragments to a single Ethernet frame. */
    } v;                             /**< Structured bit-field access for fragment and timestamp responses. */
    uint16_t Result;                 /**< Result/status code for @c EOE_TYPE_INIT_RES and @c EOE_TYPE_MACFILTER_RES. */
} EoeHeaderDataUnion;


/**
 * @brief Union providing bit-field and raw access to the EoE header info word.
 */
typedef union tEoeHeaderInfoUnion
{
    struct
    {
        uint16_t Type               : 4; /**< EoE message type identifier (e.g. FRAME_FRAG, INIT_REQ, MACFILTER_REQ). */
        uint16_t PortAssign         : 4; /**< Virtual port assignment (0 = unspecified, 1 = port 1). */
        uint16_t LastFragment       : 1; /**< Non-zero if this is the last fragment of the Ethernet frame (FRAME_FRAG only). */
        uint16_t TimeStampAppended  : 1; /**< Non-zero if a 32-bit timestamp is appended after the last fragment (FRAME_FRAG with LastFragment = 1 only). */
        uint16_t TimeStampRequested : 1; /**< Non-zero if a timestamp response is requested by the sender (FRAME_FRAG only). */
        uint16_t Reserved           : 5; /**< Reserved; must be zero. */
    } v;                                 /**< Structured bit-field access. */
    uint16_t Info;                       /**< Raw 16-bit info word. */
} EoeHeaderInfoUnion;


/**
 * @brief EtherCAT EoE (Ethernet over EtherCAT) mailbox header.
 */
typedef struct TETHERCAT_EOE_HEADER
{
    EoeHeaderInfoUnion anEoeHeaderInfoUnion; /**< Info word carrying the message type, port, and fragment control flags. */
    EoeHeaderDataUnion anEoeHeaderDataUnion; /**< Data word carrying fragment/frame numbers or a result code. */
} ETHERCAT_EOE_HEADER, *PETHERCAT_EOE_HEADER;

/** @brief Wire-size of #ETHERCAT_EOE_HEADER in bytes. */
#define ETHERCAT_EOE_HEADER_LEN ((int) sizeof(ETHERCAT_EOE_HEADER))

/* CANopen*/
#define ETHERCAT_COE_TYPE_EMERGENCY 1
#define ETHERCAT_COE_TYPE_SDOREQ    2
#define ETHERCAT_COE_TYPE_SDORES    3
#define ETHERCAT_COE_TYPE_TXPDO     4
#define ETHERCAT_COE_TYPE_RXPDO     5
#define ETHERCAT_COE_TYPE_TXPDO_RTR 6 /* Remote transmission request of TXPDO (master requested)*/
#define ETHERCAT_COE_TYPE_RXPDO_RTR 7 /* Remote transmission request of RXPDO (slave requested) */
#define ETHERCAT_COE_TYPE_SDOINFO   8

/**
 * @brief EtherCAT CoE (CANopen over EtherCAT) mailbox header.
 */
typedef union TETHERCAT_COE_HEADER
{
    struct
    {
        uint16_t Number   : 9; /**< CANopen number field (e.g. PDO number or SDO counter). */
        uint16_t Reserved : 3; /**< Reserved; must be zero. */
        uint16_t Type     : 4; /**< CANopen message type (e.g. SDO, PDO, NMT, EMCY). */
    } v;                       /**< Structured bit-field access. */
    uint16_t header;           /**< Raw 16-bit CoE header word. */
} ETHERCAT_COE_HEADER, *PETHERCAT_COE_HEADER;

/** @brief Wire-size of #ETHERCAT_COE_HEADER in bytes. */
#define ETHERCAT_COE_HEADER_LEN ((int) sizeof(ETHERCAT_COE_HEADER))


/**
 * @brief Union providing per-service-command bit-field access to the SDO command specifier byte.
 *
 * Exactly one member is valid per SDO message, selected by the service type
 * (Ccs/Scs field value and transfer direction).
 */
typedef union tSdoHeaderUnion
{
    struct
    {   /* Initiate Download Request (Ccs = 1) */
        uint8_t SizeInd   : 1; /**< Size indicator: non-zero if @c Size is valid. */
        uint8_t Expedited : 1; /**< Expedited transfer flag: non-zero if data fits in this frame. */
        uint8_t Size      : 2; /**< Number of bytes in @c Data that do NOT contain data (expedited only). */
        uint8_t Complete  : 1; /**< Complete access flag: non-zero to access all sub-indices at once. */
        uint8_t Ccs       : 3; /**< Client command specifier; must be 1 for Initiate Download Request. */
    } Idq;

    struct
    {   /* Initiate Download Response (Scs = 3) */
        uint8_t Reserved : 5; /**< Reserved; must be zero. */
        uint8_t Scs      : 3; /**< Server command specifier; must be 3 for Initiate Download Response. */
    } Ids;

    struct
    {   /* Download Segment Request (Ccs = 0) */
        uint8_t LastSeg : 1; /**< Last-segment flag: non-zero if this is the final segment. */
        uint8_t Size    : 3; /**< Number of bytes in the segment that do NOT contain data. */
        uint8_t Toggle  : 1; /**< Toggle bit; alternates between 0 and 1 for each successive segment. */
        uint8_t Ccs     : 3; /**< Client command specifier; must be 0 for Download Segment Request. */
    } Dsq;

    struct
    {   /* Download Segment Response (Scs = 1) */
        uint8_t Reserved : 4; /**< Reserved; must be zero. */
        uint8_t Toggle   : 1; /**< Toggle bit; must match the toggle bit of the corresponding request. */
        uint8_t Scs      : 3; /**< Server command specifier; must be 1 for Download Segment Response. */
    } Dss;

    struct
    {   /* Initiate Upload Request (Ccs = 2) */
        uint8_t Reserved : 4; /**< Reserved; must be zero. */
        uint8_t Complete : 1; /**< Complete access flag: non-zero to access all sub-indices at once. */
        uint8_t Ccs      : 3; /**< Client command specifier; must be 2 for Initiate Upload Request. */
    } Iuq;

    struct
    {   /* Initiate Upload Response (Scs = 2) */
        uint8_t SizeInd   : 1; /**< Size indicator: non-zero if @c Size is valid. */
        uint8_t Expedited : 1; /**< Expedited transfer flag: non-zero if data fits in this frame. */
        uint8_t Size      : 2; /**< Number of bytes in @c Data that do NOT contain data (expedited only). */
        uint8_t Complete  : 1; /**< Complete access flag: non-zero if all sub-indices are included. */
        uint8_t Scs       : 3; /**< Server command specifier; must be 2 for Initiate Upload Response. */
    } Ius;

    struct
    {   /* Upload Segment Request (Ccs = 3) */
        uint8_t Reserved : 4; /**< Reserved; must be zero. */
        uint8_t Toggle   : 1; /**< Toggle bit; alternates between 0 and 1 for each successive segment. */
        uint8_t Ccs      : 3; /**< Client command specifier; must be 3 for Upload Segment Request. */
    } Usq;

    struct
    {   /* Upload Segment Response (Scs = 0) */
        uint8_t LastSeg : 1; /**< Last-segment flag: non-zero if this is the final segment. */
        uint8_t Bytes   : 3; /**< Number of bytes in the segment that do NOT contain data. */
        uint8_t Toggle  : 1; /**< Toggle bit; must match the toggle bit of the corresponding request. */
        uint8_t Scs     : 3; /**< Server command specifier; must be 0 for Upload Segment Response. */
    } Uss;

    struct
    {   /* Abort Transfer (Ccs = 4) */
        uint8_t Reserved : 5; /**< Reserved; must be zero. */
        uint8_t Ccs      : 3; /**< Client command specifier; must be 4 for Abort Transfer. */
    } Abt;

    uint8_t CS; /**< Raw command specifier byte. */
} SdoHeaderUnion;


/**
 * @brief EtherCAT CoE SDO (Service Data Object) header.
 */
typedef struct TETHERCAT_SDO_HEADER
{
    SdoHeaderUnion anSdoHeaderUnion; /**< Command specifier byte; interpretation depends on the SDO service type. */
    uint16_t       Index;            /**< Object dictionary index of the object being accessed. */
    uint8_t        SubIndex;         /**< Sub-index within the object, or 0 for complete access. */
    uint32_t       Data;             /**< Expedited data, data size, or abort code depending on the command. */
} ETHERCAT_SDO_HEADER, *PETHERCAT_SDO_HEADER;

#define ETHERCAT_SDO_HEADER_LEN  8 /* sizeof(ETHERCAT_SDO_HEADER)*/

#define SDO_CCS_DOWNLOAD_SEGMENT  0
#define SDO_CCS_INITIATE_DOWNLOAD 1
#define SDO_CCS_INITIATE_UPLOAD   2
#define SDO_CCS_UPLOAD_SEGMENT    3
#define SDO_CCS_ABORT_TRANSFER    4

#define SDO_SCS_UPLOAD_SEGMENT    0
#define SDO_SCS_DOWNLOAD_SEGMENT  1
#define SDO_SCS_INITIATE_UPLOAD   2
#define SDO_SCS_INITIATE_DOWNLOAD 3

/* CoE SDO Information */
#define ECAT_COE_INFO_OPCODE_LIST_Q  1
#define ECAT_COE_INFO_OPCODE_LIST_S  2
#define ECAT_COE_INFO_OPCODE_OBJ_Q   3
#define ECAT_COE_INFO_OPCODE_OBJ_S   4
#define ECAT_COE_INFO_OPCODE_ENTRY_Q 5
#define ECAT_COE_INFO_OPCODE_ENTRY_S 6
#define ECAT_COE_INFO_OPCODE_ERROR_S 7

#define ECAT_COE_INFO_LIST_TYPE_LENGTH 0
#define ECAT_COE_INFO_LIST_TYPE_ALL    1
#define ECAT_COE_INFO_LIST_TYPE_PDOMAP 2
#define ECAT_COE_INFO_LIST_TYPE_BACKUP 3

#define ECAT_COE_INFO_OBJCODE_NULL      0
#define ECAT_COE_INFO_OBJCODE_DOMAIN    2
#define ECAT_COE_INFO_OBJCODE_DEFTYPE   5
#define ECAT_COE_INFO_OBJCODE_DEFSTRUCT 6
#define ECAT_COE_INFO_OBJCODE_VAR       7
#define ECAT_COE_INFO_OBJCODE_ARRAY     8
#define ECAT_COE_INFO_OBJCODE_RECORD    9

#define ECAT_COE_INFO_OBJCAT_OPTIONAL  0
#define ECAT_COE_INFO_OBJCAT_MANDATORY 1

#define ECAT_COE_INFO_OBJACCESS_RO 0x07
#define ECAT_COE_INFO_OBJACCESS_RW 0x3f

/**
 * @brief EtherCAT SDO Information list request/response payload.
 */
typedef struct TETHERCAT_SDO_INFO_LIST
{
    uint16_t ListType;    /**< List type identifier; see @c SDO_INFO_LIST_TYPE_* values. */
    struct
    {
        uint16_t Index[1]; /**< Flexible array of object indices returned in the response. */
    } Res;                 /**< Response payload containing the object index list. */
} ETHERCAT_SDO_INFO_LIST;


/**
 * @brief EtherCAT SDO Information object description payload.
 */
typedef struct TETHERCAT_SDO_INFO_OBJ
{
    uint16_t Index; /**< Object index being described. */
    struct
    {
        uint16_t DataType;    /**< Data type index of the object (refer to CoE data type index table). */
        uint8_t  MaxSubIndex; /**< Highest sub-index present in this object. */
        uint8_t  ObjCode;     /**< Object code as defined in DS 301 Table 37 (e.g. VAR, ARRAY, RECORD). */
        char     Name[1];     /**< Flexible array holding the null-terminated object name string. */
    } Res;                    /**< Response payload with object metadata and name. */
} ETHERCAT_SDO_INFO_OBJ;


/**
 * @brief EtherCAT SDO Information entry description payload.
 */
typedef struct TETHERCAT_SDO_INFO_ENTRY
{
    uint16_t Index;     /**< Object index of the entry being described. */
    uint8_t  SubIdx;    /**< Sub-index of the entry within the object. */
    uint8_t  ValueInfo; /**< Bitmask of which optional fields are present in @c Res:
                         *   bit 0 = ObjAccess, bit 1 = ObjCategory, bit 2 = PdoMapping,
                         *   bit 3 = UnitType, bit 4 = DefaultValue, bit 5 = MinValue,
                         *   bit 6 = MaxValue. */
    struct
    {
        uint16_t DataType;  /**< Data type index of this entry (refer to CoE data type index table). */
        uint16_t BitLen;    /**< Bit length of the entry value. */
        uint16_t ObjAccess; /**< Access rights bitmask: bit 0 = read, bit 1 = write, bit 2 = const,
                             *   bit 3 = PRE-OP, bit 4 = SAFE-OP, bit 5 = OP. */
    } Res;                  /**< Response payload with entry type and access metadata. */
} ETHERCAT_SDO_INFO_ENTRY;


/**
 * @brief EtherCAT SDO Information error response payload.
 */
typedef struct TETHERCAT_SDO_INFO_ERROR
{
    uint32_t ErrorCode;    /**< SDO abort/error code identifying the failure reason. */
    char     ErrorText[1]; /**< Flexible array holding the null-terminated error description string. */
} ETHERCAT_SDO_INFO_ERROR;


/**
 * @brief Union providing typed access to all SDO Information payload variants.
 */
typedef union tSdoInfoUnion
{
    ETHERCAT_SDO_INFO_LIST  List;    /**< List request/response payload. */
    ETHERCAT_SDO_INFO_OBJ   Obj;     /**< Object description payload. */
    ETHERCAT_SDO_INFO_ENTRY Entry;   /**< Entry description payload. */
    ETHERCAT_SDO_INFO_ERROR Error;   /**< Error response payload. */
    uint8_t                 Data[1]; /**< Raw byte access to the payload. */
} SdoInfoUnion;


/**
 * @brief Union providing bit-field and byte-level access to the SDO Information control octet.
 */
typedef union tSdoControlUnion
{
    struct
    {
        uint8_t OpCode     : 7; /**< SDO Information operation code; see @c SDO_INFO_TYPE_* values. */
        uint8_t InComplete : 1; /**< More-follows flag: non-zero if additional fragments are pending. */
    } v;                        /**< Structured bit-field access. */
    uint8_t Control;            /**< Raw control byte. */
} SdoControlUnion;


/**
 * @brief EtherCAT SDO Information mailbox header.
 */
typedef struct TETHERCAT_SDO_INFO_HEADER
{
    SdoControlUnion anSdoControlUnion; /**< Control byte carrying the opcode and more-follows flag. */
    uint8_t         Reserved;          /**< Reserved; must be zero. */
    uint16_t        FragmentsLeft;     /**< Number of remaining fragments in a multi-fragment transfer. */
    SdoInfoUnion    anSdoInfoUnion;    /**< Payload interpreted according to @c anSdoControlUnion.v.OpCode. */
} ETHERCAT_SDO_INFO_HEADER, *PETHERCAT_SDO_INFO_HEADER;

/** @brief Wire offset to the start of the SDO Info list response data (list request length). */
#define ETHERCAT_SDO_INFO_LISTREQ_LEN 6 /*offsetof(ETHERCAT_SDO_INFO_HEADER, anSdoInfoUnion.List.Res)*/


/* FoE (File Access over EtherCAT) — OpMode values */
#define ECAT_FOE_OPMODE_RRQ  1 /**< FoE opmode: Read Request. */
#define ECAT_FOE_OPMODE_WRQ  2 /**< FoE opmode: Write Request. */
#define ECAT_FOE_OPMODE_DATA 3 /**< FoE opmode: Data packet. */
#define ECAT_FOE_OPMODE_ACK  4 /**< FoE opmode: Acknowledge. */
#define ECAT_FOE_OPMODE_ERR  5 /**< FoE opmode: Error. */
#define ECAT_FOE_OPMODE_BUSY 6 /**< FoE opmode: Busy (slave not ready). */

/* FoE error codes */
#define ECAT_FOE_ERRCODE_NOTDEFINED     0 /**< FoE error: Not defined / unspecified. */
#define ECAT_FOE_ERRCODE_NOTFOUND       1 /**< FoE error: File not found. */
#define ECAT_FOE_ERRCODE_ACCESS         2 /**< FoE error: Access denied. */
#define ECAT_FOE_ERRCODE_DISKFULL       3 /**< FoE error: Disk full. */
#define ECAT_FOE_ERRCODE_ILLEAGAL       4 /**< FoE error: Illegal operation. */
#define ECAT_FOE_ERRCODE_PACKENO        5 /**< FoE error: Incorrect packet number. */
#define ECAT_FOE_ERRCODE_EXISTS         6 /**< FoE error: File already exists. */
#define ECAT_FOE_ERRCODE_NOUSER         7 /**< FoE error: No such user. */
#define ECAT_FOE_ERRCODE_BOOTSTRAPONLY  8 /**< FoE error: Operation only permitted in Bootstrap state. */
#define ECAT_FOE_ERRCODE_NOTINBOOTSTRAP 9 /**< FoE error: Operation not permitted in Bootstrap state. */


/**
 * @brief Union providing typed access to the FoE header data word, interpreted by @c OpMode.
 */
typedef union tFoeHeaderDataUnion
{
    uint32_t FileLength; /**< Total file length in bytes for RRQ/WRQ; 0 if unknown. */
    struct
    {
        uint16_t PacketNo;  /**< Sequential packet number for DATA and ACK frames. */
        uint16_t Reserved2; /**< Reserved; must be zero (DATA, ACK). */
    } v;                    /**< Structured access for DATA and ACK opcodes. */
    uint32_t ErrorCode;     /**< FoE error code for ERR frames; see @c ECAT_FOE_ERRCODE_* values. */
    struct
    {
        uint16_t Done;   /**< Number of bytes already transferred (BUSY). */
        uint16_t Entire; /**< Total number of bytes to be transferred (BUSY). */
    } v2;                /**< Structured access for BUSY opcode progress reporting. */
} FoeHeaderDataUnion;


/**
 * @brief EtherCAT FoE (File Access over EtherCAT) mailbox header.
 *
 * Immediately followed in the mailbox by a mode-dependent payload:
 * a file name string (RRQ, WRQ), raw data bytes (DATA), or an error
 * description string (ERR).
 */
typedef struct TETHERCAT_FOE_HEADER
{
    uint8_t            OpMode;    /**< FoE operation mode; see @c ECAT_FOE_OPMODE_* values. */
    uint8_t            Reserved1; /**< Reserved; must be zero. */
    FoeHeaderDataUnion aFoeHeaderDataUnion; /**< Mode-specific data word (file length, packet number, error code, or progress). */
    /*   typedef union tMailBoxDataUnion
    {
    char      Name[]        (RRQ, WRQ)  rest of mailbox data
    uint8_t   Data[]        (DATA)      rest of mailbox data
    char      ErrorText[]   (ERR)       rest of mailbox data
    } MailBoxDataUnion; */
} ETHERCAT_FOE_HEADER, *PETHERCAT_FOE_HEADER;

/** @brief Wire-size of #ETHERCAT_FOE_HEADER in bytes (sizeof avoided due to potential padding). */
#define ETHERCAT_FOE_HEADER_LEN 6 /*sizeof(ETHERCAT_FOE_HEADER)*/


/**
 * @brief EtherCAT firmware update command header.
 */
typedef struct
{
    uint16_t Cmd;       /**< Firmware update command identifier. */
    uint16_t Size;      /**< Size in bytes of the data payload following this header. */
    uint16_t AddressLW; /**< Low word of the target flash/memory address. */
    uint16_t AddressHW; /**< High word of the target flash/memory address. */
} TEFWUPDATE_HEADER;

/* SoE (Servo Drive Profile over EtherCAT) */
#define ECAT_SOE_OPCODE_RRQ 1 /**< SoE opcode: Read Request. */
#define ECAT_SOE_OPCODE_RRS 2 /**< SoE opcode: Read Response. */
#define ECAT_SOE_OPCODE_WRQ 3 /**< SoE opcode: Write Request. */
#define ECAT_SOE_OPCODE_WRS 4 /**< SoE opcode: Write Response. */
#define ECAT_SOE_OPCODE_NFC 5 /**< SoE opcode: Notification (command changed notification). */


/**
 * @brief Union providing bit-field and byte-level access to the SoE header control and element fields.
 */
typedef union tSoeHeaderControlUnion
{
    struct
    {
        uint8_t OpCode     : 3; /**< Operation code; see @c ECAT_SOE_OPCODE_* values (0 = unused). */
        uint8_t InComplete : 1; /**< More-follows flag: non-zero if additional fragments are pending. */
        uint8_t Error      : 1; /**< Error flag: non-zero if an error word follows the header. */
        uint8_t DriveNo    : 3; /**< Drive number addressed by this SoE message (0–7). */

        uint8_t DataState  : 1; /**< Data-state element follows (response) or is requested (request). */
        uint8_t Name       : 1; /**< Name element follows or is requested. */
        uint8_t Attribute  : 1; /**< Attribute element follows or is requested. */
        uint8_t Unit       : 1; /**< Unit element follows or is requested. */
        uint8_t Min        : 1; /**< Minimum value element follows or is requested. */
        uint8_t Max        : 1; /**< Maximum value element follows or is requested. */
        uint8_t Value      : 1; /**< Value element follows or is requested. */
        uint8_t Reserved   : 1; /**< Reserved; must be zero. */
    } v;                        /**< Structured bit-field access. */
    struct
    {
        uint8_t Control; /**< Raw control byte (OpCode, InComplete, Error, DriveNo). */
        uint8_t Element; /**< Raw element flags byte (DataState … Reserved). */
    } v2;                /**< Byte-level access to the two control octets. */
} SoeHeaderControlUnion;


/**
 * @brief Union providing dual interpretation of the SoE header data word.
 */
typedef union tSoeHeaderDataUnion
{
    uint16_t IDN;           /**< Servo IDN (parameter identifier) when @c InComplete == 0. */
    uint16_t FragmentsLeft; /**< Number of pending fragments remaining when @c InComplete == 1. */
} SoeHeaderDataUnion;


/**
 * @brief EtherCAT SoE (Servo Drive Profile over EtherCAT) mailbox header.
 *
 * Immediately followed in the mailbox by either the payload data elements
 * (when @c Error == 0) or a 16-bit error code (when @c Error == 1).
 */
typedef struct TETHERCAT_SOE_HEADER
{
    SoeHeaderControlUnion anSoeHeaderControlUnion; /**< Control and element flag fields. */
    SoeHeaderDataUnion    anSoeHeaderDataUnion;    /**< IDN or fragment count, depending on @c InComplete. */
    /* typedef union tMailBoxDataUnion
    {
    uint8_t   Data[]      rest of mailbox data  if (Error==0)
    uint16_t  ErrorCode                          if (Error==1)
    } MailBoxDataUnion; */
} ETHERCAT_SOE_HEADER, *PETHERCAT_SOE_HEADER;

/** @brief Wire-size of #ETHERCAT_SOE_HEADER in bytes. */
#define ETHERCAT_SOE_HEADER_LEN ((int) sizeof(ETHERCAT_SOE_HEADER))


/**
 * @brief EtherCAT VoE (Vendor-specific over EtherCAT) mailbox header.
 */
typedef struct TETHERCAT_VOE_HEADER
{
    uint32_t VendorID;   /**< IANA-assigned vendor identifier of the VoE protocol owner. */
    uint16_t VendorType; /**< Vendor-defined message type identifier. */
} ETHERCAT_VOE_HEADER, *PETHERCAT_VOE_HEADER;

/** @brief Wire-size of #ETHERCAT_VOE_HEADER in bytes (sizeof avoided due to potential padding). */
#define ETHERCAT_VOE_HEADER_LEN 6 /*sizeof(ETHERCAT_VOE_HEADER)*/

/**
 * @brief Initialize the EtherCAT mailbox header.
 *
 * This function initializes the EtherCAT mailbox header structure with data from a TVB buffer.
 *
 * @param pMbox Pointer to the EtherCAT mailbox header structure to be initialized.
 * @param tvb Pointer to the TVB buffer containing the data.
 * @param offset Offset within the TVB buffer where the data starts.
 */
extern void init_mbx_header(PETHERCAT_MBOX_HEADER pMbox, tvbuff_t *tvb, int offset);

DIAG_ON_PEDANTIC
#endif /* _PACKET_ECATMAILBOX_H_ */
