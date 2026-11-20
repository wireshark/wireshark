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


/*
 * Fields of the mailbox control word, as read with tvb_get_letohs(). These
 * (and the other header word accessors below) are shifts and masks rather
 * than bit-fields, whose layout depends on the compiler and on the host's
 * byte order. Also note that the structs on the wire are packed, so the
 * lengths for some are different than what sizeof() may give due to padding.
 */
#define ETHERCAT_MBOX_CHANNEL(ctrl)     ((ctrl) & 0x3F)        /**< Optional communication channel index (default = 0). */
#define ETHERCAT_MBOX_PRIORITY(ctrl)    (((ctrl) >> 6) & 0x3)  /**< Optional communication priority (default = 0; higher = more urgent). */
#define ETHERCAT_MBOX_TYPE(ctrl)        (((ctrl) >> 8) & 0xF)  /**< Mailbox protocol type; see @c ETHERCAT_MBOX_TYPE_* values. */
#define ETHERCAT_MBOX_COUNTER(ctrl)     (((ctrl) >> 12) & 0x7) /**< Sequence counter for duplicate detection (0 = counter not used). */
#define ETHERCAT_MBOX_UNSUPPORTED(ctrl) (((ctrl) >> 15) & 0x1) /**< Set by the slave when the requested protocol is not supported. */


/**
 * @brief EtherCAT mailbox header, common to all mailbox protocol frames.
 */
typedef struct TETHERCAT_MBOX_HEADER
{
    uint16_t              Length;       /**< Number of bytes of mailbox data following this header. */
    uint16_t              Address;      /**< Slave→Master: physical address of the destination station;
                                         *   Master→Slave: physical address of the source station (0 = master). */
    uint16_t              Control;      /**< Channel, priority, type, counter, and unsupported-protocol flag; see @c ETHERCAT_MBOX_TYPE() etc. */
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

/* Fields of the EoE MAC filter options word. */
#define EOE_MACFILTER_COUNT(opt)         ((opt) & 0xF)        /**< Number of valid MAC address filter entries (0–15). */
#define EOE_MACFILTER_MASK_COUNT(opt)    (((opt) >> 4) & 0x3) /**< Number of valid MAC address filter mask entries (0–3). */
#define EOE_MACFILTER_NO_BROADCASTS(opt) (((opt) >> 7) & 0x1) /**< Non-zero to suppress forwarding of broadcast frames. */


/**
 * @brief EtherCAT EoE (Ethernet over EtherCAT) MAC filter configuration.
 */
typedef struct TETHERCAT_EOE_MACFILTER
{
    uint16_t         Options;           /**< Filter count, mask count, and option flags; see @c EOE_MACFILTER_COUNT() etc. */
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


/*
 * Fields of the EoE header data word for @c EOE_TYPE_FRAME_FRAG and
 * @c EOE_TYPE_TIMESTAMP_RES; for @c EOE_TYPE_INIT_RES and
 * @c EOE_TYPE_MACFILTER_RES the word is a result code.
 */
#define EOE_DATA_FRAGMENT(data)      ((data) & 0x3F)        /**< Fragment sequence number within the current Ethernet frame. */
#define EOE_DATA_OFFSET_BUFFER(data) (((data) >> 6) & 0x3F) /**< If the fragment number != 0: byte offset of this fragment / 32; else the buffer size / 32. */
#define EOE_DATA_FRAME_NO(data)      (((data) >> 12) & 0xF) /**< Frame number correlating fragments to a single Ethernet frame. */


/* Fields of the EoE header info word. */
#define EOE_INFO_TYPE(info)                 ((info) & 0xF)         /**< EoE message type identifier (e.g. FRAME_FRAG, INIT_REQ, MACFILTER_REQ). */
#define EOE_INFO_PORT_ASSIGN(info)          (((info) >> 4) & 0xF)  /**< Virtual port assignment (0 = unspecified, 1 = port 1). */
#define EOE_INFO_LAST_FRAGMENT(info)        (((info) >> 8) & 0x1)  /**< Non-zero if this is the last fragment of the Ethernet frame (FRAME_FRAG only). */
#define EOE_INFO_TIMESTAMP_APPENDED(info)   (((info) >> 9) & 0x1)  /**< Non-zero if a 32-bit timestamp is appended after the last fragment. */
#define EOE_INFO_TIMESTAMP_REQUESTED(info)  (((info) >> 10) & 0x1) /**< Non-zero if a timestamp response is requested by the sender. */


/**
 * @brief EtherCAT EoE (Ethernet over EtherCAT) mailbox header.
 */
typedef struct TETHERCAT_EOE_HEADER
{
    uint16_t Info; /**< Info word carrying the message type, port, and fragment control flags; see @c EOE_INFO_TYPE() etc. */
    uint16_t Data; /**< Data word carrying fragment/frame numbers (see @c EOE_DATA_FRAGMENT() etc.) or a result code. */
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
typedef struct TETHERCAT_COE_HEADER
{
    uint16_t header; /**< Raw 16-bit CoE header word; see @c ETHERCAT_COE_NUMBER() and @c ETHERCAT_COE_TYPE(). */
} ETHERCAT_COE_HEADER, *PETHERCAT_COE_HEADER;

#define ETHERCAT_COE_NUMBER(hdr) ((hdr) & 0x1FF)        /**< CANopen number field (e.g. PDO number or SDO counter). */
#define ETHERCAT_COE_TYPE(hdr)   (((hdr) >> 12) & 0xF)  /**< CANopen message type (e.g. SDO, PDO, NMT, EMCY). */

/** @brief Wire-size of #ETHERCAT_COE_HEADER in bytes. */
#define ETHERCAT_COE_HEADER_LEN ((int) sizeof(ETHERCAT_COE_HEADER))


/*
 * Fields of the SDO command specifier byte. The command specifier (Ccs in
 * requests, Scs in responses) is always the top 3 bits; which of the other
 * fields are present depends on it and on the direction.
 */
#define SDO_CS_CCS(cs)       (((cs) >> 5) & 0x7) /**< Client command specifier (requests). */
#define SDO_CS_SCS(cs)       (((cs) >> 5) & 0x7) /**< Server command specifier (responses). */
#define SDO_CS_SIZE_IND(cs)  ((cs) & 0x1)        /**< Initiate Download Request / Initiate Upload Response: non-zero if the size is indicated. */
#define SDO_CS_EXPEDITED(cs) (((cs) >> 1) & 0x1) /**< Initiate Download Request / Initiate Upload Response: non-zero if the data fits in this frame. */
#define SDO_CS_SIZE(cs)      (((cs) >> 2) & 0x3) /**< Initiate Download Request / Initiate Upload Response: number of bytes of expedited data that do NOT contain data. */


/**
 * @brief EtherCAT CoE SDO (Service Data Object) header.
 */
typedef struct TETHERCAT_SDO_HEADER
{
    uint8_t        CS;               /**< Command specifier byte; see @c SDO_CS_CCS() etc. */
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


/* Fields of the SDO Information control byte. */
#define SDO_INFO_OPCODE(ctrl)     ((ctrl) & 0x7F)       /**< SDO Information operation code; see @c ECAT_COE_INFO_OPCODE_* values. */
#define SDO_INFO_INCOMPLETE(ctrl) (((ctrl) >> 7) & 0x1) /**< More-follows flag: non-zero if additional fragments are pending. */


/**
 * @brief EtherCAT SDO Information mailbox header.
 */
typedef struct TETHERCAT_SDO_INFO_HEADER
{
    uint8_t         Control;           /**< Control byte carrying the opcode and more-follows flag; see @c SDO_INFO_OPCODE() etc. */
    uint8_t         Reserved;          /**< Reserved; must be zero. */
    uint16_t        FragmentsLeft;     /**< Number of remaining fragments in a multi-fragment transfer. */
    SdoInfoUnion    anSdoInfoUnion;    /**< Payload interpreted according to @c SDO_INFO_OPCODE(Control). */
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


/*
 * The FoE header data word, as read with tvb_get_letohl(), is the file
 * length (RRQ, WRQ) or the error code (ERR); for the others:
 */
#define FOE_DATA_PACKET_NO(data)   ((data) & 0xFFFF)         /**< Sequential packet number (DATA, ACK). */
#define FOE_DATA_BUSY_DONE(data)   ((data) & 0xFFFF)         /**< Number of bytes already transferred (BUSY). */
#define FOE_DATA_BUSY_ENTIRE(data) (((data) >> 16) & 0xFFFF) /**< Total number of bytes to be transferred (BUSY). */


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
    uint32_t           Data;      /**< Mode-specific data word (file length, packet number, error code, or progress); see @c FOE_DATA_PACKET_NO() etc. */
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


/* Fields of the SoE header control byte. */
#define SOE_CTRL_OPCODE(ctrl)     ((ctrl) & 0x7)        /**< Operation code; see @c ECAT_SOE_OPCODE_* values (0 = unused). */
#define SOE_CTRL_INCOMPLETE(ctrl) (((ctrl) >> 3) & 0x1) /**< More-follows flag: non-zero if additional fragments are pending. */
#define SOE_CTRL_ERROR(ctrl)      (((ctrl) >> 4) & 0x1) /**< Error flag: non-zero if an error word follows the header. */
#define SOE_CTRL_DRIVE_NO(ctrl)   (((ctrl) >> 5) & 0x7) /**< Drive number addressed by this SoE message (0–7). */

/* Flags in the SoE header element byte: the element follows (response) or is requested (request). */
#define SOE_ELEM_DATASTATE 0x01
#define SOE_ELEM_NAME      0x02
#define SOE_ELEM_ATTRIBUTE 0x04
#define SOE_ELEM_UNIT      0x08
#define SOE_ELEM_MIN       0x10
#define SOE_ELEM_MAX       0x20
#define SOE_ELEM_VALUE     0x40


/**
 * @brief Union providing dual interpretation of the SoE header data word.
 */
typedef union tSoeHeaderDataUnion
{
    uint16_t IDN;           /**< Servo IDN (parameter identifier) when @c SOE_CTRL_INCOMPLETE(Control) == 0. */
    uint16_t FragmentsLeft; /**< Number of pending fragments remaining when @c SOE_CTRL_INCOMPLETE(Control) == 1. */
} SoeHeaderDataUnion;


/**
 * @brief EtherCAT SoE (Servo Drive Profile over EtherCAT) mailbox header.
 *
 * Immediately followed in the mailbox by either the payload data elements
 * (when @c Error == 0) or a 16-bit error code (when @c Error == 1).
 */
typedef struct TETHERCAT_SOE_HEADER
{
    uint8_t               Control;                 /**< Opcode, flags and drive number; see @c SOE_CTRL_OPCODE() etc. */
    uint8_t               Element;                 /**< Element flags; see @c SOE_ELEM_* values. */
    SoeHeaderDataUnion    anSoeHeaderDataUnion;    /**< IDN or fragment count, depending on @c SOE_CTRL_INCOMPLETE(Control). */
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
