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

typedef struct TETHERNET_ADDRESS
{
   uint8_t b[6];
} ETHERNET_ADDRESS, *PETHERNET_ADDRESS;
#define ETHERNET_ADDRESS_LEN ((int) sizeof(ETHERNET_ADDRESS))

/* Mailbox*/
#define ETHERCAT_MBOX_TYPE_ADS 1 /* AMS/ADS header follows*/
#define ETHERCAT_MBOX_TYPE_EOE 2 /* ETHERCAT_EOE_HEADER follows*/
#define ETHERCAT_MBOX_TYPE_COE 3 /* ETHERCAT_COE_HEADER follows*/
#define ETHERCAT_MBOX_TYPE_FOE 4 /* ETHERCAT_FOE_HEADER follows*/
#define ETHERCAT_MBOX_TYPE_SOE 5 /* ETHERCAT_SOE_HEADER follows*/

typedef union tMbxHeaderControlUnion
{
   uint16_t Control;
   struct
   {
      uint16_t Channel     : 6; /* optional communication channels (default = 0)*/
      uint16_t Priority    : 2; /* optional communication priority (default = 0)*/
      uint16_t Type        : 4; /* TETHERCAT_MBOX_TYPE_xxx*/
      uint16_t Counter     : 3; /* 0 = counter not used (old version)*/
      uint16_t Unsupported : 1; /* unsupported protocol detected*/
   } v;
} MbxHeaderControlUnion;

typedef struct TETHERCAT_MBOX_HEADER
{
   uint16_t Length;          /* following bytes*/
   uint16_t Address;         /* S->M: phys addr of destination; M->S: phys addr of source; 0 = master*/
   MbxHeaderControlUnion aControlUnion;
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

typedef union tEoeMacFilterOptionsUnion
{
   struct
   {
      uint16_t         MacFilterCount     :4;
      uint16_t         MacFilterMaskCount :2;
      uint16_t         Reserved1          :1;
      uint16_t         NoBroadcasts       :1;
      uint16_t         Reserved2          :8;
   } v;
   uint16_t Options;
} EoeMacFilterOptionsUnion;

typedef struct TETHERCAT_EOE_MACFILTER
{
   EoeMacFilterOptionsUnion anEoeMacFilterOptionsUnion;
   ETHERNET_ADDRESS MacFilter[16];
   ETHERNET_ADDRESS MacFilterMask[4];
} ETHERCAT_EOE_MACFILTER;
#define ETHERCAT_EOE_MACFILTER_LEN ((int) sizeof(ETHERCAT_EOE_MACFILTER))

typedef struct TETHERCAT_EOE_TIMESTAMP
{
   uint32_t TimeStamp; /* 32 bit time stamp */
} ETHERCAT_EOE_TIMESTAMP;
#define ETHERCAT_EOE_TIMESTAMP_LEN ((int) sizeof(ETHERCAT_EOE_TIMESTAMP))

typedef union tEoeHeaderDataUnion
{
   struct
   {                            /* EOE_TYPE_FRAME_FRAG and EOE_TYPE_TIMESTAMP_RES only */
      uint16_t Fragment     : 6; /* fragment number (EOE_TYPE_FRAME_FRAG only) */
      uint16_t OffsetBuffer : 6; /* byte offset multiplied by 32 (if Fragment != 0)  (EOE_TYPE_FRAME_FRAG only) */
                                /* buffer size multiplied by 32 (if Fragment == 0) (EOE_TYPE_FRAME_FRAG only)  */
      uint16_t FrameNo      : 4; /* frame number (EOE_TYPE_FRAME_FRAG and EOE_TYPE_TIMESTAMP_RES only) */
   } v;
   uint16_t Result;              /* EOE_TYPE_INIT_RES and EOE_TYPE_MACFILTER_RES only */
} EoeHeaderDataUnion;

typedef union tEoeHeaderInfoUnion
{
   struct
   {
      uint16_t Type               : 4; /* specifies following data */
      uint16_t PortAssign         : 4; /* 0 = unspecified, 1 = port 1 */
      uint16_t LastFragment       : 1; /* true if last fragment (EOE_TYPE_FRAME_FRAG only) */
      uint16_t TimeStampAppended  : 1; /* 32 bit time stamp appended  (EOE_TYPE_FRAME_FRAG with LastFragment=1 only) */
      uint16_t TimeStampRequested : 1; /* time stamp response requested (EOE_TYPE_FRAME_FRAG only) */
      uint16_t Reserved           : 5;
   } v;
   uint16_t Info;
} EoeHeaderInfoUnion;

typedef struct TETHERCAT_EOE_HEADER
{
   EoeHeaderInfoUnion anEoeHeaderInfoUnion;
   EoeHeaderDataUnion anEoeHeaderDataUnion;
} ETHERCAT_EOE_HEADER, *PETHERCAT_EOE_HEADER;
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

typedef union TETHERCAT_COE_HEADER
{
   struct
   {
      uint16_t Number   : 9; /* e.g. PDO number*/
      uint16_t Reserved : 3; /* = 0*/
      uint16_t Type     : 4; /* CANopen type*/
   } v;
   uint16_t header;
} ETHERCAT_COE_HEADER, *PETHERCAT_COE_HEADER;
#define ETHERCAT_COE_HEADER_LEN ((int) sizeof(ETHERCAT_COE_HEADER))


typedef union tSdoHeaderUnion
{
   struct
   {   /* Initiate Download Request*/
      uint8_t SizeInd   : 1;
      uint8_t Expedited : 1;
      uint8_t Size      : 2;
      uint8_t Complete  : 1;
      uint8_t Ccs       : 3; /* = 1*/
   } Idq;
   struct
   {   /* Initiate Download Response*/
      uint8_t Reserved : 5;
      uint8_t Scs      : 3; /* = 3*/
   } Ids;
   struct
   {   /* Download Segment Request*/
      uint8_t LastSeg : 1;
      uint8_t Size    : 3;
      uint8_t Toggle  : 1;
      uint8_t Ccs     : 3; /* = 0*/
   } Dsq;
   struct
   {   /* Download Segment Response*/
      uint8_t Reserved : 4;
      uint8_t Toggle   : 1;
      uint8_t Scs      : 3; /* = 1*/
   } Dss;
   struct
   {   /* Initiate Upload Request*/
      uint8_t Reserved : 4;
      uint8_t Complete : 1;
      uint8_t Ccs      : 3; /* = 2*/
   } Iuq;
   struct
   {   /* Initiate Upload Response*/
      uint8_t SizeInd   : 1;
      uint8_t Expedited : 1;
      uint8_t Size      : 2;
      uint8_t Complete  : 1;
      uint8_t Scs       : 3; /* = 2*/
   } Ius;
   struct
   {   /* Upload Segment Request*/
      uint8_t Reserved : 4;
      uint8_t Toggle   : 1;
      uint8_t Ccs      : 3; /* = 3*/
   } Usq;
   struct
   {   /* Upload Segment Response*/
      uint8_t LastSeg : 1;
      uint8_t Bytes   : 3;
      uint8_t Toggle  : 1;
      uint8_t Scs     : 3; /* = 0*/
   } Uss;
   struct
   {   /* Abort Transfer*/
      uint8_t Reserved : 5;
      uint8_t Ccs      : 3; /* = 4*/
   } Abt;
   uint8_t CS;
} SdoHeaderUnion;

typedef struct TETHERCAT_SDO_HEADER
{
   SdoHeaderUnion anSdoHeaderUnion;

   uint16_t Index;
   uint8_t SubIndex;
   uint32_t Data;
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

typedef struct TETHERCAT_SDO_INFO_LIST
{
   uint16_t ListType; /* == SDO_INFO_LIST_TYPE_XXX */
   struct
   {
      uint16_t Index[1];
   } Res;
} ETHERCAT_SDO_INFO_LIST;

typedef struct TETHERCAT_SDO_INFO_OBJ
{
   uint16_t Index;
   struct
   {
      uint16_t DataType;    /* refer to data type index */
      uint8_t MaxSubIndex; /* max subIndex */
      uint8_t ObjCode;     /* defined in DS 301 (Table 37)*/
      char    Name[1];     /* rest of mailbox data*/
   } Res;
} ETHERCAT_SDO_INFO_OBJ;

typedef struct TETHERCAT_SDO_INFO_ENTRY
{
   uint16_t Index;
   uint8_t SubIdx;
   uint8_t ValueInfo; /* bit0 = ObjAccess, bit1 = ObjCategory, bit2 = PdoMapping, bit3 = UnitType
                      bit4 = DefaultValue, bit5 = MinValue, bit6 = MaxValue*/
   struct
   {
      uint16_t DataType;  /* refer to data type index */
      uint16_t BitLen;
      uint16_t ObjAccess; /* bit0 = read; bit1 = write; bit2 = const. bit3 = 'PRE-OP'; bit4 = 'SAFE-OP'; bit5 = 'OP'.*/
   } Res;
} ETHERCAT_SDO_INFO_ENTRY;

typedef struct TETHERCAT_SDO_INFO_ERROR
{
   uint32_t ErrorCode;
   char    ErrorText[1]; /* rest of mailbox data */
} ETHERCAT_SDO_INFO_ERROR;

typedef union tSdoInfoUnion
{
   ETHERCAT_SDO_INFO_LIST  List;
   ETHERCAT_SDO_INFO_OBJ   Obj;
   ETHERCAT_SDO_INFO_ENTRY Entry;
   ETHERCAT_SDO_INFO_ERROR Error;
   uint8_t                 Data[1];
} SdoInfoUnion;

typedef union tSdoControlUnion
{
   struct
   {
      uint8_t OpCode     : 7; /* == SDO_INFO_TYPE_XXX */
      uint8_t InComplete : 1;
   } v;
   uint8_t Control;
} SdoControlUnion;

typedef struct TETHERCAT_SDO_INFO_HEADER
{
   SdoControlUnion anSdoControlUnion;
   uint8_t Reserved; /* == 0 */
   uint16_t FragmentsLeft;
   SdoInfoUnion anSdoInfoUnion;
} ETHERCAT_SDO_INFO_HEADER, *PETHERCAT_SDO_INFO_HEADER;

#define ETHERCAT_SDO_INFO_LISTREQ_LEN 6 /*offsetof(ETHERCAT_SDO_INFO_HEADER, anSdoInfoUnion.List.Res)*/

/* FoE (File Access over EtherCAT)*/
#define ECAT_FOE_OPMODE_RRQ  1
#define ECAT_FOE_OPMODE_WRQ  2
#define ECAT_FOE_OPMODE_DATA 3
#define ECAT_FOE_OPMODE_ACK  4
#define ECAT_FOE_OPMODE_ERR  5
#define ECAT_FOE_OPMODE_BUSY 6

#define ECAT_FOE_ERRCODE_NOTDEFINED     0
#define ECAT_FOE_ERRCODE_NOTFOUND       1
#define ECAT_FOE_ERRCODE_ACCESS         2
#define ECAT_FOE_ERRCODE_DISKFULL       3
#define ECAT_FOE_ERRCODE_ILLEAGAL       4
#define ECAT_FOE_ERRCODE_PACKENO        5
#define ECAT_FOE_ERRCODE_EXISTS         6
#define ECAT_FOE_ERRCODE_NOUSER         7
#define ECAT_FOE_ERRCODE_BOOTSTRAPONLY  8
#define ECAT_FOE_ERRCODE_NOTINBOOTSTRAP 9

typedef union tFoeHeaderDataUnion
{
   uint32_t FileLength; /*  (RRQ, WRQ) = 0 if unknown */
   struct
   {
      uint16_t PacketNo;  /* (DATA, ACK)*/
      uint16_t Reserved2; /* (DATA, ACK)*/
   } v;
   uint32_t ErrorCode; /* (ERR)*/
   struct
   {
      uint16_t Done;   /* (BUSY)*/
      uint16_t Entire; /* (BUSY)*/
   } v2;
} FoeHeaderDataUnion;

typedef struct TETHERCAT_FOE_HEADER
{
   uint8_t OpMode;    /* = 1 (RRQ), = 2 (WRQ), = 3 (DATA), = 4 (ACK), = 5 (ERR), = 6 (BUSY) */
   uint8_t Reserved1; /* = 0 */

   FoeHeaderDataUnion aFoeHeaderDataUnion;
   /*   typedef union tMailBoxDataUnion
   {
   char      Name[]          (RRQ, WRQ)   rest of mailbox data
   uint8_t   Data[]          (DATA)      rest of mailbox data (if OpMode = 3)
   char      ErrorText[]       (ERR)         rest of mailbox data
   } MailBoxDataUnion;*/
} ETHERCAT_FOE_HEADER, *PETHERCAT_FOE_HEADER;
#define ETHERCAT_FOE_HEADER_LEN 6 /*sizeof(ETHERCAT_FOE_HEADER)*/

typedef struct
{
   uint16_t Cmd;
   uint16_t Size;
   uint16_t AddressLW;
   uint16_t AddressHW;
} TEFWUPDATE_HEADER;


/* SoE (SOE over EtherCAT)*/
#define ECAT_SOE_OPCODE_RRQ 1
#define ECAT_SOE_OPCODE_RRS 2
#define ECAT_SOE_OPCODE_WRQ 3
#define ECAT_SOE_OPCODE_WRS 4
#define ECAT_SOE_OPCODE_NFC 5


typedef union tSoeHeaderControlUnion
{
   struct
   {
      uint8_t OpCode     : 3; /* 0 = unused, 1 = readReq, 2 = readRes, 3 = writeReq, 4 = writeRes
                             5 = notification (command changed notification)*/
      uint8_t InComplete : 1; /* more follows*/
      uint8_t Error      : 1; /* an error word follows */
      uint8_t DriveNo    : 3; /* drive number */

      uint8_t DataState  : 1; /* follows or requested */
      uint8_t Name       : 1; /* follows or requested */
      uint8_t Attribute  : 1; /* follows or requested */
      uint8_t Unit       : 1; /* follows or requested */
      uint8_t Min        : 1; /* follows or requested */
      uint8_t Max        : 1; /* follows or requested */
      uint8_t Value      : 1; /* follows or requested */
      uint8_t Reserved   : 1;
   } v;
   struct
   {
      uint8_t Control;
      uint8_t Element;
   } v2;
} SoeHeaderControlUnion;

typedef union tSoeHeaderDataUnion
{
   uint16_t IDN;           /* SOE IDN            if (InComplete==0) */
   uint16_t FragmentsLeft; /* Pending fragments  if (InComplete==1)  */
} SoeHeaderDataUnion;

typedef struct TETHERCAT_SOE_HEADER
{
   SoeHeaderControlUnion anSoeHeaderControlUnion;
   SoeHeaderDataUnion anSoeHeaderDataUnion;
   /* typedef union tMailBoxDataUnion
   {
   uint8_t   Data[]   rest of mailbox data  if (Error==0)
   uint16_t ErrorCode                        if (Error==1)
   } MailBoxDataUnion;*/
} ETHERCAT_SOE_HEADER, *PETHERCAT_SOE_HEADER;
#define ETHERCAT_SOE_HEADER_LEN ((int) sizeof(ETHERCAT_SOE_HEADER))

extern void init_mbx_header(PETHERCAT_MBOX_HEADER pMbox, tvbuff_t *tvb, int offset);

DIAG_ON_PEDANTIC
#endif /* _PACKET_ECATMAILBOX_H_ */
