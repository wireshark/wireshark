/* packet-ecatmb.h
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef _PACKET_ECATMAILBOX_H_
#define _PACKET_ECATMAILBOX_H_

/* Ensure the same data layout for all platforms */

typedef struct TETHERNET_ADDRESS
{
   guint8 b[6];
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
   guint16 Control;
   struct
   {
      guint16 Channel     : 6; /* optional communication channels (default = 0)*/
      guint16 Priority    : 2; /* optional communication priority (default = 0)*/
      guint16 Type        : 4; /* TETHERCAT_MBOX_TYPE_xxx*/
      guint16 Counter     : 3; /* 0 = counter not used (old version)*/
      guint16 Unsupported : 1; /* unsupported protocol detected*/
   } v;
} MbxHeaderControlUnion;

typedef struct TETHERCAT_MBOX_HEADER
{
   guint16 Length;          /* following bytes*/
   guint16 Address;         /* S->M: phys addr of destination; M->S: phys addr of source; 0 = master*/
   MbxHeaderControlUnion aControlUnion;
} ETHERCAT_MBOX_HEADER, *PETHERCAT_MBOX_HEADER;

#define ETHERCAT_MBOX_HEADER_LEN ((int) sizeof(ETHERCAT_MBOX_HEADER))

/*/////////////////////////////////////////////////////////////////////////////*/
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
   guint32          ContainsMacAddr        :1;
   guint32          ContainsIpAddr         :1;
   guint32          ContainsSubnetMask     :1;
   guint32          ContainsDefaultGateway :1;
   guint32          ContainsDnsServer      :1;
   guint32          ContainsDnsName        :1;
   guint32          Reserved               :26;
   ETHERNET_ADDRESS MacAddr;
   guint32          IpAddr;
   guint32          SubnetMask;
   guint32          DefaultGateway;
   guint32          DnsServer;
   char             DnsName[32];
} ETHERCAT_EOE_INIT, *PETHERCAT_EOE_INIT;*/
#define ETHERCAT_EOE_INIT_LEN 58 /*sizeof(ETHERCAT_EOE_INIT)*/

typedef union tEoeMacFilterOptionsUnion
{
   struct
   {
      guint16          MacFilterCount     :4;
      guint16          MacFilterMaskCount :2;
      guint16          Reserved1          :1;
      guint16          NoBroadcasts       :1;
      guint16          Reserved2          :8;
   } v;
   guint16 Options;
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
   guint32 TimeStamp; /* 32 bit time stamp */
} ETHERCAT_EOE_TIMESTAMP;
#define ETHERCAT_EOE_TIMESTAMP_LEN ((int) sizeof(ETHERCAT_EOE_TIMESTAMP))

typedef union tEoeHeaderDataUnion
{
   struct
   {                            /* EOE_TYPE_FRAME_FRAG and EOE_TYPE_TIMESTAMP_RES only */
      guint16 Fragment     : 6; /* fragment number (EOE_TYPE_FRAME_FRAG only) */
      guint16 OffsetBuffer : 6; /* byte offset multiplied by 32 (if Fragment != 0)  (EOE_TYPE_FRAME_FRAG only) */
                                /* buffer size multiplied by 32 (if Fragment == 0) (EOE_TYPE_FRAME_FRAG only)  */
      guint16 FrameNo      : 4; /* frame number (EOE_TYPE_FRAME_FRAG and EOE_TYPE_TIMESTAMP_RES only) */
   } v;
   guint16 Result;              /* EOE_TYPE_INIT_RES and EOE_TYPE_MACFILTER_RES only */
} EoeHeaderDataUnion;

typedef union tEoeHeaderInfoUnion
{
   struct
   {
      guint16 Type               : 4; /* specifies following data */
      guint16 PortAssign         : 4; /* 0 = unspecified, 1 = port 1 */
      guint16 LastFragment       : 1; /* TRUE if last fragment (EOE_TYPE_FRAME_FRAG only) */
      guint16 TimeStampAppended  : 1; /* 32 bit time stamp appended  (EOE_TYPE_FRAME_FRAG with LastFragment=1 only) */
      guint16 TimeStampRequested : 1; /* time stamp response requested (EOE_TYPE_FRAME_FRAG only) */
      guint16 Reserved           : 5;
   } v;
   guint16 Info;
} EoeHeaderInfoUnion;

typedef struct TETHERCAT_EOE_HEADER
{
   EoeHeaderInfoUnion anEoeHeaderInfoUnion;
   EoeHeaderDataUnion anEoeHeaderDataUnion;
} ETHERCAT_EOE_HEADER, *PETHERCAT_EOE_HEADER;
#define ETHERCAT_EOE_HEADER_LEN ((int) sizeof(ETHERCAT_EOE_HEADER))

/*/////////////////////////////////////////////////////////////////////////////*/
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
      guint16 Number   : 9; /* e.g. PDO number*/
      guint16 Reserved : 3; /* = 0*/
      guint16 Type     : 4; /* CANopen type*/
   } v;
   guint16 header;
} ETHERCAT_COE_HEADER, *PETHERCAT_COE_HEADER;
#define ETHERCAT_COE_HEADER_LEN ((int) sizeof(ETHERCAT_COE_HEADER))


typedef union tSdoHeaderUnion
{
   struct
   {   /* Initiate Download Request*/
      guint8 SizeInd   : 1;
      guint8 Expedited : 1;
      guint8 Size      : 2;
      guint8 Complete  : 1;
      guint8 Ccs       : 3; /* = 1*/
   } Idq;
   struct
   {   /* Initiate Download Response*/
      guint8 Reserved : 5;
      guint8 Scs      : 3; /* = 3*/
   } Ids;
   struct
   {   /* Download Segment Request*/
      guint8 LastSeg : 1;
      guint8 Size    : 3;
      guint8 Toggle  : 1;
      guint8 Ccs     : 3; /* = 0*/
   } Dsq;
   struct
   {   /* Download Segment Response*/
      guint8 Reserved : 4;
      guint8 Toggle   : 1;
      guint8 Scs      : 3; /* = 1*/
   } Dss;
   struct
   {   /* Initiate Upload Request*/
      guint8 Reserved : 4;
      guint8 Complete : 1;
      guint8 Ccs      : 3; /* = 2*/
   } Iuq;
   struct
   {   /* Initiate Upload Response*/
      guint8 SizeInd   : 1;
      guint8 Expedited : 1;
      guint8 Size      : 2;
      guint8 Complete  : 1;
      guint8 Scs       : 3; /* = 2*/
   } Ius;
   struct
   {   /* Upload Segment Request*/
      guint8 Reserved : 4;
      guint8 Toggle   : 1;
      guint8 Ccs      : 3; /* = 3*/
   } Usq;
   struct
   {   /* Upload Segment Response*/
      guint8 LastSeg : 1;
      guint8 Bytes   : 3;
      guint8 Toggle  : 1;
      guint8 Scs     : 3; /* = 0*/
   } Uss;
   struct
   {   /* Abort Transfer*/
      guint8 Reserved : 5;
      guint8 Ccs      : 3; /* = 4*/
   } Abt;
   guint8 CS;
} SdoHeaderUnion;

typedef struct TETHERCAT_SDO_HEADER
{
   SdoHeaderUnion anSdoHeaderUnion;

   guint16 Index;
   guint8  SubIndex;
   guint32 Data;
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
   guint16 ListType; /* == SDO_INFO_LIST_TYPE_XXX */
   struct
   {
      guint16 Index[1];
   } Res;
} ETHERCAT_SDO_INFO_LIST;

typedef struct TETHERCAT_SDO_INFO_OBJ
{
   guint16 Index;
   struct
   {
      guint16 DataType;    /* refer to data type index */
      guint8  MaxSubIndex; /* max subIndex */
      guint8  ObjCode;     /* defined in DS 301 (Table 37)*/
      char    Name[1];     /* rest of mailbox data*/
   } Res;
} ETHERCAT_SDO_INFO_OBJ;

typedef struct TETHERCAT_SDO_INFO_ENTRY
{
   guint16 Index;
   guint8  SubIdx;
   guint8  ValueInfo; /* bit0 = ObjAccess, bit1 = ObjCategory, bit2 = PdoMapping, bit3 = UnitType
                      bit4 = DefaultValue, bit5 = MinValue, bit6 = MaxValue*/
   struct
   {
      guint16 DataType;  /* refer to data type index */
      guint16 BitLen;
      guint16 ObjAccess; /* bit0 = read; bit1 = write; bit2 = const. bit3 = 'PRE-OP'; bit4 = 'SAFE-OP'; bit5 = 'OP'.*/
   } Res;
} ETHERCAT_SDO_INFO_ENTRY;

typedef struct TETHERCAT_SDO_INFO_ERROR
{
   guint32 ErrorCode;
   char    ErrorText[1]; /* rest of mailbox data */
} ETHERCAT_SDO_INFO_ERROR;

typedef union tSdoInfoUnion
{
   ETHERCAT_SDO_INFO_LIST  List;
   ETHERCAT_SDO_INFO_OBJ   Obj;
   ETHERCAT_SDO_INFO_ENTRY Entry;
   ETHERCAT_SDO_INFO_ERROR Error;
   guint8                  Data[1];
} SdoInfoUnion;

typedef union tSdoControlUnion
{
   struct
   {
      guint8  OpCode     : 7; /* == SDO_INFO_TYPE_XXX */
      guint8  InComplete : 1;
   } v;
   guint8 Control;
} SdoControlUnion;

typedef struct TETHERCAT_SDO_INFO_HEADER
{
   SdoControlUnion anSdoControlUnion;
   guint8  Reserved; /* == 0 */
   guint16 FragmentsLeft;
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
   guint32 FileLength; /*  (RRQ, WRQ) = 0 if unknown */
   struct
   {
      guint16 PacketNo;  /* (DATA, ACK)*/
      guint16 Reserved2; /* (DATA, ACK)*/
   } v;
   guint32 ErrorCode; /* (ERR)*/
   struct
   {
      guint16 Done;   /* (BUSY)*/
      guint16 Entire; /* (BUSY)*/
   } v2;
} FoeHeaderDataUnion;

typedef struct TETHERCAT_FOE_HEADER
{
   guint8 OpMode;    /* = 1 (RRQ), = 2 (WRQ), = 3 (DATA), = 4 (ACK), = 5 (ERR), = 6 (BUSY) */
   guint8 Reserved1; /* = 0 */

   FoeHeaderDataUnion aFoeHeaderDataUnion;
   /*   typedef union tMailBoxDataUnion
   {
   char      Name[]          (RRQ, WRQ)   rest of mailbox data
   guint8    Data[]          (DATA)      rest of mailbox data (if OpMode = 3)
   char      ErrorText[]       (ERR)         rest of mailbox data
   } MailBoxDataUnion;*/
} ETHERCAT_FOE_HEADER, *PETHERCAT_FOE_HEADER;
#define ETHERCAT_FOE_HEADER_LEN 6 /*sizeof(ETHERCAT_FOE_HEADER)*/

typedef struct
{
   guint16  Cmd;
   guint16  Size;
   guint16  AddressLW;
   guint16  AddressHW;
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
      guint8 OpCode     : 3; /* 0 = unused, 1 = readReq, 2 = readRes, 3 = writeReq, 4 = writeRes
                             5 = notification (command changed notification)*/
      guint8 InComplete : 1; /* more follows*/
      guint8 Error      : 1; /* an error word follows */
      guint8 DriveNo    : 3; /* drive number */

      guint8 DataState  : 1; /* follows or requested */
      guint8 Name       : 1; /* follows or requested */
      guint8 Attribute  : 1; /* follows or requested */
      guint8 Unit       : 1; /* follows or requested */
      guint8 Min        : 1; /* follows or requested */
      guint8 Max        : 1; /* follows or requested */
      guint8 Value      : 1; /* follows or requested */
      guint8 Reserved   : 1;
   } v;
   struct
   {
      guint8 Control;
      guint8 Element;
   } v2;
} SoeHeaderControlUnion;

typedef union tSoeHeaderDataUnion
{
   guint16 IDN;           /* SOE IDN            if (InComplete==0) */
   guint16 FragmentsLeft; /* Pending fragments  if (InComplete==1)  */
} SoeHeaderDataUnion;

typedef struct TETHERCAT_SOE_HEADER
{
   SoeHeaderControlUnion anSoeHeaderControlUnion;
   SoeHeaderDataUnion anSoeHeaderDataUnion;
   /* typedef union tMailBoxDataUnion
   {
   guint8    Data[]   rest of mailbox data  if (Error==0)
   guint16 ErrorCode                        if (Error==1)
   } MailBoxDataUnion;*/
} ETHERCAT_SOE_HEADER, *PETHERCAT_SOE_HEADER;
#define ETHERCAT_SOE_HEADER_LEN ((int) sizeof(ETHERCAT_SOE_HEADER))

extern void init_mbx_header(PETHERCAT_MBOX_HEADER pMbox, tvbuff_t *tvb, gint offset);

#endif
