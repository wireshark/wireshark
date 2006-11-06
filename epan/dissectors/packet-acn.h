/* packet-acn.h
 * Routines for ACN packet disassembly
 *
 * $Id$
 *
 * Copyright (c) 2003 by Erwin Rol <erwin@erwinrol.com>
 * Copyright (c) 2006 by Electronic Theatre Controls, Inc.
 *                    Bill Florac <bflorac@etcconnect.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

 /*
    Version: 0.0.9   wrf 10-25-2006 Released to Wireshark community
    Version: 0.0.10  wrf 10-25-2006 small revisions to submit...
    Version: 0.0.11  wrf 10-29-2006 revisions to submit...
 */
 
#ifndef PACKET_ACN_H__
#define PACKET_ACN_H__

// pdu flags
#define ACN_PDU_FLAG_L		0x80
#define ACN_PDU_FLAG_V		0x40
#define ACN_PDU_FLAG_H  	0x20
#define ACN_PDU_FLAG_D		0x10

#define ACN_DMP_ADT_FLAG_V 0x80
#define ACN_DMP_ADT_FLAG_R 0x40
#define ACN_DMP_ADT_FLAG_D 0x30               
#define ACN_DMP_ADT_FLAG_X 0xc0
#define ACN_DMP_ADT_FLAG_A 0x03

#define ACN_DMP_ADT_V_VIRTUAL   0
#define ACN_DMP_ADT_V_ACTUAL    1

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

#define ACN_PROTOCOL_ID_SDT           1
#define ACN_PROTOCOL_ID_DMP           2
#define ACN_PROTOCOL_ID_DMX           3

#define ACN_ADDR_NULL                 0
#define ACN_ADDR_IPV4                 1
#define ACN_ADDR_IPV6                 2
#define ACN_ADDR_IPPORT               3

// STD Messages
#define ACN_SDT_VECTOR_UNKNOWN        0
#define ACN_SDT_VECTOR_REL_WRAP       1
#define ACN_SDT_VECTOR_UNREL_WRAP     2
#define ACN_SDT_VECTOR_CHANNEL_PARAMS 3
#define ACN_SDT_VECTOR_JOIN           4
#define ACN_SDT_VECTOR_JOIN_REFUSE    5
#define ACN_SDT_VECTOR_JOIN_ACCEPT    6
#define ACN_SDT_VECTOR_LEAVE          7
#define ACN_SDT_VECTOR_LEAVING        8
#define ACN_SDT_VECTOR_CONNECT        9
#define ACN_SDT_VECTOR_CONNECT_ACCEPT 10
#define ACN_SDT_VECTOR_CONNECT_REFUSE 11
#define ACN_SDT_VECTOR_DISCONNECT     12
#define ACN_SDT_VECTOR_DISCONNECTING  13
#define ACN_SDT_VECTOR_ACK            14
#define ACN_SDT_VECTOR_NAK            15
#define ACN_SDT_VECTOR_GET_SESSION    16
#define ACN_SDT_VECTOR_SESSIONS       17

#define ACN_REFUSE_CODE_NONSPECIFIC     1
#define ACN_REFUSE_CODE_ILLEGAL_PARAMS  2  
#define ACN_REFUSE_CODE_LOW_RESOURCES   3
#define ACN_REFUSE_CODE_ALREADY_MEMBER  4  
#define ACN_REFUSE_CODE_BAD_ADDR_TYPE   5
#define ACN_REFUSE_CODE_NO_RECIP_CHAN   6

#define ACN_REASON_CODE_NONSPECIFIC         1
/*#define ACN_REASON_CODE_                  2 */
/*#define ACN_REASON_CODE_                  3 */
/*#define ACN_REASON_CODE_                  4 */
/*#define ACN_REASON_CODE_                  5 */
#define ACN_REASON_CODE_NO_RECIP_CHAN       6
#define ACN_REASON_CODE_CHANNEL_EXPIRED     7
#define ACN_REASON_CODE_LOST_SEQUENCE       8
#define ACN_REASON_CODE_SATURATED           9
#define ACN_REASON_CODE_TRANS_ADDR_CHANGING 10
#define ACN_REASON_CODE_ASKED_TO_LEAVE      11
#define ACN_REASON_CODE_NO_RECIPIENT        12

#define ACN_DMP_VECTOR_UNKNOWN              0
#define ACN_DMP_VECTOR_GET_PROPERTY         1
#define ACN_DMP_VECTOR_SET_PROPERTY         2
#define ACN_DMP_VECTOR_GET_PROPERTY_REPLY   3
#define ACN_DMP_VECTOR_EVENT                4
#define ACN_DMP_VECTOR_MAP_PROPERTY         5
#define ACN_DMP_VECTOR_UNMAP_PROPERTY       6
#define ACN_DMP_VECTOR_SUBSCRIBE            7
#define ACN_DMP_VECTOR_UNSUBSCRIBE          8
#define ACN_DMP_VECTOR_GET_PROPERTY_FAIL    9
#define ACN_DMP_VECTOR_SET_PROPERTY_FAIL    10
#define ACN_DMP_VECTOR_MAP_PROPERTY_FAIL    11
#define ACN_DMP_VECTOR_SUBSCRIBE_ACCEPT     12
#define ACN_DMP_VECTOR_SUBSCRIBE_REJECT     13
#define ACN_DMP_VECTOR_ALLOCATE_MAP         14
#define ACN_DMP_VECTOR_ALLOCATE_MAP_REPLY   15
#define ACN_DMP_VECTOR_DEALLOCATE_MAP       16

#define ACN_DMP_REASON_CODE_NONSPECIFIC                 1
#define ACN_DMP_REASON_CODE_NOT_A_PROPERTY              2
#define ACN_DMP_REASON_CODE_WRITE_ONLY                  3
#define ACN_DMP_REASON_CODE_NOT_WRITABLE                4
#define ACN_DMP_REASON_CODE_DATA_ERROR                  5
#define ACN_DMP_REASON_CODE_MAPS_NOT_SUPPORTED          6
#define ACN_DMP_REASON_CODE_SPACE_NOT_AVAILABLE         7
#define ACN_DMP_REASON_CODE_PROP_NOT_MAPABLE            8
#define ACN_DMP_REASON_CODE_MAP_NOT_ALLOCATED           9
#define ACN_DMP_REASON_CODE_SUBSCRIPTION_NOT_SUPPORTED  10
#define ACN_DMP_REASON_CODE_NO_SUBSCRIPTIONS_SUPPORTED  11



#define ACN_DMX_VECTOR      2

#define ACN_PREF_DMX_DISPLAY_HEX  0
#define ACN_PREF_DMX_DISPLAY_DEC  1
#define ACN_PREF_DMX_DISPLAY_PER  2


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
  union {
  guint8  byte;
    struct {
    guint8  dummy:4;
    guint8  D:1;
    guint8  H:1;
    guint8  V:1;
    guint8  L:1;
    };
  };
} acn_pdu_flags;


typedef struct
{
  union {
  guint8  byte;
    struct {
      guint8  A:2; //A1, A0 = Size of Address elements
      guint8  X:2; //X1, X0 = These bits are reserved and their values shall be set to 0 when encoded. Their values shall be ignored when decoding.
      guint8  D:2; //D1, D0 = Specify non-range or range address, single data, equal size or mixed size data array 
      guint8  R:1; //R = Specifies whether address is relative to last valid address in packet or not.
      guint8  V:1; //V = Specifies whether address is a virtual address or not.
    };
  };
  guint32 address;  /* or first address */
  guint32 increment;
  guint32 count;
  guint32 size;
  guint32 data_length;
} acn_dmp_adt_type;

#endif /* !PACKET_ACN_H */
