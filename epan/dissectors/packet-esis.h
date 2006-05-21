/* packet-esis.h
 * Defines and such for ESIS protocol decode.
 *
 * $Id$
 * Ralf Schneider <Ralf.Schneider@t-online.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 *
 *
 */

#ifndef _PACKET_ESIS_H
#define _PACKET_ESIS_H

/* The version we support is 1 */
#define ESIS_REQUIRED_VERSION    1

/* ESIS PDU types */
#define ESIS_ESH_PDU    02
#define ESIS_ISH_PDU    04
#define ESIS_RD_PDU     06

/* The length of the fixed part */
#define ESIS_HDR_FIXED_LENGTH 9

/* Inline Defines for masking */
#define esis_type esis_type_reserved&OSI_PDU_TYPE_MASK
#define esis_r8   esis_type_reserved&BIT_8
#define esis_r7   esis_type_reserved&BIT_7
#define esis_r6   esis_type_reserved&BIT_6

/* The fixed part (9 octets) of the ESIS protocol header */
typedef struct {
  guint8 esis_nlpi;           /* Network Layer Protocol Identifier == 0x82   */
  guint8 esis_length;         /* Header ( PDU too, NoData ) length in octets */
  guint8 esis_version;        /* ISIS version, must be 0x01 */
  guint8 esis_reserved;       /* reserved byte, must be 0   */
  guint8 esis_type_reserved;  /* packet type & MS-Bits (8-6) reserved */
  guint8 esis_holdtime[2];    /* Maximum time (sec) this PDU is valid */
  guint8 esis_checksum[2];    /* Computed on whole PDU Header, 0 means ignore */
} esis_hdr_t;

#endif /* _PACKET_ESIS_H */
