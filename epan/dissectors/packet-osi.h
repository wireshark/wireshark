/* packet-osi.h
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

#ifndef _PACKET_OSI_H
#define _PACKET_OSI_H

#include <epan/osi-utils.h>

#define PDU_TYPE_ESIS_ESH       100
#define PDU_TYPE_ESIS_ISH       101
#define PDU_TYPE_ESIS_RD        102

#define PDU_TYPE_ISIS_L1_HELLO  201
#define PDU_TYPE_ISIS_L2_HELLO  202
#define PDU_TYPE_ISIS_PTP_HELLO 203
#define PDU_TYPE_ISIS_L1_CSNP   204
#define PDU_TYPE_ISIS_L1_PSNP   205
#define PDU_TYPE_ISIS_L2_CSNP   206
#define PDU_TYPE_ISIS_L2_PSNP   207





#define PROTO_STRING_ISIS "ISO 10589 ISIS InTRA Domain Routeing Information Exchange Protocol"
#define PROTO_STRING_IDRP "ISO 10747 IDRP InTER Domain Routeing Information Exchange Protocol"
#define PROTO_STRING_ESIS "ISO 9542 ESIS Routeing Information Exchange Protocol"
#define PROTO_STRING_CLNP "ISO 8473/X.233 CLNP ConnectionLess Network Protocol"
#define PROTO_STRING_COTP "ISO 8073/X.224 COTP Connection-Oriented Transport Protocol"
#define PROTO_STRING_CLTP "ISO 8602/X.234 CLTP ConnectionLess Transport Protocol"
#define PROTO_STRING_LSP  "ISO 10589 ISIS Link State Protocol Data Unit"
#define PROTO_STRING_CSNP "ISO 10589 ISIS Complete Sequence Numbers Protocol Data Unit"
#define PROTO_STRING_PSNP "ISO 10589 ISIS Partial Sequence Numbers Protocol Data Unit"

#define OSI_PDU_TYPE_MASK 0x1f
#define BIS_PDU_TYPE MASK 0xff

/*
 * published API functions
 */

/* Exposed to be used by packet-osi-options.c */
extern int  proto_osi;

extern gboolean osi_calc_checksum( tvbuff_t *tvb, int offset, guint len, guint32* c0, guint32* c1);
extern gboolean osi_check_and_get_checksum( tvbuff_t *tvb, int offset, guint len, int offset_check, guint16* result);
extern guint32  check_atn_ec_32(tvbuff_t *tvb, guint tpdu_len, guint offset_ec_32_val, guint offset_iso8073_val, guint clnp_dst_len, const guint8 *clnp_dst, guint clnp_src_len, const guint8 *clnp_src);
extern guint16  check_atn_ec_16(tvbuff_t *tvb, guint tpdu_len, guint offset_ec_16_val, guint offset_iso8073_val, guint clnp_dst_len, const guint8 *clnp_dst, guint clnp_src_len, const guint8 *clnp_src);

#endif /* _PACKET_OSI_H */
