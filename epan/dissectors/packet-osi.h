/* packet-osi.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

extern bool osi_calc_checksum( tvbuff_t *tvb, int offset, unsigned len, uint32_t* c0, uint32_t* c1);
extern bool osi_check_and_get_checksum( tvbuff_t *tvb, int offset, unsigned len, int offset_check, uint16_t* result);
extern uint32_t check_atn_ec_32(tvbuff_t *tvb, unsigned tpdu_len, unsigned offset_ec_32_val, unsigned offset_iso8073_val, unsigned clnp_dst_len, const uint8_t *clnp_dst, unsigned clnp_src_len, const uint8_t *clnp_src);
extern uint16_t check_atn_ec_16(tvbuff_t *tvb, unsigned tpdu_len, unsigned offset_ec_16_val, unsigned offset_iso8073_val, unsigned clnp_dst_len, const uint8_t *clnp_dst, unsigned clnp_src_len, const uint8_t *clnp_src);

#endif /* _PACKET_OSI_H */
