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
#include <wsutil/value_string.h>

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

/* X.263 / ISO/IEC TR 9577 NLPID values. */

#define NLPID_NULL		0x00
#define NLPID_IPI_T_70		0x01	/* T.70, when an IPI */
#define NLPID_SPI_X_29		0x01	/* X.29, when an SPI */
#define NLPID_X_633		0x03	/* X.633 */
#define NLPID_DMS		0x03	/* Maintenace messages: AT&T TR41459, Nortel NIS A211-1, Telcordia SR-4994, ... */
#define NLPID_Q_931		0x08	/* Q.931, Q.932, X.36, ISO 11572, ISO 11582 */
#define NLPID_Q_933		0x08	/* Q.933, on Frame Relay */
#define NLPID_Q_2931		0x09	/* Q.2931 */
#define NLPID_Q_2119		0x0c	/* Q.2119 */
#define NLPID_SNAP		0x80
#define NLPID_ISO8473_CLNP	0x81	/* X.233 */
#define NLPID_ISO9542_ESIS	0x82
#define NLPID_ISO10589_ISIS	0x83
#define NLPID_ISO10747_IDRP	0x85
#define NLPID_ISO9542X25_ESIS	0x8a
#define NLPID_ISO10030		0x8c
#define NLPID_ISO11577		0x8d	/* X.273 */
#define NLPID_IP6		0x8e
#define NLPID_AVAYA_IPVPN	0x8f	/* Avaya/Extreme Fabric (SPBM) IPVPN */
#define NLPID_COMPRESSED	0xb0	/* "Data compression protocol" */
#define NLPID_TRILL		0xc0
#define NLPID_SNDCF		0xc1	/* "SubNetwork Dependent Convergence Function */
#define NLPID_IEEE_8021AQ	0xc1	/* IEEE 802.1aq (draft-ietf-isis-ieee-aq-05.txt); defined in context of ISIS "supported protocols" TLV */
#define NLPID_IP		0xcc
#define NLPID_PPP		0xcf

extern const value_string nlpid_vals[];

/*
 * 0x09 is, in Frame Relay, LMI, Q.2931.
 */
#define NLPID_LMI		0x09	/* LMI */

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
