/* packet-pgm.h
 * Declarations for pgm packet disassembly
 *
 * $Id: packet-pgm.h,v 1.4 2001/07/21 10:27:13 guy Exp $
 * 
 * Copyright (c) 2000 by Talarian Corp
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef _PACKET_PGM_H
#define _PACKET_PGM_H
typedef guint8 nchar_t;
typedef guint16 nshort_t;
typedef guint32 nlong_t;

/* The PGM main header */
typedef struct {
	nshort_t sport;            /* source port */
	nshort_t dport;            /* destination port */
	nchar_t type;              /* PGM type */
	nchar_t opts;              /* options */
	nshort_t cksum;            /* checksum */
	nchar_t gsi[6];            /* Global Source ID */
	nshort_t tsdulen;          /* TSDU length */
} pgm_type;
#define pgmhdr_ntoh(_p) \
	(_p)->sport = ntohs((_p)->sport); \
	(_p)->dport = ntohs((_p)->dport); \
	(_p)->type = ntohs((_p)->type); \
	(_p)->opts = ntohs((_p)->opts); \
	(_p)->cksum = ntohs((_p)->cksum); \
	(_p)->tsdulen = ntohs((_p)->tsdulen)

/* The PGM SPM header */
typedef struct {
	nlong_t sqn;              /* SPM's sequence number */
	nlong_t trail;            /* Trailing edge sequence number */
	nlong_t lead;             /* Leading edge sequence number */
	nshort_t path_afi;        /* NLA AFI */
	nshort_t res;             /* reserved */
	nlong_t path;             /* Path NLA */
} pgm_spm_t;
const size_t PGM_SPM_SZ = sizeof(pgm_type)+sizeof(pgm_spm_t);
#define spm_ntoh(_p) \
	(_p)->sqn = ntohl((_p)->sqn); \
	(_p)->trail = ntohl((_p)->trail); \
	(_p)->lead = ntohl((_p)->lead); \
	(_p)->path_afi = ntohs((_p)->path_afi); \
	(_p)->res = ntohs((_p)->res);

/* The PGM Data (ODATA/RDATA) header */
typedef struct {
	nlong_t sqn;              /* Data Packet sequence number */
	nlong_t trail;            /* Trailing edge sequence number */
} pgm_data_t;
#define data_ntoh(_p) \
	(_p)->sqn = ntohl((_p)->sqn); \
	(_p)->trail = ntohl((_p)->trail)
const size_t PGM_DATA_HDR_SZ = sizeof(pgm_type)+sizeof(pgm_data_t);

/* The PGM NAK (NAK/N-NAK/NCF) header */
typedef struct {
	nlong_t sqn;             /* Requested sequence number */
	nshort_t src_afi;        /* NLA AFI for source (IPv4 is set to 1) */
	nshort_t src_res;        /* reserved */
	nlong_t src;             /* Source NLA  */
	nshort_t grp_afi;        /* Multicast group AFI (IPv4 is set to 1) */
	nshort_t grp_res;        /* reserved */
	nlong_t grp;             /* Multicast group NLA */
} pgm_nak_t;
const size_t PGM_NAK_SZ = sizeof(pgm_type)+sizeof(pgm_nak_t);
#define nak_ntoh(_p) \
	(_p)->sqn = ntohl((_p)->sqn); \
	(_p)->src_afi = ntohs((_p)->src_afi); \
	(_p)->src_res = ntohs((_p)->src_res); \
	(_p)->grp_afi = ntohs((_p)->grp_afi); \
	(_p)->grp_res = ntohs((_p)->grp_res); \

/* constants for hdr types */
#if defined(PGM_SPEC_01_PCKTS)
/* old spec-01 types */
#define PGM_SPM_PCKT  0x00
#define PGM_ODATA_PCKT  0x10
#define PGM_RDATA_PCKT  0x11
#define PGM_NAK_PCKT  0x20
#define PGM_NNAK_PCKT  0x21
#define PGM_NCF_PCKT 0x30
#else
/* spec-02 types (as well as spec-04) */
#define PGM_SPM_PCKT  0x00
#define PGM_ODATA_PCKT  0x04
#define PGM_RDATA_PCKT  0x05
#define PGM_NAK_PCKT  0x08
#define PGM_NNAK_PCKT  0x09
#define PGM_NCF_PCKT 0x0A
#endif /* PGM_SPEC_01_PCKTS */

/* port swapping on NAK and NNAKs or not (default is to swap) */
/* PGM_NO_PORT_SWAP */

/* option flags (main PGM header) */
#define PGM_OPT 0x01
#define PGM_OPT_NETSIG 0x02
#define PGM_OPT_VAR_PKTLEN 0x40
#define PGM_OPT_PARITY 0x80

/* option types */
#define PGM_OPT_LENGTH 0x00
#define PGM_OPT_END 0x80
#define PGM_OPT_FRAGMENT 0x01
#define PGM_OPT_NAK_LIST 0x02
#define PGM_OPT_JOIN 0x03
#define PGM_OPT_REDIRECT 0x07
#define PGM_OPT_SYN 0x0D
#define PGM_OPT_FIN 0x0E
#define PGM_OPT_RST 0x0F
#define PGM_OPT_PARITY_PRM 0x08
#define PGM_OPT_PARITY_GRP 0x09
#define PGM_OPT_CURR_TGSIZE 0x0A

const nchar_t PGM_OPT_INVALID = 0x7F;

/* OPX bit values */
#define PGM_OPX_IGNORE	0x00
#define PGM_OPX_INVAL	0x01
#define PGM_OPX_DISCARD	0x10

/* option formats */
typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
} pgm_opt_generic_t;

typedef struct {
	nchar_t type;
	nchar_t len;
	nshort_t total_len;
} pgm_opt_length_t;

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
} pgm_opt_nak_list_t;

/* 
 * To squeeze the whole option into 255 bytes, we
 * can only have 62 in the list
 */
#define PGM_MAX_NAK_LIST_SZ (62)

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
	nlong_t opt_join_min;
} pgm_opt_join_t;

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t po;
	nlong_t prm_tgsz;
} pgm_opt_parity_prm_t;

/* OPT_PARITY_PRM P and O bits */
const nchar_t PGM_OPT_PARITY_PRM_PRO = 0x2;
const nchar_t PGM_OPT_PARITY_PRM_OND = 0x1;

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
	nlong_t prm_grp;
} pgm_opt_parity_grp_t;

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
	nlong_t prm_atgsz;
} pgm_opt_curr_tgsize_t;

#endif /* _PACKET_PGM_H */
