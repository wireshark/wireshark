/* packet-osi.h
 *
 * $Id: packet-osi.h,v 1.6 2001/03/30 10:51:50 guy Exp $
 *
 * Ethereal - Network traffic analyzer
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
*/

#ifndef _PACKET_OSI_H
#define _PACKET_OSI_H

/* OSI Global defines, common for all OSI protocols */

#define MAX_NSAP_LEN          30    
#define MAX_SYSTEMID_LEN      15    
#define MAX_AREA_LEN          30    

#define RFC1237_NSAP_LEN      20
#define RFC1237_FULLAREA_LEN  13
#define RFC1237_SYSTEMID_LEN   6
#define RFC1237_SELECTOR_LEN   1

#define RFC1237_IDI_LEN        2
#define RFC1237_AFI_LEN        1
#define RFC1237_DFI_LEN        1
#define RFC1237_ORG_LEN        3
#define RFC1237_AA_LEN         3
#define RFC1237_RSVD_LEN       2
#define RFC1237_RD_LEN         2
#define RFC1237_AREA_LEN       3


#define NSAP_IDI_ISODCC       0x39
#define NSAP_IDI_GOSIP2       0x47

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
#define PROTO_STRING_CLNP "ISO 8473 CLNP ConnectionLess Network Protocol" 
#define PROTO_STRING_COTP "ISO 8073 COTP Connection-Oriented Transport Protocol"
#define PROTO_STRING_CLTP "ISO 8602 CLTP ConnectionLess Transport Protocol"
#define PROTO_STRING_LSP  "ISO 10589 ISIS Link State Protocol Data Unit"
#define PROTO_STRING_CSNP "ISO 10589 ISIS Complete Sequence Numbers Protocol Data Unit"
#define PROTO_STRING_PSNP "ISO 10589 ISIS Partial Sequence Numbers Protocol Data Unit"

#define OSI_PDU_TYPE_MASK 0x1f
#define BIS_PDU_TYPE MASK 0xff
                             

#define BIT_1   0x01
#define BIT_2   0x02
#define BIT_3   0x04
#define BIT_4   0x08
#define BIT_5   0x10
#define BIT_6   0x20
#define BIT_7   0x40
#define BIT_8   0x80

#define BIT_9   0x0100
#define BIT_10  0x0200
#define BIT_11  0x0400
#define BIT_12  0x0800
#define BIT_13  0x1000
#define BIT_14  0x2000
#define BIT_15  0x4000
#define BIT_16  0x8000

/*
 * Dissector table for NLPIDs for protocols whose packets begin with
 * the NLPID.
 */
dissector_table_t osinl_subdissector_table;

/*
 * published API functions
 */

extern gchar *print_nsap_net ( const u_char *, int );
extern gchar *print_area     ( const u_char *, int );
extern gchar *print_system_id( const u_char *, int );
extern gchar *calc_checksum  ( tvbuff_t *, int, u_int, u_int );

#endif /* _PACKET_OSI_H */
