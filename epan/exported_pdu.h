/* 
 * exported_pdu.h
 * Routines for exported_pdu dissection
 * Copyright 2013, Anders Broman <anders-broman@ericsson.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

/**
 * This struct is used as the data part of tap_queue_packet() and contains a
 * buffer with metadata of the protocol PDU included in the tvb in the struct.
 * the meta data is in TLV form, at least one tag MUST indicat what protocol is
 * in the PDU.
 * Buffer layout:
 *   0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Option Code              |         Option Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                       Option Value                            /
 * /             variable length, aligned to 32 bits               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * /                                                               /
 * /                 . . . other options . . .                     /
 * /                                                               /
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Option Code == opt_endofopt  |  Option Length == 0          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/* Tag values */
#define EXP_PDU_TAG_END_OF_OPT         0 /**< End-of-options Tag. 
/* 1 - 9 reserved */
#define EXP_PDU_TAG_OPTIONS_LENGTH    10 /**< Total length of the options exluding this TLV */
#define EXP_PDU_TAG_LINKTYPE          11 /**< The value part is the linktype value defined by tcpdump 
                                          * http://www.tcpdump.org/linktypes.html
                                          */ 
#define EXP_PDU_TAG_PROTO_NAME        12 /**< The value part should be an ASCII non NULL terminated string 
                                          * of the sort protocol name used by Wireshark e.g "sip"
                                          * Will be used to call the next dissector.
                                          */
/* Add protocol type related tags here */
/* 13 - 19 reserved */
#define EXP_PDU_TAG_IPV4_SRC        20
#define EXP_PDU_TAG_IPV4_DST        21
#define EXP_PDU_TAG_IPV6_SRC        21
#define EXP_PDU_TAG_IPV6_DST        22

#define EXP_PDU_TAG_SRC_PORT        23
#define EXP_PDU_TAG_DST_PORT        24

#define EXP_PDU_TAG_SCTP_PPID       25

#define EXP_PDU_TAG_SS7_OPC         26
#define EXP_PDU_TAG_SS7_DPC         27


typedef struct _exp_pdu_data_t {
    int          tlv_buffer_len;
    guint8      *tlv_buffer;
    int          tvb_length;
    tvbuff_t    *pdu_tvb;
} exp_pdu_data_t;
