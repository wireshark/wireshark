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
 * Define different common tap names to extract PDU:s at different layers, otherwise one packet may
 * be exported several times at different layers if all taps are run.
 * NOTE if a new tap is added here it needs to be added to export_pdu_dlg.c and packet-exported_pdu.c
 * TODO: Use an enum_val_t instead?
 */
#define EXPORT_PDU_TAP_NAME_LAYER_3 "OSI layer 3"
#define EXPORT_PDU_TAP_NAME_LAYER_7 "OSI layer 7"
#define EXPORT_PDU_TAP_NAME_DVB_CI  "DVB-CI"

/**
 * This struct is used as the data part of tap_queue_packet() and contains a
 * buffer with metadata of the protocol PDU included in the tvb in the struct.
 * the meta data is in TLV form, at least one tag MUST indicate what protocol is
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

/* WARNING this is a first draft and tag values can be changed and tags removed
 * if you want to use this feature outside of Wireshark request a tag freeze
 * on Wireshark-dev mailing list.
 */
/* Tag values */
#define EXP_PDU_TAG_END_OF_OPT         0 /**< End-of-options Tag. */
/* 1 - 9 reserved */
#define EXP_PDU_TAG_OPTIONS_LENGTH    10 /**< Total length of the options excluding this TLV */
#define EXP_PDU_TAG_LINKTYPE          11 /**< The value part is the linktype value defined by tcpdump 
                                          * http://www.tcpdump.org/linktypes.html
                                          */ 
#define EXP_PDU_TAG_PROTO_NAME        12 /**< The value part should be an ASCII non NULL terminated string 
                                          * of the short protocol name used by Wireshark e.g "sip"
                                          * Will be used to call the next dissector.
                                          */
/* Add protocol type related tags here NOTE Only one protocol type tag may be present in a packet, the first one found will be used*/
/* 13 - 19 reserved */
#define EXP_PDU_TAG_IPV4_SRC        20
#define EXP_PDU_TAG_IPV4_DST        21
#define EXP_PDU_TAG_IPV6_SRC        22
#define EXP_PDU_TAG_IPV6_DST        23

#define EXP_PDU_TAG_PORT_TYPE       24
#define EXP_PDU_TAG_SRC_PORT        25
#define EXP_PDU_TAG_DST_PORT        26

#define EXP_PDU_TAG_SCTP_PPID       27

#define EXP_PDU_TAG_SS7_OPC         28
#define EXP_PDU_TAG_SS7_DPC         29

#define EXP_PDU_TAG_ORIG_FNO        30

#define EXP_PDU_TAG_DVBCI_EVT       31


typedef struct _exp_pdu_data_t {
    int          tlv_buffer_len;
    guint8      *tlv_buffer;
    int          tvb_length;
    tvbuff_t    *pdu_tvb;
} exp_pdu_data_t;

#define EXP_PDU_TAG_IP_SRC_BIT          0x00000001
#define EXP_PDU_TAG_IP_DST_BIT          0x00000002

#define EXP_PDU_TAG_SRC_PORT_BIT        0x00000004
#define EXP_PDU_TAG_DST_PORT_BIT        0x00000008

#define EXP_PDU_TAG_SCTP_PPID_BIT       0x00000010

#define EXP_PDU_TAG_SS7_OPC_BIT         0x00000020
#define EXP_PDU_TAG_SS7_DPC_BIT         0x00000040

#define EXP_PDU_TAG_ORIG_FNO_BIT        0x00000080

#define EXP_PDU_TAG_DVBCI_EVT_BIT       0x00000100

#define EXP_PDU_TAG_IPV4_SRC_LEN        4
#define EXP_PDU_TAG_IPV4_DST_LEN        4
#define EXP_PDU_TAG_IPV6_SRC_LEN        16
#define EXP_PDU_TAG_IPV6_DST_LEN        16

#define EXP_PDU_TAG_PORT_TYPE_LEN       4
#define EXP_PDU_TAG_SRC_PORT_LEN        4
#define EXP_PDU_TAG_DST_PORT_LEN        4

#define EXP_PDU_TAG_SCTP_PPID_LEN       4

#define EXP_PDU_TAG_SS7_OPC_LEN         8 /* 4 bytes PC, 2 bytes standard type, 1 byte NI, 1 byte padding */
#define EXP_PDU_TAG_SS7_DPC_LEN         8 /* 4 bytes PC, 2 bytes standard type, 1 byte NI, 1 byte padding */

#define EXP_PDU_TAG_ORIG_FNO_LEN        4

#define EXP_PDU_TAG_DVBCI_EVT_LEN       1

/**
 * Allocates and fills the exp_pdu_data_t struct according to the wanted_exp_tags
 * bit_fileld, if proto_name is != NULL, wtap_encap must be -1 or vice-versa
 *
 * The tags in the tag buffer SHOULD be added in numerical order.
 */
WS_DLL_PUBLIC exp_pdu_data_t *load_export_pdu_tags(packet_info *pinfo, 
                                const char* proto_name, int wtap_encap, guint32 wanted_exp_tags);
