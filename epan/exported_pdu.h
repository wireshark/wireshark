/*
 * exported_pdu.h
 * Routines for exported_pdu dissection
 * Copyright 2013, Anders Broman <anders-broman@ericsson.com>
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

#ifndef EXPORTED_PDU_H
#define EXPORTED_PDU_H

#include <config.h>

#include "ws_symbol_export.h"

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Define different common tap names to extract PDUs at different layers,
 * otherwise one packet may be exported several times at different layers
 * if all taps are run.
 */
#define EXPORT_PDU_TAP_NAME_LAYER_3 "OSI layer 3"
#define EXPORT_PDU_TAP_NAME_LAYER_7 "OSI layer 7"

/* To add dynamically an export name, call the following function
   It returns the registered tap */
WS_DLL_PUBLIC gint register_export_pdu_tap(const char *name);
WS_DLL_PUBLIC GSList *get_export_pdu_tap_list(void);

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

/*  Tag values
 *
 *  Do NOT add new values to this list without asking
 *  wireshark-dev[AT]wireshark.org for a value. Otherwise, you run the risk of
 *  using a value that's already being used for some other purpose, and of
 *  having tools that read exported_pdu captures not being able to handle
 *  captures with your new tag value, with no hope that they will ever be
 *  changed to do so (as that would destroy their ability to read captures
 *  using that value for that other purpose).
 */
#define EXP_PDU_TAG_END_OF_OPT         0 /**< End-of-options Tag. */
/* 1 - 9 reserved */
#define EXP_PDU_TAG_OPTIONS_LENGTH    10 /**< Total length of the options excluding this TLV */
#define EXP_PDU_TAG_LINKTYPE          11 /**< Deprecated - do not use */
#define EXP_PDU_TAG_PROTO_NAME        12 /**< The value part should be an ASCII non NULL terminated string
                                          * of the registered dissector used by Wireshark e.g "sip"
                                          * Will be used to call the next dissector.
                                          */
#define EXP_PDU_TAG_HEUR_PROTO_NAME   13 /**< The value part should be an ASCII non NULL terminated string
                                          * containing the heuristic unique short protocol name given
                                          * during registration, e.g "sip_udp"
                                          * Will be used to call the next dissector.
                                          */
#define EXP_PDU_TAG_DISSECTOR_TABLE_NAME 14 /**< The value part should be an ASCII non NULL terminated string
                                          * containing the dissector table name given
                                          * during registration, e.g "gsm_map.v3.arg.opcode"
                                          * Will be used to call the next dissector.
                                          */

/* Add protocol type related tags here.
 * NOTE Only one protocol type tag may be present in a packet, the first one
 * found will be used*/
/* 13 - 19 reserved */
#define EXP_PDU_TAG_IPV4_SRC        20
#define EXP_PDU_TAG_IPV4_DST        21
#define EXP_PDU_TAG_IPV6_SRC        22
#define EXP_PDU_TAG_IPV6_DST        23

#define EXP_PDU_TAG_PORT_TYPE       24  /**< value part is port_type enum from epan/address.h */
#define EXP_PDU_TAG_SRC_PORT        25
#define EXP_PDU_TAG_DST_PORT        26

#define EXP_PDU_TAG_SS7_OPC         28
#define EXP_PDU_TAG_SS7_DPC         29

#define EXP_PDU_TAG_ORIG_FNO        30

#define EXP_PDU_TAG_DVBCI_EVT       31

#define EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL 32 /**< value part is the numeric value to be used calling the dissector table
                                                      *  given with tag EXP_PDU_TAG_DISSECTOR_TABLE_NAME, must follow immediately after the table tag.
                                                      */

#define EXP_PDU_TAG_COL_PROT_TEXT   33 /**< Text string to put in COL_PROTOCOL, one use case is in conjunction with dissector tables where
                                        *   COL_PROTOCOL might not be filled in.
                                        */

typedef struct _exp_pdu_data_t {
    guint        tlv_buffer_len;
    guint8      *tlv_buffer;
    guint        tvb_captured_length;
    guint        tvb_reported_length;
    tvbuff_t    *pdu_tvb;
} exp_pdu_data_t;

#define EXP_PDU_TAG_IPV4_LEN            4
#define EXP_PDU_TAG_IPV6_LEN            16

#define EXP_PDU_TAG_PORT_TYPE_LEN       4
#define EXP_PDU_TAG_PORT_LEN            4

#define EXP_PDU_TAG_SS7_OPC_LEN         8 /* 4 bytes PC, 2 bytes standard type, 1 byte NI, 1 byte padding */
#define EXP_PDU_TAG_SS7_DPC_LEN         8 /* 4 bytes PC, 2 bytes standard type, 1 byte NI, 1 byte padding */

#define EXP_PDU_TAG_ORIG_FNO_LEN        4

#define EXP_PDU_TAG_DVBCI_EVT_LEN       1

/** Compute the size (in bytes) of a pdu item
*
@param pinfo Packet info that may contain data for the pdu item
@param data optional data of the pdu item
@return the size of the pdu item
*/
typedef int (*exp_pdu_get_size)(packet_info *pinfo, void* data);

/** Populate a buffer with pdu item data
*
@param pinfo Packet info that may contain data for the PDU item
@param data optional data of the PDU item
@param tlv_buffer buffer to be populated with PDU item
@param tlv_buffer_size size of buffer to be populated
@return the number of bytes populated to the buffer (typically PDU item size)
*/
typedef int (*exp_pdu_populate_data)(packet_info *pinfo, void* data, guint8 *tlv_buffer, guint32 tlv_buffer_size);

typedef struct exp_pdu_data_item
{
    exp_pdu_get_size size_func;
    exp_pdu_populate_data populate_data;
    void* data;
} exp_pdu_data_item_t;

/**
 Allocates and fills the exp_pdu_data_t struct according to the list of items

 The tags in the tag buffer SHOULD be added in numerical order.

 @param pinfo Packet info that may contain data for the PDU items
 @param proto_name Name of protocol that is exporting PDU
 @param tag_type Tag type for protocol's PDU. Must be EXP_PDU_TAG_PROTO_NAME or EXP_PDU_TAG_HEUR_PROTO_NAME.
 @param items PDU items to be exported
 @return filled exp_pdu_data_t struct
*/
WS_DLL_PUBLIC exp_pdu_data_t *export_pdu_create_tags(packet_info *pinfo, const char* proto_name, guint16 tag_type, const exp_pdu_data_item_t **items);

/**
 Allocates and fills the exp_pdu_data_t struct with a common list of items
 The items that will be exported as the PDU are:
 1. Source IP
 2. Destintaiton IP
 3. Port type
 4. Source Port
 5. Destination Port
 6. Original frame number

 @param pinfo Packet info that may contain data for the PDU items
 @param tag_type Tag type for protocol's PDU. Must be EXP_PDU_TAG_PROTO_NAME, EXP_PDU_TAG_HEUR_PROTO_NAME or EXP_PDU_TAG_DISSECTOR_TABLE_NAME
 @param proto_name Name of protocol that is exporting PDU
 @return filled exp_pdu_data_t struct
*/
WS_DLL_PUBLIC exp_pdu_data_t *export_pdu_create_common_tags(packet_info *pinfo, const char *proto_name, guint16 tag_type);

WS_DLL_PUBLIC exp_pdu_data_item_t exp_pdu_data_src_ip;
WS_DLL_PUBLIC exp_pdu_data_item_t exp_pdu_data_dst_ip;
WS_DLL_PUBLIC exp_pdu_data_item_t exp_pdu_data_port_type;
WS_DLL_PUBLIC exp_pdu_data_item_t exp_pdu_data_src_port;
WS_DLL_PUBLIC exp_pdu_data_item_t exp_pdu_data_dst_port;
WS_DLL_PUBLIC exp_pdu_data_item_t exp_pdu_data_orig_frame_num;

extern void export_pdu_init(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* EXPORTED_PDU_H */
