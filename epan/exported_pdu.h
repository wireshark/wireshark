/** @file
 * Routines for exported_pdu dissection
 * Copyright 2013, Anders Broman <anders-broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPORTED_PDU_H
#define EXPORTED_PDU_H

#include "ws_symbol_export.h"
#include "ws_attributes.h"

#include <glib.h>

#include <epan/tvbuff.h>
#include <epan/packet_info.h>

#include <wsutil/exported_pdu_tlvs.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Define different common tap names to extract PDUs at different layers,
 * otherwise one packet may be exported several times at different layers
 * if all taps are run.
 */
#define EXPORT_PDU_TAP_NAME_LAYER_3 "OSI layer 3"
#define EXPORT_PDU_TAP_NAME_LAYER_4 "OSI layer 4"
#define EXPORT_PDU_TAP_NAME_LAYER_7 "OSI layer 7"

/* To add dynamically an export name, call the following function
   It returns the registered tap */
WS_DLL_PUBLIC int register_export_pdu_tap(const char *name);
/* Same as above, but for export taps that use an encapsulation other
 * than WTAP_ENCAP_WIRESHARK_UPPER_PDU */
WS_DLL_PUBLIC int register_export_pdu_tap_with_encap(const char *name, int encap);
WS_DLL_PUBLIC GSList *get_export_pdu_tap_list(void);

WS_DLL_PUBLIC int export_pdu_tap_get_encap(const char* name);

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
typedef int (*exp_pdu_populate_data)(packet_info *pinfo, void* data, uint8_t *tlv_buffer, uint32_t tlv_buffer_size);

typedef struct exp_pdu_data_item
{
    exp_pdu_get_size size_func;
    exp_pdu_populate_data populate_data;
    void* data;
} exp_pdu_data_item_t;

/*
 * This struct is used as the data part of tap_queue_packet() and contains a
 * buffer with metadata of the protocol PDU included in the tvb in the struct.
 *
 * The metadata is a sequence of TLVs in the format for the header of
 * LINKTYPE_WIRESHARK_UPPER_PDU packets in pcap pcapng files.
 */
typedef struct _exp_pdu_data_t {
    unsigned     tlv_buffer_len;
    uint8_t     *tlv_buffer;
    unsigned     tvb_captured_length;
    unsigned     tvb_reported_length;
    tvbuff_t    *pdu_tvb;
} exp_pdu_data_t;

/**
 Allocates and fills the exp_pdu_data_t struct according to the list of items

 The tags in the tag buffer SHOULD be added in numerical order.

 @param pinfo Packet info that may contain data for the PDU items
 @param proto_name Name of protocol that is exporting PDU
 @param tag_type Tag type for protocol's PDU. Must be EXP_PDU_TAG_DISSECTOR_NAME or EXP_PDU_TAG_HEUR_DISSECTOR_NAME.
 @param items PDU items to be exported
 @return filled exp_pdu_data_t struct
*/
WS_DLL_PUBLIC exp_pdu_data_t *export_pdu_create_tags(packet_info *pinfo, const char* proto_name, uint16_t tag_type, const exp_pdu_data_item_t **items);

/**
 Allocates and fills the exp_pdu_data_t struct with a common list of items
 The items that will be exported as the PDU are:
 1. Source IP
 2. Destination IP
 3. Port type
 4. Source Port
 5. Destination Port
 6. Original frame number

 @param pinfo Packet info that may contain data for the PDU items
 @param tag_type Tag type for protocol's PDU. Must be EXP_PDU_TAG_DISSECTOR_NAME, EXP_PDU_TAG_HEUR_DISSECTOR_NAME or EXP_PDU_TAG_DISSECTOR_TABLE_NAME
 @param proto_name Name of protocol that is exporting PDU
 @return filled exp_pdu_data_t struct
*/
WS_DLL_PUBLIC exp_pdu_data_t *export_pdu_create_common_tags(packet_info *pinfo, const char *proto_name, uint16_t tag_type);

WS_DLL_PUBLIC int exp_pdu_data_dissector_table_num_value_size(packet_info *pinfo, void* data);
WS_DLL_PUBLIC int exp_pdu_data_dissector_table_num_value_populate_data(packet_info *pinfo, void* data, uint8_t *tlv_buffer, uint32_t buffer_size);

WS_DLL_PUBLIC exp_pdu_data_item_t exp_pdu_data_src_ip;
WS_DLL_PUBLIC exp_pdu_data_item_t exp_pdu_data_dst_ip;
WS_DLL_PUBLIC exp_pdu_data_item_t exp_pdu_data_port_type;
WS_DLL_PUBLIC exp_pdu_data_item_t exp_pdu_data_src_port;
WS_DLL_PUBLIC exp_pdu_data_item_t exp_pdu_data_dst_port;
WS_DLL_PUBLIC exp_pdu_data_item_t exp_pdu_data_orig_frame_num;

extern void export_pdu_init(void);

extern void export_pdu_cleanup(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* EXPORTED_PDU_H */
