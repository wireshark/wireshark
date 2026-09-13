/* packet-smpte-291-vanc.h
 * Shared SMPTE ST 291 ancillary-data fields and subdissector table.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SMPTE_291_VANC_H__
#define __PACKET_SMPTE_291_VANC_H__

#include <epan/packet.h>

/*
 * Context passed by an ST 291 ANC/VANC transport to a DID/SDID subdissector.
 * The interface is transport-independent and is shared by transports such as
 * ST 2110-40 and ST 2038.
 * top_tree lets an application payload promote its decode to packet level,
 * while payload_index uniquely identifies this ANC payload within the frame.
 */
typedef struct {
    proto_tree *top_tree;
    uint32_t payload_index;
    /* The canonical full-width UDW TVB supplied by the shared dispatcher. */
    tvbuff_t *full_udw_tvb;
} st291_vanc_dissector_data_t;

/* A transport-independent ST 291 packet. words contains DID, SDID/DBN,
 * DC, the UDW values, and checksum in that order. The source members describe
 * a contiguous packed representation when one exists; transports such as raw
 * SDI can instead normalize their channel-specific storage and call the word
 * entry point. */
typedef struct {
    tvbuff_t *parent_tvb;
    const uint16_t *words;
    unsigned word_count;
    uint8_t did;
    uint8_t sdid_or_dbn;
    unsigned data_count;
    uint16_t checksum;
    uint16_t checksum_calculated;
    bool did_parity_ok;
    bool second_word_parity_ok;
    bool data_count_parity_ok;
    bool checksum_ok;
    tvbuff_t *packed_udw_tvb;
    unsigned packed_udw_bit_offset;
} st291_vanc_packet_t;

/* Extract an ST 291 DID-through-checksum sequence from a contiguous MSB-first
 * 10-bit stream. available_bits bounds this packet within its transport. */
bool st291_vanc_packet_from_packed(tvbuff_t *tvb, packet_info *pinfo,
                                   unsigned bit_offset, unsigned available_bits,
                                   st291_vanc_packet_t *packet);

/* Normalize an ST 291 DID-through-checksum sequence already extracted by a
 * transport. This is the entry point for channel-aware transports such as raw
 * SDI, where successive logical words need not be contiguous in the TVB. */
bool st291_vanc_packet_from_words(tvbuff_t *parent_tvb, packet_info *pinfo,
                                  const uint16_t *words, unsigned word_count,
                                  st291_vanc_packet_t *packet);

/* Render and dispatch a normalized ST 291 packet. payload_item identifies the
 * transport-owned User Data Words field used to scope Packet Bytes sources.
 * The public table TVB remains byte-oriented, while C subdissectors obtain all
 * ten bits per word from data->full_udw_tvb. */
bool st291_vanc_dissect_packet(const st291_vanc_packet_t *packet,
                               packet_info *pinfo, proto_tree *tree,
                               proto_item *payload_item,
                               const st291_vanc_dissector_data_t *data);

proto_item *st291_tree_add_did(proto_tree *tree, tvbuff_t *tvb,
                               int offset, int length, uint8_t did);
proto_item *st291_tree_add_sdid(proto_tree *tree, tvbuff_t *tvb,
                                int offset, int length, uint8_t did, uint8_t sdid);
proto_item *st291_tree_add_dbn(proto_tree *tree, tvbuff_t *tvb,
                               int offset, int length, uint8_t dbn);
void st291_append_packet_description(proto_item *item, uint8_t did,
                                     uint8_t sdid_or_dbn);

#endif /* __PACKET_SMPTE_291_VANC_H__ */
