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
} st291_vanc_dissector_data_t;

dissector_table_t st291_get_did_sdid_table(void);

proto_item *st291_tree_add_did(proto_tree *tree, tvbuff_t *tvb,
                               int offset, int length, uint8_t did);
proto_item *st291_tree_add_sdid(proto_tree *tree, tvbuff_t *tvb,
                                int offset, int length, uint8_t did, uint8_t sdid);
proto_item *st291_tree_add_dbn(proto_tree *tree, tvbuff_t *tvb,
                               int offset, int length, uint8_t dbn);
void st291_append_packet_description(proto_item *item, uint8_t did,
                                     uint8_t sdid_or_dbn);

#endif /* __PACKET_SMPTE_291_VANC_H__ */
