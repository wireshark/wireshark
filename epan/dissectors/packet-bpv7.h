/* packet-bpv7.h
 * Definitions for Bundle Protocol Version 7 dissection.
 * References:
 *     RFC 9171: https://www.rfc-editor.org/rfc/rfc9171.html
 *
 * Copyright 2019-2021, Brian Sipos <brian.sipos@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef PACKET_BPV7_H
#define PACKET_BPV7_H

#include <ws_symbol_export.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>
#include <epan/expert.h>

#ifdef __cplusplus
extern "C" {
#endif

/* This dissector defines two layers of protocol:
 * - The BPv7 bundle format and its block types.
 * - The BPv7 Administrative Record which is a bundle payload as indicated by
 *   a primary block flag.
 *
 * BPv7 block-type-specific data (BTSD) dissectors are registered with the
 * dissector table "bpv7.block_type" and Administrative Record dissectors
 * with the table "bpv7.admin_record_type". Both use uint64_t* table keys.
 * Both use bp_dissector_data_t* as dissector user data.
 *
 * There is a BTSD heuristic dissector table "bpv7.btsd" which uses
 * bp_dissector_data_t* as dissector user data.
 *
 * Payload block (block type 1) dissection is additionally handled based on
 * bundle flags and destination EID as:
 * - If the bundle flags mark it as administrative, it is dissected as such.
 * - If the destination is a well-known SSP, the dissector table
 *   "bpv7.payload.dtn_wkssp" is used with the scheme-specific part.
 * - If the destination is "dtn" scheme, the dissector table
 *   "bpv7.payload.dtn_serv" is used with the service demux (text string).
 *   There is also Decode As behavior for dtn service demux.
 * - If the destination is "ipn" scheme, the dissector table
 *   "bpv7.payload.ipn_serv" is used with the service number (uint value).
 *   There is also Decode As behavior for ipn service number.
 * - Finally, fall through to BTSD heuristic dissection.
 * All payload dissection uses bp_dissector_data_t* as dissector user data.
 */

/** Bundle CRC types.
 * RFC 9171 Section 4.2.1.
 */
typedef enum {
    /// no CRC is present.
    BP_CRC_NONE = 0,
    /// a standard X-25 CRC-16 is present.
    BP_CRC_16 = 1,
    /// a standard CRC32C (Castagnoli) CRC-32 is present.
    BP_CRC_32 = 2,
} BundleCrcType;

/** Bundle processing control flags.
 * RFC 9171 Section 4.2.3.
 */
typedef enum {
    /// bundle deletion status reports are requested.
    BP_BUNDLE_REQ_DELETION_REPORT = 0x040000,
    /// bundle delivery status reports are requested.
    BP_BUNDLE_REQ_DELIVERY_REPORT = 0x020000,
    /// bundle forwarding status reports are requested.
    BP_BUNDLE_REQ_FORWARDING_REPORT = 0x010000,
    /// bundle reception status reports are requested.
    BP_BUNDLE_REQ_RECEPTION_REPORT = 0x004000,
    /// status time is requested in all status reports.
    BP_BUNDLE_REQ_STATUS_TIME = 0x000040,
    /// user application acknowledgement is requested.
    BP_BUNDLE_USER_APP_ACK = 0x000020,
    /// bundle must not be fragmented.
    BP_BUNDLE_NO_FRAGMENT = 0x000004,
    /// payload is an administrative record.
    BP_BUNDLE_PAYLOAD_ADMIN = 0x000002,
    /// bundle is a fragment.
    BP_BUNDLE_IS_FRAGMENT = 0x000001,
} BundleProcessingFlag;

/** Block processing control flags.
 * RFC 9171 Section 4.2.4.
 */
typedef enum {
    /// block must be removed from bundle if it can't be processed.
    BP_BLOCK_REMOVE_IF_NO_PROCESS = 0x10,
    /// bundle must be deleted if block can't be processed.
    BP_BLOCK_DELETE_IF_NO_PROCESS = 0x04,
    /// transmission of a status report is requested if block can't be processed.
    BP_BLOCK_STATUS_IF_NO_PROCESS = 0x02,
    /// block must be replicated in every fragment.
    BP_BLOCK_REPLICATE_IN_FRAGMENT = 0x01,
} BlockProcessingFlag;

/** Standard block type codes.
 * RFC 9171 Section 4.3.2 and Section 4.4.
 */
typedef enum {
    BP_BLOCKTYPE_INVALID = 0,
    /// Payload (data)
    BP_BLOCKTYPE_PAYLOAD = 1,
    /// Previous Node
    BP_BLOCKTYPE_PREV_NODE = 6,
    /// Bundle Age
    BP_BLOCKTYPE_BUNDLE_AGE = 7,
    /// Hop Count
    BP_BLOCKTYPE_HOP_COUNT = 10,
    /// Block Integrity Block
    BP_BLOCKTYPE_BIB = 11,
    /// Block Confidentiality Block
    BP_BLOCKTYPE_BCB = 12,
} BlockTypeCode;

/** Administrative record type codes.
 * RFC 9171 Section 6.1.
 */
typedef enum {
    /// Bundle status report
    BP_ADMINTYPE_BUNDLE_STATUS = 1,
} AdminRecordTypeCode;

/// DTN time with derived UTC time
typedef struct {
    /// DTN time
    uint64_t dtntime;
    /// Converted to UTC
    nstime_t utctime;
} bp_dtn_time_t;

/// Creation Timestamp used to correlate bundles
typedef struct {
    /// Absolute time
    bp_dtn_time_t abstime;
    /// Sequence number
    uint64_t seqno;
} bp_creation_ts_t;

/** Function to match the GCompareDataFunc signature.
 */
WS_DLL_PUBLIC
int bp_creation_ts_compare(const void *a, const void *b, void *user_data);

/** Endpoint ID scheme encodings.
 */
typedef enum {
    EID_SCHEME_DTN = 1,
    EID_SCHEME_IPN = 2,
} EidScheme;

/// Metadata from a Endpoint ID
typedef struct {
    /// Scheme ID number
    int64_t scheme;
    /// Derived URI text as address
    address uri;

    /// Optional DTN-scheme well-known SSP
    const char *dtn_wkssp;
    /// Optional DTN-scheme service name
    const char *dtn_serv;
    /// Optional IPN-scheme service name
    uint64_t *ipn_serv;
} bp_eid_t;

/** Construct a new timestamp.
 */
WS_DLL_PUBLIC
bp_eid_t * bp_eid_new(wmem_allocator_t *alloc);

/** Function to match the GDestroyNotify signature.
 */
WS_DLL_PUBLIC
void bp_eid_free(wmem_allocator_t *alloc, bp_eid_t *obj);

/** Function to match the GCompareFunc signature.
 */
WS_DLL_PUBLIC
bool bp_eid_equal(const void *a, const void *b);

/// Security marking metadata
typedef struct {
    /// Block numbers marking the data as security integrity protected
    wmem_map_t *data_i;
    /// Block numbers marking the data as security-modified and not decodable
    wmem_map_t *data_c;
} security_mark_t;

/// Metadata extracted from the primary block
typedef struct {
    /// Display item for the whole block
    proto_item *item_block;

    /// Bundle flags (assumed zero).
    /// Values are BundleProcessingFlag.
    uint64_t flags;
    /// Destination EID
    bp_eid_t *dst_eid;
    /// Source NID
    bp_eid_t *src_nodeid;
    /// Report-to NID
    bp_eid_t *rep_nodeid;
    /// Creation Timestamp
    bp_creation_ts_t ts;
    /// Optional fragment start offset
    uint64_t *frag_offset;
    /// Optional bundle total length
    uint64_t *total_len;
    /// CRC type code (assumed zero)
    uint64_t crc_type;
    /// Raw bytes of CRC field
    tvbuff_t *crc_field;

    security_mark_t sec;
} bp_block_primary_t;

/** Construct a new object on the file allocator.
 */
WS_DLL_PUBLIC
bp_block_primary_t * bp_block_primary_new(wmem_allocator_t *alloc);

/** Function to match the GDestroyNotify signature.
 */
WS_DLL_PUBLIC
void bp_block_primary_free(wmem_allocator_t *alloc, bp_block_primary_t *obj);

typedef struct {
    /// The index of the block within the bundle.
    /// This is for internal bookkeeping, *not* the block number.
    uint64_t blk_ix;
    /// Display item for the whole block
    proto_item *item_block;

    /// Type of this block
    uint64_t *type_code;
    /// Unique identifier for this block
    uint64_t *block_number;
    /// All flags on this block
    uint64_t flags;
    /// CRC type code (assumed zero)
    uint64_t crc_type;
    /// Raw bytes of CRC field
    tvbuff_t *crc_field;

    /// Type-specific data, unencoded
    tvbuff_t *data;
    /// Type-specific data tree
    proto_tree *tree_data;

    security_mark_t sec;
} bp_block_canonical_t;

/** Construct a new object on the file allocator.
 * @param blk_ix The index of the block within the bundle.
 * The canonical index is always greater than zero.
 */
WS_DLL_PUBLIC
bp_block_canonical_t * bp_block_canonical_new(wmem_allocator_t *alloc, uint64_t blk_ix);

WS_DLL_PUBLIC
void bp_block_canonical_delete(wmem_allocator_t *alloc, bp_block_canonical_t *obj);

/// Identification of an individual bundle
typedef struct {
    /// Normalized EID URI for the Source Node ID
    address src;
    /// Creation Timestamp
    bp_creation_ts_t ts;
    /// Pointer to external optional fragment start offset
    const uint64_t *frag_offset;
    /// Pointer to external optional bundle total length
    const uint64_t *total_len;
} bp_bundle_ident_t;

/** Construct a new object on the file allocator.
 * @param alloc The allocator to use.
 * @param src The non-null pointer to source EID.
 * @param ts The non-null pointer to Timestamp.
 * @param off Optional fragment offset value.
 * @param len Optional fragment length value.
 */
WS_DLL_PUBLIC
bp_bundle_ident_t * bp_bundle_ident_new(wmem_allocator_t *alloc, const bp_eid_t *src, const bp_creation_ts_t *ts, const uint64_t *off, const uint64_t *len);

WS_DLL_PUBLIC
void bp_bundle_ident_free(wmem_allocator_t *alloc, bp_bundle_ident_t *obj);

/** Function to match the GEqualFunc signature.
 */
WS_DLL_PUBLIC
gboolean bp_bundle_ident_equal(const void *a, const void *b);

/** Function to match the GHashFunc signature.
 */
WS_DLL_PUBLIC
unsigned bp_bundle_ident_hash(const void *key);

/// Metadata extracted per-bundle
typedef struct {
    /// Index of the frame
    uint32_t frame_num;
    /// Layer within the frame
    uint8_t layer_num;
    /// Timestamp on the frame (end time if reassembled)
    nstime_t frame_time;
    /// Bundle identity derived from #primary data
    bp_bundle_ident_t *ident;
    /// Required primary block
    bp_block_primary_t *primary;
    /// Additional blocks in order (type bp_block_canonical_t)
    wmem_list_t *blocks;
    /// Map from block number (uint64_t) to pointer to block of that number
    /// (bp_block_canonical_t owned by #blocks)
    wmem_map_t *block_nums;
    /// Map from block type code (uint64_t) to sequence (wmem_list_t) of
    /// pointers to block of that type (bp_block_canonical_t owned by #blocks)
    wmem_map_t *block_types;

    /// Payload BTSD start offset in bundle TVB
    unsigned *pyld_start;
    /// Payload BTSD length
    unsigned *pyld_len;
} bp_bundle_t;

/** Construct a new object on the file allocator.
 */
WS_DLL_PUBLIC
bp_bundle_t * bp_bundle_new(wmem_allocator_t *alloc);

/** Function to match the GDestroyNotify signature.
 */
WS_DLL_PUBLIC
void bp_bundle_free(wmem_allocator_t *alloc, bp_bundle_t *obj);

/** Extract an Endpoint ID.
 * All EID fields are allocated with wmem_file_scope().
 *
 * @param tree The tree to write items under.
 * @param hfindex The root item field.
 * @param hfindex_uri The reassembled URI item field.
 * @param pinfo Packet info to update.
 * @param tvb Buffer to read from.
 * @param[in,out] offset Starting offset within @c tvb.
 * @param[out] eid If non-null, the EID to write to.
 * @return The new tree item.
 */
WS_DLL_PUBLIC
proto_item * proto_tree_add_cbor_eid(proto_tree *tree, int hfindex, int hfindex_uri, packet_info *pinfo, tvbuff_t *tvb, int *offset, bp_eid_t *eid);

/// Metadata for an entire file
typedef struct {
    /// Map from a bundle ID (bp_bundle_ident_t) to wmem_list_t of bundle (bp_bundle_t)
    wmem_map_t *bundles;
    /// Map from subject bundle ID (bp_bundle_ident_t) to
    /// map from references (bp_bundle_ident_t) of status bundles to NULL
    /// i.e. a set
    wmem_map_t *admin_status;
} bp_history_t;

/** Data supplied to each block sub-dissector.
 */
typedef struct {
    /// The overall bundle being decoded (so far)
    bp_bundle_t *bundle;
    /// This block being decoded
    bp_block_canonical_t *block;
} bp_dissector_data_t;

#ifdef __cplusplus
}
#endif

#endif /* PACKET_BPV7_H */
