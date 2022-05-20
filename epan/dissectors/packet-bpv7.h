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
 * with the table "bpv7.admin_record_type". Both use guint64* table keys.
 * Both use bp_dissector_data_t* as dissector user data.
 *
 * There is a BTSD heuristic dissector table "bpv7.btsd" which uses
 * bp_dissector_data_t* as dissector user data.
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
    guint64 dtntime;
    /// Converted to UTC
    nstime_t utctime;
} bp_dtn_time_t;

/// Creation Timestamp used to correlate bundles
typedef struct {
    /// Absolute time
    bp_dtn_time_t abstime;
    /// Sequence number
    guint64 seqno;
} bp_creation_ts_t;

/** Construct a new timestamp.
 */
WS_DLL_PUBLIC
bp_creation_ts_t * bp_creation_ts_alloc(wmem_allocator_t *alloc);

/** Function to match the GDestroyNotify signature.
 */
WS_DLL_PUBLIC
void bp_creation_ts_free(wmem_allocator_t *alloc, bp_creation_ts_t *obj);

/** Function to match the GCompareDataFunc signature.
 */
WS_DLL_PUBLIC
gint bp_creation_ts_compare(gconstpointer a, gconstpointer b, gpointer user_data);

/** Endpoint ID scheme encodings.
 */
typedef enum {
    EID_SCHEME_DTN = 1,
    EID_SCHEME_IPN = 2,
} EidScheme;

/// Metadata from a Endpoint ID
typedef struct {
    /// Scheme ID number
    gint64 scheme;
    /// Derived URI text
    const char *uri;

    /// Optional DTN well-known SSP
    const char *dtn_wkssp;
    /// Optional URI authority part
//    const char *node_name;
    /// Optional DTN service name
    const char *dtn_serv;
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
gboolean bp_eid_equal(gconstpointer a, gconstpointer b);

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
    guint64 flags;
    /// Destination EID
    bp_eid_t *dst_eid;
    /// Source NID
    bp_eid_t *src_nodeid;
    /// Report-to NID
    bp_eid_t *rep_nodeid;
    /// Creation Timestamp
    bp_creation_ts_t ts;
    /// Optional fragment start offset
    guint64 *frag_offset;
    /// Optional bundle total length
    guint64 *total_len;
    /// CRC type code (assumed zero)
    BundleCrcType crc_type;
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
    guint64 blk_ix;
    /// Display item for the whole block
    proto_item *item_block;

    /// Type of this block
    guint64 *type_code;
    /// Unique identifier for this block
    guint64 *block_number;
    /// All flags on this block
    guint64 flags;
    /// CRC type code (assumed zero)
    BundleCrcType crc_type;
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
bp_block_canonical_t * bp_block_canonical_new(wmem_allocator_t *alloc, guint64 blk_ix);

WS_DLL_PUBLIC
void bp_block_canonical_delete(wmem_allocator_t *alloc, bp_block_canonical_t *obj);

/// Identification of an individual bundle
typedef struct {
    /// Normalized EID URI for the Source Node ID
    const char *src;
    /// Pointer to an external Creation Timestamp
    bp_creation_ts_t *ts;
    /// Pointer to external optional fragment start offset
    guint64 *frag_offset;
    /// Pointer to external optional bundle total length
    guint64 *total_len;
} bp_bundle_ident_t;

/** Construct a new object on the file allocator.
 */
WS_DLL_PUBLIC
bp_bundle_ident_t * bp_bundle_ident_new(wmem_allocator_t *alloc, bp_eid_t *src, bp_creation_ts_t *ts, guint64 *off, guint64 *len);

WS_DLL_PUBLIC
void bp_bundle_ident_free(wmem_allocator_t *alloc, bp_bundle_ident_t *obj);

/** Function to match the GCompareFunc signature.
 */
WS_DLL_PUBLIC
gboolean bp_bundle_ident_equal(gconstpointer a, gconstpointer b);

/** Function to match the GHashFunc signature.
 */
WS_DLL_PUBLIC
guint bp_bundle_ident_hash(gconstpointer key);

/// Metadata extracted per-bundle
typedef struct {
    /// Index of the frame
    guint32 frame_num;
    /// Timestamp on the frame (end time if reassembled)
    nstime_t frame_time;
    /// Bundle identity derived from #primary data
    bp_bundle_ident_t *ident;
    /// Required primary block
    bp_block_primary_t *primary;
    /// Additional blocks in order (type bp_block_canonical_t)
    wmem_list_t *blocks;
    /// Map from block number (guint64) to pointer to block of that number
    /// (bp_block_canonical_t owned by #blocks)
    wmem_map_t *block_nums;
    /// Map from block type code (guint64) to sequence (wmem_list_t) of
    /// pointers to block of that type (bp_block_canonical_t owned by #blocks)
    wmem_map_t *block_types;
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
proto_item * proto_tree_add_cbor_eid(proto_tree *tree, int hfindex, int hfindex_uri, packet_info *pinfo, tvbuff_t *tvb, gint *offset, bp_eid_t *eid);

/// Metadata for an entire file
typedef struct {
    /// Map from a bundle ID (bp_bundle_ident_t) to bundle (bp_bundle_t)
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
