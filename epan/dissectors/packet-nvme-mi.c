/* packet-nvme-mi.c
 * Routines for NVMe Management Interface (NVMe-MI), over MCTP
 * Copyright 2022, Jeremy Kerr <jk@codeconstruct.com.au>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* NVMe-MI is defined by the NVM Express Management Interface specification:
 * https://nvmexpress.org/specification/nvme-mi-specification/
 *
 * This file handles the common NVMe-MI framing (4-byte header, MIC) and
 * request/response transaction tracking.  Per-type body decoding is split
 * into separate files that each register a dissector handle into the
 * "nvme-mi.type" table keyed by the NMIMT field:
 *
 *   packet-nvme-mi-control.c  NMIMT=0  Control Primitive (section 4.2.1)
 *   packet-nvme-mi-mi.c       NMIMT=1  MI Command        (section 5)
 *   packet-nvme-mi-admin.c    NMIMT=2  Admin Command     (section 6)
 */

#include <config.h>

#include <string.h>

#include <epan/conversation.h>
#include <epan/crc32-tvb.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include <wsutil/crc32.h>
#include "packet-mctp.h"
#include "packet-nvme-mi.h"

void proto_register_nvme_mi(void);
void proto_reg_handoff_nvme_mi(void);

static int proto_nvme_mi;

#define NVME_MI_STATUS_INVALID_PARAMETER         0x04
#define NVME_MI_STATUS_UNABLE_TO_ABORT           0x08

/* Reset Type 00h, Reset NVM Subsystem (NVMe-MI 2.2 Figure 125). */
#define NVME_MI_RSTTYP_NVM_SUBSYSTEM             0x00

static dissector_handle_t nvme_mi_handle;

/* Verify the MIC; when off, the MIC is still shown and excluded from the
 * payload. */
static bool nvme_mi_check_mic = true;

/* Read the Controller Information PCIe Routing ID as an ARI Device's
 * (NVMe-MI 2.2 Figure 120 has no ARI indication). */
bool nvme_mi_ctrlinfo_ari;

/* Common NVMe-MI header fields */
static int hf_nvme_mi_mctp_mt;
static int hf_nvme_mi_mctp_ic;
static int hf_nvme_mi_csi;
static int hf_nvme_mi_type;
static int hf_nvme_mi_ror;
static int hf_nvme_mi_ciap;
static int hf_nvme_mi_meb;
static int hf_nvme_mi_mic;
static int hf_nvme_mi_mic_status;
static int hf_nvme_mi_mic_unverified;
static int hf_nvme_mi_hdr_reserved1;
static int hf_nvme_mi_hdr_reserved2;
static int hf_nvme_mi_hdr_reserved3;
static int hf_nvme_mi_pel_reserved;
static int hf_nvme_mi_mpr_reserved;

static expert_field ei_nvme_mi_duplicate_mpr;
static expert_field ei_nvme_mi_late_control_response;
static expert_field ei_nvme_mi_message_too_large;

/* Invalid Parameter Error Response - Parameter Error Location (PEL) */
static int hf_nvme_mi_status;
static int hf_nvme_mi_pel_bit;
static int hf_nvme_mi_pel_byte;

/* Error Response - the status-dependent bytes 3:1 when they carry nothing */
static int hf_nvme_mi_resp_rsvd;

/* Bytes 3:1 for Status values with no Response Message format
 * (NVMe-MI 2.2 Figure 29): Reserved runs and Vendor Specific. */
static int hf_nvme_mi_resp_undefined;
static int hf_nvme_mi_resp_vendor;

/* More Processing Required Response - More Processing Required Time (MPRT) */
static int hf_nvme_mi_mprt;

/* Request/response cross-reference fields */
static int hf_nvme_mi_response_in;
static int hf_nvme_mi_response_to;
static int hf_nvme_mi_response_time;
static int hf_nvme_mi_response_is_mpr;
static int hf_nvme_mi_prev_no_response;
static int hf_nvme_mi_replay_of;
static int hf_nvme_mi_replay_request;
static int hf_nvme_mi_replay_mpr;
static int hf_nvme_mi_replay_data;

static int ett_nvme_mi;
static int ett_nvme_mi_hdr;

static expert_field ei_nvme_mi_mic_truncated;
static expert_field ei_nvme_mi_mic_bad;
static expert_field ei_nvme_mi_req_superseded;
static expert_field ei_nvme_mi_status_absent;
static expert_field ei_nvme_mi_reserved_type;
static expert_field ei_nvme_mi_partial_replay;
static expert_field ei_nvme_mi_too_short;
static expert_field ei_nvme_mi_oob_response_ic;
static expert_field ei_nvme_mi_ror_tag_owner;
static expert_field ei_nvme_mi_control_header_flags;
static expert_field ei_nvme_mi_response_meb;
static expert_field ei_nvme_mi_aem_header;
static expert_field ei_nvme_mi_response_csi_mismatch;
static expert_field ei_nvme_mi_response_csi_candidate;
static expert_field ei_nvme_mi_aem_tag_owner;
static expert_field ei_nvme_mi_cp_csi;
static expert_field ei_nvme_mi_unable_to_abort_not_abort;
static expert_field ei_nvme_mi_reserved_status;

/* NMIMT values NVMe-MI 2.2 Figure 20 defines; others are Reserved. */
static bool
nvme_mi_type_is_known(unsigned type)
{
    return type <= NVME_MI_TYPE_AEM && type != 0x3;
}

/* Command Slot lifecycle: an AEM is neither Request nor Response (Figure 20). */
static bool
nvme_mi_type_tracks_slot(unsigned type)
{
    return nvme_mi_type_is_known(type) && type != NVME_MI_TYPE_AEM;
}

/* Dissector table keyed by the NMIMT field; sub-dissectors register here. */
static dissector_table_t nvme_mi_type_dissector_table;

/* Response Message Status (NVMe-MI 2.2 "Response Message Status Values");
 * shared with the per-type body dissectors via packet-nvme-mi.h. */
const range_string nvme_mi_status_vals[] = {
    { NVME_MI_STATUS_SUCCESS, NVME_MI_STATUS_SUCCESS, "Success" },
    { NVME_MI_STATUS_MORE_PROCESSING_REQUIRED, NVME_MI_STATUS_MORE_PROCESSING_REQUIRED, "More Processing Required" },
    { 0x02, 0x02, "Internal Error" },
    { 0x03, 0x03, "Invalid Command Opcode" },
    { NVME_MI_STATUS_INVALID_PARAMETER, NVME_MI_STATUS_INVALID_PARAMETER, "Invalid Parameter" },
    { 0x05, 0x05, "Invalid Command Size" },
    { 0x06, 0x06, "Invalid Command Input Data Size" },
    { 0x07, 0x07, "Access Denied" },
    { 0x08, 0x08, "Unable to Abort" },
    { 0x09, 0x1f, "Reserved" },
    { 0x20, 0x20, "VPD Updates Exceeded" },
    { 0x21, 0x21, "PCIe Inaccessible" },
    { 0x22, 0x22, "Management Endpoint Buffer Cleared Due to Sanitize" },
    { 0x23, 0x23, "Enclosure Services Failure" },
    { 0x24, 0x24, "Enclosure Services Transfer Failure" },
    { 0x25, 0x25, "Enclosure Failure" },
    { 0x26, 0x26, "Enclosure Services Transfer Refused" },
    { 0x27, 0x27, "Unsupported Enclosure Function" },
    { 0x28, 0x28, "Enclosure Services Unavailable" },
    { 0x29, 0x29, "Enclosure Degraded" },
    { 0x2a, 0x2a, "Sanitize In Progress" },
    { 0x2b, 0xdf, "Reserved" },
    { 0xE0, 0xFF, "Vendor Specific" },
    { 0, 0, NULL },
};

static const value_string mi_mctp_type_vals[] = {
    { 4, "NVMe-MI" },
    { 0, NULL },
};

/* The whole four-bit NMIMT domain (NVMe-MI 2.2 Figure 20). */
const value_string mi_type_vals[] = {
    { NVME_MI_TYPE_CONTROL, "Control primitive" },
    { NVME_MI_TYPE_MI,      "MI command" },
    { NVME_MI_TYPE_ADMIN,   "NVMe Admin command" },
    { 0x3,                  "Reserved" },
    { NVME_MI_TYPE_PCIE,    "PCIe command" },
    { NVME_MI_TYPE_AEM,     "Asynchronous Event" },
    { 0x6,                  "Reserved" },
    { 0x7,                  "Reserved" },
    { 0x8,                  "Reserved" },
    { 0x9,                  "Reserved" },
    { 0xA,                  "Reserved" },
    { 0xB,                  "Reserved" },
    { 0xC,                  "Reserved" },
    { 0xD,                  "Reserved" },
    { 0xE,                  "Reserved" },
    { 0xF,                  "Reserved" },
    { 0, NULL },
};

/* PCIe Command Set opcodes (NVMe-MI 2.2 Figure 151). */
const range_string nvme_mi_pcie_opcode_vals[] = {
    { 0x00, 0x00, "PCIe Configuration Read" },
    { 0x01, 0x01, "PCIe Configuration Write" },
    { 0x02, 0x02, "PCIe Memory Read" },
    { 0x03, 0x03, "PCIe Memory Write" },
    { 0x04, 0x04, "PCIe I/O Read" },
    { 0x05, 0x05, "PCIe I/O Write" },
    { 0x06, 0xFF, "Reserved" },
    { 0, 0, NULL },
};

static const true_false_string tfs_meb = { "data in MEB", "data in message" };

/* CSI is a one-bit Command Slot selector (NVMe-MI 2.2 "NVMe-MI Message
 * Fields"). */
static const true_false_string tfs_csi = { "Command Slot 1", "Command Slot 0" };

/* MPRT is a worst-case time in 100 ms units; FFFFh means >= 6,553.5 s
 * (NVMe-MI 2.2 "More Processing Required Response Fields"). */
static void
nvme_mi_fmt_mprt(char *buf, uint32_t value)
{
    if (value == 0xffff)
        snprintf(buf, ITEM_LABEL_LENGTH, ">= %.1f s (0xffff)", 6553.5);
    else
        snprintf(buf, ITEM_LABEL_LENGTH, "%u ms (%u x 100 ms)",
                 value * 100, value);
}

bool
nvme_mi_dissect_resp_status_bytes(tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree, uint8_t status)
{
    switch (status) {
    case NVME_MI_STATUS_SUCCESS:
        return true;
    case NVME_MI_STATUS_INVALID_PARAMETER:
        /* Parameter Error Location (NVMe-MI 2.2 "Invalid Parameter Error
         * Response Fields"). */
        proto_tree_add_item(tree, hf_nvme_mi_pel_bit, tvb, 1, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_pel_reserved,
                            tvb, 1, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_pel_byte, tvb, 2, 2,
                            ENC_LITTLE_ENDIAN);
        break;
    case NVME_MI_STATUS_MORE_PROCESSING_REQUIRED:
        /* Byte 1 is reserved; MPRT occupies bytes 3:2 (the "More Processing
         * Required Response Fields" figure). */
        proto_tree_add_item(tree, hf_nvme_mi_mpr_reserved,
                            tvb, 1, 1, ENC_NA);
        proto_tree_add_item(tree, hf_nvme_mi_mprt, tvb, 2, 2,
                            ENC_LITTLE_ENDIAN);
        break;
    default:
        /* Figure 29's "Response Message Format Section" column: the Generic Error
         * Response is for 02h, 03h, 05h-08h and 20h-2Ah only. */
        if (status >= NVME_MI_STATUS_VENDOR_FIRST)
            proto_tree_add_item(tree, hf_nvme_mi_resp_vendor, tvb, 1, 3,
                                ENC_NA);
        else if ((status >= NVME_MI_STATUS_RSVD_LOW_FIRST &&
                  status <= NVME_MI_STATUS_RSVD_LOW_LAST) ||
                 (status >= NVME_MI_STATUS_RSVD_HIGH_FIRST &&
                  status <= NVME_MI_STATUS_RSVD_HIGH_LAST)) {
            proto_tree_add_expert(tree, pinfo, &ei_nvme_mi_reserved_status,
                                  tvb, 0, 1);
            proto_tree_add_item(tree, hf_nvme_mi_resp_undefined, tvb, 1, 3,
                                ENC_NA);
        } else
            /* Generic Error Response: bytes 3:1 of the payload (message bytes
             * 7:5) are Reserved (the "Generic Error Response" figure). */
            proto_tree_add_item(tree, hf_nvme_mi_resp_rsvd,
                                tvb, 1, 3, ENC_LITTLE_ENDIAN);
        break;
    }
    return false;
}

static void
nvme_mi_append_status_info(packet_info *pinfo, tvbuff_t *tvb, unsigned type,
                           bool resp, unsigned payload_len)
{
    if (!resp || type == NVME_MI_TYPE_AEM || payload_len == 0 ||
        !tvb_bytes_exist(tvb, 4, 1))
        return;

    uint8_t status = tvb_get_uint8(tvb, 4);
    if (status != NVME_MI_STATUS_SUCCESS)
        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
                        rval_to_str_const(status, nvme_mi_status_vals,
                                          "Unknown status"));
}

void
nvme_mi_dissect_truncated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          proto_item *it, expert_field *ei, int hf_data, int off)
{
    expert_add_info(pinfo, it, ei);
    /* Captured, not reported: a -1 length needs a captured byte at off,
     * and a sliced frame can end exactly there. */
    if (tvb_captured_length_remaining(tvb, off) > 0)
        proto_tree_add_item(tree, hf_data, tvb, off, -1, ENC_NA);
}

bool
nvme_mi_resp_opcode(const struct nvme_mi_transaction *trans, uint8_t nmimt,
                    unsigned *opcode)
{
    if (!trans || !trans->req_parsed || trans->nmimt != nmimt) {
        *opcode = 0;
        return false;
    }

    *opcode = trans->opcode;
    return true;
}

bool
nvme_mi_recover_resp_opcode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            proto_item *it,
                            const struct nvme_mi_transaction *trans,
                            uint8_t nmimt, int hf_opcode,
                            expert_field *ei_orphan, unsigned *opcode,
                            proto_item **opcode_it)
{
    proto_item *gi;

    if (opcode_it)
        *opcode_it = NULL;

    /* Whether the opcode is known is decided here, tree or no tree. */
    if (!nvme_mi_resp_opcode(trans, nmimt, opcode)) {
        expert_add_info(pinfo, it, ei_orphan);
        return false;
    }

    gi = proto_tree_add_uint(tree, hf_opcode, tvb, 0, 0, *opcode);
    proto_item_set_generated(gi);
    if (opcode_it)
        *opcode_it = gi;
    return true;
}

/* Publish a fully parsed request context: parse into packet scope, then
 * copy once every selector is read.  'src' must be plain data. */
void *
nvme_mi_trans_publish_body_ctx(packet_info *pinfo,
                               struct nvme_mi_transaction *trans,
                               const void *src, size_t size)
{
    void *ctx;

    if (!trans)
        return NULL;
    /* Written by the first pass only: it holds what the request said. */
    if (pinfo->fd->visited && trans->body_ctx)
        return trans->body_ctx;

    /* Allocated once: "size" counts only on the first call.  A transaction has
     * one NVMe-MI Message Type, and every body dissector reaches its context
     * only after nvme_mi_recover_resp_opcode() matched trans->nmimt, so only
     * one struct type is ever stored here. */
    if (!trans->body_ctx)
        trans->body_ctx = wmem_alloc0(wmem_file_scope(), size);
    ctx = trans->body_ctx;
    memcpy(ctx, src, size);
    return ctx;
}

/* The null EID 0 (DSP0236 Table 2) is unstable across a request/response
 * pair during EID assignment, so it is kept out of conversation keys. */
static bool
nvme_mi_addr_is_null_eid(const address *addr)
{
    return addr->type == AT_MCTP && addr->len == 1 &&
           *(const uint8_t *)addr->data == 0;
}

/* True when the transport published a symmetric, non-empty physical
 * address pair, of any width. */
static bool
nvme_mi_has_phys_addrs(packet_info *pinfo)
{
    return pinfo->net_src.type != AT_NONE &&
           pinfo->net_src.len  > 0 &&
           pinfo->net_dst.type == pinfo->net_src.type &&
           pinfo->net_dst.len  == pinfo->net_src.len;
}

static void
nvme_mi_key_add_ingress_scope(conversation_element_t *key, unsigned *n,
                              const mctp_ingress_scope *scope)
{
    key[*n].type = CE_BLOB;
    key[*n].blob.val = (const uint8_t *)scope;
    key[*n].blob.len = sizeof(*scope);
    (*n)++;
}

static void
nvme_mi_key_add_pair(conversation_element_t *key, unsigned *n,
                     const address *a, const address *b)
{
    key[*n].type = CE_ADDRESS;
    copy_address_shallow(&key[*n].addr_val, a);
    (*n)++;
    key[*n].type = CE_ADDRESS;
    copy_address_shallow(&key[*n].addr_val, b);
    (*n)++;
}

/* The pair in a fixed order, so both directions name one endpoint. */
static void
nvme_mi_key_add_canonical_pair(conversation_element_t *key, unsigned *n,
                               const address *a, const address *b)
{
    if (cmp_address(a, b) <= 0)
        nvme_mi_key_add_pair(key, n, a, b);
    else
        nvme_mi_key_add_pair(key, n, b, a);
}

/* The physical-address endpoint key: the canonical pair, the scope (which
 * must outlive the lookup) and the terminator.  The caller has checked
 * nvme_mi_has_phys_addrs(). */
static void
nvme_mi_phys_endpoint_key(const packet_info *pinfo, conversation_element_t key[4],
                          const mctp_ingress_scope *scope)
{
    unsigned n = 0;

    nvme_mi_key_add_canonical_pair(key, &n, &pinfo->net_src, &pinfo->net_dst);
    nvme_mi_key_add_ingress_scope(key, &n, scope);
    key[n].type = CE_CONVERSATION_TYPE;
    key[n].conversation_type_val = CONVERSATION_NVME_MI;
}

struct nvme_mi_response {
    struct nvme_mi_transaction *trans;
    uint32_t frame;
    uint32_t header;
    bool is_mpr;
};

struct nvme_mi_replay {
    /* The last Command Message processed in the slot (NVMe-MI 2.2 Figure 46),
     * and its response, or NULL when none reached NVMe-MI. */
    struct nvme_mi_transaction *trans;
    const struct nvme_mi_response *response;
    uint32_t request_frame;
    uint8_t rro;
};

struct nvme_mi_meb_size {
    uint8_t port;
    uint32_t size;
};

struct nvme_mi_meb_commands {
    uint8_t commands[32]; /* MI opcode membership, not Admin command-list authority */
};

/* Endpoint-scoped context, on a conversation keyed on the endpoint pair. */
struct nvme_mi_endpoint {
    /* The endpoint's two Command Slots (NVMe-MI 2.2 1.8.15).  A response
     * clears one only while its own transaction is the occupant. */
    struct nvme_mi_transaction *occupant[2];
    struct nvme_mi_transaction *last_command[2];
    const struct nvme_mi_response *last_response[2];
    struct nvme_mi_replay *replay[8];
    wmem_tree_t *mebs;
    /* Keyed by PORTID, each a frame-keyed tree: the list may differ
     * among Management Endpoints (NVMe-MI 2.2 5.8.6). */
    wmem_tree_t *meb_commands;
};

void
nvme_mi_mebs_observe(struct nvme_mi_endpoint *ep, packet_info *pinfo,
                      uint8_t port, uint32_t size)
{
    if (!ep || pinfo->fd->visited)
        return;
    if (!ep->mebs)
        ep->mebs = wmem_tree_new(wmem_file_scope());
    struct nvme_mi_meb_size *obs =
        wmem_new(wmem_file_scope(), struct nvme_mi_meb_size);
    obs->port = port;
    obs->size = size;
    wmem_tree_insert32(ep->mebs, pinfo->num, obs);
}

void
nvme_mi_meb_commands_observe(struct nvme_mi_endpoint *ep, packet_info *pinfo,
                             uint8_t port, const uint8_t commands[32])
{
    if (!ep || pinfo->fd->visited)
        return;
    if (!ep->meb_commands)
        ep->meb_commands = wmem_tree_new(wmem_file_scope());
    wmem_tree_t *per_port = wmem_tree_lookup32(ep->meb_commands, port);
    if (!per_port) {
        per_port = wmem_tree_new(wmem_file_scope());
        wmem_tree_insert32(ep->meb_commands, port, per_port);
    }
    struct nvme_mi_meb_commands *obs =
        wmem_new(wmem_file_scope(), struct nvme_mi_meb_commands);
    memcpy(obs->commands, commands, sizeof(obs->commands));
    wmem_tree_insert32(per_port, pinfo->num, obs);
}

bool
nvme_mi_meb_routes(const struct nvme_mi_endpoint *ep, uint32_t frame,
                    unsigned opcode)
{
    if (!ep || !ep->mebs || !ep->meb_commands || opcode > 255)
        return false;
    const struct nvme_mi_meb_size *size =
        wmem_tree_lookup32_le(ep->mebs, frame);
    if (!size || !size->size)
        return false;
    wmem_tree_t *per_port = wmem_tree_lookup32(ep->meb_commands, size->port);
    const struct nvme_mi_meb_commands *cmds =
        per_port ? wmem_tree_lookup32_le(per_port, frame) : NULL;
    return cmds && (cmds->commands[opcode / 8] & (1U << (opcode % 8)));
}

static void
nvme_mi_clear_replay_expectations(struct nvme_mi_endpoint *ep, unsigned csi)
{
    for (unsigned tag = 0; tag < array_length(ep->replay); tag++) {
        if (ep->replay[tag] &&
            ep->replay[tag]->trans->req_csi == csi)
            ep->replay[tag] = NULL;
    }
}

static void
nvme_mi_forget_replay(struct nvme_mi_endpoint *ep, unsigned csi)
{
    ep->last_response[csi] = NULL;
    nvme_mi_clear_replay_expectations(ep, csi);
}

/* Whether a response is the replay 'r' expects.  The replay carries the
 * original's Message Header (NVMe-MI 2.2 section 4.2.1, Replay), so match that
 * when the original was seen, else the command's NMIMT and CSI. */
static bool
nvme_mi_replay_matches(const struct nvme_mi_replay *r, uint32_t header,
                       unsigned type, bool csi)
{
    if (!r)
        return false;
    if (r->response)
        return r->response->header == header;
    return r->trans->nmimt == type && r->trans->req_csi == csi;
}

/* Frame proto-data keys: 0 the transaction, 1 the endpoint, 2 a possible
 * response CSI mismatch. */
#define NVME_MI_PROTO_DATA_FRAME         0
#define NVME_MI_PROTO_DATA_ENDPOINT      1
#define NVME_MI_PROTO_DATA_CSI_CANDIDATE 2

/* First-pass snapshot: the response's named slot was empty while the other
 * slot held an unanswered same-type request (Figure 20). */
struct nvme_mi_csi_candidate {
    uint32_t req_frame;
    uint8_t  resp_csi;
    uint8_t  req_csi;
};

/* The frame's endpoint context, resolved on the first pass: the
 * transaction key without the tag, canonically ordered.  NULL without
 * physical addresses or an assigned EID. */
static struct nvme_mi_endpoint *
nvme_mi_endpoint_for_frame(packet_info *pinfo, bool resp)
{
    struct nvme_mi_endpoint *ep;
    conversation_t *conv = NULL;
    bool has_phys, eids_usable;

    ep = (struct nvme_mi_endpoint *)
        p_get_proto_data(wmem_file_scope(), pinfo, proto_nvme_mi,
                         NVME_MI_PROTO_DATA_ENDPOINT);
    if (ep || pinfo->fd->visited)
        return ep;

    has_phys    = nvme_mi_has_phys_addrs(pinfo);
    eids_usable = !nvme_mi_addr_is_null_eid(&pinfo->src) &&
                  !nvme_mi_addr_is_null_eid(&pinfo->dst);

    if (!has_phys && !eids_usable)
        return NULL;

    {
        /* At most: 2 physical addresses + 2 EIDs + scope + terminator. */
        conversation_element_t *key =
            wmem_alloc_array(pinfo->pool, conversation_element_t, 6);
        unsigned n = 0;
        mctp_ingress_scope scope;

        mctp_ingress_scope_get(pinfo, &scope);

        if (has_phys)
            nvme_mi_key_add_canonical_pair(key, &n, &pinfo->net_src, &pinfo->net_dst);
        if (eids_usable)
            nvme_mi_key_add_canonical_pair(key, &n, &pinfo->src, &pinfo->dst);

        /* The ingress domain (an EID is unique only within one network). */
        nvme_mi_key_add_ingress_scope(key, &n, &scope);

        key[n].type                  = CE_CONVERSATION_TYPE;
        key[n].conversation_type_val = CONVERSATION_NVME_MI;

        /* Cannot collide with a transaction key: the element before the scope
         * is an address here, a tag there. */
        conv = find_conversation_full(pinfo->num, key);
        if (!conv && resp && has_phys && eids_usable) {
            conversation_element_t fallback[4];

            /* A response to a Null Destination EID request: retry without EIDs. */
            nvme_mi_phys_endpoint_key(pinfo, fallback, &scope);
            conv = find_conversation_full(pinfo->num, fallback);
        }
        if (!conv)
            conv = conversation_new_full(pinfo->num, key);
    }

    ep = conversation_get_proto_data(conv, proto_nvme_mi);
    if (!ep) {
        ep = wmem_new0(wmem_file_scope(), struct nvme_mi_endpoint);
        conversation_add_proto_data(conv, proto_nvme_mi, ep);
    }

    p_add_proto_data(wmem_file_scope(), pinfo, proto_nvme_mi,
                     NVME_MI_PROTO_DATA_ENDPOINT, ep);
    return ep;
}

/* Per-slot in-flight transaction (NULL when the slot is idle); only written
 * when !pinfo->fd->visited. */
struct nvme_mi_conv_info {
    struct nvme_mi_transaction *command_slots[2];
    /* Control Primitives pair on TAG (NVMe-MI 2.2 Figure 40, 4.2.1), in a
     * slot of their own, without displacing the command transaction. */
    struct nvme_mi_transaction *cp_slot;
    /* The Control Primitive whose answer last emptied cp_slot. */
    struct nvme_mi_transaction *cp_answered;
};

/* Per-frame annotation; points into the shared transaction. */
struct nvme_mi_frame_info {
    struct nvme_mi_transaction *trans;
    struct nvme_mi_endpoint    *endpoint;
    bool                        is_interim_mpr;
    bool                        duplicate_mpr;
    /* Admitted as the answer to a Control Primitive that a later one on the
     * same tag had superseded (see cp_superseded in packet-nvme-mi.h). */
    bool                        cp_late;
    const struct nvme_mi_replay *replay;
    /* Not admitted as the answer to its slot's request: a bad MIC, an
     * unverified header-error link, NMIMT or STATUS missing (Figure 28), TAG
     * not echoed (Figure 40), or Unable to Abort with no Abort outstanding
     * (Figure 29).  It keeps its transaction for display, but gets no Request
     * In, Response Time or MPR flag.  False (zero) is admitted. */
    bool                        refused;
    /* Refused as Unable to Abort answering a Control Primitive other than
     * Abort (Figure 29, 08h). */
    bool                        unable_to_abort_not_abort;
    /* The unanswered transaction this request displaced, or NULL. */
    struct nvme_mi_transaction *superseded;
};

/* A request displaced an unanswered predecessor; the endpoint's choice
 * (NVMe-MI 2.2 section 4.2) is not on the wire, so a note.  Reset NVM
 * Subsystem is owed no response (section 5.9). */
static void
nvme_mi_note_superseded(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        proto_item *it,
                        const struct nvme_mi_transaction *prev)
{
    if (prev->req_parsed && prev->nmimt == NVME_MI_TYPE_MI &&
        prev->opcode == NVME_MI_MI_OPC_RESET &&
        prev->reset_nvm_subsystem) {
        proto_item *gi = proto_tree_add_uint(tree, hf_nvme_mi_prev_no_response,
                                             tvb, 0, 0, prev->req_frame);
        proto_item_set_generated(gi);
        return;
    }

    expert_add_info(pinfo, it, &ei_nvme_mi_req_superseded);
}

/* The frame of the outstanding request a response on `conv` would answer,
 * or 0. */
static uint32_t
nvme_mi_conv_pending_req(const conversation_t *conv, unsigned type, bool csi)
{
    const struct nvme_mi_conv_info *mi_conv =
        conversation_get_proto_data(conv, proto_nvme_mi);
    const struct nvme_mi_transaction *t;

    if (!mi_conv)
        return 0;
    if (type == NVME_MI_TYPE_CONTROL)
        t = mi_conv->cp_slot;
    else
        t = mi_conv->command_slots[csi];
    return t ? t->req_frame : 0;
}

/* The NVMe-MI conversation (Command Slots) this frame belongs to. */
static struct nvme_mi_conv_info *
nvme_mi_conv_for_frame(packet_info *pinfo, bool resp, unsigned type, bool csi)
{
    conversation_t *conv;
    struct nvme_mi_conv_info *mi_conv;

    /* Conversation key: physical address pair, the EIDs once the tag owner
     * has one, and the MCTP tag.  The tag is unique only per pair; the EIDs
     * change at assignment; one address may front several endpoints. */
    {
        bool src_owns_tag = (pinfo->srcport & 0x08) != 0;
        uint32_t tag      = src_owns_tag ? pinfo->srcport : pinfo->destport;
        bool has_phys     = nvme_mi_has_phys_addrs(pinfo);

        const address *owner_eid  = src_owns_tag ? &pinfo->src : &pinfo->dst;
        const address *device_eid = src_owns_tag ? &pinfo->dst : &pinfo->src;
        bool eids_usable = !nvme_mi_addr_is_null_eid(owner_eid);

        /* At most: 2 addresses + 2 EIDs + tag + scope + terminator. */
        conversation_element_t *key =
            wmem_alloc_array(pinfo->pool, conversation_element_t, 8);
        unsigned n = 0;
        unsigned device_eid_pos = 0;
        mctp_ingress_scope scope;

        mctp_ingress_scope_get(pinfo, &scope);

        if (has_phys)
            nvme_mi_key_add_pair(key, &n,
                    src_owns_tag ? &pinfo->net_src : &pinfo->net_dst,
                    src_owns_tag ? &pinfo->net_dst : &pinfo->net_src);

        if (eids_usable) {
            key[n].type = CE_ADDRESS;
            copy_address_shallow(&key[n].addr_val, owner_eid);
            n++;
            /* A null device EID (Table 2) is left out of the key. */
            if (!nvme_mi_addr_is_null_eid(device_eid)) {
                device_eid_pos = n;
                key[n].type = CE_ADDRESS;
                copy_address_shallow(&key[n].addr_val, device_eid);
                n++;
            }
        } else if (!has_phys) {
            /* Pre-assignment on a transport with no physical addresses:
             * the tag owner (the null EID) and the tag are all there is. */
            key[n].type = CE_ADDRESS;
            copy_address_shallow(&key[n].addr_val, owner_eid);
            n++;
        }

        key[n].type     = CE_UINT;
        key[n].uint_val = tag;
        n++;
        /* The ingress domain, after the tag. */
        nvme_mi_key_add_ingress_scope(key, &n, &scope);
        key[n].type                  = CE_CONVERSATION_TYPE;
        key[n].conversation_type_val = CONVERSATION_NVME_MI;

        conv = find_conversation_full(pinfo->num, key);
        if (resp && device_eid_pos != 0) {
            /* A response may also answer a Null Destination EID request,
             * keyed without the device EID (DSP0236 Table 2): retry that
             * shape, keeping the physical pair when the binding has one.
             * Take it when the full key has nothing, or when its slot holds
             * the later outstanding request (NVMe-MI 2.2 section 4.2). */
            conversation_element_t *fb =
                wmem_alloc_array(pinfo->pool, conversation_element_t, 8);
            conversation_t *null_conv;
            unsigned f = 0, i;

            for (i = 0; i < n; i++) {
                if (i == device_eid_pos)
                    continue;
                fb[f++] = key[i];
            }
            fb[f].type                  = CE_CONVERSATION_TYPE;
            fb[f].conversation_type_val = CONVERSATION_NVME_MI;

            null_conv = find_conversation_full(pinfo->num, fb);
            if (null_conv && (!conv ||
                    nvme_mi_conv_pending_req(null_conv, type, csi) >
                    nvme_mi_conv_pending_req(conv, type, csi)))
                conv = null_conv;
        }
        if (!conv)
            conv = conversation_new_full(pinfo->num, key);
    }
    mi_conv = conversation_get_proto_data(conv, proto_nvme_mi);
    if (!mi_conv) {
        mi_conv = wmem_new0(wmem_file_scope(), struct nvme_mi_conv_info);
        conversation_add_proto_data(conv, proto_nvme_mi, mi_conv);
    }

    return mi_conv;
}

/* Record this frame as the response a Replay would resend, if `trans` is still
 * the slot's last command: a late answer to an aborted command cannot revive
 * replay. */
static void
nvme_mi_record_response(struct nvme_mi_endpoint *ep, unsigned csi,
                        struct nvme_mi_transaction *trans, tvbuff_t *tvb,
                        packet_info *pinfo, bool is_mpr)
{
    struct nvme_mi_response *response;

    if (ep->last_command[csi] != trans)
        return;
    response = wmem_new0(wmem_file_scope(), struct nvme_mi_response);
    response->trans = trans;
    response->frame = pinfo->num;
    response->header = tvb_get_letohl(tvb, 0);
    response->is_mpr = is_mpr;
    ep->last_response[csi] = response;
}

/* The nearest unanswered primitive from `older` down the superseded chain that
 * a late response answers: by TAG, else an Abort (for Unable to Abort).  At
 * most 8 hops; NULL if none. */
static struct nvme_mi_transaction *
nvme_mi_cp_superseded_match(struct nvme_mi_transaction *older, bool by_tag, uint8_t tag)
{
    for (unsigned hops = 0; older && hops < 8; hops++) {
        if (!older->resp_frame &&
            (by_tag ? older->ctl_tag_known && older->ctl_tag == tag
                    : older->req_parsed && older->opcode == NVME_MI_CP_OPC_ABORT))
            return older;
        older = older->cp_superseded;
    }
    return NULL;
}

/* First pass: find the transaction this frame belongs to and run the Command
 * Slot lifecycle.  `epp` and `fi` are in-out; returns the frame info. */
static struct nvme_mi_frame_info *
nvme_mi_track_transaction(tvbuff_t *tvb, packet_info *pinfo, unsigned type, bool resp,
                          bool csi, bool meb, unsigned payload_len, bool integrity_ok,
                          bool mic_bad, bool status_absent,
                          unsigned transport_tag, struct nvme_mi_endpoint **epp,
                          struct nvme_mi_frame_info *fi)
{
    struct nvme_mi_endpoint *ep = *epp;
    struct nvme_mi_conv_info *mi_conv;

    /* Peek the first body bytes (status or opcode) once, so the slot
     * lifecycle never depends on a body dissector. */
    bool have_b0 = payload_len >= 1 && tvb_bytes_exist(tvb, 4, 1);
    bool have_body4 = payload_len >= 4 && tvb_bytes_exist(tvb, 4, 4);
    uint8_t b0 = have_b0 ? tvb_get_uint8(tvb, 4) : 0;

    /* A missing status leaves the slot open. */
    bool is_mpr = false;
    bool status_known = true;
    if (resp && type != NVME_MI_TYPE_CONTROL) {
        if (have_b0)
            is_mpr = b0 == NVME_MI_STATUS_MORE_PROCESSING_REQUIRED;
        else
            status_known = false;
    }

    mi_conv = nvme_mi_conv_for_frame(pinfo, resp, type, csi);

    struct nvme_mi_transaction **slot = (type == NVME_MI_TYPE_CONTROL)
                                            ? &mi_conv->cp_slot
                                            : &mi_conv->command_slots[csi];

    if (resp) {
        struct nvme_mi_transaction *trans = *slot;
        bool cp_late = false;
        /* A Control Primitive answer pairs by its TAG on Success, or as an
         * Abort's on Unable to Abort (Figures 29 and 40). */
        bool by_tag = have_body4 && b0 == NVME_MI_STATUS_SUCCESS;
        bool unable_to_abort = have_b0 && b0 == NVME_MI_STATUS_UNABLE_TO_ABORT;
        uint8_t resp_tag = by_tag ? tvb_get_uint8(tvb, 5) : 0;

        /* A late answer to a superseded Control Primitive (section 4.2.1). */
        if (!trans && type == NVME_MI_TYPE_CONTROL && !mic_bad &&
            mi_conv->cp_answered && (by_tag || unable_to_abort)) {
            trans = nvme_mi_cp_superseded_match(
                mi_conv->cp_answered->cp_superseded, by_tag, resp_tag);
            cp_late = trans != NULL;
        }
        if (trans) {

            /* Reuse the request's endpoint identity. */
            if (trans->endpoint)
                ep = trans->endpoint;

            /* Look up, decide, then commit: the first failed test is the reason. */
            bool refused = false;
            bool uta_not_abort = false;

            if (mic_bad || trans->nmimt != (uint8_t)type || status_absent) {
                refused = true;
            } else if (type == NVME_MI_TYPE_CONTROL &&
                       ((by_tag && trans->ctl_tag_known &&
                         resp_tag != trans->ctl_tag) ||
                        (unable_to_abort && trans->req_parsed &&
                         trans->opcode != NVME_MI_CP_OPC_ABORT))) {
                /* A wrong TAG echo, or Unable to Abort for a non-Abort: first
                 * look among the superseded primitives (section 4.2.1). */
                struct nvme_mi_transaction *older = nvme_mi_cp_superseded_match(
                    trans->cp_superseded, by_tag, resp_tag);

                if (older) {
                    trans = older;
                    cp_late = true;
                    if (trans->endpoint)
                        ep = trans->endpoint;
                } else {
                    refused = true;
                    uta_not_abort = unable_to_abort;
                }
            }

            fi = wmem_new0(wmem_file_scope(), struct nvme_mi_frame_info);
            fi->trans = trans;
            fi->endpoint = ep;
            fi->is_interim_mpr = is_mpr;
            fi->refused = refused;
            fi->unable_to_abort_not_abort = uta_not_abort;
            fi->cp_late = cp_late;
            if (!refused && is_mpr) {
                fi->duplicate_mpr = trans->mpr_count != 0;
                trans->mpr_count++;
            }
            p_add_proto_data(wmem_file_scope(), pinfo, proto_nvme_mi,
                             NVME_MI_PROTO_DATA_FRAME, fi);

            if (ep && !refused && status_known &&
                type != NVME_MI_TYPE_CONTROL)
                nvme_mi_record_response(ep, csi, trans, tvb, pinfo, is_mpr);

            /* Control Primitive outcomes change endpoint state only when admitted
             * and answering the last primitive (section 4.2.1). */
            if (ep && !refused && !cp_late &&
                !trans->req_mic_bad && trans->req_parsed &&
                type == NVME_MI_TYPE_CONTROL && trans->ctl_tag_known &&
                trans->req_csi == (uint8_t)csi &&
                payload_len == 4 && by_tag) {
                uint16_t cpsr = tvb_get_letohs(tvb, 6);
                if (trans->opcode == NVME_MI_CP_OPC_ABORT &&
                    (cpsr & 3) != 3) {
                    /* MI 2.2 section 4.2.1.3 (Abort), Figs 29/42: Success with CPAS 00/01/10 only.
                     * Only a verified response undoes a Security Send. */
                    if ((cpsr & 3) == 1 && integrity_ok && ep->occupant[csi])
                        nvme_mi_admin_command_aborted(pinfo, ep->occupant[csi]);
                    ep->occupant[csi] = NULL;
                    ep->last_command[csi] = NULL;
                    nvme_mi_forget_replay(ep, csi);
                } else if (trans->opcode == NVME_MI_CP_OPC_REPLAY) {
                    nvme_mi_clear_replay_expectations(ep, csi);
                    if ((cpsr & 1) && ep->last_command[csi]) {
                        struct nvme_mi_replay *expectation =
                            wmem_new(wmem_file_scope(), struct nvme_mi_replay);
                        /* RR with no response seen: the original was paused or
                         * cut off in the Transmit state (section 4.2.1.5). */
                        expectation->trans = ep->last_command[csi];
                        expectation->response = ep->last_response[csi];
                        expectation->request_frame = trans->req_frame;
                        expectation->rro = trans->replay_rro;
                        ep->replay[transport_tag] = expectation;
                    }
                }
            }

            /* Commit.  An MPR, an unknown status or a bad MIC leaves the slot open. */
            if (!refused && !is_mpr && status_known) {
                trans->resp_frame = pinfo->num;
                /* A late answer leaves the newer primitive in the slot. */
                if (!cp_late) {
                    *slot = NULL;
                    if (type == NVME_MI_TYPE_CONTROL)
                        mi_conv->cp_answered = trans;
                }
                /* Release the endpoint slot only if this transaction holds it. */
                if (type != NVME_MI_TYPE_CONTROL && ep && ep->occupant[csi] == trans)
                    ep->occupant[csi] = NULL;
            }
        } else if (type != NVME_MI_TYPE_CONTROL &&
                   pinfo->ptype == PT_MCTP && !mic_bad) {
            const struct nvme_mi_transaction *other =
                mi_conv->command_slots[!csi];

            if (other && other->nmimt == (uint8_t)type &&
                other->req_csi == (uint8_t)!csi && !other->resp_frame &&
                other->req_frame < pinfo->num) {
                struct nvme_mi_csi_candidate *cand =
                    wmem_new(wmem_file_scope(), struct nvme_mi_csi_candidate);

                cand->req_frame = other->req_frame;
                cand->resp_csi  = (uint8_t)csi;
                cand->req_csi   = other->req_csi;
                p_add_proto_data(wmem_file_scope(), pinfo, proto_nvme_mi,
                                 NVME_MI_PROTO_DATA_CSI_CANDIDATE, cand);
            }
        }
    } else {
        /* A request's failed MIC may not mean the endpoint discarded it. */
        struct nvme_mi_transaction *trans =
            wmem_new0(wmem_file_scope(), struct nvme_mi_transaction);
        trans->endpoint  = ep;
        trans->req_frame = pinfo->num;
        trans->req_time  = pinfo->fd->abs_ts;
        trans->nmimt     = (uint8_t)type;
        /* The request's integrity verdict, for retention only. */
        trans->req_integrity_ok = integrity_ok;
        trans->req_mic_bad      = mic_bad;
        /* The slot this request named, for the response to echo. */
        trans->req_csi       = (uint8_t)csi;
        trans->req_meb       = meb;
        if (ep)
            ep->replay[transport_tag] = NULL;
        /* Capture fixed CP metadata independently of body/tree dispatch. */
        if (type == NVME_MI_TYPE_CONTROL && have_body4) {
            trans->opcode = b0;
            trans->ctl_tag = tvb_get_uint8(tvb, 5);
            trans->ctl_tag_known = true;
            trans->req_parsed = true;
            trans->replay_rro = tvb_get_uint8(tvb, 6);
        }

        /* Record the opcode here, so recovery survives a disabled body. */
        if (type != NVME_MI_TYPE_CONTROL && have_b0) {
            trans->opcode     = b0;
            trans->req_parsed = true;
        }

        /* A Reset's RSTTYP too (NMD0 bits 31:24, message byte 11;
         * Figures 67 and 125), so that a Reset NVM Subsystem is owed no
         * response (section 5.9) with the body disabled or the capture
         * cut after byte 11.  The whole NCREQ must be reported. */
        if (type == NVME_MI_TYPE_MI &&
            trans->opcode == NVME_MI_MI_OPC_RESET &&
            payload_len >= 12 && tvb_bytes_exist(tvb, 11, 1))
            trans->reset_nvm_subsystem =
                tvb_get_uint8(tvb, 11) == NVME_MI_RSTTYP_NVM_SUBSYSTEM;

        fi = wmem_new0(wmem_file_scope(), struct nvme_mi_frame_info);
        fi->trans = trans;
        fi->endpoint = ep;
        /* A displaced Control Primitive is not reported (section 4.2.1). */
        /* Displacement is asked of the endpoint's slots. */
        if (type != NVME_MI_TYPE_CONTROL && ep) {
            fi->superseded = ep->occupant[csi];
            ep->occupant[csi] = trans;
            ep->last_command[csi] = trans;
            nvme_mi_forget_replay(ep, csi);
        }
        p_add_proto_data(wmem_file_scope(), pinfo, proto_nvme_mi,
                         NVME_MI_PROTO_DATA_FRAME, fi);

        if (type == NVME_MI_TYPE_CONTROL && *slot &&
            (*slot)->nmimt == NVME_MI_TYPE_CONTROL && !(*slot)->resp_frame)
            trans->cp_superseded = *slot;
        *slot = trans;
    }

    *epp = ep;
    return fi;
}

static int
dissect_nvme_mi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                void *data)
{
    /* MCTP passes the message's start time; other callers pass NULL. */
    const nstime_t *start_time = data ? (const nstime_t *)data : &pinfo->abs_ts;
    proto_tree *nvme_mi_tree, *nvme_mi_hdr_tree;
    unsigned len, payload_len, type;
    bool resp, mic_enabled;
    proto_item *ti, *it2;
    tvbuff_t *sub_tvb;
    uint32_t mic_crc = 0;
    bool mic_computed = false;
    bool csi;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NVMe-MI");
    col_clear(pinfo->cinfo, COL_INFO);

    len = tvb_reported_length(tvb);
    /* Before the length check, so a short message is still NVMe-MI. */
    ti = proto_tree_add_item(tree, proto_nvme_mi, tvb, 0, -1, ENC_NA);
    if (len < 4) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Bogus length %u, minimum %u",
                     len, 4);
        expert_add_info(pinfo, ti, &ei_nvme_mi_too_short);
        return tvb_captured_length(tvb);
    }

    nvme_mi_tree = proto_item_add_subtree(ti, ett_nvme_mi);

    /* MI 2.2 section 3.1: includes the IC/type byte; in-band uses MDTS instead.
     * Only MCTP dispatch currently reaches this dissector. */
    bool out_of_band = pinfo->ptype == PT_MCTP;
    if (out_of_band && len > 4224)
        expert_add_info(pinfo, ti, &ei_nvme_mi_message_too_large);

    proto_item *hdr_it;
    nvme_mi_hdr_tree = proto_tree_add_subtree(nvme_mi_tree, tvb, 0, 4,
        ett_nvme_mi_hdr, &hdr_it, "NVMe-MI header");

    proto_tree_add_item(nvme_mi_hdr_tree, hf_nvme_mi_mctp_mt,
                        tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_item *ic_it =
        proto_tree_add_item_ret_boolean(nvme_mi_hdr_tree, hf_nvme_mi_mctp_ic,
                                        tvb, 0, 4, ENC_LITTLE_ENDIAN,
                                        &mic_enabled);
    proto_item *csi_it =
        proto_tree_add_item_ret_boolean(nvme_mi_hdr_tree, hf_nvme_mi_csi,
                                        tvb, 0, 4, ENC_LITTLE_ENDIAN, &csi);
    proto_item *type_it =
        proto_tree_add_item_ret_uint(nvme_mi_hdr_tree, hf_nvme_mi_type,
                                     tvb, 0, 4, ENC_LITTLE_ENDIAN, &type);
    proto_item *ror_it =
        proto_tree_add_item_ret_boolean(nvme_mi_hdr_tree, hf_nvme_mi_ror,
                                        tvb, 0, 4, ENC_LITTLE_ENDIAN, &resp);
    bool meb;
    bool ciap;
    proto_item *ciap_it =
        proto_tree_add_item_ret_boolean(nvme_mi_hdr_tree, hf_nvme_mi_ciap,
                                        tvb, 0, 4, ENC_LITTLE_ENDIAN, &ciap);
    proto_item *meb_it =
        proto_tree_add_item_ret_boolean(nvme_mi_hdr_tree, hf_nvme_mi_meb,
                                        tvb, 0, 4, ENC_LITTLE_ENDIAN, &meb);

    proto_tree_add_item(nvme_mi_hdr_tree, hf_nvme_mi_hdr_reserved1,
                        tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(nvme_mi_hdr_tree, hf_nvme_mi_hdr_reserved2,
                        tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(nvme_mi_hdr_tree, hf_nvme_mi_hdr_reserved3,
                        tvb, 0, 4, ENC_LITTLE_ENDIAN);
    if (out_of_band && (resp || type == NVME_MI_TYPE_AEM) && !mic_enabled)
        expert_add_info(pinfo, ic_it, &ei_nvme_mi_oob_response_ic);
    if (type == NVME_MI_TYPE_CONTROL) {
        /* Figure 20: a Control Primitive request with either bit set draws
         * an Invalid Parameter Error Response whose PEL names that bit. */
        if (ciap)
            expert_add_info_format(pinfo, ciap_it,
                &ei_nvme_mi_control_header_flags,
                resp ? "CIAP set to 1 is prohibited in a Control Primitive"
                       " (NVMe-MI 'NVMe-MI Message Fields')"
                     : "CIAP set to 1 is prohibited in a Control Primitive;"
                       " the Management Endpoint returns an Invalid Parameter"
                       " Error Response with PEL indicating CIAP"
                       " (NVMe-MI 'NVMe-MI Message Fields')");
        if (meb)
            expert_add_info_format(pinfo, meb_it,
                &ei_nvme_mi_control_header_flags,
                resp ? "MEB set to 1 is prohibited in a Control Primitive"
                       " (NVMe-MI 'NVMe-MI Message Fields')"
                     : "MEB set to 1 is prohibited in a Control Primitive;"
                       " the Management Endpoint returns an Invalid Parameter"
                       " Error Response with PEL indicating MEB"
                       " (NVMe-MI 'NVMe-MI Message Fields')");
    } else if (type == NVME_MI_TYPE_AEM) {
        /* MI 2.2 Figure 20: ROR does not apply to an AEM and is cleared, as
         * are CIAP and MEB; section 4.4.4 a): Tag Owner is set. */
        proto_item_append_text(ror_it, " (not applicable to AEMs)");
        if (resp)
            expert_add_info_format(pinfo, ror_it, &ei_nvme_mi_aem_header,
                "ROR shall be cleared to 0 in an Asynchronous Event Message"
                " (NVMe-MI 'NVMe-MI Message Fields')");
        if (ciap)
            expert_add_info_format(pinfo, ciap_it, &ei_nvme_mi_aem_header,
                "CIAP shall be cleared to 0 in an Asynchronous Event Message"
                " (NVMe-MI 'NVMe-MI Message Fields')");
        if (meb)
            expert_add_info_format(pinfo, meb_it, &ei_nvme_mi_aem_header,
                "MEB set to 1 is prohibited outside a Command Message"
                " (NVMe-MI 'NVMe-MI Message Fields')");
        if (csi)
            expert_add_info_format(pinfo, csi_it, &ei_nvme_mi_aem_header,
                "CSI shall be cleared to 0 in an Asynchronous Event Message"
                " (NVMe-MI 'NVMe-MI Message Fields')");
        if (out_of_band && !(pinfo->srcport & 0x08))
            expert_add_info(pinfo, hdr_it, &ei_nvme_mi_aem_tag_owner);
    } else if (resp && meb) {
        expert_add_info(pinfo, meb_it, &ei_nvme_mi_response_meb);
    }
    /* MI 2.2 sections 4.2.1.1 and 4.2.1.2: CSI is unused by Pause and
     * Resume, and set it draws an Invalid Parameter Error Response. */
    if (type == NVME_MI_TYPE_CONTROL && !resp && csi && len >= 5 &&
        tvb_bytes_exist(tvb, 4, 1) && tvb_get_uint8(tvb, 4) <= 0x01)
        expert_add_info(pinfo, csi_it, &ei_nvme_mi_cp_csi);
    /* MI 2.2 Figure 20 (TP6042): a Responder drops a message with ROR set
     * that arrives as a request, without an Error Response.  MCTP requests
     * carry Tag Owner (DSP0235), so ROR must agree with it; a disagreeing
     * message takes no part in Command Slot pairing. */
    bool ror_mismatch = out_of_band && type != NVME_MI_TYPE_AEM &&
        resp == ((pinfo->srcport & 0x08) != 0);
    if (ror_mismatch)
        expert_add_info_format(pinfo, ror_it, &ei_nvme_mi_ror_tag_owner,
            resp ? "ROR is set but the MCTP Tag Owner bit marks this a"
                   " request: the Responder drops it without a response and"
                   " sets BPOPL (NVMe-MI 'NVMe-MI Message Fields')"
                 : "ROR marks a Request Message but the MCTP Tag Owner bit"
                   " is clear; requests are sent with Tag Owner set");

    struct nvme_mi_frame_info *fi = p_get_proto_data(wmem_file_scope(), pinfo,
                                                     proto_nvme_mi,
                                                     NVME_MI_PROTO_DATA_FRAME);
    struct nvme_mi_endpoint *ep = nvme_mi_endpoint_for_frame(pinfo, resp);
    if (fi && fi->endpoint)
        ep = fi->endpoint;
    unsigned transport_tag = pinfo->srcport & 0x07;
    const struct nvme_mi_replay *replay = fi ? fi->replay : NULL;
    if (!pinfo->fd->visited && resp &&
        type != NVME_MI_TYPE_CONTROL && nvme_mi_type_tracks_slot(type) &&
        !(pinfo->srcport & 0x08)) {
        const struct nvme_mi_replay *candidate =
            ep ? ep->replay[transport_tag] : NULL;

        if (nvme_mi_replay_matches(candidate, tvb_get_letohl(tvb, 0),
                                   type, csi))
            replay = candidate;
    }
    bool partial_replay = replay && replay->rro != 0;
    bool replay_response = false;

    payload_len = len - 4;
    if (mic_enabled) {
        if (payload_len < 4) {
            /* IC set but no room for a MIC: keep the bytes as payload. */
            expert_add_info(pinfo, ic_it, &ei_nvme_mi_mic_truncated);
            mic_enabled = false;
        } else {
            /* MIC: CRC-32C over the message, little-endian (Appendix B); the
             * helper returns wire order, hence CRC32C_SWAP.  Skipped on a
             * sliced frame, so no throw precedes the slot lifecycle. */
            if (nvme_mi_check_mic && !partial_replay &&
                tvb_bytes_exist(tvb, 0, payload_len)) {
                /* CRC32C_SWAP expands its argument four times: swap a
                 * variable, not the call, or the CRC runs four times. */
                mic_crc = ~crc32c_tvb_offset_calculate(tvb, 0, payload_len,
                                                       0xffffffff);
                mic_crc = CRC32C_SWAP(mic_crc);
                mic_computed = true;
            }
            payload_len -= 4;
        }
    }

    /* integrity_ok: the check ran and passed; mic_bad: it ran and failed.
     * No verdict leaves both false. */
    bool mic_verified = mic_enabled && mic_computed &&
                        tvb_bytes_exist(tvb, payload_len + 4, 4);
    bool integrity_ok = mic_verified &&
                        tvb_get_letohl(tvb, payload_len + 4) == mic_crc;
    bool mic_bad      = mic_verified && !integrity_ok;

    /* The ROR bit does not apply to an Asynchronous Event Message, so it is
     * neither a request nor a response (NVMe-MI 2.2 "NVMe-MI Message
     * Fields"). */
    if (type == NVME_MI_TYPE_AEM)
        col_add_fstr(pinfo->cinfo, COL_INFO, "NVMe-MI %s",
                     val_to_str_const(type, mi_type_vals, "Reserved type"));
    else
        col_add_fstr(pinfo->cinfo, COL_INFO, "NVMe-MI %s %s",
                     val_to_str_const(type, mi_type_vals, "Reserved type"),
                     tfs_get_string(resp, &tfs_response_request));

    /* No STATUS reported: every Response Message starts with one (Figure 28;
     * Control Primitives, Figure 40). */
    bool status_absent = resp && nvme_mi_type_tracks_slot(type) &&
                         !partial_replay && payload_len == 0;
    bool replayed_final = replay && replay->response &&
        replay->response->is_mpr && !partial_replay && payload_len > 0 &&
        tvb_bytes_exist(tvb, 4, 1) &&
        tvb_get_uint8(tvb, 4) != NVME_MI_STATUS_MORE_PROCESSING_REQUIRED;

    if (!pinfo->fd->visited && replay) {
        fi = wmem_new0(wmem_file_scope(), struct nvme_mi_frame_info);
        fi->trans = replay->trans;
        fi->endpoint = ep;
        fi->replay = replay;
        fi->refused = mic_bad || status_absent;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_nvme_mi,
                         NVME_MI_PROTO_DATA_FRAME, fi);
        /* A retransmitted MPR (Fig 29) leaves the lifecycle untouched. */
        if (!fi->refused)
            ep->replay[transport_tag] = NULL;
        /* With no original seen, this copy is the command's response, and
         * takes the original's place in the slot lifecycle.  A nonzero RRO
         * means a response of more than one packet, which an MPR (Figure 34,
         * 12 bytes) never is. */
        if (!fi->refused && (!replay->response || replayed_final)) {
            replay_response = true;
            struct nvme_mi_transaction *cmd = replay->trans;
            struct nvme_mi_endpoint *cep = cmd->endpoint;
            bool status_known = partial_replay ||
                                (payload_len >= 1 && tvb_bytes_exist(tvb, 4, 1));
            bool is_mpr = !partial_replay && status_known &&
                          tvb_get_uint8(tvb, 4) ==
                              NVME_MI_STATUS_MORE_PROCESSING_REQUIRED;

            if (status_known && !is_mpr) {
                if (!cmd->resp_frame)
                    cmd->resp_frame = pinfo->num;
                if (cep->occupant[cmd->req_csi] == cmd)
                    cep->occupant[cmd->req_csi] = NULL;
            }
            if (!partial_replay && status_known)
                nvme_mi_record_response(cep, cmd->req_csi, cmd, tvb, pinfo,
                                        is_mpr);
        }
    }

    /* The Command Slot lifecycle; an AEM or Reserved type owns no slot. */
    if (!pinfo->fd->visited && !replay && !ror_mismatch &&
        nvme_mi_type_tracks_slot(type))
        fi = nvme_mi_track_transaction(tvb, pinfo, type, resp, csi, meb, payload_len,
                                       integrity_ok, mic_bad, status_absent,
                                       transport_tag, &ep, fi);

    /* An error response may echo an invalid NMIMT (MI 2.2 4.1.2, Figures
     * 28-32): only the Generic and Invalid Parameter formats. */
    uint8_t reserved_status = 0;
    bool reserved_error = !nvme_mi_type_is_known(type) && resp &&
        payload_len == 4 && tvb_bytes_exist(tvb, 4, 4);
    if (reserved_error) {
        reserved_status = tvb_get_uint8(tvb, 4);
        reserved_error = (reserved_status >= 0x02 && reserved_status <= 0x08) ||
                         (reserved_status >= 0x20 && reserved_status <= 0x2a);
    }
    if (!nvme_mi_type_is_known(type) && !reserved_error)
        expert_add_info(pinfo, type_it, &ei_nvme_mi_reserved_type);

    /* Cross-references; none for a refused response. */
    if (fi && !fi->refused) {
        if (resp) {
            if (fi->trans->req_frame) {
                nstime_t ns;
                /* MI 2.2 section 1.8.41 measures to the start of the response.
                 * Request time remains the request's completion timestamp. */
                nstime_delta(&ns, start_time,
                             &fi->trans->req_time);

                it2 = proto_tree_add_uint(nvme_mi_tree, hf_nvme_mi_response_to,
                                          tvb, 0, 0, fi->trans->req_frame);
                proto_item_set_generated(it2);
                it2 = proto_tree_add_time(nvme_mi_tree, hf_nvme_mi_response_time,
                                          tvb, 0, 0, &ns);
                proto_item_set_generated(it2);
                if (out_of_band && fi->trans->req_csi != (uint8_t)csi &&
                    /* 4.2.1.1/4.2.1.2: Pause and Resume name no slot. */
                    !(type == NVME_MI_TYPE_CONTROL &&
                      (!fi->trans->req_parsed || fi->trans->opcode <= 0x01)))
                    expert_add_info_format(pinfo, csi_it,
                        &ei_nvme_mi_response_csi_mismatch,
                        "Response CSI %u does not name Command Slot %u of its"
                        " request in frame %u (NVMe-MI 'NVMe-MI Message Fields')",
                        (unsigned)csi, fi->trans->req_csi,
                        fi->trans->req_frame);
            }
            if (fi->is_interim_mpr) {
                it2 = proto_tree_add_boolean(nvme_mi_tree,
                                             hf_nvme_mi_response_is_mpr,
                                             tvb, 0, 0, true);
                proto_item_set_generated(it2);
            }
            if (fi->duplicate_mpr)
                proto_tree_add_expert(nvme_mi_tree, pinfo, &ei_nvme_mi_duplicate_mpr,
                                      tvb, 4, 1);
            if (fi->cp_late)
                proto_tree_add_expert(nvme_mi_tree, pinfo,
                                      &ei_nvme_mi_late_control_response,
                                      tvb, 4, 1);
        } else {
            if (fi->superseded)
                nvme_mi_note_superseded(tvb, pinfo, nvme_mi_tree, ti,
                                        fi->superseded);
            if (fi->trans->resp_frame) {
                it2 = proto_tree_add_uint(nvme_mi_tree, hf_nvme_mi_response_in,
                                          tvb, 0, 0, fi->trans->resp_frame);
                proto_item_set_generated(it2);
            }
        }
    }

    if (resp && !fi) {
        const struct nvme_mi_csi_candidate *cand =
            p_get_proto_data(wmem_file_scope(), pinfo, proto_nvme_mi,
                             NVME_MI_PROTO_DATA_CSI_CANDIDATE);
        if (cand)
            expert_add_info_format(pinfo, csi_it,
                &ei_nvme_mi_response_csi_candidate,
                "Possible response CSI mismatch: CSI %u has no matching"
                " request; an outstanding same-type request names CSI %u"
                " in frame %u (a missing request or reused tag is also"
                " possible)", cand->resp_csi, cand->req_csi,
                cand->req_frame);
    }

    if (fi && fi->refused && fi->unable_to_abort_not_abort)
        proto_tree_add_expert(nvme_mi_tree, pinfo,
                              &ei_nvme_mi_unable_to_abort_not_abort,
                              tvb, 4, 1);

    /* No STATUS reported (Figure 28), on every pass; not for a sliced one. */
    if (status_absent)
        expert_add_info(pinfo, ti, &ei_nvme_mi_status_absent);

    sub_tvb = tvb_new_subset_length(tvb, 4, payload_len);

    struct nvme_mi_dissect_ctx ctx = {
        .resp         = resp,
        .integrity_ok = integrity_ok,
        .admitted     = fi && !fi->refused,
        .replay       = replay != NULL,
        .replay_response = replay_response,
        .meb          = resp ? (fi && fi->trans->req_meb) : meb,
        .trans        = fi ? fi->trans : NULL,
        .endpoint     = ep,
    };
    /* Retention, then publication, then display. */
    if (type == NVME_MI_TYPE_MI)
        nvme_mi_mi_pre_observe(sub_tvb, pinfo, &ctx);

    /* The integrity verdict, before the body, which may throw.  A sliced MIC
     * is "missing"; sliced covered bytes are unverified. */
    if (mic_enabled) {
        unsigned mic_flags;

        if (!tvb_bytes_exist(tvb, payload_len + 4, 4))
            mic_flags = PROTO_CHECKSUM_NOT_PRESENT;
        else if (mic_computed)
            mic_flags = PROTO_CHECKSUM_VERIFY;
        else
            mic_flags = PROTO_CHECKSUM_NO_FLAGS;

        proto_tree_add_checksum(nvme_mi_tree, tvb, payload_len + 4,
                                hf_nvme_mi_mic, hf_nvme_mi_mic_status,
                                &ei_nvme_mi_mic_bad, pinfo, mic_crc,
                                ENC_LITTLE_ENDIAN, mic_flags);

        if (nvme_mi_check_mic && !partial_replay &&
            mic_flags != PROTO_CHECKSUM_VERIFY) {
            proto_item *unverified = proto_tree_add_boolean(nvme_mi_tree,
                hf_nvme_mi_mic_unverified, tvb, payload_len + 4, 0, TRUE);
            proto_item_set_generated(unverified);
            proto_item_set_hidden(unverified);
        }
    }

    if (replay) {
        if (replay->response && !replayed_final) {
            it2 = proto_tree_add_uint(nvme_mi_tree, hf_nvme_mi_replay_of,
                                      tvb, 0, 0, replay->response->frame);
            proto_item_set_generated(it2);
        }
        it2 = proto_tree_add_uint(nvme_mi_tree, hf_nvme_mi_replay_request,
                                  tvb, 0, 0, replay->request_frame);
        proto_item_set_generated(it2);
        if (replay->response && replay->response->is_mpr && !replayed_final) {
            it2 = proto_tree_add_boolean(nvme_mi_tree, hf_nvme_mi_replay_mpr,
                                         tvb, 0, 0, true);
            proto_item_set_generated(it2);
        }
        if (partial_replay) {
            /* section 4.2.1.5: the suffix is neither a body nor a CRC input. */
            expert_add_info_format(pinfo, ti, &ei_nvme_mi_partial_replay,
                    "Partial replay from packet %u: association retained;"
                    " response body and original MIC not reconstructed",
                    replay->rro);
            proto_tree_add_item(nvme_mi_tree, hf_nvme_mi_replay_data,
                                sub_tvb, 0, -1, ENC_NA);
            return tvb_captured_length(tvb);
        }
    }

    if (reserved_error) {
        proto_tree_add_item(nvme_mi_tree, hf_nvme_mi_status, sub_tvb, 0, 1,
                            ENC_NA);
        nvme_mi_dissect_resp_status_bytes(sub_tvb, pinfo, nvme_mi_tree,
                                          reserved_status);
        nvme_mi_append_status_info(pinfo, tvb, type, resp, payload_len);
        return tvb_captured_length(tvb);
    }

    /* Fall back to data only when bytes are left. */
    if (!dissector_try_uint_with_data(nvme_mi_type_dissector_table, type,
                                      sub_tvb, pinfo, nvme_mi_tree, false,
                                      &ctx) && payload_len > 0)
        call_data_dissector(sub_tvb, pinfo, nvme_mi_tree);

    nvme_mi_append_status_info(pinfo, tvb, type, resp, payload_len);
    return tvb_captured_length(tvb);
}

void
proto_register_nvme_mi(void)
{
    /* *INDENT-OFF* */
    static hf_register_info hf[] = {
        { &hf_nvme_mi_hdr_reserved1,
          { "Reserved (NMP)", "nvme-mi.header.reserved1",
            FT_UINT32, BASE_HEX, NULL, 0x00000600, NULL, HFILL } },
        { &hf_nvme_mi_hdr_reserved2,
          { "Reserved (byte 2)", "nvme-mi.header.reserved2",
            FT_UINT32, BASE_HEX, NULL, 0x00fc0000, NULL, HFILL } },
        { &hf_nvme_mi_hdr_reserved3,
          { "Reserved (byte 3)", "nvme-mi.header.reserved3",
            FT_UINT32, BASE_HEX, NULL, 0xff000000, NULL, HFILL } },
        { &hf_nvme_mi_pel_reserved,
          { "Reserved", "nvme-mi.pel.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xf8, NULL, HFILL } },
        { &hf_nvme_mi_mpr_reserved,
          { "Reserved", "nvme-mi.mpr.reserved",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Byte 5 of the NVMe-MI 'More Processing Required Response'", HFILL } },
        /* Common NVMe-MI header (4 bytes, NVMe-MI 2.2 "NVMe-MI Message
         * Fields") */
        { &hf_nvme_mi_mctp_mt,
          { "MCTP message type", "nvme-mi.mctp-mt",
            FT_UINT32, BASE_HEX, VALS(mi_mctp_type_vals), 0x7f,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mctp_ic,
          { "MCTP IC", "nvme-mi.mctp-ic",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL },
        },
        { &hf_nvme_mi_csi,
          { "CSI", "nvme-mi.csi",
            FT_BOOLEAN, 32, TFS(&tfs_csi), 0x00000100,
            "Command Slot Identifier", HFILL },
        },
        { &hf_nvme_mi_type,
          { "Type", "nvme-mi.type",
            FT_UINT32, BASE_HEX, VALS(mi_type_vals),
            0x00007800,
            NULL, HFILL },
        },
        { &hf_nvme_mi_ror,
          { "ROR", "nvme-mi.ror",
            FT_BOOLEAN, 32, TFS(&tfs_response_request), 0x00008000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_ciap,
          { "CIAP", "nvme-mi.ciap",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00020000,
            "Command Initiated Auto Pause: pause the Management Endpoint when"
            " this Command Message enters the Process state", HFILL },
        },
        { &hf_nvme_mi_meb,
          { "MEB", "nvme-mi.meb",
            FT_BOOLEAN, 32, TFS(&tfs_meb), 0x00010000,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mic,
          { "Message Integrity Check", "nvme-mi.mic",
            FT_UINT32, BASE_HEX, NULL, 0,
            "CRC-32C over the NVMe-MI Message ahead of it, little-endian"
            " (NVMe-MI Appendix B)",
            HFILL },
        },
        { &hf_nvme_mi_mic_status,
          { "Message Integrity Check Status", "nvme-mi.mic.status",
            FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_mic_unverified,
          { "Message Integrity Check Unverified", "nvme-mi.mic_unverified",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            "The MIC could not be verified against all captured bytes", HFILL },
        },

        /* Invalid Parameter Error Response (status 04h) - Parameter Error
         * Location over payload bytes 3:1; shared by the command message
         * types via nvme_mi_dissect_invalid_param_resp(). */
        { &hf_nvme_mi_pel_bit,
          { "Bit Location (BITLOC)", "nvme-mi.pel.bit",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            "Least-significant bit of the parameter in error", HFILL },
        },
        { &hf_nvme_mi_status,
          { "Status", "nvme-mi.status",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(nvme_mi_status_vals), 0,
            "Common Error Response status for a reserved NMIMT request",
            HFILL },
        },
        { &hf_nvme_mi_pel_byte,
          { "Byte Location (BYTLOC)", "nvme-mi.pel.byte",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Offset of the least-significant byte of the parameter in"
            " error, relative to the start of the Request Message", HFILL },
        },

        /* More Processing Required Response MPRT, payload bytes 3:2
         * (NVMe-MI 2.2 Figure 34), via nvme_mi_dissect_resp_status_bytes(). */
        { &hf_nvme_mi_mprt,
          { "More Processing Required Time (MPRT)", "nvme-mi.mprt",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(nvme_mi_fmt_mprt), 0,
            "Worst-case additional processing time before the final"
            " Response Message (NVMe-MI 'More Processing Required"
            " Response Fields')", HFILL },
        },
        { &hf_nvme_mi_resp_rsvd,
          { "Reserved", "nvme-mi.resp_reserved",
            FT_UINT24, BASE_HEX, NULL, 0,
            "Reserved in an Error Response that carries no Parameter Error"
            " Location or More Processing Required Time (NVMe-MI"
            " 'Generic Error Response')", HFILL },
        },
        { &hf_nvme_mi_resp_undefined,
          { "Undefined Response Data", "nvme-mi.resp_undefined",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Response bytes 7:5 for a Reserved Status (NVMe-MI 'Response Message Status Values')",
            HFILL },
        },
        { &hf_nvme_mi_resp_vendor,
          { "Vendor Specific Response Data", "nvme-mi.resp_vendor",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Response bytes 7:5 for a Vendor Specific Status (NVMe-MI"
            " 'Response Message Status Values')", HFILL },
        },

        /* Request/response cross-reference (generated fields) */
        { &hf_nvme_mi_response_in,
          { "Response In", "nvme-mi.response_in",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            "The response to this NVMe-MI request is in this frame", HFILL }
        },
        { &hf_nvme_mi_response_to,
          { "Request In", "nvme-mi.response_to",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            "This is a response to the NVMe-MI request in this frame", HFILL }
        },
        { &hf_nvme_mi_response_time,
          { "Response Time", "nvme-mi.response_time",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "The time between the request and the response", HFILL }
        },
        { &hf_nvme_mi_response_is_mpr,
          { "More Processing Required", "nvme-mi.response_is_mpr",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "This is an interim response; the endpoint will send a final"
            " response when processing is complete", HFILL }
        },
        { &hf_nvme_mi_prev_no_response,
          { "Previous Request Expects No Response", "nvme-mi.prev_no_response",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0,
            "The previous request on this slot was a Reset NVM Subsystem,"
            " which is owed no response (NVMe-MI section 5.9)",
            HFILL }
        },
        { &hf_nvme_mi_replay_of,
          { "Replay of response", "nvme-mi.replay_of",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_replay_request,
          { "Replay requested in", "nvme-mi.replay_request",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0,
            NULL, HFILL },
        },
        { &hf_nvme_mi_replay_mpr,
          { "Replayed MPR", "nvme-mi.replay_mpr",
            FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL },
        },
        { &hf_nvme_mi_replay_data,
          { "Unreconstructed replay data", "nvme-mi.replay_data",
            FT_BYTES, SEP_SPACE, NULL, 0, NULL, HFILL },
        },

    };
    /* *INDENT-ON* */

    static int *ett[] = {
        &ett_nvme_mi,
        &ett_nvme_mi_hdr,
    };

    static ei_register_info ei[] = {
        { &ei_nvme_mi_late_control_response,
          { "nvme-mi.late_control_response", PI_SEQUENCE, PI_NOTE,
            "Response to a Control Primitive, arriving after a later Control"
            " Primitive on the same MCTP tag; only the response to the last"
            " Control Primitive is guaranteed (NVMe-MI 'Control Primitives')",
            EXPFILL } },
        { &ei_nvme_mi_duplicate_mpr,
          { "nvme-mi.duplicate_mpr", PI_SEQUENCE, PI_WARN,
            "More than one MPR for a Command Message without Replay", EXPFILL } },
        { &ei_nvme_mi_message_too_large,
          { "nvme-mi.message_too_large", PI_PROTOCOL, PI_WARN,
            "Out-of-band NVMe-MI message exceeds 4224 bytes", EXPFILL } },
        { &ei_nvme_mi_mic_truncated,
          { "nvme-mi.mic_truncated", PI_MALFORMED, PI_WARN,
            "IC bit is set but the message is too short to contain a MIC;"
            " trailing bytes treated as payload", EXPFILL }
        },
        { &ei_nvme_mi_mic_bad,
          { "nvme-mi.mic_bad", PI_CHECKSUM, PI_WARN,
            "Message Integrity Check does not match the computed CRC-32C",
            EXPFILL }
        },
        /* PI_NOTE: broader than the error section 4.2 defines (a request the
         * endpoint discarded on a bad MIC also matches), so not a warning. */
        { &ei_nvme_mi_req_superseded,
          { "nvme-mi.req_superseded", PI_SEQUENCE, PI_NOTE,
            "The previous request on this command slot was left unanswered;"
            " request/response tracking assumes this request supersedes it,"
            " but the endpoint may instead have discarded this one and kept"
            " servicing the previous request", EXPFILL }
        },
        { &ei_nvme_mi_status_absent,
          { "nvme-mi.status_absent", PI_MALFORMED, PI_ERROR,
            "Response Message reports no Status byte (NVMe-MI 'Response"
            " Message Fields' makes STATUS mandatory at message byte 4); the"
            " outcome is unknown, so the command slot stays open and this"
            " message is not credited as the response to it", EXPFILL }
        },
        { &ei_nvme_mi_reserved_type,
          { "nvme-mi.reserved_type", PI_PROTOCOL, PI_WARN,
            "NVMe-MI Message Type is Reserved (NVMe-MI 'NVMe-MI"
            " Message Fields'); the"
            " message body cannot be decoded and the message takes no part in"
            " command slot tracking", EXPFILL }
        },
        { &ei_nvme_mi_partial_replay,
          { "nvme-mi.partial_replay", PI_UNDECODED, PI_NOTE,
            "Partial replay: response body and original MIC not reconstructed",
            EXPFILL }
        },
        { &ei_nvme_mi_too_short,
          { "nvme-mi.too_short", PI_MALFORMED, PI_ERROR,
            "NVMe-MI message is shorter than the four-byte NVMe-MI Message"
            " Header, so it cannot be a complete NVMe-MI Message (NVMe-MI"
            " 'NVMe-MI Message Fields')", EXPFILL }
        },
        { &ei_nvme_mi_ror_tag_owner,
          { "nvme-mi.ror_tag_owner", PI_PROTOCOL, PI_WARN,
            "The ROR bit disagrees with the MCTP Tag Owner bit", EXPFILL }
        },
        { &ei_nvme_mi_oob_response_ic,
          { "nvme-mi.oob_response_ic", PI_PROTOCOL, PI_NOTE,
            "The IC bit shall be set on out-of-band Response and Asynchronous"
            " Event Messages (NVMe-MI 'NVMe-MI Message Fields')", EXPFILL }
        },
        { &ei_nvme_mi_control_header_flags,
          { "nvme-mi.control_header_flags", PI_PROTOCOL, PI_WARN,
            "CIAP or MEB set to 1 is prohibited in a Control Primitive"
            " (NVMe-MI 'NVMe-MI Message Fields')", EXPFILL }
        },
        { &ei_nvme_mi_response_meb,
          { "nvme-mi.response_meb", PI_PROTOCOL, PI_WARN,
            "MEB set to 1 is prohibited outside a Command Message; a Response"
            " Message clears it (NVMe-MI 'NVMe-MI Message Fields')", EXPFILL }
        },
        { &ei_nvme_mi_aem_header,
          { "nvme-mi.aem_header", PI_PROTOCOL, PI_WARN,
            "Asynchronous Event Message header field shall be cleared to 0"
            " (NVMe-MI 'NVMe-MI Message Fields')", EXPFILL }
        },
        { &ei_nvme_mi_response_csi_mismatch,
          { "nvme-mi.response_csi_mismatch", PI_PROTOCOL, PI_WARN,
            "Response CSI does not name the Command Slot of its request"
            " (NVMe-MI 'NVMe-MI Message Fields')", EXPFILL }
        },
        { &ei_nvme_mi_response_csi_candidate,
          { "nvme-mi.response_csi_candidate", PI_SEQUENCE, PI_NOTE,
            "Possible response CSI mismatch (NVMe-MI 'NVMe-MI Message Fields')",
            EXPFILL }
        },
        { &ei_nvme_mi_aem_tag_owner,
          { "nvme-mi.aem_tag_owner", PI_PROTOCOL, PI_WARN,
            "An Asynchronous Event Message is sent with the MCTP Tag Owner bit"
            " set (NVMe-MI section 4.4.4)", EXPFILL }
        },
        { &ei_nvme_mi_cp_csi,
          { "nvme-mi.cp_csi", PI_PROTOCOL, PI_NOTE,
            "CSI is not used by Pause or Resume and should be cleared to 0;"
            " if set, the Management Endpoint returns an Invalid Parameter"
            " Error Response (NVMe-MI sections 4.2.1.1, 4.2.1.2)",
            EXPFILL }
        },
        { &ei_nvme_mi_unable_to_abort_not_abort,
          { "nvme-mi.unable_to_abort_not_abort", PI_SEQUENCE, PI_WARN,
            "Unable to Abort answers only an Abort Control Primitive"
            " (NVMe-MI 'Response Message Status Values'); not linked to the"
            " outstanding"
            " Control Primitive", EXPFILL }
        },
        { &ei_nvme_mi_reserved_status,
          { "nvme-mi.reserved_status", PI_PROTOCOL, PI_WARN,
            "Response Message Status is a Reserved value (NVMe-MI"
            " 'Response Message Status Values')", EXPFILL }
        },
    };

    expert_module_t *expert_nvme_mi;

    proto_nvme_mi = proto_register_protocol("NVMe-MI", "NVMe-MI", "nvme-mi");
    proto_register_field_array(proto_nvme_mi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_nvme_mi = expert_register_protocol(proto_nvme_mi);
    expert_register_field_array(expert_nvme_mi, ei, array_length(ei));

    nvme_mi_type_dissector_table = register_dissector_table("nvme-mi.type",
            "NVMe-MI Message Type", proto_nvme_mi, FT_UINT8, BASE_HEX);

    module_t *nvme_mi_module = prefs_register_protocol(proto_nvme_mi, NULL);
    prefs_register_bool_preference(nvme_mi_module, "check_mic",
            "Validate the Message Integrity Check",
            "Whether to compute the CRC-32C over each NVMe-MI message and"
            " verify it against the Message Integrity Check (MIC).",
            &nvme_mi_check_mic);
    prefs_register_bool_preference(nvme_mi_module, "ctrlinfo_ari",
            "Controller Information reports an ARI Device",
            "Whether the PCIe Routing ID in Controller Information is read as"
            " an ARI Device's 8-bit Function Number (NVMe-MI 'Controller Information"
            " Data Structure');"
            " the message does not say.",
            &nvme_mi_ctrlinfo_ari);

    nvme_mi_handle = register_dissector_with_description("nvme-mi",
            "NVMe-MI over MCTP", dissect_nvme_mi, proto_nvme_mi);
}

void
proto_reg_handoff_nvme_mi(void)
{
    dissector_add_uint("mctp.type", MCTP_TYPE_NVME, nvme_mi_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
