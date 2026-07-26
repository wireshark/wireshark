/* packet-nvme-mi.h
 * Shared types for NVMe Management Interface (NVMe-MI) dissectors
 * Copyright 2026, Brandon Chiu
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_NVME_MI_H__
#define __PACKET_NVME_MI_H__

#include <epan/packet.h>

/* NVMe-MI Message Type (NMIMT) values — NVMe-MI 2.1 Figure 20.
 * 3h and 6h-Fh are Reserved. */
enum nvme_mi_msg_type {
    NVME_MI_TYPE_CONTROL = 0x0,
    NVME_MI_TYPE_MI      = 0x1,
    NVME_MI_TYPE_ADMIN   = 0x2,
    NVME_MI_TYPE_PCIE    = 0x4,
    NVME_MI_TYPE_AEM     = 0x5,   /* Asynchronous Event Message (§4.1.3) */
};

/*
 * Response Message Status values (NVMe-MI 2.1 Figure 29).  The status byte is
 * common to every response message type, so the table is shared by all the
 * per-type body dissectors.  Defined in packet-nvme-mi.c.
 */
extern const value_string nvme_mi_status_vals[];

/*
 * NVMe-MI Message Type (NMIMT) names (NVMe-MI 2.1 Figure 12).  Defined in
 * packet-nvme-mi.c and shared so the command-list entry decode (which carries
 * an NMIMT in each entry) renders the same names as the message header.
 */
extern const value_string mi_type_vals[];

/* Status values the body dissectors branch on (subset of status values). */
#define NVME_MI_STATUS_SUCCESS                   0x00
#define NVME_MI_STATUS_MORE_PROCESSING_REQUIRED  0x01
#define NVME_MI_STATUS_INVALID_PARAMETER         0x04

/*
 * Decode payload bytes 3:1 of a Response Message according to its Response
 * Message Status.  Those bytes are status-dependent and mutually exclusive:
 * the Parameter Error Location on an Invalid Parameter Error Response
 * (NVMe-MI 2.1 Figure 32), the More Processing Required Time on a More
 * Processing Required Response (Figure 34), and Reserved on any other Error
 * Response (Figure 30).  Only a Success Response gives them a command-specific
 * meaning, so this returns true in that case alone and the caller renders the
 * bytes itself (the MI NVMe Management Response, the Admin reserved dwords).
 *
 * The error-response formats are defined at the message level and shared by
 * every command message type, so the MI/Admin/PCIe body dissectors all call
 * this rather than each decoding them -- and none of them mislabels an error
 * response's bytes as command-specific.  The caller must have at least 4
 * payload bytes.  Defined in packet-nvme-mi.c.
 */
bool nvme_mi_dissect_resp_status_bytes(tvbuff_t *tvb, proto_tree *tree,
                                       uint8_t status);

/*
 * Flag a truncated/short payload via the given expert field and render any
 * bytes remaining from `off` raw under `hf_data`.  Shared by the body
 * dissectors so the "expert + leftover bytes" rendering is defined once.
 * Defined in packet-nvme-mi.c.
 */
void nvme_mi_dissect_truncated(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, proto_item *it,
                               expert_field *ei, int hf_data, int off);

/*
 * Per-transaction state shared across the request frame and every response
 * frame (including MPR interim responses) that belongs to the same command.
 * Allocated in wmem_file_scope().
 *
 * The per-type fields below are owned by the body dissector, not the framing
 * layer: the body dissector fills them in while dissecting the request and
 * reads them back when the matching response is dissected (the response
 * carries no opcode of its own).  'opcode' is the per-type opcode (CP CPO /
 * MI opcode / Admin opcode); any further per-type request state lives behind
 * 'body_ctx'.
 */
struct nvme_mi_transaction {
    uint32_t  req_frame;
    uint32_t  resp_frame;   /* 0 until a non-MPR response is seen */
    nstime_t  req_time;
    /*
     * true once the request 'opcode' (the command byte at payload offset 0)
     * has been recorded: by the always-run framing layer for Admin/MI Command
     * Messages, or by the Control body once past its >= 4-byte guard.  Stays
     * false when the request was too short to record an opcode; the response
     * side must then treat the opcode as unknown (zero-filled, not observed)
     * rather than interpreting it.  Independent of body_ctx, which the body
     * dissector populates separately and which may be NULL even when
     * req_parsed is true (e.g. an Admin request truncated below its 64-byte
     * SQE, or a disabled body protocol).
     */
    bool      req_parsed;
    /*
     * NMIMT of the request that owns 'opcode' and 'body_ctx'.  ADMIN and MI
     * requests share the same per-CSI command slot, so a response of one type
     * can land on a slot opened by a request of the other type; the response
     * side must check this matches its own NMIMT before trusting opcode or
     * casting body_ctx.  Set by the framing layer when the request is seen.
     */
    uint8_t   nmimt;
    unsigned  opcode;
    /*
     * Opaque per-opcode request context, owned entirely by the body
     * dissector that handles this transaction's NMIMT (the framing layer
     * never looks inside).  Allocated in wmem_file_scope() while dissecting
     * the request and read back when dissecting the matching response(s),
     * for request parameters that select the response layout or that the
     * response must echo (e.g. the MI Read NVMe-MI Data Structure DTYP, the
     * Configuration Set/Get CONFIGID, or the Control Primitive tag).  NULL
     * when the request did not carry those fields (truncated) or no request
     * was seen.
     */
    void     *body_ctx;
};

/*
 * Passed as the 'data' void-pointer through the "nvme-mi.type" dissector
 * table so each sub-dissector receives request/response context without
 * needing a global.  The framing layer always passes a valid pointer, but
 * the table is globally registered and external callers (e.g. Lua scripts
 * driving it directly) may pass NULL, so sub-dissectors must reject a NULL
 * data pointer:
 *
 *   if (!data) return 0;
 *
 * trans may be NULL when no matching request has been seen yet.
 */
struct nvme_mi_dissect_ctx {
    bool                        resp;
    struct nvme_mi_transaction *trans;
};

/*
 * Response opcode recovery, shared by the command-message body dissectors.  A
 * response carries no opcode of its own, so it must be recovered from the
 * matching request.  When 'trans' is a parsed request of NMIMT 'nmimt', adds a
 * generated 'hf_opcode' item carrying the recovered opcode (returned via
 * '*opcode'), and returns that proto_item so the caller can append a name.
 * Otherwise (no request, truncated request, or a request of a different
 * NMIMT that happens to share the slot) fires 'ei_orphan' against 'it' and
 * returns NULL with '*opcode' set to 0.  Defined in packet-nvme-mi.c.
 */
proto_item *nvme_mi_recover_resp_opcode(tvbuff_t *tvb, packet_info *pinfo,
                                        proto_tree *tree, proto_item *it,
                                        const struct nvme_mi_transaction *trans,
                                        uint8_t nmimt, int hf_opcode,
                                        expert_field *ei_orphan,
                                        unsigned *opcode);

/*
 * Return the transaction's per-opcode request context, allocating it (zeroed,
 * 'size' bytes, wmem_file_scope) on first use.  Lets each body dissector store
 * its own struct in trans->body_ctx without repeating the allocate-once
 * idiom.  'trans' must be non-NULL.  Defined in packet-nvme-mi.c.
 */
void *nvme_mi_trans_body_ctx(struct nvme_mi_transaction *trans, size_t size);

#endif /* __PACKET_NVME_MI_H__ */

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
