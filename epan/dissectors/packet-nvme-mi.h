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

/* NVMe-MI Message Type (NMIMT) values — NVMe-MI 2.1 Figure 12 */
enum nvme_mi_msg_type {
    NVME_MI_TYPE_CONTROL = 0x0,
    NVME_MI_TYPE_MI      = 0x1,
    NVME_MI_TYPE_ADMIN   = 0x2,
    NVME_MI_TYPE_PCIE    = 0x4,
};

/*
 * Response Message Status values (NVMe-MI 2.1 Figure 29).  The status byte is
 * common to every response message type, so the table is shared by all the
 * per-type body dissectors.  Defined in packet-nvme-mi.c.
 */
extern const value_string nvme_mi_status_vals[];

/* Status values the body dissectors branch on (subset of status values). */
#define NVME_MI_STATUS_SUCCESS                   0x00
#define NVME_MI_STATUS_MORE_PROCESSING_REQUIRED  0x01
#define NVME_MI_STATUS_INVALID_PARAMETER         0x04

/*
 * Decode the Parameter Error Location (PEL) of an Invalid Parameter Error
 * Response (status 04h) over payload bytes 3:1.  The error response format is
 * defined at the message level and shared by every command message type, so
 * the MI/Admin/PCIe body dissectors all call this rather than each decoding
 * the field.  The caller must have at least 4 payload bytes.  Defined in
 * packet-nvme-mi.c.
 */
void nvme_mi_dissect_invalid_param_resp(tvbuff_t *tvb, proto_tree *tree);

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
     * true once the request body dissector has recorded the per-type fields
     * below.  Stays false when the request was too truncated to parse; the
     * response side must then treat them as unknown (they are zero-filled,
     * not observed) rather than interpreting them.
     */
    bool      req_parsed;
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
