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

/* NVMe-MI Message Type (NMIMT) values (NVMe-MI 2.2 Figure 20). */
enum nvme_mi_msg_type {
    NVME_MI_TYPE_CONTROL = 0x0,
    NVME_MI_TYPE_MI      = 0x1,
    NVME_MI_TYPE_ADMIN   = 0x2,
    NVME_MI_TYPE_PCIE    = 0x4,
    NVME_MI_TYPE_AEM     = 0x5,   /* Asynchronous Event Message (§4.1.3) */
};

/* Response Message Status values (NVMe-MI 2.2 Figure 29). */
extern const range_string nvme_mi_status_vals[];

/* NMIMT names over the whole four-bit domain (NVMe-MI 2.2 Figure 20). */
extern const value_string mi_type_vals[];

extern const range_string nvme_mi_pcie_opcode_vals[];

/* Status values the body dissectors branch on. */
#define NVME_MI_STATUS_SUCCESS                   0x00
#define NVME_MI_STATUS_MORE_PROCESSING_REQUIRED  0x01

/* Figure 29 Status runs with no Response Message format (inclusive). */
#define NVME_MI_STATUS_RSVD_LOW_FIRST            0x09
#define NVME_MI_STATUS_RSVD_LOW_LAST             0x1f
#define NVME_MI_STATUS_RSVD_HIGH_FIRST           0x2b
#define NVME_MI_STATUS_RSVD_HIGH_LAST            0xdf
#define NVME_MI_STATUS_VENDOR_FIRST              0xe0

/* A non-Success Status whose 4-byte Response Message format the spec
 * defines (NVMe-MI 2.2 Figures 30-34): not Reserved, not Vendor Specific
 * (E0h-FFh). */
static inline bool
nvme_mi_status_has_response_format(uint8_t status)
{
    return status != NVME_MI_STATUS_SUCCESS &&
           !(status >= NVME_MI_STATUS_RSVD_LOW_FIRST &&
             status <= NVME_MI_STATUS_RSVD_LOW_LAST) &&
           !(status >= NVME_MI_STATUS_RSVD_HIGH_FIRST);
}

/* "nvme-mi.ctrlinfo_ari": read the Controller Information Routing ID as ARI. */
extern bool nvme_mi_ctrlinfo_ari;

/* MI Reset (NVMe-MI 2.2 Figure 68): Reset NVM Subsystem has no response. */
#define NVME_MI_MI_OPC_RESET                     0x07

/* Control Primitive opcodes the framing layer tracks (NVMe-MI 2.2 Figure 38). */
#define NVME_MI_CP_OPC_ABORT                     0x02
#define NVME_MI_CP_OPC_REPLAY                    0x04

/* Decode Response Message bytes 3:1 by Status (NVMe-MI 2.2 Figures 30-34).
 * Needs >= 4 payload bytes.  Returns true for a Success Response, whose
 * bytes the caller renders. */
bool nvme_mi_dissect_resp_status_bytes(tvbuff_t *tvb, packet_info *pinfo,
                                       proto_tree *tree, uint8_t status);

/* Flag a short payload with 'ei' and render the rest from 'off' raw. */
void nvme_mi_dissect_truncated(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, proto_item *it,
                               expert_field *ei, int hf_data, int off);

struct nvme_mi_endpoint;

/* Per-transaction state shared by a request and its responses; file scope. */
struct nvme_mi_transaction {
    struct nvme_mi_endpoint *endpoint;
    uint32_t  req_frame;
    uint32_t  resp_frame;   /* 0 until a non-MPR response is seen */
    uint32_t  mpr_count;    /* Admitted, original MPRs; Replay does not increment. */
    nstime_t  req_time;
    bool      req_parsed;       /* 'opcode' was recorded */
    bool      req_integrity_ok; /* the request's MIC verified good */
    bool      req_mic_bad;      /* the request's MIC verified bad */
    uint8_t   nmimt;            /* NMIMT of the request owning opcode/body_ctx */
    unsigned  opcode;
    uint8_t   ctl_tag;          /* Control Primitive Tag (NVMe-MI 2.2 Figure 40) */
    bool      ctl_tag_known;
    uint8_t   req_csi;          /* the request's Command Slot Identifier */
    bool      req_meb;          /* routing is selected by the request */
    uint8_t   replay_rro;  /* Fig 46: packet offset, not a byte offset */
    struct nvme_mi_transaction *cp_superseded; /* unanswered CP this one displaced */
    bool      reset_nvm_subsystem; /* an MI Reset owed no response (section 5.9) */
    void     *body_ctx;         /* the body dissector's request context, or NULL */
};

/* MEB observations and routing: MEBS needs a proven current physical port,
 * and routing a command-list PORTID that matches it. */
void nvme_mi_mebs_observe(struct nvme_mi_endpoint *ep, packet_info *pinfo,
                          uint8_t port, uint32_t size);
void nvme_mi_meb_commands_observe(struct nvme_mi_endpoint *ep, packet_info *pinfo,
                                 uint8_t port, const uint8_t commands[32]);
bool nvme_mi_meb_routes(const struct nvme_mi_endpoint *ep, uint32_t frame,
                         unsigned opcode);

/* The "nvme-mi.type" table's 'data'.  External callers may pass NULL, so
 * sub-dissectors must reject it; trans is NULL with no request seen. */
struct nvme_mi_dissect_ctx {
    bool                        resp;
    bool                        integrity_ok; /* MIC present and good */
    bool                        admitted;
    bool                        replay;       /* no state effects; nonzero RRO: raw only */
    bool                        replay_response; /* the replay is the command's response of record */
    bool                        meb;
    struct nvme_mi_transaction *trans;
    struct nvme_mi_endpoint    *endpoint;     /* NULL outside the framing layer */
};

/* The response's opcode from its request, if one of NMIMT 'nmimt' was parsed. */
bool nvme_mi_resp_opcode(const struct nvme_mi_transaction *trans,
                         uint8_t nmimt, unsigned *opcode);

/* Admit MEB observations in an NMIMT 1h message, before body
 * dissection and independent of the tree. */
void nvme_mi_mi_pre_observe(tvbuff_t *body_tvb, packet_info *pinfo,
                            const struct nvme_mi_dissect_ctx *ctx);

/* nvme_mi_resp_opcode() plus the orphan expert; '*opcode' is 0 on false.
 * '*opcode_it' (optional) gets the generated item, NULL without a tree:
 * display only, never decide on it. */
bool nvme_mi_recover_resp_opcode(tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree, proto_item *it,
                                 const struct nvme_mi_transaction *trans,
                                 uint8_t nmimt, int hf_opcode,
                                 expert_field *ei_orphan, unsigned *opcode,
                                 proto_item **opcode_it);

/* An Abort Success with CPAS 01b ended 'trans' before it took effect. */
void nvme_mi_admin_command_aborted(packet_info *pinfo,
                                   const struct nvme_mi_transaction *trans);

/* Copy a fully parsed request context in, on the first pass; NULL when
 * 'trans' is NULL. */
void *nvme_mi_trans_publish_body_ctx(packet_info *pinfo,
                                     struct nvme_mi_transaction *trans,
                                     const void *src, size_t size);

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
