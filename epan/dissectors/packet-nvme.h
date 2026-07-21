/* packet-nvme.h
 * data structures for NVMe Dissection
 * Copyright 2016
 * Code by Parav Pandit
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef _PACKET_NVME_H_
#define _PACKET_NVME_H_

#define NVME_CMD_SIZE 64
#define NVME_CQE_SIZE 16

#define NVME_FABRIC_OPC 0x7F
#define NVME_FCTYPE_PROP_SET  0x0
#define NVME_FCTYPE_CONNECT   0x1
#define NVME_FCTYPE_PROP_GET  0x4
#define NVME_FCTYPE_AUTH_SEND 0x5
#define NVME_FCTYPE_AUTH_RECV 0x6
#define NVME_FCTYPE_DISCONNECT 0x8

/*
 * NVMe Admin command opcodes.  Promoted here from packet-nvme.c so transports
 * that reuse the admin-command decode (e.g. NVMe-MI over MCTP) can share both
 * the opcode constants and the dissector below.  The 0x14-0x8c entries are the
 * Admin opcodes that NVMe-MI 2.1 Figure 134 permits over the Management
 * Interface.
 */
#define NVME_AQ_OPC_DELETE_SQ              0x00
#define NVME_AQ_OPC_CREATE_SQ              0x01
#define NVME_AQ_OPC_GET_LOG_PAGE           0x02
#define NVME_AQ_OPC_DELETE_CQ              0x04
#define NVME_AQ_OPC_CREATE_CQ              0x05
#define NVME_AQ_OPC_IDENTIFY               0x06
#define NVME_AQ_OPC_ABORT                  0x08
#define NVME_AQ_OPC_SET_FEATURES           0x09
#define NVME_AQ_OPC_GET_FEATURES           0x0a
#define NVME_AQ_OPC_ASYNC_EVE_REQ          0x0c
#define NVME_AQ_OPC_NS_MGMT                0x0d
#define NVME_AQ_OPC_FW_COMMIT              0x10
#define NVME_AQ_OPC_FW_IMG_DOWNLOAD        0x11
#define NVME_AQ_OPC_SELF_TEST              0x14
#define NVME_AQ_OPC_NS_ATTACH              0x15
#define NVME_AQ_OPC_KEEP_ALIVE             0x18
#define NVME_AQ_OPC_VIRT_MGMT              0x1c
#define NVME_AQ_OPC_CAP_MGMT               0x20
#define NVME_AQ_OPC_LOCKDOWN               0x24
#define NVME_AQ_OPC_CLEAR_EXP_NVM_CFG      0x28
#define NVME_AQ_OPC_CREATE_EXP_NVM_SUBSYS  0x2a
#define NVME_AQ_OPC_MANAGE_EXP_NVM_SUBSYS  0x2d
#define NVME_AQ_OPC_MANAGE_EXP_NS          0x31
#define NVME_AQ_OPC_MANAGE_EXP_PORT        0x35
#define NVME_AQ_OPC_FORMAT_NVM             0x80
#define NVME_AQ_OPC_SECURITY_SEND          0x81
#define NVME_AQ_OPC_SECURITY_RECV          0x82
#define NVME_AQ_OPC_SANITIZE               0x84
#define NVME_AQ_OPC_GET_LBA_STATUS         0x86
#define NVME_AQ_OPC_SANITIZE_NS            0x8c

#define NVME_IDENTIFY_CNS_IDENTIFY_NS      0x0
#define NVME_IDENTIFY_CNS_IDENTIFY_CTRL    0x1
#define NVME_IDENTIFY_CNS_IDENTIFY_NSLIST  0x2


struct nvme_q_ctx {
    wmem_tree_t *pending_cmds;
    wmem_tree_t *done_cmds;
    wmem_tree_t *data_requests;
    wmem_tree_t *data_responses;
    wmem_tree_t *data_offsets;
    uint16_t    qid;
};

#define NVME_CMD_MAX_TRS (16)

struct nvme_cmd_ctx {
    uint32_t cmd_pkt_num;  /* pkt number of the cmd */
    uint32_t cqe_pkt_num;  /* pkt number of the cqe */

    uint32_t data_req_pkt_num;
    uint32_t data_tr_pkt_num[NVME_CMD_MAX_TRS];
    uint32_t first_tr_psn;

    nstime_t cmd_start_time;
    nstime_t cmd_end_time;
    uint32_t tr_bytes;   /* bytes transferred so far */
    bool fabric;     /* indicate whether cmd fabric type or not */

    union {
        struct {
            uint16_t cns;
        } cmd_identify;
        struct {
            uint64_t off;
            unsigned records;
            unsigned tr_rcrd_id;
            unsigned tr_off;
            unsigned tr_sub_entries;
            uint16_t lsi;
            uint8_t lid;
            uint8_t lsp;
            uint8_t uid_idx;
            uint8_t tr_type;
        } get_logpage;
        struct {
            uint8_t fid;
        } set_features;
        struct {
            union {
                struct {
                    uint8_t offset;
                } prop_get;
                struct {
                    uint16_t qid;
                } cnct;
            };
            uint8_t fctype; /* fabric cmd type */
        } fabric_cmd;
    } cmd_ctx;
    uint8_t opcode;
};

extern int hf_nvmeof_cmd_pkt;
extern int hf_nvmeof_data_req;

const char *get_nvmeof_cmd_string(uint8_t fctype);

void
nvme_publish_qid(proto_tree *tree, int field_index, uint16_t qid);

void
nvme_publish_cmd_latency(proto_tree *tree, struct nvme_cmd_ctx *cmd_ctx,
                         int field_index);
void
nvme_publish_to_cmd_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx);
void
nvme_publish_to_cqe_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx);
void
nvme_publish_to_data_req_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx);
void
nvme_publish_to_data_resp_link(proto_tree *tree, tvbuff_t *tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx);
void
nvme_publish_link(proto_tree *tree, tvbuff_t *tvb, int hf_index,
                             uint32_t pkt_no, bool zero_ok);

void nvme_update_cmd_end_info(packet_info *pinfo, struct nvme_cmd_ctx *cmd_ctx);

void
nvme_add_cmd_to_pending_list(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                             struct nvme_cmd_ctx *cmd_ctx,
                             void *ctx, uint16_t cmd_id);
void* nvme_lookup_cmd_in_pending_list(struct nvme_q_ctx *q_ctx, uint16_t cmd_id);

struct keyed_data_req
{
    uint64_t addr;
    uint32_t key;
    uint32_t size;
};

void
dissect_nvmeof_fabric_cmd(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *nvme_tree,
                                struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd, unsigned off, bool link_data_req);
void
dissect_nvmeof_cmd_data(tvbuff_t *data_tvb, packet_info *pinfo, proto_tree *data_tree,
                                 unsigned pkt_off, struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd, unsigned len);
void
dissect_nvmeof_fabric_cqe(tvbuff_t *nvme_tvb, packet_info *pinfo,
                        proto_tree *nvme_tree,
                        struct nvme_cmd_ctx *cmd_ctx, unsigned off);

void
nvme_add_data_request(struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx,
                                struct keyed_data_req *req);

struct nvme_cmd_ctx*
nvme_lookup_data_request(struct nvme_q_ctx *q_ctx, struct keyed_data_req *req);

void
nvme_add_data_tr_pkt(struct nvme_q_ctx *q_ctx,
                       struct nvme_cmd_ctx *cmd_ctx, uint32_t rkey, uint32_t frame_num);
struct nvme_cmd_ctx*
nvme_lookup_data_tr_pkt(struct nvme_q_ctx *q_ctx,
                          uint32_t rkey, uint32_t frame_num);

void
nvme_add_data_tr_off(struct nvme_q_ctx *q_ctx, uint32_t off, uint32_t frame_num);

uint32_t
nvme_lookup_data_tr_off(struct nvme_q_ctx *q_ctx, uint32_t frame_num);

void
nvme_add_cmd_cqe_to_done_list(struct nvme_q_ctx *q_ctx,
                              struct nvme_cmd_ctx *cmd_ctx, uint16_t cmd_id);
void*
nvme_lookup_cmd_in_done_list(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                             uint16_t cmd_id);

void dissect_nvme_cmd_sgl(tvbuff_t *cmd_tvb, proto_tree *cmd_tree, int field_index,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx, unsigned cmd_off, bool visited);

void
dissect_nvme_cmd(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx);

void nvme_update_transfer_request(packet_info *pinfo, struct nvme_cmd_ctx *cmd_ctx, struct nvme_q_ctx *q_ctx);

void
dissect_nvme_data_response(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx, unsigned len, bool is_inline);

void
dissect_nvme_cqe(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx);

/**
 * Returns string representation of opcode according
 * to opcode and queue id
 */
const char *
nvme_get_opcode_string(uint8_t opcode, uint16_t qid);

/* CSTS.SHST shutdown-status names; shared with the NVMe-MI CHDS decode. */
extern const value_string shst_table[];

/**
 * Decode the opcode-specific Admin SQE command dwords (CDW10-CDW15, at offset
 * 40 of the 64-byte SQE) into tree.  cmd_ctx->opcode selects the per-opcode
 * decoder; the opcode-specific cmd_ctx->cmd_ctx.* fields are populated in place
 * and the opcode detail (Identify CNS name, Get Log Page name) is appended to
 * COL_INFO.  Shared by the NVMe transports and the NVMe-MI Admin dissector,
 * which present the same SQE layout from offset 40 onward.
 */
void
nvme_dissect_admin_sqe_cdws(tvbuff_t *sqe_tvb, packet_info *pinfo,
                            proto_tree *tree, struct nvme_cmd_ctx *cmd_ctx);

/*
 * Tells if opcode can be an opcode of io queue.
 * Used to "Guess" queue type for nvme-tcp in case that "connect"
 * command was not recorded
 */
int
nvme_is_io_queue_opcode(uint8_t opcode);

#endif

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
