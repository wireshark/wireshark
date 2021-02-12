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

struct nvme_q_ctx {
    wmem_tree_t *pending_cmds;
    wmem_tree_t *done_cmds;
    wmem_tree_t *data_requests;
    wmem_tree_t *data_responses;
    guint16     qid;
};

struct nvme_cmd_ctx {
    guint32 cmd_pkt_num;  /* pkt number of the cmd */
    guint32 cqe_pkt_num;  /* pkt number of the cqe */

    guint32 data_req_pkt_num;
    guint32 data_resp_pkt_num;

    nstime_t cmd_start_time;
    nstime_t cmd_end_time;
    gboolean fabric;     /* indicate whether cmd fabric type or not */

    guint8  opcode;
    guint32 remote_key;
    guint16 resp_type;
};

void
nvme_publish_qid(proto_tree *tree, int field_index, guint16 qid);

void
nvme_publish_cmd_latency(proto_tree *tree, struct nvme_cmd_ctx *cmd_ctx,
                         int field_index);
void
nvme_publish_cqe_to_cmd_link(proto_tree *cqe_tree, tvbuff_t *cqe_tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx);
void
nvme_publish_cmd_to_cqe_link(proto_tree *cmd_tree, tvbuff_t *cqe_tvb,
                             int hf_index, struct nvme_cmd_ctx *cmd_ctx);

void
nvme_publish_data_pdu_to_cmd_link(proto_tree *pdu_tree, tvbuff_t *nvme_tvb,
                           int hf_index, struct nvme_cmd_ctx *cmd_ctx);

void nvme_update_cmd_end_info(packet_info *pinfo, struct nvme_cmd_ctx *cmd_ctx);

void
nvme_add_cmd_to_pending_list(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                             struct nvme_cmd_ctx *cmd_ctx,
                             void *ctx, guint16 cmd_id);
void* nvme_lookup_cmd_in_pending_list(struct nvme_q_ctx *q_ctx, guint16 cmd_id);

void nvme_add_data_request(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                           struct nvme_cmd_ctx *cmd_ctx, void *ctx);
void* nvme_lookup_data_request(struct nvme_q_ctx *q_ctx, guint32 key);

void
nvme_add_data_response(struct nvme_q_ctx *q_ctx,
                       struct nvme_cmd_ctx *cmd_ctx, guint32 rkey);
void*
nvme_lookup_data_response(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                          guint32 rkey);

void
nvme_add_cmd_cqe_to_done_list(struct nvme_q_ctx *q_ctx,
                              struct nvme_cmd_ctx *cmd_ctx, guint16 cmd_id);
void*
nvme_lookup_cmd_in_done_list(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                             guint16 cmd_id);

void dissect_nvme_cmd_sgl(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                          int field_index, struct nvme_cmd_ctx *cmd_ctx);

void
dissect_nvme_cmd(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx);

void
dissect_nvme_data_response(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx, guint len);

void
dissect_nvme_cqe(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_cmd_ctx *cmd_ctx);

/**
 * Returns string representation of opcode according
 * to opcode and queue id
 */
const gchar *
nvme_get_opcode_string(guint8  opcode, guint16 qid);

/*
 * Tells if opcode can be an opcode of io queue.
 * Used to "Guess" queue type for nvme-tcp in case that "connect"
 * command was not recorded
 */
int
nvme_is_io_queue_opcode(guint8  opcode);

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
