/* packet-nvme.h
 * data structures for NVMe Dissection
 * Copyright 2016
 * Code by Parav Pandit
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef _PACKET_NVME_H_
#define _PACKET_NVME_H_

#define NVME_CMD_SIZE 64
#define NVME_CQE_SIZE 16

struct nvme_q_ctx {
    wmem_tree_t *pending_cmds;
    wmem_tree_t *done_cmds;
    guint16     qid;
};

struct nvme_cmd_ctx {
    guint32 cmd_pkt_num;  /* pkt number of the cmd */
    guint32 cqe_pkt_num;  /* pkt number of the cqe */

    nstime_t cmd_start_time;
    nstime_t cmd_end_time;
    gboolean fabric;     /* indicate whether cmd fabric type or not */
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

void nvme_update_cmd_end_info(packet_info *pinfo, struct nvme_cmd_ctx *cmd_ctx);

void
nvme_add_cmd_to_pending_list(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                             struct nvme_cmd_ctx *cmd_ctx,
                             void *ctx, guint16 cmd_id);
void* nvme_lookup_cmd_in_pending_list(struct nvme_q_ctx *q_ctx, guint16 cmd_id);

void
nvme_add_cmd_cqe_to_done_list(struct nvme_q_ctx *q_ctx,
                              struct nvme_cmd_ctx *cmd_ctx, guint16 cmd_id);
void*
nvme_lookup_cmd_in_done_list(packet_info *pinfo, struct nvme_q_ctx *q_ctx,
                             guint16 cmd_id);

void dissect_nvme_cmd_sgl(tvbuff_t *cmd_tvb, proto_tree *cmd_tree,
                          int field_index);
void
dissect_nvme_cmd(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_q_ctx *q_ctx, struct nvme_cmd_ctx *cmd_ctx);
void
dissect_nvme_cqe(tvbuff_t *nvme_tvb, packet_info *pinfo, proto_tree *root_tree,
                 struct nvme_cmd_ctx *cmd_ctx);

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
