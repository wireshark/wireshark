/* packet-rsvd.c
 * Routines for RSVD dissection
 * Copyright 2015, Richard Sharpe <realrichardsharpe@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * RSVD, documented in [MS-RSVD].pdf, by Microsoft, the Remote Shared Virtual
 * Disk protocol.
 */

#include "config.h"

#include <epan/conversation.h>
#include <epan/packet.h>
#if 0
#include "packet-smb-common.h"
#endif
#include "packet-windows-common.h"
#include "packet-scsi.h"

void proto_register_rsvd(void);

static int proto_rsvd = -1;
static int hf_svhdx_protocol_id = -1;
static int hf_svhdx_protocol_version = -1;
static int hf_svhdx_operation_code = -1;
static int hf_svhdx_status = -1;
static int hf_svhdx_request_id = -1;
static int hf_svhdx_tunnel_scsi_length = -1;
static int hf_svhdx_tunnel_scsi_reserved1 = -1;
static int hf_svhdx_tunnel_scsi_cdb_length = -1;
static int hf_svhdx_tunnel_scsi_sense_info_ex_length = -1;
static int hf_svhdx_tunnel_scsi_data_in = -1;
static int hf_svhdx_tunnel_scsi_reserved2 =  -1;
static int hf_svhdx_tunnel_scsi_srb_flags = -1;
static int hf_svhdx_tunnel_scsi_data_transfer_length = -1;
static int hf_svhdx_tunnel_scsi_reserved3 = -1;
static int hf_svhdx_tunnel_scsi_cdb = -1;
static int hf_svhdx_tunnel_scsi_cdb_padding = -1;
static int hf_svhdx_tunnel_scsi_data = -1;
static int hf_svhdx_tunnel_scsi_auto_generated_sense = -1;
static int hf_svhdx_tunnel_scsi_srb_status = -1;
static int hf_svhdx_tunnel_scsi_sense_data_ex = -1;
static int hf_svhdx_tunnel_scsi_status = -1;
static int hf_svhdx_tunnel_file_info_server_version = -1;
static int hf_svhdx_tunnel_file_info_sector_size = -1;
static int hf_svhdx_tunnel_file_info_physical_sector_size = -1;
static int hf_svhdx_tunnel_file_info_reserved = -1;
static int hf_svhdx_tunnel_file_info_virtual_size = -1;
static int hf_svhdx_tunnel_disk_info_reserved1 = -1;
static int hf_svhdx_tunnel_disk_info_blocksize = -1;
static int hf_svhdx_tunnel_disk_info_linkage_id = -1;
static int hf_svhdx_tunnel_disk_info_disk_type = -1;
static int hf_svhdx_tunnel_disk_info_disk_format = -1;
static int hf_svhdx_tunnel_disk_info_is_mounted = -1;
static int hf_svhdx_tunnel_disk_info_is_4k_aligned = -1;
static int hf_svhdx_tunnel_disk_info_reserved = -1;
static int hf_svhdx_tunnel_disk_info_file_size = -1;
static int hf_svhdx_tunnel_disk_info_virtual_disk_id = -1;
static int hf_svhdx_tunnel_validate_disk_reserved = -1;
static int hf_svhdx_tunnel_validate_disk_is_valid_disk = -1;
static int hf_svhdx_tunnel_srb_status_status_key = -1;
static int hf_svhdx_tunnel_srb_status_reserved = -1;
static int hf_svhdx_tunnel_srb_status_sense_info_auto_generated = -1;
static int hf_svhdx_tunnel_srb_status_srb_status = -1;
static int hf_svhdx_tunnel_srb_status_scsi_status = -1;
static int hf_svhdx_tunnel_srb_status_sense_info_ex_length = -1;
static int hf_svhdx_tunnel_srb_status_sense_data_ex = -1;
static int hf_svhdx_tunnel_safe_virtual_size = -1;
static int hf_svhdx_tunnel_transaction_id = -1;
static int hf_svhdx_tunnel_meta_operation_type = -1;
static int hf_svhdx_tunnel_padding = -1;
static int hf_svhdx_tunnel_resize_new_size = -1;
static int hf_svhdx_tunnel_resize_expand_only_flag = -1;
static int hf_svhdx_tunnel_resize_allow_unsafe_virt_size_flag = -1;
static int hf_svhdx_tunnel_resize_shrink_to_minimum_safe_size_flag = -1;
static int hf_svhdx_tunnel_meta_operation_start_reserved = -1;
static int hf_svhdx_tunnel_snapshot_type = -1;
static int hf_svhdx_tunnel_snapshot_id = -1;
static int hf_svhdx_tunnel_create_snapshot_flags = -1;
static int hf_svhdx_tunnel_create_snapshot_flag_enable_change_tracking = -1;
static int hf_svhdx_tunnel_create_snapshot_stage1 = -1;
static int hf_svhdx_tunnel_create_snapshot_stage2 = -1;
static int hf_svhdx_tunnel_create_snapshot_stage3 = -1;
static int hf_svhdx_tunnel_create_snapshot_stage4 = -1;
static int hf_svhdx_tunnel_create_snapshot_stage5 = -1;
static int hf_svhdx_tunnel_create_snapshot_stage6 = -1;
static int hf_svhdx_tunnel_create_snapshot_parameters_payload_size = -1;
static int hf_svhdx_tunnel_convert_dst_vhdset_name_len = -1;
static int hf_svhdx_tunnel_convert_dst_vhdset_name = -1;
static int hf_svhdx_tunnel_delete_snapshot_persist_reference = -1;
static int hf_svhdx_tunnel_meta_op_query_progress_current_progress = -1;
static int hf_svhdx_tunnel_meta_op_query_progress_complete_value = -1;
static int hf_svhdx_tunnel_vhdset_information_type = -1;
static int hf_svhdx_tunnel_vhdset_snapshot_creation_time = -1;
static int hf_svhdx_tunnel_vhdset_is_valid_snapshot = -1;
static int hf_svhdx_tunnel_vhdset_parent_snapshot_id = -1;
static int hf_svhdx_tunnel_vhdset_log_file_id = -1;

static gint ett_rsvd = -1;
static gint ett_svhdx_tunnel_op_header = -1;
static gint ett_svhdx_tunnel_scsi_request = -1;
static gint ett_rsvd_create_snapshot_flags = -1;

static const value_string rsvd_operation_code_vals[] = {
        { 0x02001001, "RSVD_TUNNEL_GET_INITIAL_INFO" },
        { 0x02001002, "RSVD_TUNNEL_SCSI" },
        { 0x02001003, "RSVD_TUNNEL_CHECK_CONNECTION_STATUS" },
        { 0x02001004, "RSVD_TUNNEL_SRB_STATUS" },
        { 0x02001005, "RSVD_TUNNEL_GET_DISK_INFO" },
        { 0x02001006, "RSVD_TUNNEL_VALIDATE_DISK" },
        { 0x02002101, "RSVD_TUNNEL_META_OPERATION_START" },
        { 0x02002002, "RSVD_TUNNEL_META_OPERATION_QUERY_PROGRESS" },
        { 0x02002005, "RSVD_TUNNEL_VHDSET_QUERY_INFORMATION" },
        { 0x02002006, "RSVD_TUNNEL_DELETE_SNAPSHOT" },
        { 0x02002008, "RSVD_TUNNEL_CHANGE_TRACKING_GET_PARAMETERS" },
        { 0x02002009, "RSVD_TUNNEL_CHANGE_TRACKING_START" },
        { 0x0200200A, "RSVD_TUNNEL_CHANGE_TRACKING_STOP" },
        { 0x0200200C, "RSVD_TUNNEL_QUERY_VIRTUAL_DISK_CHANGES" },
        { 0x0200200D, "RSVD_TUNNEL_QUERY_SAFE_SIZE" },
        { 0, NULL }
};

static const value_string rsvd_sense_info_vals[] = {
        { 0x0, "Sense Info Not Auto Generated" },
        { 0x1, "Sense Info Auto Generated" },
        { 0, NULL }
};

static const value_string rsvd_disk_type_vals[] = {
        { 0x02, "VHD_TYPE_FIXED" },
        { 0x03, "VHD_TYPE_DYNAMIC" },
        { 0, NULL }
};

static const value_string rsvd_disk_format_vals[] = {
        { 0x03, "VIRTUAL_STORAGE_TYPE_DEVICE_VHDX" },
        { 0x04, "VIRTUAL_STORAGE_TYPE_DEVICE_VHDSET" },
        { 0, NULL }
};

/*
 * We need this data to handle SCSI requests and responses, I think
 */
typedef struct _rsvd_task_data_t {
        guint32 request_frame;
        guint32 response_frame;
        itlq_nexus_t *itlq;
} rsvd_task_data_t;

typedef struct _rsvd_conv_data_t {
        wmem_map_t *tasks;
        wmem_tree_t *itl;
        rsvd_task_data_t *task;
        conversation_t *conversation;
} rsvd_conv_data_t;

static rsvd_conv_data_t *rsvd_conv_data = NULL;

static proto_tree *top_tree = NULL;

static itl_nexus_t *
get_itl_nexus(packet_info *pinfo)
{
    itl_nexus_t *itl = NULL;

    if (!(itl = (itl_nexus_t *)wmem_tree_lookup32_le(rsvd_conv_data->itl, pinfo->num))) {
        itl = wmem_new(wmem_file_scope(), itl_nexus_t);
        itl->cmdset = 0xff;
        itl->conversation = rsvd_conv_data->conversation;
        wmem_tree_insert32(rsvd_conv_data->itl, pinfo->num, itl);
    }

    return itl;
}

static int
dissect_RSVD_GET_INITIAL_INFO(tvbuff_t *tvb, proto_tree *parent_tree, int offset, gint16 len, gboolean request)
{
    proto_tree *gfi_sub_tree;
    proto_item *gfi_sub_item;

    if (!request) {
        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_GET_INITIAL_INFO_RESPONSE");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_file_info_server_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_file_info_sector_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_file_info_physical_sector_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_file_info_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_file_info_virtual_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }

    return offset;
}

static const value_string rsvd_data_in_vals[] = {
        { 0x00, "Client is requesting data from the server" },
        { 0x01, "Client is sending data to the server" },
        { 0x02, "Client is neither sending nor requesting an additional data buffer" },
        { 0, NULL }
};

static void
dissect_scsi_payload_databuffer(tvbuff_t *tvb, packet_info *pinfo, int offset, guint32 data_transfer_length, gboolean request)
{
    tvbuff_t *data_tvb = NULL;
    int tvb_len, tvb_rlen;

    tvb_len = tvb_captured_length_remaining(tvb, offset);
    if (tvb_len > (int)data_transfer_length)
        tvb_len = data_transfer_length;

    tvb_rlen = tvb_reported_length_remaining(tvb, offset);
    if (tvb_rlen > (int)data_transfer_length)
        tvb_rlen = data_transfer_length;

    data_tvb = tvb_new_subset_length_caplen(tvb, offset, tvb_len, tvb_rlen);

    if (rsvd_conv_data->task && rsvd_conv_data->task->itlq) {
        rsvd_conv_data->task->itlq->task_flags = SCSI_DATA_READ |
                                                 SCSI_DATA_WRITE;
        rsvd_conv_data->task->itlq->data_length = data_transfer_length;
        rsvd_conv_data->task->itlq->bidir_data_length = data_transfer_length;
        dissect_scsi_payload(data_tvb, pinfo, top_tree, request,
                             rsvd_conv_data->task->itlq,
                             get_itl_nexus(pinfo), 0);
    }
}

/*
 * Dissect a tunnelled SCSI request and call the SCSI dissector where
 * needed.
 */
static int
dissect_RSVD_TUNNEL_SCSI(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, gint16 len, gboolean request, guint64 request_id)
{
    proto_tree *sub_tree;
    proto_item *sub_item;
    guint32 cdb_length;
    guint8 data_in;
    guint32 data_transfer_length;
    guint32 sense_info_ex_length;
    conversation_t *conversation;

    conversation = find_or_create_conversation(pinfo);
    rsvd_conv_data = (rsvd_conv_data_t *)conversation_get_proto_data(conversation, proto_rsvd);

    if (!rsvd_conv_data) {
        rsvd_conv_data = wmem_new(wmem_file_scope(), rsvd_conv_data_t);
        rsvd_conv_data->tasks = wmem_map_new(wmem_file_scope(),
                                             wmem_int64_hash,
                                             g_int64_equal);
        rsvd_conv_data->itl   = wmem_tree_new(wmem_file_scope());
        rsvd_conv_data->conversation = conversation;
        conversation_add_proto_data(conversation, proto_rsvd, rsvd_conv_data);
    }

    rsvd_conv_data->task = NULL;
    if (!pinfo->fd->visited) {
        guint64 *key_copy = wmem_new(wmem_file_scope(), guint64);

        *key_copy = request_id;
        rsvd_conv_data->task = wmem_new(wmem_file_scope(), rsvd_task_data_t);
        rsvd_conv_data->task->request_frame=pinfo->num;
        rsvd_conv_data->task->response_frame=0;
        rsvd_conv_data->task->itlq = NULL;
        wmem_map_insert(rsvd_conv_data->tasks, (const void *)key_copy,
                        rsvd_conv_data->task);
    } else {
        rsvd_conv_data->task = (rsvd_task_data_t *)wmem_map_lookup(rsvd_conv_data->tasks, (const void *)&request_id);
    }

    sub_tree = proto_tree_add_subtree_format(parent_tree, tvb, offset, len, ett_svhdx_tunnel_scsi_request, &sub_item, "SVHDX_TUNNEL_SCSI_%s", (request ? "REQUEST" : "RESPONSE"));

    if (request) {
        tvbuff_t *scsi_cdb = NULL;

        /* Length */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* Reserved1 */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_reserved1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* CDBLength */
        cdb_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_cdb_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* SensInfoExLength */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_sense_info_ex_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* DataIn */
        data_in = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_data_in, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* Reserved2 */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_reserved2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* SrbFlags */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_srb_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* DataTransferLength */
        data_transfer_length = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_data_transfer_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* CDBBuffer */
        scsi_cdb = tvb_new_subset_length_caplen(tvb,
                                  offset,
                                  cdb_length,
                                  tvb_reported_length_remaining(tvb, offset));
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_cdb, tvb, offset, cdb_length, ENC_NA);
        offset += cdb_length;
        if (cdb_length < 16) {
            /*
             * CDBBuffer is always 16 bytes - see MS-RSVD section 2.2.4.7
             * "SVHDX_TUNNEL_SCSI_REQUEST Structure":
             *
             *     https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rsvd/e8bcb003-97b3-41ef-9689-cd2d1668a9cc
             *
             * If CDB is actually smaller, we need to define padding bytes
             */
            guint32 cdb_padding_length = 16 - cdb_length;
            proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_cdb_padding, tvb, offset, cdb_padding_length, ENC_NA);
            offset += cdb_padding_length;
        }

        /* Reserved3 */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_reserved3, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* DataBuffer */
        if (data_transfer_length) {
            proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_data, tvb, offset, data_transfer_length, ENC_NA);
        }

        /*
         * Now the SCSI Request
         */
        if (rsvd_conv_data->task && !rsvd_conv_data->task->itlq) {
            rsvd_conv_data->task->itlq = wmem_new(wmem_file_scope(),
                                                  itlq_nexus_t);
            rsvd_conv_data->task->itlq->first_exchange_frame = pinfo->num;
            rsvd_conv_data->task->itlq->last_exchange_frame = 0;
            rsvd_conv_data->task->itlq->lun = 0xffff;
            rsvd_conv_data->task->itlq->scsi_opcode = 0xffff;
            rsvd_conv_data->task->itlq->task_flags = 0;
            rsvd_conv_data->task->itlq->data_length = 0;
            rsvd_conv_data->task->itlq->bidir_data_length = 0;
            rsvd_conv_data->task->itlq->flags = 0;
            rsvd_conv_data->task->itlq->alloc_len = 0;
            rsvd_conv_data->task->itlq->fc_time = pinfo->abs_ts;
            rsvd_conv_data->task->itlq->extra_data = NULL;
        }

        if (rsvd_conv_data->task && rsvd_conv_data->task->itlq) {
            dissect_scsi_cdb(scsi_cdb, pinfo, top_tree, SCSI_DEV_SMC, rsvd_conv_data->task->itlq, get_itl_nexus(pinfo));
            if (data_in == 0) { /* Only OUT operations have meaningful SCSI payload in request packet */
                dissect_scsi_payload_databuffer(tvb, pinfo, offset, data_transfer_length, request);
            }
        }

        /* increment after DataBuffer */
        offset += data_transfer_length;
    } else {
        guint8 scsi_status = 0;

        /* Length */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* A */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_auto_generated_sense, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* SrbStatus */
        proto_tree_add_bits_item(sub_tree, hf_svhdx_tunnel_scsi_srb_status, tvb, offset * 8 + 1, 7, ENC_BIG_ENDIAN);
        offset++;

        /* ScsiStatus */
        scsi_status = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* CdbLength */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_cdb_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* SensInfoExLength */
        sense_info_ex_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_sense_info_ex_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* DataIn */
        data_in = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_data_in, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* Reserved */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_reserved2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* SrbFlags */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_srb_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* DataTransferLength */
        data_transfer_length = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_data_transfer_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* SenseDataEx */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_sense_data_ex, tvb, offset, sense_info_ex_length, ENC_NA);
        offset += sense_info_ex_length;

        /* DataBuffer */
        if (data_transfer_length) {
            proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_data, tvb, offset, data_transfer_length, ENC_NA);

            if (data_in == 1) { /* Only IN operations have meaningful SCSI payload in reply packet */
                dissect_scsi_payload_databuffer(tvb, pinfo, offset, data_transfer_length, request);
            }

            offset += data_transfer_length;
        }

        /*
         * Now, the SCSI response
         */
        if (rsvd_conv_data->task && rsvd_conv_data->task->itlq) {
            dissect_scsi_rsp(tvb, pinfo, top_tree, rsvd_conv_data->task->itlq, get_itl_nexus(pinfo), scsi_status);
        }
    }

    return offset;
}

static int
dissect_RSVD_SRB_STATUS(tvbuff_t *tvb, proto_tree *parent_tree, int offset, gint16 len, gboolean request)
{
    proto_tree *gfi_sub_tree;
    proto_item *gfi_sub_item;

    if (request) {
        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_SRB_STATUS_REQUEST");

        /* StatusKey */
        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_srb_status_status_key, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        /* Reserved */
        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_srb_status_reserved, tvb, offset, 1, ENC_NA);
        offset += 27;
    } else {
        guint8 sense_info_length;

        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_SRB_STATUS_RESPONSE");

        /* StatusKey */
        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_srb_status_status_key, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        /* SenseInfoAutoGenerated and SrbStatus */
        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_srb_status_sense_info_auto_generated, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(gfi_sub_tree, hf_svhdx_tunnel_srb_status_srb_status, tvb, offset * 8 + 1, 7, ENC_BIG_ENDIAN);
        offset += 1;

        /* ScsiStatus */
        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_srb_status_scsi_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        /* SenseInfoExLength */
        sense_info_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_srb_status_sense_info_ex_length, tvb, offset, 1, ENC_NA);
        offset += 1;

        /* SenseDataEx */
        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_srb_status_sense_data_ex, tvb, offset, sense_info_length, ENC_NA);
        offset += sense_info_length;
    }

    return offset;
}

static int
dissect_RSVD_GET_DISK_INFO(tvbuff_t *tvb, proto_tree *parent_tree, int offset, gint16 len, gboolean request)
{
    proto_tree *gfi_sub_tree;
    proto_item *gfi_sub_item;

    if (request) {
        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_GET_DISK_INFO_REQUEST");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_reserved1, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_blocksize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_linkage_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
        offset += 16;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_is_mounted, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_is_4k_aligned, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_file_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_virtual_disk_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
        offset += 16;
    } else {
        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_GET_DISK_INFO_RESPONSE");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_disk_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_disk_format, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_blocksize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_linkage_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
        offset += 16;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_is_mounted, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_is_4k_aligned, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_file_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_virtual_disk_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
        offset += 16;
    }

    return offset;
}

static int
dissect_RSVD_VALIDATE_DISK(tvbuff_t *tvb, proto_tree *parent_tree, int offset, gint16 len, gboolean request)
{
    proto_tree *gfi_sub_tree;
    proto_item *gfi_sub_item;

    if (request) {
        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_VALIDATE_DISK_REQUEST");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_validate_disk_reserved, tvb, offset, 56, ENC_NA);
        offset += 56;
    } else {
        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_VALIDATE_DISK_RESPONSE");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_validate_disk_is_valid_disk, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    return offset;
}

static const value_string rsvd_meta_operation_type_vals[] = {
        { 0x00, "SvhdxMetaOperationTypeResize" },
        { 0x01, "SvhdxMetaOperationTypeCreateSnapshot" },
        { 0x02, "SvhdxMetaOperationTypeOptimize" },
        { 0x03, "SvhdxMetaOperationTypeExtractVHD" },
        { 0x04, "SvhdxMetaOperationTypeConvertToVHDSet" },
        { 0x05, "SvhdxMetaOperationTypeApplySnapshot" },
        { 0, NULL }
};

static const value_string svhdx_snapshot_type_vals[] = {
        { 0x01, "SvhdxSnapshotTypeVM" },
        { 0x03, "SvhdxSnapshotTypeCDP" },
        { 0x04, "SvhdxSnapshotTypeWriteable" },
        { 0, NULL }
};

static const value_string svhdx_snapshot_stage_vals[] = {
        { 0x00, "SvhdxSnapshotStageInvalid" },
        { 0x01, "SvhdxSnapshotStageInitialize" },
        { 0x02, "SvhdxSnapshotStageBlockIO" },
        { 0x03, "SvhdxSnapshotStageSwitchObjectStore" },
        { 0x04, "SvhdxSnapshotStageUnblockIO" },
        { 0x05, "SvhdxSnapshotStageFinalize" },
        { 0, NULL }
};

#define SVHDX_SNAPSHOT_DISK_FLAG_ENABLE_CHANGE_TRACKING 0x00000001

static int
dissect_RSVD2_META_OPERATION_START(tvbuff_t *tvb, proto_tree *parent_tree, int offset, gint16 len, gboolean request)
{
    static int * const meta_operation_create_snapshot_flags[] = {
        &hf_svhdx_tunnel_create_snapshot_flag_enable_change_tracking,
        NULL
    };

    guint32 operation_type = 0;
    guint32 length = 0;
    proto_tree *gfi_sub_tree;
    proto_item *gfi_sub_item;

    if (request) {

        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_META_OPERATION_START_REQUEST");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_transaction_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
        offset += 16;

        operation_type = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_meta_operation_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_padding, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        switch (operation_type) {
        case 0x00: /* SvhdxMetaOperationTypeResize */
            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_resize_new_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_resize_expand_only_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_resize_allow_unsafe_virt_size_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_resize_shrink_to_minimum_safe_size_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_meta_operation_start_reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        case 0x01: /* SvhdxMetaOperationTypeCreateSnapshot */
            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_snapshot_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_bitmask(gfi_sub_tree, tvb, offset, hf_svhdx_tunnel_create_snapshot_flags,
                                   ett_rsvd_create_snapshot_flags, meta_operation_create_snapshot_flags, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_create_snapshot_stage1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_create_snapshot_stage2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_create_snapshot_stage3, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_create_snapshot_stage4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_create_snapshot_stage5, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_create_snapshot_stage6, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_snapshot_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
            offset += 16;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_create_snapshot_parameters_payload_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            break;
        case 0x02: /* SvhdxMetaOperationTypeOptimize */
            /* No Data, field MUST be empty */
            break;
        case 0x03: /* SvhdxMetaOperationTypeExtractVHD */
            /* TODO */
            break;
        case 0x04: /* SvhdxMetaOperationTypeConvertToVHDSet */
            length = tvb_get_letohl(tvb, offset);
            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_convert_dst_vhdset_name_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            if (length) {
                proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_convert_dst_vhdset_name, tvb, offset, length, ENC_UTF_16|ENC_LITTLE_ENDIAN);
            }
            break;

        case 0x05: /* SvhdxMetaOperationTypeApplySnapshot */
            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_snapshot_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_snapshot_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
            offset += 16;

            break;
        }
    }
    return offset;
}

static int
dissect_RSVD2_META_OPERATION_QUERY_PROGRESS(tvbuff_t *tvb,
            proto_tree *parent_tree, int offset, gint16 len, gboolean request, guint32 status)
{
    proto_tree *gfi_sub_tree;
    proto_item *gfi_sub_item;

    if (request) {
        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_META_OPERATION_QUERY_PROGRESS_REQUEST");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_transaction_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
        offset += 16;
    } else {
        if (status == 0) { /* If status is not successful, RSVD response buffer is filled by data from request buffer and we should not parse output structure */
            gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_META_OPERATION_QUERY_PROGRESS_RESPONSE");

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_meta_op_query_progress_current_progress, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_meta_op_query_progress_complete_value, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
        }
    }
    return offset;
}

static const value_string svhdx_vhdset_information_type_vals[] = {
        { 0x02, "SvhdxVHDSetInformationTypeSnapshotList" },
        { 0x05, "SvhdxVHDSetInformationTypeSnapshotEntry" },
        { 0x08, "SvhdxVHDSetInformationTypeOptimizeNeeded" },
        { 0x09, "SvhdxVHDSetInformationTypeCdpSnapshotRoot" },
        { 0x0A, "SvhdxVHDSetInformationTypeCdpSnapshotActiveList" },
        { 0x0C, "SvhdxVHDSetInformationTypeCdpSnapshotInactiveList" },
        { 0, NULL }
};
static int
dissect_RSVD2_VHDSET_QUERY_INFORMATION(tvbuff_t *tvb, proto_tree *parent_tree, int offset, gint16 len, gboolean request)
{
    proto_tree *gfi_sub_tree;
    proto_item *gfi_sub_item;

    if (request) {
        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_VHDSET_QUERY_INFORMATION_REQUEST");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_vhdset_information_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_snapshot_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_snapshot_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
        offset += 16;
    } else {
        guint32 vhdset_info_type = tvb_get_letohl(tvb, offset);
        switch (vhdset_info_type) {
        case 0x02: /* SvhdxVHDSetInformationTypeSnapshotList */
            gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_VHDSET_QUERY_INFORMATION_SNAPSHOT_LIST_RESPONSE");

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_vhdset_information_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            /* TODO: make full dissection */

            break;
        case 0x05: /* SvhdxVHDSetInformationTypeSnapshotEntry */
            gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_VHDSET_QUERY_INFORMATION_SNAPSHOT_ENTRY_RESPONSE");

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_vhdset_information_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_padding, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            offset = dissect_nt_64bit_time(tvb, gfi_sub_tree, offset, hf_svhdx_tunnel_vhdset_snapshot_creation_time);

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_snapshot_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_vhdset_is_valid_snapshot, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_snapshot_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
            offset += 16;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_vhdset_parent_snapshot_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
            offset += 16;

            proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_vhdset_log_file_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
            offset += 16;

            break;
        }
    }
    return offset;
}

static int
dissect_RSVD2_DELETE_SNAPSHOT(tvbuff_t *tvb, proto_tree *parent_tree, int offset, gint16 len, gboolean request)
{
    proto_tree *gfi_sub_tree;
    proto_item *gfi_sub_item;

    if (request) {
        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_DELETE_SNAPSHOT_REQUEST");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_snapshot_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
        offset += 16;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_delete_snapshot_persist_reference, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_snapshot_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    return offset;
}

static int
dissect_RSVD2_QUERY_SAFE_SIZE(tvbuff_t *tvb, proto_tree *parent_tree, int offset, gint16 len, gboolean request)
{
    proto_tree *gfi_sub_tree;
    proto_item *gfi_sub_item;

    if (!request) {
        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_QUERY_SAFE_SIZE_RESPONSE");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_safe_virtual_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }
    return offset;
}

static int
dissect_rsvd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
    guint32 header_bytes = 0;
    guint proto_id = 0;
    guint proto_version = 0;
    guint32 operation_code = 0;
    guint32 status;
    proto_item *ti;
    proto_tree *rsvd_tree;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint       offset = 0;
    guint16 len;
    guint64 request_id = 0;
    gboolean request = *(gboolean *)data;

    top_tree = parent_tree;

    len = tvb_reported_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RSVD");

    col_clear(pinfo->cinfo, COL_INFO);

    /*
     * The header bytes need to be pulled in as a 32bit LE value. And the
     * header is the same in a request or a response ...
     */
    header_bytes = tvb_get_letohl(tvb, 0); /* Get the header bytes */
    proto_id = header_bytes >> 24;
    proto_version = (header_bytes >> 12) & 0x0FFF;
    operation_code = header_bytes;

    ti = proto_tree_add_item(parent_tree, proto_rsvd, tvb, offset, -1, ENC_NA);

    rsvd_tree = proto_item_add_subtree(ti, ett_rsvd);

    sub_tree = proto_tree_add_subtree(rsvd_tree, tvb, offset, (len>16) ? 16 : len, ett_svhdx_tunnel_op_header, &sub_item, "SVHDX_TUNNEL_OPERATION_HEADER");

    /* ProtocolID */
    proto_tree_add_uint(sub_tree, hf_svhdx_protocol_id, tvb, offset, 4, proto_id);

    /* ProtocolVersion */
    proto_tree_add_uint(sub_tree, hf_svhdx_protocol_version, tvb, offset, 4, proto_version);

    /* Operation Code */
    proto_tree_add_uint(sub_tree, hf_svhdx_operation_code, tvb, offset, 4, operation_code);
    offset += 4;

    /* Status */
    status = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(sub_tree, hf_svhdx_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* RequestId */
    request_id = tvb_get_ntoh64(tvb, offset);
    proto_tree_add_item(sub_tree, hf_svhdx_request_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                    val_to_str(operation_code,
                               rsvd_operation_code_vals,
                               "Unknown Operation Code (0x%08X)"),
                    request ? "Request" : "Response");

    proto_item_append_text(ti, ", %s %s",
                          val_to_str(operation_code,
                                     rsvd_operation_code_vals,
                                     "Unknown Operation Code (0x%08X)"),
                          request ? "Request" : "Response");
    /*
     * Now process the individual requests ...
     */
    switch (operation_code) {
    case 0x02001001:
        offset += dissect_RSVD_GET_INITIAL_INFO(tvb, rsvd_tree, offset, len - offset, request);
        break;

    case 0x02001002:
        offset += dissect_RSVD_TUNNEL_SCSI(tvb, pinfo, rsvd_tree, offset, len - offset, request, request_id);
        break;

    case 0x02001003:

        /*
         * There is nothing more here.
         */

        break;

    case 0x02001004:
        offset += dissect_RSVD_SRB_STATUS(tvb, rsvd_tree, offset, len - offset, request);
        break;

    case 0x02001005:
        offset += dissect_RSVD_GET_DISK_INFO(tvb, rsvd_tree, offset, len - offset, request);
        break;

    case 0x02001006:
        offset += dissect_RSVD_VALIDATE_DISK(tvb, rsvd_tree, offset, len - offset, request);
        break;
    /* RSVD v2 operations */
    case 0x02002101:
        offset += dissect_RSVD2_META_OPERATION_START(tvb, rsvd_tree, offset, len - offset, request);
        break;

    case 0x02002002:
        offset += dissect_RSVD2_META_OPERATION_QUERY_PROGRESS(tvb, rsvd_tree, offset, len - offset, request, status);
        break;

    case 0x02002005:
        offset += dissect_RSVD2_VHDSET_QUERY_INFORMATION(tvb, rsvd_tree, offset, len - offset, request);
        break;

    case 0x02002006:
        offset += dissect_RSVD2_DELETE_SNAPSHOT(tvb, rsvd_tree, offset, len - offset, request);
        break;

    case 0x0200200D:
        offset += dissect_RSVD2_QUERY_SAFE_SIZE(tvb, rsvd_tree, offset, len - offset, request);
        break;

    /* TODO: implement more dissectors for RSVD v2 */

    default:
        break;
    }

    return offset;
}

void
proto_register_rsvd(void)
{

    static hf_register_info hf[] = {
                { &hf_svhdx_protocol_id,
                  { "ProtocolId", "rsvd.svhdx_protocol_id", FT_UINT8, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_protocol_version,
                  { "ProtocolVersion", "rsvd.svhdx_protocol_version", FT_UINT16, BASE_DEC,
                     NULL, 0, NULL, HFILL }},

                { &hf_svhdx_operation_code,
                  { "OperationCode", "rsvd.svhdx_operation_code", FT_UINT32, BASE_HEX,
                     VALS(rsvd_operation_code_vals), 0, "Operation Code", HFILL }},

                { &hf_svhdx_status,
                  { "Status", "rsvd.svhdx_status", FT_UINT32, BASE_HEX | BASE_EXT_STRING,
                    &NT_errors_ext, 0, NULL, HFILL }},


                { &hf_svhdx_request_id,
                  { "RequestId", "rsvd.svhdx_request_id", FT_UINT64, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_length,
                  { "Length", "rsvd.svhdx_length", FT_UINT16, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_reserved1,
                  { "Reserved1", "rsvd.svhdx_scsi_reserved1", FT_UINT16, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_cdb_length,
                  { "CDBLength", "rsvd.svhdx_scsi_cdb_length", FT_UINT8, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_sense_info_ex_length,
                  { "SenseInfoExLength", "rsvd.svhdx_scsi_sense_info_ex_length", FT_UINT8, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_data_in,
                  { "DataIn", "rsvd.svhdx_scsi_data_in", FT_UINT8, BASE_HEX,
                    VALS(rsvd_data_in_vals), 0, "SCSI CDB transfer type", HFILL }},

                { &hf_svhdx_tunnel_scsi_reserved2,
                  { "Reserved2", "rsvd.svhdx_scsi_reserved2", FT_UINT8, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_srb_flags,
                  { "SRBFlags", "rsvd.svhdx_scsi_srbflags", FT_UINT32, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_data_transfer_length,
                  { "DataTransferLength", "rsvd.svhdx_scsi_data_transfer_length", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_reserved3,
                  { "Reserved3", "rsvd.svhdx_scsi_reserved3", FT_UINT32, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_cdb,
                  { "CDB", "rsvd.svhdx_scsi_cdb", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_cdb_padding,
                  { "CDBPadding", "rsvd.svhdx_scsi_cdb_padding", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_data,
                  {"Data", "rsvd.svhdx_scsi_data", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_auto_generated_sense,
                  {"AutoGeneratedSenseInfo", "rsvd.svhdx_auto_generated_sense_info", FT_UINT8, BASE_HEX,
                    VALS(rsvd_sense_info_vals), 0x80, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_srb_status,
                  { "SrbStatus", "rsvd.svhdx_srb_status", FT_UINT8, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_status,
                  { "ScsiStatus", "rsvd.svhdx_scsi_status", FT_UINT8, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_sense_data_ex,
                  { "SenseDataEx", "rsvd.svhdx_scsi_sense_data_ex", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_file_info_server_version,
                  { "ServerVersion", "rsvd.svhdx_file_info_server_version", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_file_info_sector_size,
                  { "SectorSize", "rsvd.svhdx_file_info_sector_size", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_file_info_physical_sector_size,
                  { "PhysicalSectorSize", "rsvd.svhdx_file_info_physical_sector_size", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_file_info_reserved,
                  { "Reserved", "rsvd.svhdx_file_info_reserved", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_file_info_virtual_size,
                  { "VirtualSize", "rsvd.svhdx_file_info_virtual_size", FT_UINT64, BASE_DEC,
                    NULL, 0, NULL, HFILL }},


                { &hf_svhdx_tunnel_disk_info_reserved1,
                  { "Reserved1", "rsvd.svhdx_disk_info_reserved1", FT_UINT64, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_disk_info_blocksize,
                  { "BlockSize", "rsvd.svhdx_disk_info_blocksize", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_disk_info_linkage_id,
                  { "LinkageID", "rsvd.svhdx_disk_info_linkage_id", FT_GUID, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_disk_info_disk_type,
                  { "DiskType", "rsvd.svhdx_disk_info_disk_type", FT_UINT16, BASE_HEX,
                     VALS(rsvd_disk_type_vals), 0, "Disk Type", HFILL }},

                { &hf_svhdx_tunnel_disk_info_disk_format,
                  { "DiskFormat", "rsvd.svhdx_disk_info_disk_format", FT_UINT16, BASE_HEX,
                     VALS(rsvd_disk_format_vals), 0, "Disk Format", HFILL }},

                { &hf_svhdx_tunnel_disk_info_is_mounted,
                  { "IsMounted", "rsvd.svhdx_tunnel_disk_info_is_mounted", FT_UINT8, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_disk_info_is_4k_aligned,
                  { "Is4KAligned", "rsvd.svhdx_tunnel_disk_info_is_4k_aligned", FT_UINT8, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_disk_info_reserved,
                  { "Reserved", "rsvd.svhdx_disk_info_reserved", FT_UINT16, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_disk_info_file_size,
                  { "FileSize", "rsvd.svhdx_disk_info_file_size", FT_UINT64, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_disk_info_virtual_disk_id,
                  { "VirtualDiskId", "rsvd.svhdx_disk_info_virtual_disk_id", FT_GUID, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_validate_disk_reserved,
                  { "Reserved", "rsvd.svhdx_tunnel_validate_disk_reserved", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_validate_disk_is_valid_disk,
                  { "IsValidDisk", "rsvd.svhdx_validate_disk_is_valid_disk", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_srb_status_status_key,
                  { "StatusKey", "rsvd.svhdx_srb_status_key", FT_UINT8, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_srb_status_reserved,
                  { "Reserved", "rsvd.svhdx_srb_status_reserved", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_srb_status_sense_info_auto_generated,
                  { "SenseInfoAutoGenerated", "rsvd.svhdx_sense_info_auto_generated", FT_UINT8, BASE_HEX,
                    VALS(rsvd_sense_info_vals), 0x80, NULL, HFILL }},

                { &hf_svhdx_tunnel_srb_status_srb_status,
                  { "SrbStatus", "rsvd.svhdx_srb_status_srb_status", FT_UINT8, BASE_HEX,
                    NULL, 0x7f, NULL, HFILL }},

                { &hf_svhdx_tunnel_srb_status_scsi_status,
                  { "SrbStatus", "rsvd.svhdx_srb_status_scsi_status", FT_UINT8, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_srb_status_sense_info_ex_length,
                  { "SenseInfoExLength", "rsvd.svhdx_srb_status_sense_info_ex_length", FT_UINT8, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_srb_status_sense_data_ex,
                  { "Reserved", "rsvd.svhdx_srb_status_sense_data_ex", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_safe_virtual_size,
                  { "SafeVirtualSize", "rsvd.svhdx_safe_size", FT_UINT64, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_transaction_id,
                  { "TransactionId", "rsvd.svhdx_meta_operation.transaction_id", FT_GUID, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_meta_operation_type,
                  { "OperationType", "rsvd.svhdx_meta_operation.type", FT_UINT32, BASE_HEX,
                    VALS(rsvd_meta_operation_type_vals), 0, "Type of meta-operation", HFILL }},

                { &hf_svhdx_tunnel_padding,
                  { "Padding", "rsvd.svhdx_padding", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_resize_new_size,
                  { "NewSize", "rsvd.svhdx_meta_operation.new_size", FT_UINT64, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_resize_expand_only_flag,
                  { "ExpandOnly", "rsvd.svhdx_meta_operation.expand_only", FT_BOOLEAN, 8,
                    NULL, 0, "Indicates that shared virtual disk size can only expand", HFILL }},

                { &hf_svhdx_tunnel_resize_allow_unsafe_virt_size_flag,
                  { "AllowUnsafeVirtualSize", "rsvd.svhdx_meta_operation.allow_unsafe_virt_size", FT_BOOLEAN, 8,
                    NULL, 0, "Indicates that the shared virtual disk size can be less than the data it currently contains", HFILL }},

                { &hf_svhdx_tunnel_resize_shrink_to_minimum_safe_size_flag,
                  { "ShrinkToMinimumSafeSize", "rsvd.svhdx_meta_operation.shrink_to_minimum_safe_size", FT_BOOLEAN, 8,
                    NULL, 0, "Indicates that the shared virtual disk size can be shrunk to the data it currently contains", HFILL }},

                { &hf_svhdx_tunnel_meta_operation_start_reserved,
                  { "Reserved", "rsvd.svhdx_meta_operation.reserved", FT_UINT8, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_snapshot_type,
                  { "SnapshotType", "rsvd.svhdx_snapshot_type", FT_UINT32, BASE_HEX,
                    VALS(svhdx_snapshot_type_vals), 0, "Type of snapshot", HFILL }},

                { &hf_svhdx_tunnel_snapshot_id,
                  { "SnapshotId", "rsvd.svhdx_snapshot_id", FT_GUID, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_create_snapshot_flags,
                  { "Flags", "rsvd.svhdx_meta_operation.create_snapshot_flags", FT_UINT32, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_create_snapshot_flag_enable_change_tracking,
                  { "SVHDX_SNAPSHOT_DISK_FLAG_ENABLE_CHANGE_TRACKING", "rsvd.svhdx_meta_operation.create_snapshot_flag_enable_change_tracking", FT_BOOLEAN, 32,
                    NULL, SVHDX_SNAPSHOT_DISK_FLAG_ENABLE_CHANGE_TRACKING, "Change tracking to be enabled when snapshot is taken", HFILL }},

                { &hf_svhdx_tunnel_create_snapshot_stage1,
                  { "Stage1", "rsvd.svhdx_meta_operation.create_snapshot_stage1", FT_UINT32, BASE_HEX,
                    VALS(svhdx_snapshot_stage_vals), 0, "The first stage", HFILL }},

                { &hf_svhdx_tunnel_create_snapshot_stage2,
                  { "Stage2", "rsvd.svhdx_meta_operation.create_snapshot_stage2", FT_UINT32, BASE_HEX,
                    VALS(svhdx_snapshot_stage_vals), 0, "The second stage", HFILL }},

                { &hf_svhdx_tunnel_create_snapshot_stage3,
                  { "Stage3", "rsvd.svhdx_meta_operation.create_snapshot_stage3", FT_UINT32, BASE_HEX,
                    VALS(svhdx_snapshot_stage_vals), 0, "The third stage", HFILL }},

                { &hf_svhdx_tunnel_create_snapshot_stage4,
                  { "Stage4", "rsvd.svhdx_meta_operation.create_snapshot_stage4", FT_UINT32, BASE_HEX,
                    VALS(svhdx_snapshot_stage_vals), 0, "The fourth stage", HFILL }},

                { &hf_svhdx_tunnel_create_snapshot_stage5,
                  { "Stage5", "rsvd.svhdx_meta_operation.create_snapshot_stage5", FT_UINT32, BASE_HEX,
                    VALS(svhdx_snapshot_stage_vals), 0, "The fifth stage", HFILL }},

                { &hf_svhdx_tunnel_create_snapshot_stage6,
                  { "Stage6", "rsvd.svhdx_meta_operation.create_snapshot_stage6", FT_UINT32, BASE_HEX,
                    VALS(svhdx_snapshot_stage_vals), 0, "The sixth stage", HFILL }},

                { &hf_svhdx_tunnel_create_snapshot_parameters_payload_size,
                  { "ParametersPayloadSize", "rsvd.svhdx_meta_operation.create_snapshot_params_payload_size", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_convert_dst_vhdset_name_len,
                  { "DestinationVhdSetNameLength", "rsvd.svhdx_meta_operation.dst_vhdset_name_len", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_convert_dst_vhdset_name,
                  { "DestinationVhdSetName", "rsvd.svhdx_meta_operation.dst_vhdset_name", FT_STRING, BASE_NONE,
                    NULL, 0, "Name for the new VHD set be created", HFILL }},

                { &hf_svhdx_tunnel_delete_snapshot_persist_reference,
                  { "PersistReference", "rsvd.svhdx_delete_snapshot_persist_reference", FT_BOOLEAN, 4,
                    NULL, 0, "Indicate if the snapshot needs to be persisted", HFILL }},

                { &hf_svhdx_tunnel_meta_op_query_progress_current_progress,
                  { "CurrentProgressValue", "rsvd.svhdx_query_progress.current_progress", FT_UINT64, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_meta_op_query_progress_complete_value,
                  { "CompleteValue", "rsvd.svhdx_query_progress.complete_value", FT_UINT64, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_vhdset_information_type,
                  { "VHDSetInformationType", "rsvd.svhdx_vhdset_information_type", FT_UINT32, BASE_HEX,
                    VALS(svhdx_vhdset_information_type_vals), 0, "The information type requested", HFILL }},

                { &hf_svhdx_tunnel_vhdset_snapshot_creation_time,
                  { "SnapshotCreationTime", "rsvd.svhdx_vhdset_snapshot_creation_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
                    NULL, 0, "Time when this object was created", HFILL }},

                { &hf_svhdx_tunnel_vhdset_is_valid_snapshot,
                  { "IsValidSnapshot", "rsvd.svhdx_vhdset_is_valid_snapshot", FT_BOOLEAN, 4,
                    NULL, 0, "Set to 1 when the snapshot is valid", HFILL }},

                { &hf_svhdx_tunnel_vhdset_parent_snapshot_id,
                  { "ParentSnapshotId", "rsvd.svhdx_vhdxset_parent_snapshot_id", FT_GUID, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_vhdset_log_file_id,
                  { "LogFileId", "rsvd.svhdx_vhdxset_log_file_id", FT_GUID, BASE_NONE,
                    NULL, 0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_rsvd,
        &ett_svhdx_tunnel_op_header,
        &ett_svhdx_tunnel_scsi_request,
        &ett_rsvd_create_snapshot_flags
    };

    proto_rsvd = proto_register_protocol("Remote Shared Virtual Disk",
            "RSVD", "rsvd");

    register_dissector("rsvd", dissect_rsvd, proto_rsvd);
    proto_register_field_array(proto_rsvd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
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
