/* packet-usbms-uasp.c
 * Routines for USB Attached SCSI dissection
 * Copyright 2021, Aidan MacDonald <amachronic@protonmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <epan/packet.h>
#include "packet-usb.h"
#include "packet-scsi.h"

void proto_register_uasp(void);
void proto_reg_handoff_uasp(void);

#define IF_PROTOCOL_UAS 0x62

static dissector_handle_t uasp_descriptor_handle;
static dissector_handle_t uasp_bulk_handle;

static int proto_uasp;

static int hf_pipe_usage_descr_pipe_id;
static int hf_uas_iu_id;
static int hf_uas_tag;
static int hf_uas_cmd_command_priority;
static int hf_uas_cmd_task_attribute;
static int hf_uas_cmd_additional_cdb_length;
static int hf_uas_sense_status_qualifier;
static int hf_uas_sense_status;
static int hf_uas_sense_length;
static int hf_uas_response_additional_info;
static int hf_uas_response_code;
static int hf_uas_taskmgmt_function;
static int hf_uas_taskmgmt_tag_of_managed_task;
static int hf_uas_tag_started_frame;
static int hf_uas_tag_completed_frame;
static int hf_uas_tag_read_ready_frame;
static int hf_uas_tag_write_ready_frame;
static int hf_uas_tag_data_recv_frame;
static int hf_uas_tag_data_sent_frame;

static int ett_uasp;
static int ett_uasp_desc;

#define DT_PIPE_USAGE 0x24

static const value_string uasp_descriptor_type_vals[] = {
    {DT_PIPE_USAGE, "Pipe Usage"},
    {0, NULL}
};

static value_string_ext uasp_descriptor_type_vals_ext =
    VALUE_STRING_EXT_INIT(uasp_descriptor_type_vals);

#define COMMAND_PIPE_ID  0x01
#define STATUS_PIPE_ID   0x02
#define DATA_IN_PIPE_ID  0x03
#define DATA_OUT_PIPE_ID 0x04

static const value_string uasp_pipe_id_vals[] = {
    {COMMAND_PIPE_ID,  "Command"},
    {STATUS_PIPE_ID,   "Status"},
    {DATA_IN_PIPE_ID,  "Data-In"},
    {DATA_OUT_PIPE_ID, "Data-Out"},
    {0, NULL}
};

#define COMMAND_IU_ID       0x01
#define SENSE_IU_ID         0x03
#define RESPONSE_IU_ID      0x04
#define TASK_MGMT_IU_ID     0x05
#define READ_READY_IU_ID    0x06
#define WRITE_READY_IU_ID   0x07

static const value_string uasp_iu_id_vals[] = {
    {COMMAND_IU_ID,     "Command IU"},
    {SENSE_IU_ID,       "Sense IU"},
    {RESPONSE_IU_ID,    "Response IU"},
    {TASK_MGMT_IU_ID,   "Task Management IU"},
    {READ_READY_IU_ID,  "Read Ready IU"},
    {WRITE_READY_IU_ID, "Write Ready IU"},
    {0, NULL},
};

typedef struct _uasp_itlq_nexus_t {
    uint16_t tag;                /* tag for this ITLQ nexus */
    uint32_t started_frame;      /* when tag was first seen */
    uint32_t completed_frame;    /* when tag was completed */
    uint32_t read_ready_frame;   /* when read ready was issued for tag */
    uint32_t write_ready_frame;  /* when write ready was issued for tag */
    uint32_t data_recv_frame;    /* when read data was received for tag */
    uint32_t data_sent_frame;    /* when write data was sent for tag */
    itl_nexus_t* itl;
    itlq_nexus_t itlq;
} uasp_itlq_nexus_t;

typedef struct _uasp_conv_info_t {
    /* for keeping track of what endpoint is used for what */
    uint8_t command_endpoint;
    uint8_t status_endpoint;
    uint8_t data_in_endpoint;
    uint8_t data_out_endpoint;

    /* tag of each read/write ready IU; indexed by pinfo->num */
    wmem_tree_t* read_ready;
    wmem_tree_t* write_ready;

    /* ITL nexus; indexed by LUN */
    wmem_tree_t* itl;

    /* UASP ITLQ nexus per command; multi part key
     * [0] = UAS tag
     * [1] = pinfo->num */
    wmem_tree_t* itlq;
} uasp_conv_info_t;

static uasp_conv_info_t*
get_uasp_conv_info(usb_conv_info_t *usb_conv_info)
{
    uasp_conv_info_t *uasp_conv_info = (uasp_conv_info_t *)usb_conv_info->class_data;

    if (!uasp_conv_info) {
        uasp_conv_info = wmem_new(wmem_file_scope(), uasp_conv_info_t);
        uasp_conv_info->command_endpoint = 0;
        uasp_conv_info->status_endpoint = 0;
        uasp_conv_info->data_in_endpoint = 0;
        uasp_conv_info->data_out_endpoint = 0;
        uasp_conv_info->read_ready = wmem_tree_new(wmem_file_scope());
        uasp_conv_info->write_ready = wmem_tree_new(wmem_file_scope());
        uasp_conv_info->itl = wmem_tree_new(wmem_file_scope());
        uasp_conv_info->itlq = wmem_tree_new(wmem_file_scope());

        usb_conv_info->class_data = uasp_conv_info;
        usb_conv_info->class_data_type = USB_CONV_MASS_STORAGE_UASP;
    } else if (usb_conv_info->class_data_type != USB_CONV_MASS_STORAGE_UASP) {
        return NULL;
    }

    return uasp_conv_info;
}

static uint16_t
get_scsi_lun(tvbuff_t* tvb, int offset)
{
    uint16_t lun;

    /* Copied from packet-iscsi.c - not really correct but good enough... */
    if (tvb_get_uint8(tvb, offset) & 0x40) {
        /* volume set addressing */
        lun = tvb_get_uint8(tvb, offset) & 0x3f;
        lun <<= 8;
        lun |= tvb_get_uint8(tvb,offset + 1);
    } else {
        lun = tvb_get_uint8(tvb, offset + 1);
    }

    return lun;
}

static uasp_itlq_nexus_t*
create_itlq_nexus(packet_info *pinfo, uasp_conv_info_t *uasp_conv_info, uint16_t lun, uint16_t tag)
{
    wmem_tree_key_t key[3];
    uint32_t tag32 = tag;
    itl_nexus_t *itl;
    uasp_itlq_nexus_t *uitlq;

    /* ensure ITL nexus exists */
    itl = (itl_nexus_t *)wmem_tree_lookup32(uasp_conv_info->itl, lun);
    if(!itl) {
        itl = wmem_new(wmem_file_scope(), itl_nexus_t);
        itl->cmdset = 0xff;
        itl->conversation = NULL;
        wmem_tree_insert32(uasp_conv_info->itl, lun, itl);
    }

    /* ensure ITLQ nexus exists */
    key[0].length = 1;
    key[0].key = &tag32;
    key[1].length = 1;
    key[1].key = &pinfo->num;
    key[2].length = 0;

    uitlq = (uasp_itlq_nexus_t *)wmem_tree_lookup32_array(uasp_conv_info->itlq, key);
    if(!uitlq) {
        uitlq = wmem_new(wmem_file_scope(), uasp_itlq_nexus_t);
        uitlq->tag = tag;
        uitlq->started_frame = pinfo->num;
        uitlq->completed_frame = 0;
        uitlq->read_ready_frame = 0;
        uitlq->write_ready_frame = 0;
        uitlq->data_sent_frame = 0;
        uitlq->data_recv_frame = 0;
        uitlq->itl = itl;
        uitlq->itlq.lun = lun;
        uitlq->itlq.scsi_opcode = 0xffff;
        uitlq->itlq.task_flags = 0;
        uitlq->itlq.data_length = 0;
        uitlq->itlq.bidir_data_length = 0;
        uitlq->itlq.fc_time = pinfo->abs_ts;
        uitlq->itlq.first_exchange_frame = pinfo->num;
        uitlq->itlq.last_exchange_frame = 0;
        uitlq->itlq.flags = 0;
        uitlq->itlq.alloc_len = 0;
        uitlq->itlq.extra_data = NULL;

        wmem_tree_insert32_array(uasp_conv_info->itlq, key, uitlq);
    }

    return uitlq;
}

static uasp_itlq_nexus_t*
get_itlq_nexus(packet_info* pinfo, uasp_conv_info_t *uasp_conv_info, uint16_t tag)
{
    uint32_t tag32 = tag;
    wmem_tree_key_t key[3];
    uasp_itlq_nexus_t *uitlq;

    key[0].length = 1;
    key[0].key = &tag32;
    key[1].length = 1;
    key[1].key = &pinfo->num;
    key[2].length = 0;

    uitlq = (uasp_itlq_nexus_t *)wmem_tree_lookup32_array_le(uasp_conv_info->itlq, key);
    if(!uitlq || uitlq->tag != tag)
        return NULL;

    return uitlq;
}

static void
create_ready_iu(wmem_tree_t* tree, packet_info* pinfo, uint16_t tag)
{
    wmem_tree_insert32(tree, pinfo->num, GUINT_TO_POINTER(tag));
}

static uint16_t
get_ready_iu(wmem_tree_t* tree, packet_info* pinfo)
{
    return GPOINTER_TO_UINT(wmem_tree_lookup32_le(tree, pinfo->num));
}

#define DATA_WRITE  (-1)
#define DATA_READ   (-2)

static void
add_uasp_tag_links(tvbuff_t *tvb, proto_tree *uasp_tree, uasp_itlq_nexus_t *uitlq, int kind)
{
    proto_item *ti;

    if (!uitlq)
        return;

    if (uitlq->started_frame && kind != COMMAND_IU_ID && kind != TASK_MGMT_IU_ID) {
        ti = proto_tree_add_uint(uasp_tree, hf_uas_tag_started_frame, tvb, 0, 0, uitlq->started_frame);
        proto_item_set_generated(ti);
    }

    if (uitlq->read_ready_frame && kind != READ_READY_IU_ID) {
        ti = proto_tree_add_uint(uasp_tree, hf_uas_tag_read_ready_frame, tvb, 0, 0, uitlq->read_ready_frame);
        proto_item_set_generated(ti);
    }

    if (uitlq->write_ready_frame && kind != WRITE_READY_IU_ID) {
        ti = proto_tree_add_uint(uasp_tree, hf_uas_tag_write_ready_frame, tvb, 0, 0, uitlq->write_ready_frame);
        proto_item_set_generated(ti);
    }

    if (uitlq->data_recv_frame && kind != DATA_READ) {
        ti = proto_tree_add_uint(uasp_tree, hf_uas_tag_data_recv_frame, tvb, 0, 0, uitlq->data_recv_frame);
        proto_item_set_generated(ti);
    }

    if (uitlq->data_sent_frame && kind != DATA_WRITE) {
        ti = proto_tree_add_uint(uasp_tree, hf_uas_tag_data_sent_frame, tvb, 0, 0, uitlq->data_sent_frame);
        proto_item_set_generated(ti);
    }

    if (uitlq->completed_frame && kind != SENSE_IU_ID && kind != RESPONSE_IU_ID) {
        ti = proto_tree_add_uint(uasp_tree, hf_uas_tag_completed_frame, tvb, 0, 0, uitlq->completed_frame);
        proto_item_set_generated(ti);
    }
}

static int
dissect_uasp_iu(tvbuff_t *tvb, packet_info *pinfo,
                proto_tree *parent_tree, proto_tree *uasp_tree,
                usb_conv_info_t *usb_conv_info _U_, uasp_conv_info_t *uasp_conv_info)
{
    uint8_t            iu_id;
    uint8_t            status;
    uint16_t           tag;
    uint16_t           lun;
    uasp_itlq_nexus_t *uitlq = NULL;
    int                rlen, len;
    tvbuff_t          *cdb_tvb;

    /* an IU header is 4 bytes */
    if (tvb_reported_length(tvb) < 4)
        return 0;

    iu_id = tvb_get_uint8(tvb, 0);
    tag = tvb_get_ntohs(tvb, 2);

    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(iu_id, uasp_iu_id_vals, "Unknown IU [0x%02x]"));

    proto_tree_add_item(uasp_tree, hf_uas_iu_id, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(uasp_tree, hf_uas_tag, tvb, 2, 2, ENC_BIG_ENDIAN);

    switch(iu_id) {
    case COMMAND_IU_ID:
        proto_tree_add_item(uasp_tree, hf_uas_cmd_command_priority, tvb, 4, 1, ENC_NA);
        proto_tree_add_item(uasp_tree, hf_uas_cmd_task_attribute, tvb, 4, 1, ENC_NA);
        proto_tree_add_item(uasp_tree, hf_uas_cmd_additional_cdb_length, tvb, 6, 1, ENC_NA);
        dissect_scsi_lun(uasp_tree, tvb, 8);

        lun = get_scsi_lun(tvb, 8);
        uitlq = create_itlq_nexus(pinfo, uasp_conv_info, lun, tag);

        rlen = 16 + tvb_get_uint8(tvb, 6);
        len = rlen;

        if (len > tvb_captured_length_remaining(tvb, 16))
            len = tvb_captured_length_remaining(tvb, 16);

        if (len) {
            cdb_tvb = tvb_new_subset_length_caplen(tvb, 16, len, rlen);
            dissect_scsi_cdb(cdb_tvb, pinfo, parent_tree, SCSI_DEV_UNKNOWN,
                             &uitlq->itlq, uitlq->itl);
        }

        break;

    case SENSE_IU_ID:
        proto_tree_add_item(uasp_tree, hf_uas_sense_status_qualifier, tvb, 4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(uasp_tree, hf_uas_sense_status, tvb, 6, 1, ENC_NA);
        proto_tree_add_item(uasp_tree, hf_uas_sense_length, tvb, 14, 2, ENC_BIG_ENDIAN);

        uitlq = get_itlq_nexus(pinfo, uasp_conv_info, tag);
        if (uitlq) {
            uitlq->completed_frame = pinfo->num;
            uitlq->itlq.last_exchange_frame = pinfo->num;

            status = tvb_get_uint8(tvb, 6);
            dissect_scsi_rsp(tvb, pinfo, parent_tree, &uitlq->itlq, uitlq->itl, status);

            /* dissect sense info, if any */
            rlen = tvb_get_ntohs(tvb, 14);
            if (rlen) {
                dissect_scsi_snsinfo(tvb, pinfo, parent_tree, 16, rlen, &uitlq->itlq, uitlq->itl);
            }
        }

        break;

    case RESPONSE_IU_ID:
        proto_tree_add_item(uasp_tree, hf_uas_response_additional_info, tvb, 4, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(uasp_tree, hf_uas_response_code, tvb, 7, 1, ENC_NA);
        break;

    case TASK_MGMT_IU_ID:
        proto_tree_add_item(uasp_tree, hf_uas_taskmgmt_function, tvb, 4, 1, ENC_NA);
        proto_tree_add_item(uasp_tree, hf_uas_taskmgmt_tag_of_managed_task, tvb, 6, 2, ENC_BIG_ENDIAN);
        dissect_scsi_lun(uasp_tree, tvb, 8);
        break;

    case READ_READY_IU_ID:
        uitlq = get_itlq_nexus(pinfo, uasp_conv_info, tag);
        if (uitlq)
            uitlq->read_ready_frame = pinfo->num;

        create_ready_iu(uasp_conv_info->read_ready, pinfo, tag);
        break;

    case WRITE_READY_IU_ID:
        uitlq = get_itlq_nexus(pinfo, uasp_conv_info, tag);
        if (uitlq)
            uitlq->write_ready_frame = pinfo->num;

        create_ready_iu(uasp_conv_info->write_ready, pinfo, tag);
        break;
    }

    add_uasp_tag_links(tvb, uasp_tree, uitlq, iu_id);

    return tvb_captured_length(tvb);
}

static int
dissect_uasp_data(tvbuff_t *tvb, packet_info *pinfo,
                  proto_tree *parent_tree, proto_tree *uasp_tree,
                  usb_conv_info_t *usb_conv_info, uasp_conv_info_t *uasp_conv_info)
{
    proto_item        *ti;
    uint16_t           tag;
    uasp_itlq_nexus_t *uitlq;
    bool               is_request;

    is_request = (usb_conv_info->direction == P2P_DIR_SENT) ? true : false;

    /* TODO - fetch tag from USB 3.0 Bulk Streams.
     *
     * It seems Wireshark doesn't track the stream ID so we can't yet
     * dissect UASP over USB 3.0 traffic. (The Linux kernel doesn't even
     * export an URB's stream ID, so OS support for this might be spotty
     * or even non-existent...)
     */
    if (is_request)
        tag = get_ready_iu(uasp_conv_info->write_ready, pinfo);
    else
        tag = get_ready_iu(uasp_conv_info->read_ready, pinfo);

    /* add tag to tree */
    ti = proto_tree_add_uint(uasp_tree, hf_uas_tag, tvb, 0, 0, tag);
    proto_item_set_generated(ti);

    uitlq = get_itlq_nexus(pinfo, uasp_conv_info, tag);
    if (uitlq) {
        if (is_request)
            uitlq->data_sent_frame = pinfo->num;
        else
            uitlq->data_recv_frame = pinfo->num;

        add_uasp_tag_links(tvb, uasp_tree, uitlq, is_request ? DATA_WRITE : DATA_READ);
        dissect_scsi_payload(tvb, pinfo, parent_tree, is_request, &uitlq->itlq, uitlq->itl, 0);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_uasp_bulk(tvbuff_t *tvb,
                  packet_info *pinfo,
                  proto_tree *parent_tree,
                  void *data)
{
    typedef int(*uasp_dissector_t)(tvbuff_t *, packet_info *, proto_tree *,
                                   proto_tree *, usb_conv_info_t *, uasp_conv_info_t *);

    proto_tree        *uasp_tree;
    proto_item        *ti;
    uasp_dissector_t  dissector = NULL;
    uint8_t           endpoint;
    usb_conv_info_t  *usb_conv_info = (usb_conv_info_t *)data;
    uasp_conv_info_t *uasp_conv_info = get_uasp_conv_info(usb_conv_info);

    if (!uasp_conv_info)
        return 0;

    endpoint = usb_conv_info->endpoint;
    if (endpoint == uasp_conv_info->command_endpoint ||
        endpoint == uasp_conv_info->status_endpoint)
        dissector = dissect_uasp_iu;
    else if (endpoint == uasp_conv_info->data_in_endpoint ||
             endpoint == uasp_conv_info->data_out_endpoint)
        dissector = dissect_uasp_data;
    else
        return 0;

    col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "UASP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_protocol_format(parent_tree, proto_uasp, tvb, 0, -1,
                                        "USB Attached SCSI");
    uasp_tree = proto_item_add_subtree(ti, ett_uasp);

    return dissector(tvb, pinfo, parent_tree, uasp_tree, usb_conv_info, uasp_conv_info);
}

static int
dissect_uasp_descriptor(tvbuff_t *tvb,
                        packet_info *pinfo _U_,
                        proto_tree *parent_tree,
                        void *data _U_)
{
    uint8_t           desc_type;
    uint8_t           desc_len;
    proto_tree       *desc_tree;
    proto_tree       *desc_tree_item;
    usb_conv_info_t  *usb_conv_info = (usb_conv_info_t *)data;
    usb_trans_info_t *usb_trans_info = NULL;
    uasp_conv_info_t *uasp_conv_info;

    if (usb_conv_info)
        usb_trans_info = usb_conv_info->usb_trans_info;

    /* Descriptor must have a length and type field. */
    if (tvb_reported_length(tvb) < 2)
        return 0;

    desc_len = tvb_get_uint8(tvb, 0);
    desc_type = tvb_get_uint8(tvb, 1);

    if (desc_type != DT_PIPE_USAGE)
        return 0;

    desc_tree = proto_tree_add_subtree(parent_tree, tvb, 0, desc_len,
                                       ett_uasp_desc, &desc_tree_item,
                                       "UAS PIPE USAGE DESCRIPTOR");

    dissect_usb_descriptor_header(desc_tree, tvb, 0,
                                  &uasp_descriptor_type_vals_ext);
    proto_tree_add_item(desc_tree, hf_pipe_usage_descr_pipe_id,
                        tvb, 2, 1, ENC_NA);

    /* The pipe usage descriptor should follow the endpoint descriptor
     * of the endpoint it applies to. Keep track of the pipe ID for the
     * endpoint so the bulk dissector can distinguish between commands
     * and data reliably */
    if (!pinfo->fd->visited && usb_trans_info && usb_trans_info->interface_info) {
        uint8_t endpoint = usb_trans_info->interface_info->endpoint;
        uint8_t pipe_id = tvb_get_uint8(tvb, 2);

        uasp_conv_info = get_uasp_conv_info(usb_trans_info->interface_info);
        if (uasp_conv_info) {
            switch (pipe_id) {
            case COMMAND_PIPE_ID:
                uasp_conv_info->command_endpoint = endpoint;
                break;
            case STATUS_PIPE_ID:
                uasp_conv_info->status_endpoint = endpoint;
                break;
            case DATA_IN_PIPE_ID:
                uasp_conv_info->data_in_endpoint = endpoint;
                break;
            case DATA_OUT_PIPE_ID:
                uasp_conv_info->data_out_endpoint = endpoint;
                break;
            }
        }
    }

    return desc_len;
}

void
proto_register_uasp(void)
{
    static hf_register_info hf[] = {
        { &hf_pipe_usage_descr_pipe_id,
          { "bPipeID", "uasp.pipe_usage.bPipeID",
            FT_UINT8, BASE_HEX, VALS(uasp_pipe_id_vals), 0x00, NULL, HFILL } },

        { &hf_uas_iu_id,
          { "IU ID", "uasp.iu_id",
            FT_UINT8, BASE_HEX, VALS(uasp_iu_id_vals), 0x00, NULL, HFILL } },
        { &hf_uas_tag,
          { "Tag", "uasp.tag",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL } },

        { &hf_uas_cmd_command_priority,
          { "Command Priority", "uasp.command.priority",
            FT_UINT8, BASE_DEC, NULL, 0x78, NULL, HFILL } },
        { &hf_uas_cmd_task_attribute,
          { "Task Attribute", "uasp.command.task_attr",
            FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL } },
        { &hf_uas_cmd_additional_cdb_length,
          { "Additional CDB Length", "uasp.command.add_cdb_length",
            FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL } },

        { &hf_uas_sense_status_qualifier,
          { "Status Qualifier", "uasp.sense.status_qualifier",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_uas_sense_status,
          { "Status", "uasp.sense.status",
            FT_UINT8, BASE_DEC, VALS(scsi_status_val), 0x00, NULL, HFILL } },
        { &hf_uas_sense_length,
          { "Length", "uasp.sense.length",
            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL } },

        { &hf_uas_response_additional_info,
          { "Additional Response Info", "uasp.response.add_info",
            FT_UINT24, BASE_HEX, NULL, 0x00, NULL, HFILL } },
        { &hf_uas_response_code,
          { "Response Code", "uasp.response.code",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },

        { &hf_uas_taskmgmt_function,
          { "Task Management Function", "uasp.task_mgmt.function",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },
        { &hf_uas_taskmgmt_tag_of_managed_task,
          { "Tag of Managed Task", "uasp.task_mgmt.managed_tag",
            FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL } },

        { &hf_uas_tag_started_frame,
          { "Tag started in", "uasp.tag_started_frame", FT_FRAMENUM, BASE_NONE, NULL, 0,
            "The command with this tag was started in this frame", HFILL } },
        { &hf_uas_tag_completed_frame,
          { "Tag completed in", "uasp.tag_completed_frame", FT_FRAMENUM, BASE_NONE, NULL, 0,
            "The command with this tag was completed in this frame", HFILL } },
        { &hf_uas_tag_read_ready_frame,
          { "Tag read ready in", "uasp.tag_read_ready_frame", FT_FRAMENUM, BASE_NONE, NULL, 0,
            "The request data for the tag became ready in this frame", HFILL } },
        { &hf_uas_tag_write_ready_frame,
          { "Tag write ready in", "uasp.tag_write_ready_frame", FT_FRAMENUM, BASE_NONE, NULL, 0,
            "The request data for the tag became ready in this frame", HFILL } },
        { &hf_uas_tag_data_recv_frame,
          { "Tag data received in", "uasp.tag_data_recv_frame", FT_FRAMENUM, BASE_NONE, NULL, 0,
            "The response data for the tag was transmitted in this frame", HFILL } },
        { &hf_uas_tag_data_sent_frame,
          { "Tag data sent in", "uasp.tag_data_sent_frame", FT_FRAMENUM, BASE_NONE, NULL, 0,
            "The request data for the tag was transmitted in this frame", HFILL } },
    };

    static int *uasp_subtrees[] = {
        &ett_uasp,
        &ett_uasp_desc,
    };

    proto_uasp = proto_register_protocol("USB Attached SCSI", "UASP", "uasp");
    proto_register_field_array(proto_uasp, hf, array_length(hf));
    proto_register_subtree_array(uasp_subtrees, array_length(uasp_subtrees));

    uasp_descriptor_handle = register_dissector("uasp", dissect_uasp_descriptor, proto_uasp);
    uasp_bulk_handle = register_dissector("uasp.bulk", dissect_uasp_bulk, proto_uasp);
}

void
proto_reg_handoff_uasp(void)
{
    dissector_add_uint("usbms.descriptor", IF_PROTOCOL_UAS, uasp_descriptor_handle);
    dissector_add_uint("usbms.bulk", IF_PROTOCOL_UAS, uasp_bulk_handle);
}
