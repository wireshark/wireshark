/* packet-usbms-bot.c
 *
 * usb mass storage (bulk-only transport) dissector
 * Ronnie Sahlberg 2006
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <epan/packet.h>
#include "packet-usb.h"
#include "packet-scsi.h"

void proto_register_usbms_bot(void);
void proto_reg_handoff_usbms_bot(void);

#define IF_PROTOCOL_BULK_ONLY 0x50

/* protocols and header fields */
static int proto_usbms_bot;
static int hf_usbms_bot_dCBWSignature;
static int hf_usbms_bot_dCBWTag;
static int hf_usbms_bot_dCBWDataTransferLength;
static int hf_usbms_bot_dCBWFlags;
static int hf_usbms_bot_dCBWTarget;
static int hf_usbms_bot_dCBWLUN;
static int hf_usbms_bot_dCBWCBLength;
static int hf_usbms_bot_dCSWSignature;
static int hf_usbms_bot_dCSWDataResidue;
static int hf_usbms_bot_dCSWStatus;
static int hf_usbms_bot_request;
static int hf_usbms_bot_value;
static int hf_usbms_bot_index;
static int hf_usbms_bot_length;
static int hf_usbms_bot_maxlun;

static int ett_usbms_bot;

static dissector_handle_t usbms_bot_bulk_handle;
static dissector_handle_t usbms_bot_control_handle;

/* there is one such structure for each masstorage conversation */
typedef struct _usbms_bot_conv_info_t {
    wmem_tree_t *itl;           /* indexed by LUN */
    wmem_tree_t *itlq;          /* pinfo->num */
} usbms_bot_conv_info_t;


static const value_string status_vals[] = {
    {0x00,      "Command Passed"},
    {0x01,      "Command Failed"},
    {0x02,      "Phase Error"},
    {0, NULL}
};

static void
dissect_usbms_bot_reset(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, bool is_request, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    if(is_request){
        proto_tree_add_item(tree, hf_usbms_bot_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_usbms_bot_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_usbms_bot_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        /*offset += 2;*/
    } else {
        /* no data in reset response */
    }
}

static void
dissect_usbms_bot_get_max_lun(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, bool is_request, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    if(is_request){
        proto_tree_add_item(tree, hf_usbms_bot_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_usbms_bot_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_usbms_bot_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        /*offset += 2;*/
    } else {
        proto_tree_add_item(tree, hf_usbms_bot_maxlun, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        /*offset++;*/
    }
}


typedef void (*usb_setup_dissector)(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, bool is_request, usb_trans_info_t *usb_trans_info, usb_conv_info_t *usb_conv_info);

typedef struct _usb_setup_dissector_table_t {
    uint8_t request;
    usb_setup_dissector dissector;
} usb_setup_dissector_table_t;
#define USB_SETUP_RESET               0xff
#define USB_SETUP_GET_MAX_LUN         0xfe
static const usb_setup_dissector_table_t setup_dissectors[] = {
    {USB_SETUP_RESET,          dissect_usbms_bot_reset},
    {USB_SETUP_GET_MAX_LUN,    dissect_usbms_bot_get_max_lun},
    {0, NULL}
};
static const value_string setup_request_names_vals[] = {
    {USB_SETUP_RESET,          "RESET"},
    {USB_SETUP_GET_MAX_LUN,    "GET MAX LUN"},
    {0, NULL}
};

/* Dissector for mass storage control .
 * Returns tvb_captured_length(tvb) if a class specific dissector was found
 * and 0 othervise.
 */
static int
dissect_usbms_bot_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
    bool is_request;
    usb_conv_info_t *usb_conv_info;
    usb_trans_info_t *usb_trans_info;
    int offset=0;
    usb_setup_dissector dissector = NULL;
    const usb_setup_dissector_table_t *tmp;
    proto_tree *tree;
    proto_item *ti;

    /* Reject the packet if data or usb_trans_info are NULL */
    if (data == NULL || ((usb_conv_info_t *)data)->usb_trans_info == NULL)
        return 0;
    usb_conv_info = (usb_conv_info_t *)data;
    usb_trans_info = usb_conv_info->usb_trans_info;

    is_request=(pinfo->srcport==NO_ENDPOINT);

    /* See if we can find a class specific dissector for this request */
    for(tmp=setup_dissectors;tmp->dissector;tmp++){
        if (tmp->request == usb_trans_info->setup.request){
            dissector=tmp->dissector;
            break;
        }
    }
    /* No we could not find any class specific dissector for this request
     * return 0 and let USB try any of the standard requests.
     */
    if(!dissector){
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBMS");
    ti = proto_tree_add_protocol_format(parent_tree, proto_usbms_bot, tvb, 0, -1, "USB Mass Storage");
    tree = proto_item_add_subtree(ti, ett_usbms_bot);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
        val_to_str(usb_trans_info->setup.request, setup_request_names_vals, "Unknown type %x"),
        is_request?"Request":"Response");

    if(is_request){
        proto_tree_add_item(tree, hf_usbms_bot_request, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }

    dissector(pinfo, tree, tvb, offset, is_request, usb_trans_info, usb_conv_info);
    return tvb_captured_length(tvb);
}

static proto_tree *
create_usbms_bot_protocol_tree(tvbuff_t *tvb, proto_tree *parent_tree)
{
    proto_tree *tree;
    proto_item *ti;

    ti = proto_tree_add_protocol_format(parent_tree, proto_usbms_bot, tvb, 0, -1, "USB Mass Storage");
    tree = proto_item_add_subtree(ti, ett_usbms_bot);

    return tree;
}

static int
dissect_usbms_bot_cbw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, usbms_bot_conv_info_t *usbms_bot_conv_info)
{
    proto_tree *tree = create_usbms_bot_protocol_tree(tvb, parent_tree);
    tvbuff_t *cdb_tvb;
    int offset=0;
    int cdbrlen, cdblen;
    uint8_t lun, flags;
    uint32_t datalen;
    itl_nexus_t *itl;
    itlq_nexus_t *itlq;

    /* dCBWSignature */
    proto_tree_add_item(tree, hf_usbms_bot_dCBWSignature, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;

    /* dCBWTag */
    proto_tree_add_item(tree, hf_usbms_bot_dCBWTag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;

    /* dCBWDataTransferLength */
    proto_tree_add_item(tree, hf_usbms_bot_dCBWDataTransferLength, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    datalen=tvb_get_letohl(tvb, offset);
    offset+=4;

    /* dCBWFlags */
    proto_tree_add_item(tree, hf_usbms_bot_dCBWFlags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    flags=tvb_get_uint8(tvb, offset);
    offset+=1;

    /* dCBWLUN */
    proto_tree_add_item(tree, hf_usbms_bot_dCBWTarget, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usbms_bot_dCBWLUN, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    lun=tvb_get_uint8(tvb, offset)&0x0f;
    offset+=1;

    /* make sure we have a ITL structure for this LUN */
    itl=(itl_nexus_t *)wmem_tree_lookup32(usbms_bot_conv_info->itl, lun);
    if(!itl){
        itl=wmem_new(wmem_file_scope(), itl_nexus_t);
        itl->cmdset=0xff;
        itl->conversation=NULL;
        wmem_tree_insert32(usbms_bot_conv_info->itl, lun, itl);
    }

    /* make sure we have an ITLQ structure for this LUN/transaction */
    itlq=(itlq_nexus_t *)wmem_tree_lookup32(usbms_bot_conv_info->itlq, pinfo->num);
    if(!itlq){
        itlq=wmem_new(wmem_file_scope(), itlq_nexus_t);
        itlq->lun=lun;
        itlq->scsi_opcode=0xffff;
        itlq->task_flags=0;
        if(datalen){
            if(flags&0x80){
                itlq->task_flags|=SCSI_DATA_READ;
            } else {
                itlq->task_flags|=SCSI_DATA_WRITE;
            }
        }
        itlq->data_length=datalen;
        itlq->bidir_data_length=0;
        itlq->fc_time=pinfo->abs_ts;
        itlq->first_exchange_frame=pinfo->num;
        itlq->last_exchange_frame=0;
        itlq->flags=0;
        itlq->alloc_len=0;
        itlq->extra_data=NULL;
        wmem_tree_insert32(usbms_bot_conv_info->itlq, pinfo->num, itlq);
    }

    /* dCBWCBLength */
    proto_tree_add_item(tree, hf_usbms_bot_dCBWCBLength, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    cdbrlen=tvb_get_uint8(tvb, offset)&0x1f;
    offset+=1;

    cdblen=cdbrlen;
    if(cdblen>tvb_captured_length_remaining(tvb, offset)){
        cdblen=tvb_captured_length_remaining(tvb, offset);
    }
    if(cdblen){
        cdb_tvb=tvb_new_subset_length_caplen(tvb, offset, cdblen, cdbrlen);
        dissect_scsi_cdb(cdb_tvb, pinfo, parent_tree, SCSI_DEV_UNKNOWN, itlq, itl);
    }
    return tvb_captured_length(tvb);
}

static int
dissect_usbms_bot_csw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, usbms_bot_conv_info_t *usbms_bot_conv_info)
{
    proto_tree *tree = create_usbms_bot_protocol_tree(tvb, parent_tree);
    int offset=0;
    uint8_t status;
    itl_nexus_t *itl;
    itlq_nexus_t *itlq;

    /* dCSWSignature */
    proto_tree_add_item(tree, hf_usbms_bot_dCSWSignature, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;

    /* dCSWTag */
    proto_tree_add_item(tree, hf_usbms_bot_dCBWTag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;

    /* dCSWDataResidue */
    proto_tree_add_item(tree, hf_usbms_bot_dCSWDataResidue, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;

    /* dCSWStatus */
    proto_tree_add_item(tree, hf_usbms_bot_dCSWStatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    status=tvb_get_uint8(tvb, offset);
    /*offset+=1;*/

    itlq=(itlq_nexus_t *)wmem_tree_lookup32_le(usbms_bot_conv_info->itlq, pinfo->num);
    if(!itlq){
        return tvb_captured_length(tvb);
    }
    itlq->last_exchange_frame=pinfo->num;

    itl=(itl_nexus_t *)wmem_tree_lookup32(usbms_bot_conv_info->itl, itlq->lun);
    if(!itl){
        return tvb_captured_length(tvb);
    }

    if(!status){
        dissect_scsi_rsp(tvb, pinfo, parent_tree, itlq, itl, 0);
    } else {
        /* just send "check condition" */
        dissect_scsi_rsp(tvb, pinfo, parent_tree, itlq, itl, 0x02);
    }
    return tvb_captured_length(tvb);
}

static bool
usbms_bot_bulk_is_cbw(tvbuff_t *tvb, int offset, bool is_request)
{
    return is_request && (tvb_reported_length(tvb)==(unsigned)offset+31) &&
           tvb_get_letohl(tvb, offset) == 0x43425355;
}

static bool
usbms_bot_bulk_is_csw(tvbuff_t *tvb, int offset, bool is_request)
{
    return !is_request && (tvb_reported_length(tvb)==(unsigned)offset+13) &&
           tvb_get_letohl(tvb, offset) == 0x53425355;
}

/* dissector for mass storage bulk data */
static int
dissect_usbms_bot_bulk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
    usb_conv_info_t *usb_conv_info;
    usbms_bot_conv_info_t *usbms_bot_conv_info;
    int offset=0;
    bool is_request;
    itl_nexus_t *itl;
    itlq_nexus_t *itlq;
    tvbuff_t *payload_tvb;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    usb_conv_info = (usb_conv_info_t *)data;

    /* verify that we do have a usbms_bot_conv_info */
    usbms_bot_conv_info=(usbms_bot_conv_info_t *)usb_conv_info->class_data;
    if(!usbms_bot_conv_info){
        usbms_bot_conv_info=wmem_new(wmem_file_scope(), usbms_bot_conv_info_t);
        usbms_bot_conv_info->itl=wmem_tree_new(wmem_file_scope());
        usbms_bot_conv_info->itlq=wmem_tree_new(wmem_file_scope());
        usb_conv_info->class_data=usbms_bot_conv_info;
        usb_conv_info->class_data_type = USB_CONV_MASS_STORAGE_BOT;
    } else if (usb_conv_info->class_data_type != USB_CONV_MASS_STORAGE_BOT) {
        /* Don't dissect if another USB type is in the conversation */
        return 0;
    }

    is_request=(pinfo->srcport==NO_ENDPOINT);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBMS");

    col_clear(pinfo->cinfo, COL_INFO);


    /*
     * SCSI CDB inside CBW
     */
    if (usbms_bot_bulk_is_cbw(tvb, offset, is_request)) {
        return dissect_usbms_bot_cbw(tvb, pinfo, parent_tree, usbms_bot_conv_info);
    }


    /*
     * SCSI RESPONSE inside CSW
     */
    if (usbms_bot_bulk_is_csw(tvb, offset, is_request)) {
        return dissect_usbms_bot_csw(tvb, pinfo, parent_tree, usbms_bot_conv_info);
    }

    /*
     * Ok it was neither CDB not STATUS so just assume it is either data in/out
     */
    itlq=(itlq_nexus_t *)wmem_tree_lookup32_le(usbms_bot_conv_info->itlq, pinfo->num-1);
    if(!itlq){
        create_usbms_bot_protocol_tree(tvb, parent_tree);
        return tvb_captured_length(tvb);
    }

    itl=(itl_nexus_t *)wmem_tree_lookup32(usbms_bot_conv_info->itl, itlq->lun);
    if(!itl){
        create_usbms_bot_protocol_tree(tvb, parent_tree);
        return tvb_captured_length(tvb);
    }

    /*
     * Workaround USBLL reassembly limitations by anticipating concatenated
     * SCSI Data IN with CSW and SCSI Data OUT with next CBW. Proper would
     * involve implementing a framework to allow USB class dissectors to signal
     * expected transfer length on Bulk IN or Bulk OUT endpoint whenever CBW is
     * encountered.
     */
    payload_tvb = tvb_new_subset_length(tvb, 0, itlq->data_length);
    if (usbms_bot_bulk_is_cbw(tvb, itlq->data_length, is_request)) {
        tvbuff_t *cbw_tvb = tvb_new_subset_length(tvb, itlq->data_length, 31);

        dissect_scsi_payload(payload_tvb, pinfo, parent_tree, is_request, itlq, itl, 0);
        dissect_usbms_bot_cbw(cbw_tvb, pinfo, parent_tree, usbms_bot_conv_info);
        return tvb_captured_length(tvb);
    } else if (usbms_bot_bulk_is_csw(tvb, itlq->data_length, is_request)) {
        tvbuff_t *csw_tvb = tvb_new_subset_length(tvb, itlq->data_length, 13);

        dissect_scsi_payload(payload_tvb, pinfo, parent_tree, is_request, itlq, itl, 0);
        dissect_usbms_bot_csw(csw_tvb, pinfo, parent_tree, usbms_bot_conv_info);
        return tvb_captured_length(tvb);
    }

    /* Create empty protocol tree so "usbms" filter displays this packet */
    create_usbms_bot_protocol_tree(tvb, parent_tree);
    dissect_scsi_payload(payload_tvb, pinfo, parent_tree, is_request, itlq, itl, 0);
    return tvb_captured_length(payload_tvb);
}

static bool
dissect_usbms_bot_bulk_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    static const unsigned char usbc[] = {0x55, 0x53, 0x42, 0x43};
    static const unsigned char usbs[] = {0x55, 0x53, 0x42, 0x53};
    if (tvb_reported_length(tvb) < 4)
        return false;

    if (tvb_memeql(tvb, 0, usbc, sizeof(usbc)) == 0 ||
        tvb_memeql(tvb, 0, usbs, sizeof(usbs)) == 0) {
        dissect_usbms_bot_bulk(tvb, pinfo, tree, data);
        return true;
    }

    return false;
}

void
proto_register_usbms_bot(void)
{
    static hf_register_info hf[] = {
        { &hf_usbms_bot_dCBWSignature,
        { "Signature", "usbms.dCBWSignature", FT_UINT32, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usbms_bot_dCBWTag,
        { "Tag", "usbms.dCBWTag", FT_UINT32, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usbms_bot_dCBWDataTransferLength,
        { "DataTransferLength", "usbms.dCBWDataTransferLength", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usbms_bot_dCBWFlags,
        { "Flags", "usbms.dCBWFlags", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usbms_bot_dCBWTarget,
        { "Target", "usbms.dCBWTarget", FT_UINT8, BASE_HEX_DEC,
          NULL, 0x70, "Target Number when enabling multi-target mode", HFILL }},

        { &hf_usbms_bot_dCBWLUN,
        { "LUN", "usbms.dCBWLUN", FT_UINT8, BASE_HEX,
          NULL, 0x0f, NULL, HFILL }},

        { &hf_usbms_bot_dCBWCBLength,
        { "CDB Length", "usbms.dCBWCBLength", FT_UINT8, BASE_HEX,
          NULL, 0x1f, NULL, HFILL }},

        { &hf_usbms_bot_dCSWSignature,
        { "Signature", "usbms.dCSWSignature", FT_UINT32, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usbms_bot_dCSWDataResidue,
        { "DataResidue", "usbms.dCSWDataResidue", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usbms_bot_dCSWStatus,
        { "Status", "usbms.dCSWStatus", FT_UINT8, BASE_HEX,
          VALS(status_vals), 0x0, NULL, HFILL }},

        { &hf_usbms_bot_request,
        { "bRequest", "usbms.setup.bRequest", FT_UINT8, BASE_HEX, VALS(setup_request_names_vals), 0x0,
                NULL, HFILL }},

        { &hf_usbms_bot_value,
        { "wValue", "usbms.setup.wValue", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_usbms_bot_index,
        { "wIndex", "usbms.setup.wIndex", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_usbms_bot_length,
        { "wLength", "usbms.setup.wLength", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_usbms_bot_maxlun,
        { "Max LUN", "usbms.setup.maxlun", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

    };

    static int *usbms_bot_subtrees[] = {
            &ett_usbms_bot,
    };


    proto_usbms_bot = proto_register_protocol("USB Mass Storage", "USBMS", "usbms");
    proto_register_field_array(proto_usbms_bot, hf, array_length(hf));
    proto_register_subtree_array(usbms_bot_subtrees, array_length(usbms_bot_subtrees));

    usbms_bot_bulk_handle = register_dissector("usbms", dissect_usbms_bot_bulk, proto_usbms_bot);
    usbms_bot_control_handle = register_dissector("usbms.control", dissect_usbms_bot_control, proto_usbms_bot);
}

void
proto_reg_handoff_usbms_bot(void)
{
    dissector_add_uint("usbms.bulk", IF_PROTOCOL_BULK_ONLY, usbms_bot_bulk_handle);
    dissector_add_uint("usbms.control", IF_PROTOCOL_BULK_ONLY, usbms_bot_control_handle);

    heur_dissector_add("usb.bulk", dissect_usbms_bot_bulk_heur,
                       "Mass Storage USB Bulk-Only Transport bulk endpoint",
                       "ms_usb_bulk", proto_usbms_bot, HEURISTIC_ENABLE);
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
