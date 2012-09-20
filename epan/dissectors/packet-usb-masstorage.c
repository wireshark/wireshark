/* packet-usb-masstorage.c
 *
 * $Id$
 *
 * usb mass storage dissector
 * Ronnie Sahlberg 2006
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


#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include "packet-usb.h"
#include "packet-scsi.h"

/* protocols and header fields */
static int proto_usb_ms = -1;
static int hf_usb_ms_dCBWSignature = -1;
static int hf_usb_ms_dCBWTag = -1;
static int hf_usb_ms_dCBWDataTransferLength = -1;
static int hf_usb_ms_dCBWFlags = -1;
static int hf_usb_ms_dCBWLUN = -1;
static int hf_usb_ms_dCBWCBLength = -1;
static int hf_usb_ms_dCSWSignature = -1;
static int hf_usb_ms_dCSWDataResidue = -1;
static int hf_usb_ms_dCSWStatus = -1;
static int hf_usb_ms_request = -1;
static int hf_usb_ms_value = -1;
static int hf_usb_ms_index = -1;
static int hf_usb_ms_length = -1;
static int hf_usb_ms_maxlun = -1;

static gint ett_usb_ms = -1;


/* there is one such structure for each masstorage conversation */
typedef struct _usb_ms_conv_info_t {
    emem_tree_t *itl;		/* indexed by LUN */
    emem_tree_t *itlq;		/* pinfo->fd->num */
} usb_ms_conv_info_t;


static const value_string status_vals[] = {
    {0x00,	"Command Passed"},
    {0x01,	"Command Failed"},
    {0x02,	"Phase Error"},
    {0, NULL}
};




static void
dissect_usb_ms_reset(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, gboolean is_request, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    if(is_request){
        proto_tree_add_item(tree, hf_usb_ms_value, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_usb_ms_index, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_usb_ms_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        /*offset += 2;*/
    } else {
        /* no data in reset response */
    }
}

static void
dissect_usb_ms_get_max_lun(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, gboolean is_request, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    if(is_request){
        proto_tree_add_item(tree, hf_usb_ms_value, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_usb_ms_index, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_usb_ms_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        /*offset += 2;*/
    } else {
        proto_tree_add_item(tree, hf_usb_ms_maxlun, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }
}


typedef void (*usb_setup_dissector)(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gboolean is_request, usb_trans_info_t *usb_trans_info, usb_conv_info_t *usb_conv_info);

typedef struct _usb_setup_dissector_table_t {
    guint8 request;
    usb_setup_dissector dissector;
} usb_setup_dissector_table_t;
#define USB_SETUP_RESET               0xff
#define USB_SETUP_GET_MAX_LUN         0xfe
static const usb_setup_dissector_table_t setup_dissectors[] = {
    {USB_SETUP_RESET,          dissect_usb_ms_reset},
    {USB_SETUP_GET_MAX_LUN,    dissect_usb_ms_get_max_lun},
    {0, NULL}
};
static const value_string setup_request_names_vals[] = {
    {USB_SETUP_RESET,          "RESET"},
    {USB_SETUP_GET_MAX_LUN,    "GET MAX LUN"},
    {0, NULL}
};

/* Dissector for mass storage control .
 * Returns TRUE if a class specific dissector was found
 * and FALSE othervise.
 */
static gint
dissect_usb_ms_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gboolean is_request;
    usb_conv_info_t *usb_conv_info;
    usb_trans_info_t *usb_trans_info;
    int offset=0;
    usb_setup_dissector dissector;
    const usb_setup_dissector_table_t *tmp;


    is_request=(pinfo->srcport==NO_ENDPOINT);

    usb_conv_info=pinfo->usb_conv_info;
    usb_trans_info=usb_conv_info->usb_trans_info;


    /* See if we can find a class specific dissector for this request */
    dissector=NULL;
    for(tmp=setup_dissectors;tmp->dissector;tmp++){
        if (tmp->request == usb_trans_info->setup.request){
            dissector=tmp->dissector;
            break;
        }
    }
    /* No we could not find any class specific dissector for this request
     * return FALSE and let USB try any of the standard requests.
     */
    if(!dissector){
        return FALSE;
    }


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBMS");

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
            val_to_str(usb_trans_info->setup.request, setup_request_names_vals, "Unknown type %x"),
            is_request?"Request":"Response");
    }

    if(is_request){
        proto_tree_add_item(tree, hf_usb_ms_request, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }

    dissector(pinfo, tree, tvb, offset, is_request, usb_trans_info, usb_conv_info);
    return TRUE;
}


/* dissector for mass storage bulk data */
static void
dissect_usb_ms_bulk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
    usb_conv_info_t *usb_conv_info;
    usb_ms_conv_info_t *usb_ms_conv_info;
    proto_tree *tree=NULL;
    guint32 signature=0;
    int offset=0;
    gboolean is_request;
    itl_nexus_t *itl;
    itlq_nexus_t *itlq;

    usb_conv_info=pinfo->usb_conv_info;
    /* verify that we do have a usb_ms_conv_info */
    usb_ms_conv_info=usb_conv_info->class_data;
    if(!usb_ms_conv_info){
        usb_ms_conv_info=se_alloc(sizeof(usb_ms_conv_info_t));
        usb_ms_conv_info->itl=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "USB ITL");
        usb_ms_conv_info->itlq=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "USB ITLQ");
        usb_conv_info->class_data=usb_ms_conv_info;
    }


    is_request=(pinfo->srcport==NO_ENDPOINT);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBMS");

    col_clear(pinfo->cinfo, COL_INFO);


    if(parent_tree){
        proto_item *ti = NULL;
        ti = proto_tree_add_protocol_format(parent_tree, proto_usb_ms, tvb, 0, -1, "USB Mass Storage");

        tree = proto_item_add_subtree(ti, ett_usb_ms);
    }

    signature=tvb_get_letohl(tvb, offset);


    /*
     * SCSI CDB inside CBW
     */
    if(is_request&&(signature==0x43425355)&&(tvb_length(tvb)==31)){
        tvbuff_t *cdb_tvb;
        int cdbrlen, cdblen;
        guint8 lun, flags;
        guint32 datalen;

        /* dCBWSignature */
        proto_tree_add_item(tree, hf_usb_ms_dCBWSignature, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;

        /* dCBWTag */
        proto_tree_add_item(tree, hf_usb_ms_dCBWTag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;

        /* dCBWDataTransferLength */
        proto_tree_add_item(tree, hf_usb_ms_dCBWDataTransferLength, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        datalen=tvb_get_letohl(tvb, offset);
        offset+=4;

        /* dCBWFlags */
        proto_tree_add_item(tree, hf_usb_ms_dCBWFlags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        flags=tvb_get_guint8(tvb, offset);
        offset+=1;

        /* dCBWLUN */
        proto_tree_add_item(tree, hf_usb_ms_dCBWLUN, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        lun=tvb_get_guint8(tvb, offset)&0x0f;
        offset+=1;

        /* make sure we have a ITL structure for this LUN */
        itl=(itl_nexus_t *)se_tree_lookup32(usb_ms_conv_info->itl, lun);
        if(!itl){
            itl=se_alloc(sizeof(itl_nexus_t));
            itl->cmdset=0xff;
            itl->conversation=NULL;
            se_tree_insert32(usb_ms_conv_info->itl, lun, itl);
        }

        /* make sure we have an ITLQ structure for this LUN/transaction */
        itlq=(itlq_nexus_t *)se_tree_lookup32(usb_ms_conv_info->itlq, pinfo->fd->num);
        if(!itlq){
            itlq=se_alloc(sizeof(itlq_nexus_t));
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
            itlq->fc_time=pinfo->fd->abs_ts;
            itlq->first_exchange_frame=pinfo->fd->num;
            itlq->last_exchange_frame=0;
            itlq->flags=0;
            itlq->alloc_len=0;
            itlq->extra_data=NULL;
            se_tree_insert32(usb_ms_conv_info->itlq, pinfo->fd->num, itlq);
        }

        /* dCBWCBLength */
        proto_tree_add_item(tree, hf_usb_ms_dCBWCBLength, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        cdbrlen=tvb_get_guint8(tvb, offset)&0x1f;
        offset+=1;

        cdblen=cdbrlen;
        if(cdblen>tvb_length_remaining(tvb, offset)){
            cdblen=tvb_length_remaining(tvb, offset);
        }
        if(cdblen){
            cdb_tvb=tvb_new_subset(tvb, offset, cdblen, cdbrlen);
            dissect_scsi_cdb(cdb_tvb, pinfo, parent_tree, SCSI_DEV_UNKNOWN, itlq, itl);
        }
        return;
    }


    /*
     * SCSI RESPONSE inside CSW
     */
    if((!is_request)&&(signature==0x53425355)&&(tvb_length(tvb)==13)){
        guint8 status;

        /* dCSWSignature */
        proto_tree_add_item(tree, hf_usb_ms_dCSWSignature, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;

        /* dCSWTag */
        proto_tree_add_item(tree, hf_usb_ms_dCBWTag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;

        /* dCSWDataResidue */
        proto_tree_add_item(tree, hf_usb_ms_dCSWDataResidue, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;

        /* dCSWStatus */
        proto_tree_add_item(tree, hf_usb_ms_dCSWStatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        status=tvb_get_guint8(tvb, offset);
        /*offset+=1;*/

        itlq=(itlq_nexus_t *)se_tree_lookup32_le(usb_ms_conv_info->itlq, pinfo->fd->num);
        if(!itlq){
            return;
        }
        itlq->last_exchange_frame=pinfo->fd->num;

        itl=(itl_nexus_t *)se_tree_lookup32(usb_ms_conv_info->itl, itlq->lun);
        if(!itl){
            return;
        }

        if(!status){
            dissect_scsi_rsp(tvb, pinfo, parent_tree, itlq, itl, 0);
        } else {
            /* just send "check condition" */
            dissect_scsi_rsp(tvb, pinfo, parent_tree, itlq, itl, 0x02);
        }
        return;
    }

    /*
     * Ok it was neither CDB not STATUS so just assume it is either data in/out
     */
    itlq=(itlq_nexus_t *)se_tree_lookup32_le(usb_ms_conv_info->itlq, pinfo->fd->num);
    if(!itlq){
        return;
    }

    itl=(itl_nexus_t *)se_tree_lookup32(usb_ms_conv_info->itl, itlq->lun);
    if(!itl){
        return;
    }

    dissect_scsi_payload(tvb, pinfo, parent_tree, is_request, itlq, itl, 0);

}

void
proto_register_usb_ms(void)
{
    static hf_register_info hf[] = {
        { &hf_usb_ms_dCBWSignature,
        { "Signature", "usbms.dCBWSignature", FT_UINT32, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_ms_dCBWTag,
        { "Tag", "usbms.dCBWTag", FT_UINT32, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_ms_dCBWDataTransferLength,
        { "DataTransferLength", "usbms.dCBWDataTransferLength", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_ms_dCBWFlags,
        { "Flags", "usbms.dCBWFlags", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_ms_dCBWLUN,
        { "LUN", "usbms.dCBWLUN", FT_UINT8, BASE_HEX,
          NULL, 0x0f, NULL, HFILL }},

        { &hf_usb_ms_dCBWCBLength,
        { "CDB Length", "usbms.dCBWCBLength", FT_UINT8, BASE_HEX,
          NULL, 0x1f, NULL, HFILL }},

        { &hf_usb_ms_dCSWSignature,
        { "Signature", "usbms.dCSWSignature", FT_UINT32, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_ms_dCSWDataResidue,
        { "DataResidue", "usbms.dCSWDataResidue", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_ms_dCSWStatus,
        { "Status", "usbms.dCSWStatus", FT_UINT8, BASE_HEX,
          VALS(status_vals), 0x0, NULL, HFILL }},

        { &hf_usb_ms_request,
        { "bRequest", "usbms.setup.bRequest", FT_UINT8, BASE_HEX, VALS(setup_request_names_vals), 0x0,
                NULL, HFILL }},

        { &hf_usb_ms_value,
        { "wValue", "usbms.setup.wValue", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_usb_ms_index,
        { "wIndex", "usbms.setup.wIndex", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_usb_ms_length,
        { "wLength", "usbms.setup.wLength", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_usb_ms_maxlun,
        { "Max LUN", "usbms.setup.maxlun", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

    };

    static gint *usb_ms_subtrees[] = {
            &ett_usb_ms,
    };


    proto_usb_ms = proto_register_protocol("USB Mass Storage", "USBMS", "usbms");
    proto_register_field_array(proto_usb_ms, hf, array_length(hf));
    proto_register_subtree_array(usb_ms_subtrees, array_length(usb_ms_subtrees));

    register_dissector("usbms", dissect_usb_ms_bulk, proto_usb_ms);
}

void
proto_reg_handoff_usb_ms(void)
{
    dissector_handle_t usb_ms_bulk_handle;
    dissector_handle_t usb_ms_control_handle;

    usb_ms_bulk_handle = find_dissector("usbms");
    dissector_add_uint("usb.bulk", IF_CLASS_MASSTORAGE, usb_ms_bulk_handle);

    usb_ms_control_handle = new_create_dissector_handle(dissect_usb_ms_control, proto_usb_ms);
    dissector_add_uint("usb.control", IF_CLASS_MASSTORAGE, usb_ms_control_handle);
}
