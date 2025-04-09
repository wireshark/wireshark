/* packet-usb-ptp.c
 *
 * USB Packet Dissector :
 *     - Picture Transfer Protocol (PTP)
 *     - Media   Transfer Protocol (MTP)
 *
 * (c)2013 Max Baker <max@warped.org>
 * (c)2022 Jake Merdich <jake@merdich.com>
 *
 * Much of this adapted from libgphoto2/libgphoto2/camlibs/ptp2/
 *
 * Copyright (C) 2001 Mariusz Woloszyn <emsi@ipartners.pl>
 * Copyright (C) 2003-2012 Marcus Meissner <marcus@jet.franken.de>
 * Copyright (C) 2006-2008 Linus Walleij <triad@df.lth.se>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * References:
 *
 * USB still image capture device definition 1.0
 * https://www.usb.org/document-library/still-image-capture-device-definition-10-and-errata-16-mar-2007
 *
 * Media Transfer Protocol v1.1 Spec
 * https://www.usb.org/document-library/media-transfer-protocol-v11-spec-and-mtp-v11-adopters-agreement
 *
 *
 * TODO:
 *      - Any and all further decode of returned objects.   Requires adding more sub-dissectors for MTP and PTP objects.
 *          Example : dissect_usb_ptp_get_device_info
 *        There is extensive support in libgphoto2 for these objects that can be ported over here if people want these.
 */

#include "config.h"

#include <glib.h>
#include <wsutil/wmem/wmem.h>
#include <wsutil/array.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include "packet-usb.h"
#include "packet-usb-ptp.h"

/* Handlers */
static int proto_usb_ptp;
static int ett_usb_ptp;
static int ett_usb_ptp_device_info;
static int ett_usb_ptp_object_array;
static int ett_usb_ptp_parameters;

/* Header Fields */
static int hf_container_length;
static int hf_container_type;
static int hf_operation_code;
static int hf_response_code;
static int hf_event_code;
static int hf_transaction_id;
static int hf_payload;
/* Device Info */
static int hf_devinfo_standardversion;
static int hf_devinfo_vendorextensionid;
static int hf_devinfo_vendorextensionversion;
static int hf_devinfo_vendorextensiondesc;
static int hf_devinfo_functionalmode;
static int hf_devinfo_operationsupported;
static int hf_devinfo_eventsupported;
static int hf_devinfo_devicepropertysupported;
static int hf_devinfo_captureformat;
static int hf_devinfo_imageformat;
static int hf_devinfo_manufacturer;
static int hf_devinfo_model;
static int hf_devinfo_deviceversion;
static int hf_devinfo_serialnumber;
static int hf_storageid;
/* Parameters */
static int hf_cmd_parameter;
static int hf_response_parameter;
static int hf_event_parameter;
/* Commands */
static int hf_cmd_devicepropvalue;
static int hf_cmd_devicepropdesc;
static int hf_cmd_objformatcode;
static int hf_cmd_objpropcode;
static int hf_objhandle;
/* Expert fields */
static expert_field ei_ptp_undecoded           = EI_INIT;

/* Determine which classes this device lives in */
static uint32_t
usb_ptp_flavor(packet_info *pinfo, void* data)
{
    (void)pinfo;
    uint32_t             flavor;
    usb_conv_info_t     *usb_conv_info = NULL;

    /* Put camera into different classes depending on vendor id, etc
     * Based on libgphoto/camlibs/ptp2/library.c:fixup_cached_deviceinfo()
     */
    flavor = USB_PTP_FLAVOR_ALL;
    usb_conv_info = (usb_conv_info_t *)data;

    /* The future may bring more complicated decode here, but for now we
     * just guess additional vendor exts based on VID.
     * Real implementations have to handle enough quirks that they maintain
     * whitelists of devices to communicate properly. This implementation
     * is much more basic.
     */

    if (!usb_conv_info)
        return flavor;

    switch (usb_conv_info->deviceVendor) {
        case USB_PTP_VENDOR_CANON:
            flavor |= USB_PTP_FLAVOR_CANON;
            break;
        case USB_PTP_VENDOR_NIKON:
            flavor |= USB_PTP_FLAVOR_NIKON;
            break;
        case USB_PTP_VENDOR_FUJI:
            flavor |= USB_PTP_FLAVOR_FUJI;
            break;
        case USB_PTP_VENDOR_KODAK:
            flavor |= USB_PTP_FLAVOR_KODAK;
            break;
        case USB_PTP_VENDOR_CASIO:
            flavor |= USB_PTP_FLAVOR_CASIO;
            break;
        case USB_PTP_VENDOR_OLYMPUS:
            flavor |= USB_PTP_FLAVOR_OLYMPUS;
            break;
        case USB_PTP_VENDOR_LEICA:
            flavor |= USB_PTP_FLAVOR_LEICA;
            break;
        case USB_PTP_VENDOR_PARROT:
            flavor |= USB_PTP_FLAVOR_PARROT;
            break;
        case USB_PTP_VENDOR_PANASONIC:
            flavor |= USB_PTP_FLAVOR_PANASONIC;
            break;
        case USB_PTP_VENDOR_SONY:
            flavor |= USB_PTP_FLAVOR_SONY;
            break;
        default:
            break;
    }

    /* TODO: ANDROID */

    return flavor;
}

static const usb_ptp_value_string_masked_t *
table_value_from_mask(uint32_t valmask, uint32_t val, const usb_ptp_value_string_masked_t *table)
{
    int i = 0;
    uint32_t mask;

    if (!table)
        return NULL;

    /* Two-pass approach here -- first we check w/out MTP mask bit set, then with
     * the idea being that vendor codes will take precedence over MTP codes in the case of a conflict
     * */

    mask = valmask & ~USB_PTP_FLAVOR_MTP;
    while (table[i].strptr)
    {
        /* Check that the value matches and the mask matches on any bit*/
        if ( (table[i].value == val) && (table[i].mask&mask) )
        {
            return &table[i];
        }
        i++;
    }

    /* 2nd Pass - try this w/ MTP if set */
    mask = valmask;
    if (mask & USB_PTP_FLAVOR_MTP)
    {
        i=0;
        while (table[i].strptr)
        {
            /* Check that the value matches and the mask matches on any bit*/
            if ( (table[i].value == val) && (table[i].mask&mask) )
            {
                return &table[i];
            }
            i++;
        }
    }

    /* No Match */
    return NULL;
}

/* Add a value from a 16-bit masked value table */
static void
proto_tree_add_item_mask(packet_info *pinfo,proto_tree *tree, usb_conv_info_t* usb_conv_info, int hf,
        tvbuff_t *tvb, const int length, const int offset, const int add_info, const usb_ptp_value_string_masked_t *vals)
{
    const usb_ptp_value_string_masked_t *vsm = NULL;
    usb_ptp_conv_info_t *usb_ptp_conv_info = NULL;
    uint16_t val;
    const char *desc;

    /* If we're parsing a command parameter the parameter field is 32-bits, but we're only using 16-bits for these tables.
     * MSBs are silently dropped  */
    val = tvb_get_letohs(tvb,offset);

    usb_ptp_conv_info = (usb_ptp_conv_info_t *) usb_conv_info->class_data;

    /* May not have the packet annotated, and may not have any value table for this header field */
    if (vals && usb_ptp_conv_info)
        vsm = table_value_from_mask(usb_ptp_conv_info->flavor,val,vals);

    /* Add this string onto the info column value if wanted */
    if (add_info && vsm)
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s",vsm->strptr);
    }

    desc = vsm ? vsm->strptr : "Unknown";
    proto_tree_add_uint_format_value(tree, hf,tvb,offset,length,val,"%s (0x%04x)",desc,val);
}

/* Add a PTP-style unicode string*/
static int
usb_ptp_add_uint_string(proto_tree *tree, int hf, tvbuff_t *tvb, int offset, char* save_to _U_)
{
    uint8_t length;
    char    *str;

    /* First byte is the number of characters in UCS-2, including the terminating NULL */
    length = tvb_get_uint8(tvb, offset) * 2;
    offset += 1;
    str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_LITTLE_ENDIAN | ENC_UCS_2);
    proto_tree_add_string(tree, hf, tvb, offset, length, str);
    offset += length;

    /* Save to data structure (optional) */
    save_to = g_strdup(str);

    return offset;
}

/* Add Indexed array of 32-bit objects (not masked) */
static int
usb_ptp_add_array_il(packet_info *pinfo _U_,proto_tree *parent_tree, int hf,  tvbuff_t *tvb, int offset, const char *str)
{
    uint32_t                     length;
    uint32_t                     i;
    proto_tree                  *tree              = NULL;

    /* First 32-bits is the count of 16-bit objects in array */
    length = tvb_get_letohl(tvb, offset);

    /* Create Device Info Tree */
    if (parent_tree)
    {
        tree = proto_tree_add_subtree_format(parent_tree, tvb, offset, ((4*length)+4), ett_usb_ptp_object_array, NULL,
                                             "%s (%d)", str, length);
    }
    offset += 4;

    if (!length)
        return offset;

    for (i=0; i<length; i++)
    {
        proto_tree_add_item(tree,hf,tvb,offset,4,ENC_LITTLE_ENDIAN);
        offset+=4;
    }

    return offset;
}

/* Add Indexed array of 16-bit objects (masked)*/
static int
usb_ptp_add_array_is(packet_info *pinfo,proto_tree *parent_tree, usb_conv_info_t* conv_info, int hf,  tvbuff_t *tvb, int offset, const char *str, const usb_ptp_value_string_masked_t *vals)
{
    uint32_t                     length;
    uint32_t                     i;
    proto_tree                  *tree              = NULL;

    /* First 32-bits is the count of 16-bit objects in array */
    length = tvb_get_letohl(tvb, offset);

    /* Create Device Info Tree */
    if (parent_tree)
    {
        tree = proto_tree_add_subtree_format(parent_tree, tvb, offset, ((2*length)+4), ett_usb_ptp_object_array, NULL,
                                             "%s (%d)", str, length);
    }

    offset += 4;

    if (!length)
        return offset;

    for (i=0; i<length; i++)
    {
        proto_tree_add_item_mask(pinfo,tree,conv_info,hf,tvb,2,offset,0,vals);
        offset+=2;
    }

    return offset;
}

static void
dissect_usb_ptp_get_device_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, usb_conv_info_t *conv_info, int offset)
{
    proto_tree *tree = NULL;
    usb_ptp_conv_info_t   *usb_ptp_conv_info;
    usb_ptp_device_info_t *usb_ptp_device_info;
    uint16_t vendor_extension_id;

    /* Create device info struct if not there already and attach it */
    usb_ptp_conv_info   = (usb_ptp_conv_info_t *) conv_info->class_data;
    usb_ptp_device_info = usb_ptp_conv_info->device_info;
    if (!usb_ptp_device_info)
    {
        usb_ptp_device_info = wmem_new0(pinfo->pool, usb_ptp_device_info_t);
    }

    /* Create Device Info Tree */
    if (parent_tree)
    {
        tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_usb_ptp_device_info, NULL, "DEVICE INFORMATION");
    }

    /* Add Elements to struct and gui */
    usb_ptp_device_info->StandardVersion = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree,hf_devinfo_standardversion              ,tvb,offset,2,  ENC_LITTLE_ENDIAN);
    offset+=2;
    usb_ptp_device_info->VendorExtensionID = tvb_get_letohl(tvb, offset);
    vendor_extension_id = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree,hf_devinfo_vendorextensionid            ,tvb,offset,4,  ENC_LITTLE_ENDIAN);
    offset+=4;
    usb_ptp_device_info->VendorExtensionVersion = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree,hf_devinfo_vendorextensionversion       ,tvb,offset,2,  ENC_LITTLE_ENDIAN);
    offset+=2;
    offset = usb_ptp_add_uint_string(tree, hf_devinfo_vendorextensiondesc,tvb,offset,usb_ptp_device_info->VendorExtensionDesc);
    proto_tree_add_item(tree,hf_devinfo_functionalmode               ,tvb,offset,2,  ENC_LITTLE_ENDIAN);
    offset+=2;
    /* TODO: Store array values in dev_info struct */
    offset = usb_ptp_add_array_is(pinfo,tree,conv_info,hf_devinfo_operationsupported     ,tvb,offset,"OPERATIONS SUPPORTED",usb_ptp_oc_mvals);
    offset = usb_ptp_add_array_is(pinfo,tree,conv_info,hf_devinfo_eventsupported         ,tvb,offset,"EVENTS SUPPORTED",usb_ptp_ec_mvals);
    offset = usb_ptp_add_array_is(pinfo,tree,conv_info,hf_devinfo_devicepropertysupported,tvb,offset,"DEVICE PROPERTIES SUPPORTED",usb_ptp_dpc_mvals);
    offset = usb_ptp_add_array_is(pinfo,tree,conv_info,hf_devinfo_captureformat          ,tvb,offset,"CAPTURE FORMATS SUPPORTED",usb_ptp_ofc_mvals);
    offset = usb_ptp_add_array_is(pinfo,tree,conv_info,hf_devinfo_imageformat            ,tvb,offset,"IMAGE FORMATS SUPPORTED",usb_ptp_ofc_mvals);
    offset = usb_ptp_add_uint_string(tree,hf_devinfo_manufacturer      ,tvb,offset,usb_ptp_device_info->Manufacturer);
    offset = usb_ptp_add_uint_string(tree,hf_devinfo_model             ,tvb,offset,usb_ptp_device_info->Model);
    offset = usb_ptp_add_uint_string(tree,hf_devinfo_deviceversion     ,tvb,offset,usb_ptp_device_info->DeviceVersion);
    /*offset = */usb_ptp_add_uint_string(tree,hf_devinfo_serialnumber      ,tvb,offset,usb_ptp_device_info->SerialNumber);

    /* Post Proc of this table */

    /* Enable/Disable MTP Extensions */
    if (vendor_extension_id == USB_PTP_VENDOR_EXT_MTP)
    {
        usb_ptp_conv_info->flavor |= USB_PTP_FLAVOR_MTP;
    } else
    {
        usb_ptp_conv_info->flavor = usb_ptp_conv_info->flavor & ~USB_PTP_FLAVOR_MTP;
    }
}

static void
dissect_usb_ptp_params(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset,int hf)
{
    unsigned length_tvb;
    uint32_t remaining;
    proto_tree *tree = NULL;

    length_tvb = tvb_captured_length(tvb);
    remaining = length_tvb-offset;

    if (!remaining)
        return;

    if (parent_tree)
    {
        tree = proto_tree_add_subtree(parent_tree, tvb, offset, remaining, ett_usb_ptp_parameters, NULL, "PARAMETERS");
    }

    while (remaining >= 4)
    {
        proto_tree_add_item(tree,hf,tvb,offset,4,ENC_LITTLE_ENDIAN);
        offset+=4;
        remaining-=4;
    }
}

static void
dissect_usb_ptp_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, urb_info_t *urb, uint16_t ptp_type,
        uint16_t ptp_code, const usb_ptp_value_string_masked_t *vsm _U_, int offset)
{
    unsigned length_payload;
    usb_conv_info_t *usb_conv_info = urb->conv;

    switch(ptp_type)
    {
        case USB_PTP_TYPE_DATA:
            switch (ptp_code)
            {
                case USB_PTP_OC_GETDEVICEINFO:
                    dissect_usb_ptp_get_device_info(tvb,pinfo,tree,usb_conv_info,offset);
                    return;
                case USB_PTP_OC_GETSTORAGEIDS:
                    offset = usb_ptp_add_array_il(pinfo,tree,hf_storageid,tvb,offset,"STORAGE IDS");
                    break;
                case USB_PTP_OC_GETOBJECTHANDLES:
                    offset = usb_ptp_add_array_il(pinfo,tree,hf_objhandle,tvb,offset,"OBJECT HANDLES");
                    break;
                /*case USB_PTP_OC_SETDEVICEPROPVALUE: TODO
                 *    return dissect_usb_ptp_set_device_prop_value(tvb,pinfo,tree,offset); */
                case USB_PTP_OC_GETOBJECTPROPSSUPPORTED:
                    /*offset = */usb_ptp_add_array_is(pinfo,tree,usb_conv_info,hf_cmd_objpropcode,tvb,offset,"OBJECT PROPERTY CODES",usb_ptp_opc_mvals);
                    return;
                default:
                    break;
            }
            break;
        case USB_PTP_TYPE_CMD:
            switch (ptp_code)
            {
                case USB_PTP_OC_SETDEVICEPROPVALUE:
                    proto_tree_add_item_mask(pinfo,tree,usb_conv_info,hf_cmd_devicepropvalue,tvb,4,offset,1,usb_ptp_dpc_mvals);
                    offset+=4;
                    break;
                case USB_PTP_OC_GETDEVICEPROPDESC:
                    proto_tree_add_item_mask(pinfo,tree,usb_conv_info,hf_cmd_devicepropdesc,tvb,4,offset,1,usb_ptp_dpc_mvals);
                    offset+=4;
                    break;
                case USB_PTP_OC_GETOBJECTPROPSSUPPORTED:
                    proto_tree_add_item_mask(pinfo,tree,usb_conv_info,hf_cmd_objformatcode,tvb,4,offset,1,usb_ptp_ofc_mvals);
                    offset+=4;
                    break;
                case USB_PTP_OC_GETOBJECTPROPDESC:
                    proto_tree_add_item_mask(pinfo,tree,usb_conv_info,hf_cmd_objpropcode  ,tvb,4,offset,1,usb_ptp_opc_mvals);
                    offset+=4;
                    proto_tree_add_item_mask(pinfo,tree,usb_conv_info,hf_cmd_objformatcode,tvb,4,offset,1,usb_ptp_ofc_mvals);
                    offset+=4;
                    break;
                default:
                    dissect_usb_ptp_params(tvb,pinfo,tree,offset,hf_cmd_parameter);
                    return;
                    break;
            }
            break;
        case USB_PTP_TYPE_RESPONSE:
            dissect_usb_ptp_params(tvb,pinfo,tree,offset,hf_response_parameter);
            return;
        case USB_PTP_TYPE_EVENT:
            dissect_usb_ptp_params(tvb,pinfo,tree,offset,hf_event_parameter);
            return;
        default:
            break;
    }
    /* Default is to just label generic bytes */
    length_payload = tvb_captured_length(tvb) - offset;
    if ( !length_payload )
        return;

    /* TODO: Auto-detect strings -- look for string length + null char match */

    proto_tree_add_item(tree, hf_payload,tvb, offset, length_payload, ENC_NA );
}

static int
dissect_usb_ptp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
    urb_info_t *urb = (urb_info_t *) data;
    proto_tree *tree = NULL;
    unsigned length_tvb;
    uint16_t ptp_type;
    uint16_t ptp_code;
    uint32_t ptp_tid;
    /*uint32_t ptp_length _U_;*/
    int offset = 0;
    const char *ptp_code_desc = "";
    const char *col_class = "?";
    usb_ptp_conv_info_t *usb_ptp_conv_info;
    const usb_ptp_value_string_masked_t *vsm = NULL;

    if(!urb)
        return 0;

    length_tvb = tvb_captured_length(tvb);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USB-PTP");

    /* Add our own class information to usb_conv_info */
    usb_ptp_conv_info = (usb_ptp_conv_info_t *) urb->conv->class_data;
    if(!usb_ptp_conv_info)
    {
        usb_ptp_conv_info = wmem_new0(wmem_file_scope(), usb_ptp_conv_info_t);
        urb->conv->class_data = usb_ptp_conv_info;
        usb_ptp_conv_info->flavor = usb_ptp_flavor(pinfo, urb->conv);
    }

    if (parent_tree)
    {
        proto_item *ti = NULL;
        ti = proto_tree_add_protocol_format(parent_tree, proto_usb_ptp, tvb, 0, -1, "USB-PTP");
        tree = proto_item_add_subtree(ti, ett_usb_ptp);
    }

    /* PTP Is defined as Class=6, SubClass=1, Protocol=1 */
    if (!(   (urb->conv->interfaceSubclass == IF_CLASS_IMAGE_SUBCLASS_PTP)
          && (urb->conv->interfaceProtocol == IF_CLASS_IMAGE_PROTOCOL_PTP) ))
    {
        proto_tree_add_expert(tree, pinfo, &ei_ptp_undecoded, tvb, 0, length_tvb);
        return 0;
    }

    proto_tree_add_item(tree, hf_container_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    /*ptp_length = tvb_get_letohl(tvb,offset);*/
    offset+=4;
    proto_tree_add_item(tree, hf_container_type,   tvb, offset, 2, ENC_LITTLE_ENDIAN);
    ptp_type = tvb_get_letohs(tvb,offset);
    offset+=2;
    ptp_code = tvb_get_letohs(tvb,offset);

    switch(ptp_type)
    {
        case USB_PTP_TYPE_DATA:
            col_class = "DAT";
            /* "The Data Block will use the OperationCode from the Command Block" [1] 7.1.1 */
            vsm = table_value_from_mask(usb_ptp_conv_info->flavor,ptp_code,usb_ptp_oc_mvals);
            ptp_code_desc = vsm ? vsm->strptr : "UNKNOWN";
            proto_tree_add_uint_format_value(tree, hf_operation_code,tvb, offset, 2, ptp_code,
                    "%s (0x%04x)",ptp_code_desc,ptp_code);
            break;
        case USB_PTP_TYPE_CMD:
            col_class = "CMD";
            vsm = table_value_from_mask(usb_ptp_conv_info->flavor,ptp_code,usb_ptp_oc_mvals);
            ptp_code_desc = vsm ? vsm->strptr : "UNKNOWN";
            proto_tree_add_uint_format_value(tree, hf_operation_code,tvb, offset, 2, ptp_code,
                    "%s (0x%04x)",ptp_code_desc,ptp_code);
            break;
        case USB_PTP_TYPE_RESPONSE:
            col_class ="RSP";
            vsm = table_value_from_mask(usb_ptp_conv_info->flavor,ptp_code,usb_ptp_rc_mvals);
            ptp_code_desc = vsm ? vsm->strptr : "UNKNOWN";
            proto_tree_add_uint_format_value(tree, hf_response_code,tvb, offset, 2, ptp_code,
                    "%s (0x%04x)",ptp_code_desc,ptp_code);
            break;
        case USB_PTP_TYPE_EVENT:
            col_class = "EVT";
            vsm = table_value_from_mask(usb_ptp_conv_info->flavor,ptp_code,usb_ptp_ec_mvals);
            ptp_code_desc = vsm ? vsm->strptr : "UNKNOWN";
            proto_tree_add_uint_format_value(tree, hf_event_code,tvb, offset, 2, ptp_code,
                    "%s (0x%04x)",ptp_code_desc,ptp_code);
            break;
        default:
            proto_tree_add_expert(tree, pinfo, &ei_ptp_undecoded, tvb, offset, 2);
            break;
    }
    offset +=2;

    proto_tree_add_item(tree, hf_transaction_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    ptp_tid = tvb_get_letohl(tvb,offset);
    offset+=4;

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %08x (%04x) %s",
            col_class, ptp_tid, ptp_code, ptp_code_desc );

    /* Pass along if we have a payload */
    if ( (length_tvb-offset) > 0 )
    {
        dissect_usb_ptp_payload(tvb,pinfo,tree, urb, ptp_type,ptp_code,vsm,offset);
    }

    return offset;
}

void
proto_register_usb_ptp(void)
{
    /* header field array
    * struct header_field_info {
    *     const char      *name;
    *     const char      *abbrev;
    *     enum ftenum     type;
    *     int             display;
    *     const void      *strings;
    *     uint32_t        bitmask;
    *     const char      *blurb;
    *     .....
    * };
    */

    static hf_register_info hf[] = {
        { &hf_container_length                        ,
        { "Container Length"                          , "usb-ptp.container.length"              , FT_UINT32 , BASE_DEC  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_container_type                          ,
        { "Container Type"                            , "usb-ptp.container.type"                , FT_UINT16 , BASE_HEX  ,
        &usb_ptp_container_type_vals                  , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_operation_code                          ,
        { "Operation Code"                            , "usb-ptp.operation.code"                , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_event_code                              ,
        { "Event Code"                                , "usb-ptp.event.code"                    , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_transaction_id                          ,
        { "Transaction ID"                            , "usb-ptp.transaction.id"                , FT_UINT32 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_payload                                 ,
        { "Payload"                                   , "usb-ptp.payload"                       , FT_BYTES  , BASE_NONE ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_cmd_parameter                           ,
        { "Parameter"                                 , "usb-ptp.command.parameter"             , FT_UINT32 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_response_code                           ,
        { "Response Code"                             , "usb-ptp.response.code"                 , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_response_parameter                      ,
        { "Parameter"                                 , "usb-ptp.response.parameter"            , FT_UINT32 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_event_parameter                         ,
        { "Parameter"                                 , "usb-ptp.event.parameter"               , FT_UINT32 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_devinfo_standardversion                 ,
        { "Standard Version"                          , "usb-ptp.device.standardversion"        , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_devinfo_vendorextensionid               ,
        { "Vendor Extension ID"                       , "usb-ptp.device.vendorextensionid"      , FT_UINT32 , BASE_HEX  ,
        VALS(usb_ptp_vendor_vals)                     , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_devinfo_vendorextensionversion          ,
        { "Vendor Extension Version"                  , "usb-ptp.device.vendorextensionversion" , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_devinfo_vendorextensiondesc             ,
        { "Vendor Extension Description"              , "usb-ptp.device.vendorextensiondesc"    , FT_STRING , BASE_NONE ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_devinfo_functionalmode                  ,
        { "Functional Mode"                           , "usb-ptp.device.functionalmode"         , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_devinfo_operationsupported              ,
        { "Operation Supported"                       , "usb-ptp.device.operationssupported"    , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_devinfo_eventsupported                  ,
        { "Event Supported"                           , "usb-ptp.device.eventsupported"         , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_devinfo_devicepropertysupported         ,
        { "Device Property"                           , "usb-ptp.device.propertysupported"      , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_devinfo_captureformat                   ,
        { "Capture Format"                            , "usb-ptp.device.captureformat"          , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_devinfo_imageformat                     ,
        { "Image Format"                              , "usb-ptp.device.imageformat"            , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_devinfo_manufacturer                    ,
        { "Manufacturer"                              , "usb-ptp.device.manufacturer"           , FT_STRING , BASE_NONE ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_devinfo_model                           ,
        { "Model"                                     , "usb-ptp.device.model"                  , FT_STRING , BASE_NONE ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_devinfo_deviceversion                   ,
        { "Device Version"                            , "usb-ptp.device.deviceversion"          , FT_STRING , BASE_NONE ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_devinfo_serialnumber                    ,
        { "Serial Number"                             , "usb-ptp.device.serialnumber"           , FT_STRING , BASE_NONE ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_cmd_devicepropvalue                     ,
        { "Device Property"                           , "usb-ptp.device.property"               , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_cmd_devicepropdesc                      ,
        { "Device Property"                           , "usb-ptp.device.propertydesc"           , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_storageid                               ,
        { "Storage ID"                                , "usb-ptp.device.storageid"              , FT_UINT32 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_cmd_objformatcode                       ,
        { "Object Format Code"                        , "usb-ptp.object.format"                 , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_cmd_objpropcode                         ,
        { "Object Prop Code"                          , "usb-ptp.object.code"                   , FT_UINT16 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}   ,
        { &hf_objhandle                               ,
        { "Object Handle"                             , "usb-ptp.object.handle"                 , FT_UINT32 , BASE_HEX  ,
        NULL                                          , 0x0                                     , NULL      , HFILL}}
        };

    static int *usb_ptp_ett[] = {
        &ett_usb_ptp,
        &ett_usb_ptp_device_info,
        &ett_usb_ptp_object_array,
        &ett_usb_ptp_parameters
    };

    static ei_register_info ei[] = {
        { &ei_ptp_undecoded, { "usb-ptp.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
    };

    expert_module_t* expert_usb_ptp;


    proto_usb_ptp = proto_register_protocol("USB Picture Transfer Protocol", "USB-PTP", "usb-ptp");
    proto_register_field_array(proto_usb_ptp, hf, array_length(hf));
    proto_register_subtree_array(usb_ptp_ett, array_length(usb_ptp_ett));
    expert_usb_ptp = expert_register_protocol(proto_usb_ptp);
    expert_register_field_array(expert_usb_ptp, ei, array_length(ei));

    register_dissector("usb-ptp", dissect_usb_ptp, proto_usb_ptp);
}

void
proto_reg_handoff_usb_ptp(void)
{
    dissector_handle_t usb_ptp_dissector_handle;
    usb_ptp_dissector_handle = find_dissector("usb-ptp");
    dissector_add_uint("usb.bulk", IF_CLASS_IMAGE, usb_ptp_dissector_handle);
}
