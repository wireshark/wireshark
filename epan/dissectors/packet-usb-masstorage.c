/* packet-usb-masstorage.c
 * USB Mass Storage class stub dissector
 * Copyright 2021, Aidan MacDonald <amachronic@protonmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-usb.h"

static int proto_usb_ms;

static dissector_handle_t usb_ms_bulk_handle;
static dissector_handle_t usb_ms_control_handle;
static dissector_handle_t usb_ms_interrupt_handle;
static dissector_handle_t usb_ms_descriptor_handle;

static dissector_table_t usb_ms_bulk_dissector_table;
static dissector_table_t usb_ms_control_dissector_table;
static dissector_table_t usb_ms_interrupt_dissector_table;
static dissector_table_t usb_ms_descriptor_dissector_table;

void proto_register_usb_ms(void);
void proto_reg_handoff_usb_ms(void);

#define MSC_SUBCLASS_SCSI_COMMAND_SET_NOT_REPORTED 0x00
#define MSC_SUBCLASS_RBC                           0x01
#define MSC_SUBCLASS_MMC_5_ATAPI                   0x02
#define MSC_SUBCLASS_OBSOLETE_QIC_157              0x03
#define MSC_SUBCLASS_UFI                           0x04
#define MSC_SUBCLASS_OBSOLETE_SFF_8070I            0x05
#define MSC_SUBCLASS_SCSI_TRANSPARENT_COMMAND_SET  0x06
#define MSC_SUBCLASS_LSD_FS                        0x07
#define MSC_SUBCLASS_IEEE_1667                     0x08
#define MSC_SUBCLASS_VENDOR                        0xFF

static const value_string usb_massstorage_subclass_vals[] = {
    {MSC_SUBCLASS_SCSI_COMMAND_SET_NOT_REPORTED, "SCSI command set not reported"},
    {MSC_SUBCLASS_RBC,                           "RBC"},
    {MSC_SUBCLASS_MMC_5_ATAPI,                   "MMC-5 (ATAPI)"},
    {MSC_SUBCLASS_OBSOLETE_QIC_157,              "Obsolete (was QIC-157)"},
    {MSC_SUBCLASS_UFI,                           "UFI"},
    {MSC_SUBCLASS_OBSOLETE_SFF_8070I,            "Obsolete (was SFF-8070i)"},
    {MSC_SUBCLASS_SCSI_TRANSPARENT_COMMAND_SET,  "SCSI transparent command set"},
    {MSC_SUBCLASS_LSD_FS,                        "LSD FS"},
    {MSC_SUBCLASS_IEEE_1667,                     "IEEE 1667"},
    {MSC_SUBCLASS_VENDOR,                        "Specific to device vendor"},
    {0, NULL}
};
value_string_ext ext_usb_massstorage_subclass_vals = VALUE_STRING_EXT_INIT(usb_massstorage_subclass_vals);

#define MSC_PROTOCOL_CBI_NO_INTERRUPT   0x00
#define MSC_PROTOCOL_CBI_WITH_INTERRUPT 0x01
#define MSC_PROTOCOL_OBSOLETE           0x02
#define MSC_PROTOCOL_BULK_ONLY          0x50
#define MSC_PROTOCOL_UAS                0x62
#define MSC_PROTOCOL_VENDOR             0xFF

static const value_string usb_massstorage_protocol_vals[] = {
    {MSC_PROTOCOL_CBI_NO_INTERRUPT,   "Control/Bulk/Interrupt (CBI) Transport with command completion interrupt"},
    {MSC_PROTOCOL_CBI_WITH_INTERRUPT, "Control/Bulk/Interrupt (CBI) Transport with no command completion interrupt"},
    {MSC_PROTOCOL_OBSOLETE,           "Obsolete"},
    {MSC_PROTOCOL_BULK_ONLY,          "Bulk-Only (BBB) Transport"},
    {MSC_PROTOCOL_UAS,                "UAS"},
    {MSC_PROTOCOL_VENDOR,             "Specific to device vendor"},
    {0, NULL}
};
value_string_ext usb_massstorage_protocol_vals_ext = VALUE_STRING_EXT_INIT(usb_massstorage_protocol_vals);

static int
dissect_usb_ms_bulk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
    usb_conv_info_t *usb_conv_info;

    usb_conv_info = (usb_conv_info_t *)data;

    return dissector_try_uint_new(usb_ms_bulk_dissector_table, usb_conv_info->interfaceProtocol, tvb, pinfo, parent_tree, true, usb_conv_info);
}

static int
dissect_usb_ms_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
    usb_conv_info_t *usb_conv_info;

    usb_conv_info = (usb_conv_info_t *)data;

    return dissector_try_uint_new(usb_ms_control_dissector_table, usb_conv_info->interfaceProtocol, tvb, pinfo, parent_tree, true, usb_conv_info);
}

static int
dissect_usb_ms_interrupt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
    usb_conv_info_t *usb_conv_info;

    usb_conv_info = (usb_conv_info_t *)data;

    return dissector_try_uint_new(usb_ms_interrupt_dissector_table, usb_conv_info->interfaceProtocol, tvb, pinfo, parent_tree, true, usb_conv_info);
}

static int
dissect_usb_ms_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
    usb_conv_info_t *usb_conv_info;

    usb_conv_info = (usb_conv_info_t *)data;

    return dissector_try_uint_new(usb_ms_descriptor_dissector_table, usb_conv_info->interfaceProtocol, tvb, pinfo, parent_tree, true, usb_conv_info);
}

void
proto_register_usb_ms(void)
{
    proto_usb_ms = proto_register_protocol("USB Mass Storage Class", "USBMSClass", "usbmsclass");

    usb_ms_bulk_handle = register_dissector("usbmsclass.bulk", dissect_usb_ms_bulk, proto_usb_ms);
    usb_ms_control_handle = register_dissector("usbmsclass.control", dissect_usb_ms_control, proto_usb_ms);
    usb_ms_interrupt_handle = register_dissector("usbmsclass.interrupt", dissect_usb_ms_interrupt, proto_usb_ms);
    usb_ms_descriptor_handle = register_dissector("usbmsclass.descriptor", dissect_usb_ms_descriptor, proto_usb_ms);

    usb_ms_bulk_dissector_table = register_dissector_table("usbms.bulk",
        "USBMS bulk endpoint", proto_usb_ms, FT_UINT8, BASE_HEX);
    usb_ms_control_dissector_table = register_dissector_table("usbms.control",
        "USBMS control endpoint", proto_usb_ms, FT_UINT8, BASE_HEX);
    usb_ms_interrupt_dissector_table = register_dissector_table("usbms.interrupt",
        "USBMS interrupt endpoint", proto_usb_ms, FT_UINT8, BASE_HEX);
    usb_ms_descriptor_dissector_table = register_dissector_table("usbms.descriptor",
        "USBMS descriptor", proto_usb_ms, FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_usb_ms(void)
{
    dissector_add_uint("usb.bulk", IF_CLASS_MASS_STORAGE, usb_ms_bulk_handle);
    dissector_add_uint("usb.control", IF_CLASS_MASS_STORAGE, usb_ms_control_handle);
    dissector_add_uint("usb.interrupt", IF_CLASS_MASS_STORAGE, usb_ms_interrupt_handle);
    dissector_add_uint("usb.descriptor", IF_CLASS_MASS_STORAGE, usb_ms_descriptor_handle);
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
