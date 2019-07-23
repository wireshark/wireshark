/* packet-usbll.c
 *
 * 2019 Tomasz Mon <desowin@gmail.com>
 *
 * USB link layer dissector
 *
 * This code is separated from packet-usb.c on purpose.
 * It is important to note that packet-usb.c operates on the USB URB level.
 * The idea behind this file is to transform low level link layer data
 * (captured by hardware sniffers) into structures that resemble URB and pass
 * such URB to the URB common dissection code.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/crc16-tvb.h>
#include <wsutil/crc5.h>

static int proto_usbll = -1;

/* Fields defined by USB 2.0 standard */
static int hf_usbll_pid = -1;
static int hf_usbll_addr = -1;
static int hf_usbll_endp = -1;
static int hf_usbll_crc5 = -1;
static int hf_usbll_crc5_status = -1;
static int hf_usbll_data = -1;
static int hf_usbll_data_crc = -1;
static int hf_usbll_data_crc_status = -1;
static int hf_usbll_sof_framenum = -1;
static int hf_usbll_split_hub_addr = -1;
static int hf_usbll_split_sc = -1;
static int hf_usbll_split_port = -1;
static int hf_usbll_split_s = -1;
static int hf_usbll_split_e = -1;
static int hf_usbll_split_iso_se = -1;
static int hf_usbll_split_et = -1;
static int hf_usbll_split_crc5 = -1;
static int hf_usbll_split_crc5_status = -1;

static int ett_usbll = -1;

static expert_field ei_invalid_pid = EI_INIT;
static expert_field ei_undecoded = EI_INIT;
static expert_field ei_wrong_crc5 = EI_INIT;
static expert_field ei_wrong_split_crc5 = EI_INIT;
static expert_field ei_wrong_crc16 = EI_INIT;

static dissector_handle_t usbll_handle;

/* USB packet ID is 4-bit. It is send in octet alongside complemented form.
 * The list of PIDs is available in Universal Serial Bus Specification Revision 2.0,
 * Table 8-1. PID Types
 * Packets here are sorted by the complemented form (high nibble).
 */
#define USB_PID_DATA_MDATA         0x0F
#define USB_PID_HANDSHAKE_STALL    0x1E
#define USB_PID_TOKEN_SETUP        0x2D
#define USB_PID_SPECIAL_PRE_OR_ERR 0x3C
#define USB_PID_DATA_DATA1         0x4B
#define USB_PID_HANDSHAKE_NAK      0x5A
#define USB_PID_TOKEN_IN           0x69
#define USB_PID_SPECIAL_SPLIT      0x78
#define USB_PID_DATA_DATA2         0x87
#define USB_PID_HANDSHAKE_NYET     0x96
#define USB_PID_TOKEN_SOF          0xA5
#define USB_PID_SPECIAL_PING       0xB4
#define USB_PID_DATA_DATA0         0xC3
#define USB_PID_HANDSHAKE_ACK      0xD2
#define USB_PID_TOKEN_OUT          0xE1
#define USB_PID_SPECIAL_RESERVED   0xF0
static const value_string usb_packetid_vals[] = {
    {USB_PID_DATA_MDATA,         "MDATA"},
    {USB_PID_HANDSHAKE_STALL,    "STALL"},
    {USB_PID_TOKEN_SETUP,        "SETUP"},
    {USB_PID_SPECIAL_PRE_OR_ERR, "PRE/ERR"},
    {USB_PID_DATA_DATA1,         "DATA1"},
    {USB_PID_HANDSHAKE_NAK,      "NAK"},
    {USB_PID_TOKEN_IN,           "IN"},
    {USB_PID_SPECIAL_SPLIT,      "SPLIT"},
    {USB_PID_DATA_DATA2,         "DATA2"},
    {USB_PID_HANDSHAKE_NYET,     "NYET"},
    {USB_PID_TOKEN_SOF,          "SOF"},
    {USB_PID_SPECIAL_PING,       "PING"},
    {USB_PID_DATA_DATA0,         "DATA0"},
    {USB_PID_HANDSHAKE_ACK,      "ACK"},
    {USB_PID_TOKEN_OUT,          "OUT"},
    {USB_PID_SPECIAL_RESERVED,   "Reserved"},
    {0, NULL}
};
static value_string_ext usb_packetid_vals_ext =
    VALUE_STRING_EXT_INIT(usb_packetid_vals);

static const value_string usb_start_complete_vals[] = {
    {0, "Start"},
    {1, "Complete"},
    {0, NULL}
};

static const value_string usb_split_speed_vals[] = {
    {0, "Full"},
    {1, "Low"},
    {0, NULL}
};

static const value_string usb_split_iso_se_vals[] = {
    {0, "High-speed data is the middle of the fullspeed data payload"},
    {1, "High-speed data is the beginning of the full-speed data payload"},
    {2, "High-speed data is the end of the full-speed data payload"},
    {3, "High-speed data is all of the full-speed data payload"},
    {0, NULL}
};

#define USB_EP_TYPE_CONTROL     0
#define USB_EP_TYPE_ISOCHRONOUS 1
#define USB_EP_TYPE_BULK        2
#define USB_EP_TYPE_INTERRUPT   3
static const value_string usb_endpoint_type_vals[] = {
    {USB_EP_TYPE_CONTROL,     "Control"},
    {USB_EP_TYPE_ISOCHRONOUS, "Isochronous"},
    {USB_EP_TYPE_BULK,        "Bulk"},
    {USB_EP_TYPE_INTERRUPT,   "Interrupt"},
    {0, NULL}
};

static int
dissect_usbll_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    proto_item       *item;
    proto_tree       *tree;
    gint              offset = 0;
    guint32           pid;
    const gchar      *str;

    tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_usbll, &item, "USB Packet");

    item = proto_tree_add_item_ret_uint(tree, hf_usbll_pid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &pid);
    offset++;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBLL");
    str = try_val_to_str(pid, usb_packetid_vals);
    if (str)
    {
        col_set_str(pinfo->cinfo, COL_INFO, str);
    }
    else
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Invalid Packet ID (0x%02x)", pid);
        expert_add_info(pinfo, item, &ei_invalid_pid);
    }

    switch (pid)
    {
    case USB_PID_TOKEN_SETUP:
    case USB_PID_TOKEN_OUT:
    case USB_PID_TOKEN_IN:
    case USB_PID_SPECIAL_PING:
    {
        guint16 address_bits;
        static const int *address_fields[] = {
            &hf_usbll_addr,
            &hf_usbll_endp,
            NULL
        };

        address_bits = tvb_get_letohs(tvb, offset);
        proto_tree_add_bitmask_list_value(tree, tvb, offset, 2, address_fields, address_bits);
        proto_tree_add_checksum(tree, tvb, offset,
            hf_usbll_crc5, hf_usbll_crc5_status, &ei_wrong_crc5, pinfo,
            crc5_usb_11bit_input(address_bits),
            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
        offset += 2;
        break;
    }
    case USB_PID_DATA_DATA0:
    case USB_PID_DATA_DATA1:
    case USB_PID_DATA_DATA2:
    case USB_PID_DATA_MDATA:
    {
        /* TODO: How to determine the expected DATA size? */
        gint data_size = tvb_reported_length_remaining(tvb, offset) - 2;
        if (data_size > 0)
        {
            proto_tree_add_item(tree, hf_usbll_data, tvb, offset, data_size, ENC_NA);
            offset += data_size;
        }
        proto_tree_add_checksum(tree, tvb, offset,
            hf_usbll_data_crc, hf_usbll_data_crc_status, &ei_wrong_crc16, pinfo,
            crc16_usb_tvb_offset(tvb, 1, offset - 1),
            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
        offset += 2;
        break;
    }
    case USB_PID_HANDSHAKE_ACK:
    case USB_PID_HANDSHAKE_NAK:
    case USB_PID_HANDSHAKE_NYET:
    case USB_PID_HANDSHAKE_STALL:
        break;
    case USB_PID_TOKEN_SOF:
    {
        guint32 frame;
        proto_tree_add_item_ret_uint(tree, hf_usbll_sof_framenum, tvb, offset, 2, ENC_LITTLE_ENDIAN, &frame);
        proto_tree_add_checksum(tree, tvb, offset,
            hf_usbll_crc5, hf_usbll_crc5_status, &ei_wrong_crc5, pinfo,
            crc5_usb_11bit_input(frame),
            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
        offset += 2;
        break;
    }
    case USB_PID_SPECIAL_SPLIT:
    {
        /* S/E fields have special meaning for Isochronous transfers */
        gint32 tmp = tvb_get_gint24(tvb, offset, ENC_LITTLE_ENDIAN);
        static const int *split_fields[] = {
            &hf_usbll_split_hub_addr,
            &hf_usbll_split_sc,
            &hf_usbll_split_port,
            &hf_usbll_split_s,
            &hf_usbll_split_e,
            &hf_usbll_split_et,
            NULL
        };
        static const int *split_iso_fields[] = {
            &hf_usbll_split_hub_addr,
            &hf_usbll_split_sc,
            &hf_usbll_split_port,
            &hf_usbll_split_iso_se,
            &hf_usbll_split_et,
            NULL
        };

        if (((tmp & 0x060000) >> 17) == USB_EP_TYPE_ISOCHRONOUS)
        {
            proto_tree_add_bitmask_list(tree, tvb, offset, 3, split_iso_fields, ENC_LITTLE_ENDIAN);
        }
        else
        {
            proto_tree_add_bitmask_list(tree, tvb, offset, 3, split_fields, ENC_LITTLE_ENDIAN);
        }
        proto_tree_add_checksum(tree, tvb, offset,
            hf_usbll_split_crc5, hf_usbll_split_crc5_status, &ei_wrong_split_crc5, pinfo,
            crc5_usb_19bit_input(tmp),
            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
        offset += 3;
        break;
    }
    case USB_PID_SPECIAL_PRE_OR_ERR:
        break;
    case USB_PID_SPECIAL_RESERVED:
        break;
    default:
        break;
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        proto_tree_add_expert(tree, pinfo, &ei_undecoded, tvb, offset, -1);
        offset += tvb_captured_length_remaining(tvb, offset);
    }

    return offset;
}

void
proto_register_usbll(void)
{
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_usbll_pid,
            { "PID", "usbll.pid",
              FT_UINT8, BASE_HEX|BASE_EXT_STRING, &usb_packetid_vals_ext, 0x00,
              "USB Packet ID", HFILL }},

        { &hf_usbll_addr,
            { "Address", "usbll.addr",
              FT_UINT16, BASE_DEC, NULL, 0x007F,
              NULL, HFILL }},
        { &hf_usbll_endp,
            { "Endpoint", "usbll.endp",
              FT_UINT16, BASE_DEC, NULL, 0x0780,
              NULL, HFILL }},
        { &hf_usbll_crc5,
            { "CRC5", "usbll.crc5",
              FT_UINT16, BASE_HEX, NULL, 0xF800,
              NULL, HFILL }},
        { &hf_usbll_crc5_status,
            { "CRC5 Status", "usbll.crc5.status",
              FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0,
              NULL, HFILL }},
        { &hf_usbll_data,
            { "Data", "usbll.data",
              FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }},
        { &hf_usbll_data_crc,
            { "CRC", "usbll.crc16",
              FT_UINT16, BASE_HEX, NULL, 0x0000,
              NULL, HFILL }},
        { &hf_usbll_data_crc_status,
            { "CRC Status", "usbll.crc16.status",
              FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0,
              NULL, HFILL }},
        { &hf_usbll_sof_framenum,
            { "Frame Number", "usbll.frame_num",
              FT_UINT16, BASE_DEC, NULL, 0x07FF,
              NULL, HFILL }},

        { &hf_usbll_split_hub_addr,
            { "Hub Address", "usbll.split_hub_addr",
              FT_UINT24, BASE_DEC, NULL, 0x00007F,
              NULL, HFILL }},
        { &hf_usbll_split_sc,
            { "SC", "usbll.split_sc",
              FT_UINT24, BASE_DEC, VALS(usb_start_complete_vals), 0x000080,
              NULL, HFILL }},
        { &hf_usbll_split_port,
            { "Port", "usbll.split_port",
              FT_UINT24, BASE_DEC, NULL, 0x007F00,
              NULL, HFILL }},
        { &hf_usbll_split_s,
            { "Speed", "usbll.split_s",
              FT_UINT24, BASE_DEC, VALS(usb_split_speed_vals), 0x008000,
              NULL, HFILL }},
        { &hf_usbll_split_e,
            { "E", "usbll.split_e",
              FT_UINT24, BASE_DEC, NULL, 0x010000,
              "Unused. Must be 0.", HFILL }},
        { &hf_usbll_split_iso_se,
            { "Start and End", "usbll.split_se",
              FT_UINT24, BASE_DEC, VALS(usb_split_iso_se_vals), 0x018000,
              NULL, HFILL }},
        { &hf_usbll_split_et,
            { "Endpoint Type", "usbll.split_et",
              FT_UINT24, BASE_DEC, VALS(usb_endpoint_type_vals), 0x060000,
              NULL, HFILL }},
        { &hf_usbll_split_crc5,
            { "CRC5", "usbll.split_crc5",
              FT_UINT24, BASE_HEX, NULL, 0xF80000,
              NULL, HFILL }},
        { &hf_usbll_split_crc5_status,
            { "CRC5 Status", "usbll.split_crc5.status",
              FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0,
              NULL, HFILL }},
    };

    static ei_register_info ei[] = {
        { &ei_invalid_pid, { "usbll.invalid_pid", PI_MALFORMED, PI_ERROR, "Invalid USB Packet ID", EXPFILL }},
        { &ei_undecoded, { "usbll.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
        { &ei_wrong_crc5, { "usbll.crc5.wrong", PI_PROTOCOL, PI_WARN, "Wrong CRC", EXPFILL }},
        { &ei_wrong_split_crc5, { "usbll.split_crc5.wrong", PI_PROTOCOL, PI_WARN, "Wrong CRC", EXPFILL }},
        { &ei_wrong_crc16, { "usbll.crc16.wrong", PI_PROTOCOL, PI_WARN, "Wrong CRC", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_usbll,
    };

    proto_usbll = proto_register_protocol("USB Link Layer", "USBLL", "usbll");
    proto_register_field_array(proto_usbll, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module = expert_register_protocol(proto_usbll);
    expert_register_field_array(expert_module, ei, array_length(ei));

    register_dissector("usbll", dissect_usbll_packet, proto_usbll);
}

void
proto_reg_handoff_usbll(void)
{
    usbll_handle = create_dissector_handle(dissect_usbll_packet, proto_usbll);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USB_2_0, usbll_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
