/* packet-bthci_vendor.c
 * Routines for the Bluetooth HCI Vendors Commands/Events
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tap.h>

#include "packet-bluetooth.h"
#include "packet-bthci_cmd.h"
#include "packet-bthci_evt.h"


static int proto_bthci_vendor_intel;

static int hf_intel_opcode;
static int hf_intel_opcode_ogf;
static int hf_intel_opcode_ocf;
static int hf_intel_parameter_length;
static int hf_intel_number_of_allowed_command_packets;
static int hf_intel_event_code;
static int hf_intel_status;
static int hf_intel_line;
static int hf_intel_module;
static int hf_intel_reason;
static int hf_intel_zero;
static int hf_intel_number_of_packets;
static int hf_intel_source;
static int hf_intel_reset_type;
static int hf_intel_reset_reason;
static int hf_intel_ddc_status;
static int hf_intel_bd_data_status;
static int hf_intel_secure_send_commands_result;
static int hf_intel_handle;
static int hf_intel_access_address;
static int hf_intel_scan_status;
static int hf_intel_scan_status_reserved;
static int hf_intel_scan_status_page_scan;
static int hf_intel_scan_status_inquiry_scan;
static int hf_intel_link_pdu_trace_type;
static int hf_intel_link_clock;
static int hf_intel_link_id;
static int hf_intel_link_count;
static int hf_intel_bd_addr;
static int hf_intel_packet_table;
static int hf_intel_exception_type;
static int hf_intel_reset_reset_type;
static int hf_intel_reset_patch_enable;
static int hf_intel_reset_ddc_reload;
static int hf_intel_reset_boot_option;
static int hf_intel_reset_boot_address;
static int hf_intel_hardware_platform;
static int hf_intel_hardware_variant;
static int hf_intel_hardware_revision;
static int hf_intel_firmware_variant;
static int hf_intel_firmware_revision;
static int hf_intel_firmware_build_version_nn;
static int hf_intel_firmware_build_version_cw;
static int hf_intel_firmware_build_version_yy;
static int hf_intel_firmware_patch;
static int hf_intel_identifier;
static int hf_intel_secure_send_type;
static int hf_intel_manufacturer_mode;
static int hf_intel_manufacturer_reset;
static int hf_intel_transmit_traces;
static int hf_intel_transmit_arq;
static int hf_intel_receive_traces;
static int hf_intel_stimulated_exception_type;
static int hf_intel_mem_address;
static int hf_intel_mem_mode;
static int hf_intel_mem_length;
static int hf_intel_ddc_config_length;
static int hf_intel_set_event_mask;
static int hf_intel_set_event_mask_reserved_15_63;
static int hf_intel_set_event_mask_firmware_trace_string;
static int hf_intel_set_event_mask_le_link_established;
static int hf_intel_set_event_mask_reserved_12;
static int hf_intel_set_event_mask_system_exception;
static int hf_intel_set_event_mask_fatal_exception;
static int hf_intel_set_event_mask_debug_exception;
static int hf_intel_set_event_mask_reserved_8;
static int hf_intel_set_event_mask_scan_status;
static int hf_intel_set_event_mask_reserved_3_6;
static int hf_intel_set_event_mask_ptt_switch_notification;
static int hf_intel_set_event_mask_sco_rejected_via_lmp;
static int hf_intel_set_event_mask_bootup;
static int hf_intel_data;

static int * const hfx_intel_scan_status[] = {
    &hf_intel_scan_status_reserved,
    &hf_intel_scan_status_page_scan,
    &hf_intel_scan_status_inquiry_scan,
    NULL
};

static int * const hfx_intel_set_event_mask[] = {
    &hf_intel_set_event_mask_reserved_15_63,
    &hf_intel_set_event_mask_firmware_trace_string,
    &hf_intel_set_event_mask_le_link_established,
    &hf_intel_set_event_mask_reserved_12,
    &hf_intel_set_event_mask_system_exception,
    &hf_intel_set_event_mask_fatal_exception,
    &hf_intel_set_event_mask_debug_exception,
    &hf_intel_set_event_mask_reserved_8,
    &hf_intel_set_event_mask_scan_status,
    &hf_intel_set_event_mask_reserved_3_6,
    &hf_intel_set_event_mask_ptt_switch_notification,
    &hf_intel_set_event_mask_sco_rejected_via_lmp,
    &hf_intel_set_event_mask_bootup,
    NULL
};

static dissector_handle_t bthci_vendor_intel_handle;
static dissector_handle_t btlmp_handle;
static dissector_handle_t btle_handle;

static int ett_intel;
static int ett_intel_opcode;
static int ett_intel_scan_status;
static int ett_intel_set_event_mask;

static expert_field ei_intel_undecoded;
static expert_field ei_intel_unexpected_parameter;
static expert_field ei_intel_unexpected_data;

#define INTEL_OPCODE_VALS(base) \
    { (base) | 0x0001,  "Reset" }, \
    { (base) | 0x0002,  "No Operation" }, \
    { (base) | 0x0005,  "Read Version" }, \
    { (base) | 0x0006,  "Set UART Baudrate" }, \
    { (base) | 0x0007,  "Enable LPM" }, \
    { (base) | 0x0008,  "PCM Write Configuration" }, \
    { (base) | 0x0009,  "Secure Send" }, \
    { (base) | 0x000D,  "Read Secure Boot Params" }, \
    { (base) | 0x000E,  "Write Secure Boot Params" }, \
    { (base) | 0x000F,  "Unlock" }, \
    { (base) | 0x0010,  "Change UART Baudrate" }, \
    { (base) | 0x0011,  "Manufacturer Mode" }, \
    { (base) | 0x0012,  "Read Link RSSI" }, \
    { (base) | 0x0022,  "Get Exception Info" }, \
    { (base) | 0x0024,  "Clear Exception Info" }, \
    { (base) | 0x002F,  "Write BD Data" }, \
    { (base) | 0x0030,  "Read BD Data" }, \
    { (base) | 0x0031,  "Write BD Address" }, \
    { (base) | 0x0032,  "Flow Specification" }, \
    { (base) | 0x0034,  "Read Secure ID" }, \
    { (base) | 0x0038,  "Set Synchronous USB Interface Type" }, \
    { (base) | 0x0039,  "Config Synchronous Interface" }, \
    { (base) | 0x003F,  "SW RF Kill" }, \
    { (base) | 0x0043,  "Activate/Deactivate Traces" }, \
    { (base) | 0x004D,  "Stimulate Exception" }, \
    { (base) | 0x0050,  "Read HW Version" }, \
    { (base) | 0x0052,  "Set Event Mask" }, \
    { (base) | 0x0053,  "Config_Link_Controller" }, \
    { (base) | 0x0089,  "DDC Write" }, \
    { (base) | 0x008A,  "DDC Read" }, \
    { (base) | 0x008B,  "DDC Config Write" }, \
    { (base) | 0x008C,  "DDC Config Read" }, \
    { (base) | 0x008D,  "Memory Read" }, \
    { (base) | 0x008E,  "Memory Write" }

static const value_string intel_opcode_ocf_vals[] = {
    INTEL_OPCODE_VALS(0x0),
    { 0, NULL }
};

static const value_string intel_opcode_vals[] = {
    INTEL_OPCODE_VALS(0x3F << 10),
    { 0, NULL }
};

static const value_string intel_event_code_vals[] = {
    { 0x01,  "Fatal Exception" },
    { 0x02,  "Bootup" },
    { 0x05,  "Default BD Data" },
    { 0x06,  "Secure Send Commands Result" },
    { 0x08,  "Debug Exception" },
    { 0x0F,  "LE Link Established" },
    { 0x11,  "Scan Status" },
    { 0x16,  "Activate/Deactivate Traces Complete" },
    { 0x17,  "Link PDU Trace" },
    { 0x19,  "Write BD Data Complete" },
    { 0x25,  "SCO Rejected via LMP" },
    { 0x26,  "PTT Switch Notification" },
    { 0x29,  "System Exception" },
    { 0x2C,  "FW Trace String" },
    { 0x2E,  "FW Trace Binary" },
    { 0, NULL }
};

static const value_string intel_module_vals[] = {
    { 0x01,  "BC" },
    { 0x02,  "HCI" },
    { 0x03,  "LLC" },
    { 0x04,  "OS" },
    { 0x05,  "LM" },
    { 0x06,  "SC" },
    { 0x07,  "SP" },
    { 0x08,  "OSAL" },
    { 0x09,  "LC" },
    { 0x0A,  "APP" },
    { 0x0B,  "TLD" },
    { 0xF0,  "Debug" },
    { 0, NULL }
};

static const value_string intel_source_vals[] = {
    { 0x00,  "Bootloader" },
    { 0x01,  "Operational Firmware" },
    { 0x02,  "Self Test Firmware" },
    { 0, NULL }
};

static const value_string intel_reset_type_vals[] = {
    { 0x00,  "Hardware Reset" },
    { 0x01,  "Soft Watchdog Reset" },
    { 0x02,  "Soft Software Reset" },
    { 0x03,  "Hard Watchdog Reset" },
    { 0x04,  "Hard Software Reset" },
    { 0, NULL }
};

static const value_string intel_reset_reason_vals[] = {
    { 0x00,  "Power On" },
    { 0x01,  "Reset Command" },
    { 0x02,  "Intel Reset Command" },
    { 0x03,  "Watchdog" },
    { 0x04,  "Fatal Exception" },
    { 0x05,  "System Exception" },
    { 0xFF,  "Unknown" },
    { 0, NULL }
};

static const value_string intel_ddc_status_vals[] = {
    { 0x00,  "Firmware Default" },
    { 0x01,  "Firmware Default Plus OTP" },
    { 0x02,  "Persistent RAM" },
    { 0x03,  "Not Used" },
    { 0, NULL }
};

static const value_string intel_bd_data_status_vals[] = {
    { 0x02,  "Invalid Manufacturing Data" },
    { 0, NULL }
};

static const value_string intel_secure_send_commands_result_vals[] = {
    { 0x00,  "Success" },
    { 0x01,  "General Failure" },
    { 0x02,  "Hardware Failure" },
    { 0x03,  "Signature Verification Failed" },
    { 0x04,  "Parsing Error of Command Buffer" },
    { 0x05,  "Command Execution Failure" },
    { 0x06,  "Command Parameters Error" },
    { 0x07,  "Command Missing" },
    { 0, NULL }
};

static const value_string intel_link_pdu_trace_type_vals[] = {
    { 0x00,  "LMP Rx" },
    { 0x01,  "LMP Tx" },
    { 0x02,  "LMP Ack" },
    { 0x03,  "LL Rx" },
    { 0x04,  "LL Tx" },
    { 0x05,  "LL Ack" },
    { 0, NULL }
};

static const value_string intel_packet_table_vals[] = {
    { 0x00,  "Basic Rate" },
    { 0x01,  "Enhanced Data Rate" },
    { 0, NULL }
};

static const value_string intel_exception_type_vals[] = {
    { 0x00,  "No Exception" },
    { 0x01,  "Undefined Instruction" },
    { 0x02,  "Prefetch Abort" },
    { 0x03,  "Data Abort" },
    { 0, NULL }
};

static const value_string intel_reset_reset_type_vals[] = {
    { 0x00,  "Soft Software Reset" },
    { 0x01,  "Hard Software Reset" },
    { 0, NULL }
};

static const value_string intel_reset_patch_enable_vals[] = {
    { 0x00,  "Disabled" },
    { 0x01,  "Enabled" },
    { 0, NULL }
};

static const value_string intel_reset_ddc_reload_vals[] = {
    { 0x00,  "Disabled" },
    { 0x01,  "Reload from OTP" },
    { 0, NULL }
};

static const value_string intel_secure_send_type_vals[] = {
    { 0x00,  "Init" },
    { 0x01,  "Data" },
    { 0x02,  "Sign" },
    { 0x03,  "PKey" },
    { 0, NULL }
};

static const value_string intel_manufacturer_mode_vals[] = {
    { 0x00,  "Disabled" },
    { 0x01,  "Enabled" },
    { 0, NULL }
};

static const value_string intel_manufacturer_reset_vals[] = {
    { 0x00,  "No Reset" },
    { 0x01,  "Reset and Deactivate Patches" },
    { 0x02,  "Reset and Activate Patches" },
    { 0, NULL }
};

static const value_string intel_stimulated_exception_type_vals[] = {
    { 0x00,  "Fatal Exception" },
    { 0x01,  "Debug Exception" },
    { 0, NULL }
};

static const value_string intel_mem_mode_vals[] = {
    { 0x00,  "Byte Access" },
    { 0x01,  "Half Word Access" },
    { 0x02,  "Word Access" },
    { 0, NULL }
};


void proto_register_bthci_vendor_intel(void);
void proto_reg_handoff_bthci_vendor_intel(void);

static int
dissect_bthci_vendor_intel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item        *main_item;
    proto_tree        *main_tree;
    proto_item        *opcode_item;
    proto_tree        *opcode_tree;
    proto_item        *sub_item;
    bluetooth_data_t  *bluetooth_data;
    int                offset = 0;
    int                offset_parameters;
    uint16_t           opcode;
    uint16_t           ocf;
    const char        *description;
    uint8_t            length;
    uint8_t            event_code;
    uint8_t            status;
    uint8_t            type;
    uint32_t           interface_id;
    uint32_t           adapter_id;

    bluetooth_data = (bluetooth_data_t *) data;
    if (bluetooth_data) {
        interface_id  = bluetooth_data->interface_id;
        adapter_id    = bluetooth_data->adapter_id;
    } else {
        interface_id  = HCI_INTERFACE_DEFAULT;
        adapter_id    = HCI_ADAPTER_DEFAULT;
    }

    main_item = proto_tree_add_item(tree, proto_bthci_vendor_intel, tvb, 0, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_intel);

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_CMD_INTEL");
        col_set_str(pinfo->cinfo, COL_INFO, "Sent Intel ");

        opcode_item = proto_tree_add_item(main_tree, hf_intel_opcode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        opcode_tree = proto_item_add_subtree(opcode_item, ett_intel_opcode);
        opcode = tvb_get_letohs(tvb, offset);
        proto_tree_add_item(opcode_tree, hf_intel_opcode_ogf, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(opcode_tree, hf_intel_opcode_ocf, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        ocf = opcode & 0x03ff;
        offset+=2;

        description = val_to_str_const(ocf, intel_opcode_ocf_vals, "unknown");
        if (g_strcmp0(description, "unknown") != 0)
            col_append_str(pinfo->cinfo, COL_INFO, description);
        else
            col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown Command 0x%04X (opcode 0x%04X)", ocf, opcode);

        if (have_tap_listener(bluetooth_hci_summary_tap)) {
            bluetooth_hci_summary_tap_t  *tap_hci_summary;

            tap_hci_summary = wmem_new(pinfo->pool, bluetooth_hci_summary_tap_t);
            tap_hci_summary->interface_id  = interface_id;
            tap_hci_summary->adapter_id    = adapter_id;

            tap_hci_summary->type = BLUETOOTH_HCI_SUMMARY_VENDOR_OPCODE;
            tap_hci_summary->ogf = opcode >> 10;
            tap_hci_summary->ocf = ocf;
            if (try_val_to_str(ocf, intel_opcode_ocf_vals))
                tap_hci_summary->name = description;
            else
                tap_hci_summary->name = NULL;
            tap_queue_packet(bluetooth_hci_summary_tap, pinfo, tap_hci_summary);
        }

        proto_tree_add_item(main_tree, hf_intel_parameter_length, tvb, offset, 1, ENC_NA);
        length = tvb_get_uint8(tvb, offset);
        offset += 1;

        offset_parameters = offset;

        switch(ocf) {
        case 0x0001: /* Reset */
            proto_tree_add_item(main_tree, hf_intel_reset_reset_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_reset_patch_enable, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_reset_ddc_reload, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_reset_ddc_reload, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_reset_boot_option, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_reset_boot_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            break;
        case 0x0002: /* No Operation */
        case 0x0006: /* Set UART Baudrate */
        case 0x0007: /* Enable LPM */
        case 0x0008: /* PCM Write Configuration */
        case 0x000E: /* Write Secure Boot Params */
        case 0x000F: /* Unlock */
        case 0x0010: /* Change UART Baudrate */
        case 0x0012: /* Read Link RSSI */
        case 0x0022: /* Get Exception Info */
        case 0x0024: /* Clear Exception Info */
        case 0x0032: /* Flow Specification */
        case 0x0034: /* Read Secure ID */
        case 0x0038: /* Set Synchronous USB Interface Type */
        case 0x0039: /* Config Synchronous Interface */
        case 0x0050: /* Read HW Version */
        case 0x0053: /* Config_Link_Controller */
        case 0x0089: /* DDC Write */
        case 0x008A: /* DDC Read */
        case 0x008C: /* DDC Config Read */
        case 0x008D: /* Memory Read */
            /* unknown */

            break;
        case 0x0005: /* Read Version */
        case 0x000D: /* Read Secure Boot Params */
        case 0x0030: /* Read BD Data */
        case 0x003F: /* SW RF Kill */
            /* nop */

            break;
        case 0x0009: /* Secure Send */
            proto_tree_add_item(main_tree, hf_intel_secure_send_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (length - 1 > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, length, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
                offset += length - 1;
            }

            break;
        case 0x0011: /* Manufacturer Mode */
            proto_tree_add_item(main_tree, hf_intel_manufacturer_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_manufacturer_reset, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x002F: /* Write BD Data */
            offset = dissect_bd_addr(hf_intel_bd_addr, pinfo, main_tree, tvb, offset, false, interface_id, adapter_id, NULL);

            sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, 6, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
            offset += 6;

            sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, 8, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
            offset += 8;

            sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, 1, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
            offset += 1;

            if (length - 6 - 8 - 1 > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, length - 6 - 8 - 1, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
                offset += length - 6 - 8 - 1;
            }

            break;
        case 0x0031: /* Write BD Address */
            offset = dissect_bd_addr(hf_intel_bd_addr, pinfo, main_tree, tvb, offset, false, interface_id, adapter_id, NULL);

            break;
        case 0x0043: /* Activate/Deactivate Traces */
            proto_tree_add_item(main_tree, hf_intel_transmit_traces, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_transmit_arq, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_receive_traces, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x004D: /* Stimulate Exception */
            proto_tree_add_item(main_tree, hf_intel_stimulated_exception_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x0052: /* Set Event Mask */
            proto_tree_add_bitmask(main_tree, tvb, offset, hf_intel_set_event_mask, ett_intel_set_event_mask, hfx_intel_set_event_mask, ENC_LITTLE_ENDIAN);
            offset += 8;

            break;
        case 0x008B: /* DDC Config Write */
            while (length > 0) {
                uint8_t ddc_config_length;

                proto_tree_add_item(main_tree, hf_intel_ddc_config_length, tvb, offset, 1, ENC_NA);
                ddc_config_length = tvb_get_uint8(tvb, offset);
                offset += 1;

                proto_tree_add_item(main_tree, hf_intel_identifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, ddc_config_length - 2, ENC_NA);
                offset += ddc_config_length - 2;

                length -= 1 + ddc_config_length;
            }

            break;
        case 0x008E: /* Memory Write */
            proto_tree_add_item(main_tree, hf_intel_mem_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(main_tree, hf_intel_mem_mode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_mem_length, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, tvb_get_uint8(tvb, offset - 1), ENC_NA);
            offset += tvb_get_uint8(tvb, offset - 1);

            break;
        default:
            if (length > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, length, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
                offset += length;
            }
        }

        if (offset - offset_parameters < length) {
            sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, length - (offset - offset_parameters), ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_intel_unexpected_parameter);
            offset += length - (offset - offset_parameters);
        }

        break;
    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_EVT_INTEL");
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd Intel ");

        event_code = tvb_get_uint8(tvb, offset);

        if (try_val_to_str(event_code, intel_event_code_vals))
            description = val_to_str(event_code, intel_event_code_vals, "Unknown 0x%08x");
        else
            description = val_to_str_ext(event_code, &bthci_evt_evt_code_vals_ext, "Unknown 0x%08x");
        col_append_str(pinfo->cinfo, COL_INFO, description);
        proto_tree_add_item(main_tree, hf_intel_event_code, tvb, offset, 1, ENC_NA);
        offset += 1;

        if (have_tap_listener(bluetooth_hci_summary_tap)) {
            bluetooth_hci_summary_tap_t  *tap_hci_summary;

            tap_hci_summary = wmem_new(pinfo->pool, bluetooth_hci_summary_tap_t);
            tap_hci_summary->interface_id  = interface_id;
            tap_hci_summary->adapter_id    = adapter_id;

            tap_hci_summary->type = BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT;
            tap_hci_summary->event = event_code;
            if (try_val_to_str_ext(event_code, &bthci_evt_evt_code_vals_ext))
                tap_hci_summary->name = description;
            else
                tap_hci_summary->name = NULL;
            tap_queue_packet(bluetooth_hci_summary_tap, pinfo, tap_hci_summary);
        }

        proto_tree_add_item(main_tree, hf_intel_parameter_length, tvb, offset, 1, ENC_NA);
        length = tvb_get_uint8(tvb, offset);
        offset += 1;

        offset_parameters = offset;

        switch (event_code) {
        case 0x0e: /* Command Complete */
            proto_tree_add_item(main_tree, hf_intel_number_of_allowed_command_packets, tvb, offset, 1, ENC_NA);
            offset += 1;

            opcode_item = proto_tree_add_item(main_tree, hf_intel_opcode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            opcode_tree = proto_item_add_subtree(opcode_item, ett_intel_opcode);
            opcode = tvb_get_letohs(tvb, offset);
            proto_tree_add_item(opcode_tree, hf_intel_opcode_ogf, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(opcode_tree, hf_intel_opcode_ocf, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            ocf = opcode & 0x03ff;
            offset += 2;

            description = val_to_str_const(ocf, intel_opcode_ocf_vals, "unknown");
            if (g_strcmp0(description, "unknown") != 0)
                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", description);
            else
                col_append_fstr(pinfo->cinfo, COL_INFO, " (Unknown Command 0x%04X [opcode 0x%04X])", ocf, opcode);

            if (have_tap_listener(bluetooth_hci_summary_tap)) {
                bluetooth_hci_summary_tap_t  *tap_hci_summary;

                tap_hci_summary = wmem_new(pinfo->pool, bluetooth_hci_summary_tap_t);
                tap_hci_summary->interface_id  = interface_id;
                tap_hci_summary->adapter_id    = adapter_id;

                tap_hci_summary->type = BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT_OPCODE;
                tap_hci_summary->ogf = opcode >> 10;
                tap_hci_summary->ocf = ocf;
                if (try_val_to_str(ocf, intel_opcode_ocf_vals))
                    tap_hci_summary->name = description;
                else
                    tap_hci_summary->name = NULL;
                tap_queue_packet(bluetooth_hci_summary_tap, pinfo, tap_hci_summary);
            }

            proto_tree_add_item(main_tree, hf_intel_status, tvb, offset, 1, ENC_NA);
            status = tvb_get_uint8(tvb, offset);
            offset += 1;

            switch (ocf) {
            case 0x0001: /* Reset */
            case 0x0009: /* Secure Send */
            case 0x0011: /* Manufacturer Mode */
            case 0x0031: /* Write BD Address */
            case 0x003F: /* SW RF Kill */
            case 0x004D: /* Stimulate Exception */
            case 0x0052: /* Set Event Mask */
            case 0x008E: /* Memory Write */
                /* nop */

                break;
            case 0x0002: /* No Operation */
            case 0x0006: /* Set UART Baudrate */
            case 0x0007: /* Enable LPM */
            case 0x0008: /* PCM Write Configuration */
            case 0x000D: /* Read Secure Boot Params */
            case 0x000E: /* Write Secure Boot Params */
            case 0x000F: /* Unlock */
            case 0x0010: /* Change UART Baudrate */
            case 0x0012: /* Read Link RSSI */
            case 0x0022: /* Get Exception Info */
            case 0x0024: /* Clear Exception Info */
            case 0x002F: /* Write BD Data */
            case 0x0032: /* Flow Specification */
            case 0x0034: /* Read Secure ID */
            case 0x0038: /* Set Synchronous USB Interface Type */
            case 0x0039: /* Config Synchronous Interface */
            case 0x0043: /* Activate/Deactivate Traces */
            case 0x0050: /* Read HW Version */
            case 0x0053: /* Config_Link_Controller */
            case 0x0089: /* DDC Write */
            case 0x008A: /* DDC Read */
            case 0x008C: /* DDC Config Read */
            case 0x008D: /* Memory Read */
                /* unknown */

                if (length > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, length, ENC_NA);
                    if (status == STATUS_SUCCESS)
                        expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
                    else
                        expert_add_info(pinfo, sub_item, &ei_intel_unexpected_parameter);
                    offset += length;
                }
                break;
            case 0x0005: /* Read Version */
                proto_tree_add_item(main_tree, hf_intel_hardware_platform, tvb, offset, length, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_intel_hardware_variant, tvb, offset, length, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_intel_hardware_revision, tvb, offset, length, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_intel_firmware_variant, tvb, offset, length, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_intel_firmware_revision, tvb, offset, length, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_intel_firmware_build_version_nn, tvb, offset, length, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_intel_firmware_build_version_cw, tvb, offset, length, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_intel_firmware_build_version_yy, tvb, offset, length, ENC_NA);
                offset += 1;

                proto_tree_add_item(main_tree, hf_intel_firmware_patch, tvb, offset, length, ENC_NA);
                offset += 1;

                break;
            case 0x0030: /* Read BD Data */
                offset = dissect_bd_addr(hf_intel_bd_addr, pinfo, main_tree, tvb, offset, false, interface_id, adapter_id, NULL);

                break;
            case 0x008B: /* DDC Config Write */
                proto_tree_add_item(main_tree, hf_intel_identifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                break;
            default:
                if (length > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, length, ENC_NA);
                    if (status == STATUS_SUCCESS)
                        expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
                    else
                        expert_add_info(pinfo, sub_item, &ei_intel_unexpected_parameter);
                    offset += length;
                }

                break;
            }

            break;

        case 0x01: /* Fatal Exception */
        case 0x08: /* Debug Exception */
            proto_tree_add_item(main_tree, hf_intel_line, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_intel_module, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_reason, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x02: /* Bootup */
            proto_tree_add_item(main_tree, hf_intel_zero, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_number_of_packets, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_source, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_reset_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_reset_reason, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_ddc_status, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x05: /* Default BD Data */
            proto_tree_add_item(main_tree, hf_intel_bd_data_status, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x06: /* Secure Send Commands Result */
            proto_tree_add_item(main_tree, hf_intel_secure_send_commands_result, tvb, offset, 1, ENC_NA);
            offset += 1;

            opcode_item = proto_tree_add_item(main_tree, hf_intel_opcode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            opcode_tree = proto_item_add_subtree(opcode_item, ett_intel_opcode);
            proto_tree_add_item(opcode_tree, hf_intel_opcode_ogf, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(opcode_tree, hf_intel_opcode_ocf, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_intel_status, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x0F: /* LE Link Established */
            proto_tree_add_item(main_tree, hf_intel_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, 8, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
            offset += 8;

            proto_tree_add_item(main_tree, hf_intel_access_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, length - 2 - 8 - 4, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
            offset += length - 2 - 8 - 4;

            break;
        case 0x11: /* Scan Status */
            proto_tree_add_bitmask(main_tree, tvb, offset, hf_intel_scan_status, ett_intel_scan_status, hfx_intel_scan_status, ENC_NA);
            offset += 1;

            break;
        case 0x16: /* Activate/Deactivate Traces Complete */
            proto_tree_add_item(main_tree, hf_intel_status, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x17: /* Link PDU Trace */
            proto_tree_add_item(main_tree, hf_intel_link_pdu_trace_type, tvb, offset, 1, ENC_NA);
            type = tvb_get_uint8(tvb, offset);
            offset += 1;

            proto_tree_add_item(main_tree, hf_intel_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            switch (type) {
            case 0x00: /* LMP Rx*/
                sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, 1, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
                offset += 1;

                call_dissector(btlmp_handle, tvb_new_subset_length(tvb, offset, length - 3 - 4), pinfo, tree);
                offset += length - 3 - 4;

                proto_tree_add_item(main_tree, hf_intel_link_clock, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                break;
            case 0x01: /* LMP Tx*/
                sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, 1, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
                offset += 1;

                call_dissector(btlmp_handle, tvb_new_subset_length(tvb, offset, length - 3 - 5), pinfo, tree);
                offset += length - 3 - 5;

                proto_tree_add_item(main_tree, hf_intel_link_clock, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_intel_link_id, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            case 0x02: /* LMP Ack */
                proto_tree_add_item(main_tree, hf_intel_link_clock, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(main_tree, hf_intel_link_id, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            case 0x03: /* LL Rx */
            case 0x04: /* LL Tx */
                proto_tree_add_item(main_tree, hf_intel_link_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_intel_link_id, tvb, offset, 1, ENC_NA);
                offset += 1;

                sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, 2, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
                offset += 2;

                call_dissector(btle_handle, tvb_new_subset_length(tvb, offset, length - 3 - 2 - 1 - 2), pinfo, tree);
                offset += length - 3 - 2 - 1 - 2;

                break;
            case 0x05: /* LL Ack */
                proto_tree_add_item(main_tree, hf_intel_link_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(main_tree, hf_intel_link_id, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            };

            break;
        case 0x19: /* Write BD Data Complete */
            proto_tree_add_item(main_tree, hf_intel_status, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x25: /* SCO Rejected via LMP */
            offset = dissect_bd_addr(hf_intel_bd_addr, pinfo, main_tree, tvb, offset, false, interface_id, adapter_id, NULL);

            proto_tree_add_item(main_tree, hf_intel_reason, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x26: /* PTT Switch Notification */
            proto_tree_add_item(main_tree, hf_intel_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_intel_packet_table, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x29: /* System Exception */
            proto_tree_add_item(main_tree, hf_intel_exception_type, tvb, offset, 1, ENC_NA);
            offset += 1;

            sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, length - 1, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
            offset += length - 1;

            break;
        case 0x2C: /* FW Trace String */
        case 0x2E: /* FW Trace Binary */
            sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, length, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
            offset += length;

            break;
        default:
            if (length > 0) {
                sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, length, ENC_NA);
                expert_add_info(pinfo, sub_item, &ei_intel_undecoded);
                offset += length;
            }
        }

        if (offset - offset_parameters < length) {
            sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, length - (offset - offset_parameters), ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_intel_unexpected_parameter);
            offset += length - (offset - offset_parameters);
        }

        break;

    case P2P_DIR_UNKNOWN:
    default:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_INTEL");
        col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection Intel ");

        if (tvb_captured_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
            offset += tvb_captured_length_remaining(tvb, offset);
        }
        break;
    }

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        sub_item = proto_tree_add_item(main_tree, hf_intel_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
        expert_add_info(pinfo, sub_item, &ei_intel_unexpected_data);
        offset += tvb_captured_length_remaining(tvb, offset);
    }

    return offset;
}

void
proto_register_bthci_vendor_intel(void)
{
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_intel_opcode,
          { "Command Opcode",                              "bthci_vendor.intel.opcode",
            FT_UINT16, BASE_HEX, VALS(intel_opcode_vals), 0x0,
            "HCI Command Opcode", HFILL }
        },
        { &hf_intel_opcode_ogf,
          { "Opcode Group Field",                          "bthci_vendor.intel.opcode.ogf",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &bthci_cmd_ogf_vals_ext, 0xfc00,
            NULL, HFILL }
        },
        { &hf_intel_opcode_ocf,
          { "Opcode Command Field",                        "bthci_vendor.intel.opcode.ocf",
            FT_UINT16, BASE_HEX, VALS(intel_opcode_ocf_vals), 0x03ff,
            NULL, HFILL }
        },
        { &hf_intel_parameter_length,
          { "Parameter Total Length",                      "bthci_vendor.intel.parameter_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_number_of_allowed_command_packets,
          { "Number of Allowed Command Packets",           "bthci_vendor.intel.number_of_allowed_command_packets",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_event_code,
          { "Event Code",                                  "bthci_vendor.intel.event_code",
            FT_UINT8, BASE_HEX, VALS(intel_event_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_status,
          { "Status",                                      "bthci_vendor.intel.status",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &bthci_cmd_status_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_line,
          { "Line",                                        "bthci_vendor.intel.line",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_module,
          { "Module",                                      "bthci_vendor.intel.module",
            FT_UINT8, BASE_HEX, VALS(intel_module_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_reason,
          { "Reason",                                      "bthci_vendor.intel.reason",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_zero,
          { "Zero",                                        "bthci_vendor.intel.zero",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_number_of_packets,
          { "Number of Packets",                           "bthci_vendor.intel.number_of_packets",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_source,
          { "Source",                                      "bthci_vendor.intel.source",
            FT_UINT8, BASE_HEX, VALS(intel_source_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_reset_type,
          { "Reset Type",                                  "bthci_vendor.intel.reset_type",
            FT_UINT8, BASE_HEX, VALS(intel_reset_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_reset_reason,
          { "Reset Reason",                                "bthci_vendor.intel.reset_reason",
            FT_UINT8, BASE_HEX, VALS(intel_reset_reason_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_ddc_status,
          { "DDC Status",                                  "bthci_vendor.intel.ddc_status",
            FT_UINT8, BASE_HEX, VALS(intel_ddc_status_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_bd_data_status,
          { "BD Data Status",                              "bthci_vendor.intel.bd_data_status",
            FT_UINT8, BASE_HEX, VALS(intel_bd_data_status_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_secure_send_commands_result,
          { "Secure Send Commands Result",                 "bthci_vendor.intel.secure_send_commands_result",
            FT_UINT8, BASE_HEX, VALS(intel_secure_send_commands_result_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_handle,
          { "Handle",                                      "bthci_vendor.intel.handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_access_address,
          { "Access Address",                              "bthci_vendor.intel.access_address",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_scan_status,
          { "Scan Status",                                 "bthci_vendor.intel.scan_status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_scan_status_reserved,
          { "Reserved",                                    "bthci_vendor.intel.scan_status.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_intel_scan_status_page_scan,
          { "Page Scan",                                   "bthci_vendor.intel.scan_status.page_scan",
            FT_UINT8, BASE_HEX, NULL, 0x2,
            NULL, HFILL }
        },
        { &hf_intel_scan_status_inquiry_scan,
          { "Inquiry Scan",                                "bthci_vendor.intel.scan_status.inquiry_scan",
            FT_UINT8, BASE_HEX, NULL, 0x1,
            NULL, HFILL }
        },
        { &hf_intel_link_pdu_trace_type,
          { "Link PDU Trace Type",                         "bthci_vendor.intel.link_pdu_trace_type",
            FT_UINT8, BASE_HEX, VALS(intel_link_pdu_trace_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_link_clock,
          { "Clock",                                       "bthci_vendor.intel.clock",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_link_id,
          { "ID",                                          "bthci_vendor.intel.id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_link_count,
          { "Count",                                       "bthci_vendor.intel.count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_bd_addr,
          { "BD_ADDR",                                     "bthci_vendor.intel.bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "Bluetooth Device Address", HFILL}
        },
        { &hf_intel_packet_table,
          { "Packet Table",                                "bthci_vendor.intel.packet_table",
            FT_UINT8, BASE_HEX, VALS(intel_packet_table_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_exception_type,
          { "Exception Type",                              "bthci_vendor.intel.exception_type",
            FT_UINT8, BASE_HEX, VALS(intel_exception_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_reset_reset_type,
          { "Type",                                        "bthci_vendor.intel.reset.type",
            FT_UINT8, BASE_HEX, VALS(intel_reset_reset_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_reset_patch_enable,
          { "Patch Enable",                                "bthci_vendor.intel.reset.patch_enable",
            FT_UINT8, BASE_HEX, VALS(intel_reset_patch_enable_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_reset_ddc_reload,
          { "DDC Reload",                                  "bthci_vendor.intel.reset.ddc_reload",
            FT_UINT8, BASE_HEX, VALS(intel_reset_ddc_reload_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_reset_boot_option,
          { "Boot Option",                                 "bthci_vendor.intel.reset.boot.option",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_reset_boot_address,
          { "Boot Address",                                "bthci_vendor.intel.reset.boot.address",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_hardware_platform,
          { "Hardware Platform",                           "bthci_vendor.intel.hardware.platform",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_hardware_variant,
          { "Hardware Variant",                            "bthci_vendor.intel.hardware.variant",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_hardware_revision,
          { "Hardware Revision",                           "bthci_vendor.intel.hardware.revision",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_firmware_variant,
          { "Firmware Variant",                            "bthci_vendor.intel.firmware.variant",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_firmware_revision,
          { "Firmware Revision",                           "bthci_vendor.intel.firmware.revision",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_firmware_build_version_nn,
          { "Firmware Build Version nn",                   "bthci_vendor.intel.firmware.build_version.nn",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_firmware_build_version_cw,
          { "Firmware Build Version cw",                   "bthci_vendor.intel.firmware.build_version.cw",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_firmware_build_version_yy,
          { "Firmware Build Version yy",                   "bthci_vendor.intel.firmware.build_version.yy",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_firmware_patch,
          { "Firmware Patch",                              "bthci_vendor.intel.firmware.patch",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_identifier,
          { "Identifier",                                  "bthci_vendor.intel.identifier",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_secure_send_type,
          { "Type",                                        "bthci_vendor.intel.secure_send.type",
            FT_UINT8, BASE_HEX, VALS(intel_secure_send_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_manufacturer_mode,
          { "Manufacturer Mode",                            "bthci_vendor.intel.manufacturer.mode",
            FT_UINT8, BASE_HEX, VALS(intel_manufacturer_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_manufacturer_reset,
          { "Manufacturer Reset",                           "bthci_vendor.intel.manufacturer.reset",
            FT_UINT8, BASE_HEX, VALS(intel_manufacturer_reset_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_transmit_traces,
          { "Transmit Traces",                             "bthci_vendor.intel.transmit_traces",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_transmit_arq,
          { "Transmit ARQ",                                "bthci_vendor.intel.transmit_arq",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_receive_traces,
          { "Receive Traces",                              "bthci_vendor.intel.receive_traces",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_stimulated_exception_type,
          { "Stimulated Exception Type",                   "bthci_vendor.intel.stimulated_exception_type",
            FT_UINT8, BASE_HEX, VALS(intel_stimulated_exception_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_mem_address,
          { "Address",                                     "bthci_vendor.intel.mem.address",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_mem_mode,
          { "Mode",                                        "bthci_vendor.intel.mem.mode",
            FT_UINT8, BASE_HEX, VALS(intel_mem_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_intel_mem_length,
          { "Length",                                      "bthci_vendor.intel.mem.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_ddc_config_length,
          { "Length",                                      "bthci_vendor.intel.ddc_config.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_set_event_mask,
          { "Event Mask",                                  "bthci_vendor.intel.event_mask",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_intel_set_event_mask_reserved_15_63,
          { "Reserved",                                    "bthci_vendor.intel.event_mask.reserved.15_63",
            FT_UINT64, BASE_HEX, NULL, UINT64_C(0xFFFFFFFFFFFF8000),
            NULL, HFILL }
        },
        { &hf_intel_set_event_mask_firmware_trace_string,
          { "Firmware Trace String",                       "bthci_vendor.intel.event_mask.firmware_trace_string",
            FT_BOOLEAN, 64, NULL, 0x0000000000004000,
            NULL, HFILL }
        },
        { &hf_intel_set_event_mask_le_link_established,
          { "LE Link_Established",                         "bthci_vendor.intel.event_mask.le_link_established",
            FT_BOOLEAN, 64, NULL, 0x0000000000002000,
            NULL, HFILL }
        },
        { &hf_intel_set_event_mask_reserved_12,
          { "Reserved",                                    "bthci_vendor.intel.event_mask.reserved.12",
            FT_UINT64, BASE_HEX, NULL, 0x0000000000001000,
            NULL, HFILL }
        },
        { &hf_intel_set_event_mask_system_exception,
          { "System Exception",                            "bthci_vendor.intel.event_mask.system_exception",
            FT_BOOLEAN, 64, NULL, 0x0000000000000800,
            NULL, HFILL }
        },
        { &hf_intel_set_event_mask_fatal_exception,
          { "Fatal Exception",                             "bthci_vendor.intel.event_mask.fatal_exception",
            FT_BOOLEAN, 64, NULL, 0x0000000000000400,
            NULL, HFILL }
        },
        { &hf_intel_set_event_mask_debug_exception,
          { "Debug Exception",                             "bthci_vendor.intel.event_mask.debug_exception",
            FT_BOOLEAN, 64, NULL, 0x0000000000000200,
            NULL, HFILL }
        },
        { &hf_intel_set_event_mask_reserved_8,
          { "Reserved",                                    "bthci_vendor.intel.event_mask.reserved",
            FT_UINT64, BASE_HEX, NULL, 0x0000000000000100,
            NULL, HFILL }
        },
        { &hf_intel_set_event_mask_scan_status,
          { "Scan Status",                                 "bthci_vendor.intel.event_mask.scan_status",
            FT_BOOLEAN, 64, NULL, 0x0000000000000080,
            NULL, HFILL }
        },
        { &hf_intel_set_event_mask_reserved_3_6,
          { "Reserved",                                    "bthci_vendor.intel.event_mask.reserved.3_6",
            FT_UINT64, BASE_HEX, NULL, 0x0000000000000078,
            NULL, HFILL }
        },
        { &hf_intel_set_event_mask_ptt_switch_notification,
          { "PTT Switch Notification",                     "bthci_vendor.intel.event_mask.ptt_switch_notification",
            FT_BOOLEAN, 64, NULL, 0x0000000000000004,
            NULL, HFILL }
        },
        { &hf_intel_set_event_mask_sco_rejected_via_lmp,
          { "SCO Rejected via LMP",                        "bthci_vendor.intel.event_mask.sco_rejected_via_lmp",
            FT_BOOLEAN, 64, NULL, 0x0000000000000002,
            NULL, HFILL }
        },
        { &hf_intel_set_event_mask_bootup,
          { "Bootup",                                      "bthci_vendor.intel.event_mask.bootup",
            FT_BOOLEAN, 64, NULL, 0x0000000000000001,
            NULL, HFILL }
        },
        { &hf_intel_data,
            { "Data",                                      "bthci_vendor.intel.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_intel,
        &ett_intel_opcode,
        &ett_intel_scan_status,
        &ett_intel_set_event_mask
    };

    static ei_register_info ei[] = {
        { &ei_intel_undecoded,             { "bthci_vendor.intel.undecoded",            PI_UNDECODED, PI_NOTE, "Undecoded", EXPFILL }},
        { &ei_intel_unexpected_parameter,  { "bthci_vendor.intel.unexpected_parameter", PI_PROTOCOL, PI_WARN,  "Unexpected parameter", EXPFILL }},
        { &ei_intel_unexpected_data,       { "bthci_vendor.intel.unexpected_data",      PI_PROTOCOL, PI_WARN,  "Unexpected data", EXPFILL }},
    };

    proto_bthci_vendor_intel = proto_register_protocol("Bluetooth Intel HCI",
            "HCI Intel", "bthci_vendor.intel");

    bthci_vendor_intel_handle = register_dissector("bthci_vendor.intel", dissect_bthci_vendor_intel, proto_bthci_vendor_intel);

    proto_register_field_array(proto_bthci_vendor_intel, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module = expert_register_protocol(proto_bthci_vendor_intel);
    expert_register_field_array(expert_module, ei, array_length(ei));
}

void
proto_reg_handoff_bthci_vendor_intel(void)
{
    btlmp_handle = find_dissector_add_dependency("btlmp", proto_bthci_vendor_intel);
    btle_handle  = find_dissector_add_dependency("btle",  proto_bthci_vendor_intel);

    dissector_add_for_decode_as("bthci_cmd.vendor", bthci_vendor_intel_handle);

    dissector_add_uint("bluetooth.vendor", 0x0002, bthci_vendor_intel_handle);
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
