/* file-ttl.c
 *
 * TTX Logger (TTL) file format from TTTech Computertechnik AG dissector by
 * Giovanni Musto <giovanni.musto@partner.italdesign.it>
 * Copyright 2024 Giovanni Musto
 *
 * This dissector allows to parse TTL files.
 * You can find the PDF with the documentation of the format at
 * https://servicearea.tttech-auto.com/ (registration and approval required).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tvbuff.h>
#include <epan/tfs.h>

#include <wiretap/ttl.h>

static int proto_ttl;

static dissector_handle_t xml_handle;

static int hf_ttl_header;
static int hf_ttl_header_magic;
static int hf_ttl_header_file_format_version;
static int hf_ttl_header_block_size;
static int hf_ttl_header_header_size;
static int hf_ttl_header_logfile_info;

static int hf_ttl_header_logfile_info_logger_sn;
static int hf_ttl_header_logfile_info_logger_sw_version;
static int hf_ttl_header_logfile_info_measurement_creation_date;
static int hf_ttl_header_logfile_info_measurement_creation_timestamp;
static int hf_ttl_header_logfile_info_supplier_name;
static int hf_ttl_header_logfile_info_description;
static int hf_ttl_header_logfile_info_hw_version;
static int hf_ttl_header_logfile_info_configuration_file_name;
static int hf_ttl_header_logfile_info_tracefile_sorted;
static int hf_ttl_header_logfile_info_tracefile_split_index;
static int hf_ttl_header_logfile_info_completion_date;
static int hf_ttl_header_logfile_info_completion_timestamp;
static int hf_ttl_header_logfile_info_tc_sw_bootloader_version;
static int hf_ttl_header_logfile_info_tc_sw_firmware_version;
static int hf_ttl_header_logfile_info_most25_fw_version;
static int hf_ttl_header_logfile_info_most150_fw_version;
static int hf_ttl_header_logfile_info_split_file_creation_date;
static int hf_ttl_header_logfile_info_split_file_creation_timestamp;
static int hf_ttl_header_logfile_info_unused_bytes;
static int hf_ttl_header_logfile_info_sleep_counter;
static int hf_ttl_header_logfile_info_reserved_bytes;
static int hf_ttl_header_configuration;

static int hf_ttl_trace_data;
static int hf_ttl_block;
static int hf_ttl_trace_data_entry;
static int hf_ttl_trace_data_entry_size;
static int hf_ttl_trace_data_entry_type;
static int hf_ttl_trace_data_entry_dest_addr;
static int hf_ttl_trace_data_entry_dest_addr_cascade;
static int hf_ttl_trace_data_entry_dest_addr_device_logger;
static int hf_ttl_trace_data_entry_dest_addr_device_tap;
static int hf_ttl_trace_data_entry_dest_addr_function_fpga;
static int hf_ttl_trace_data_entry_dest_addr_function_atom;
static int hf_ttl_trace_data_entry_dest_addr_function_tricore1;
static int hf_ttl_trace_data_entry_dest_addr_function_tricore2;
static int hf_ttl_trace_data_entry_dest_addr_function_tricore3;
static int hf_ttl_trace_data_entry_dest_addr_function_tda4x;
static int hf_ttl_trace_data_entry_dest_addr_function_fpgaa;
static int hf_ttl_trace_data_entry_dest_addr_function_fpgab;
static int hf_ttl_trace_data_entry_dest_addr_function_pt15_fpga;
static int hf_ttl_trace_data_entry_dest_addr_function_pt20_fpga;
static int hf_ttl_trace_data_entry_dest_addr_function_pc3_fpga;
static int hf_ttl_trace_data_entry_dest_addr_function_pc3_aurix;
static int hf_ttl_trace_data_entry_dest_addr_function_zelda_canfd;
static int hf_ttl_trace_data_entry_dest_addr_function_zelda_lin;
static int hf_ttl_trace_data_entry_dest_addr_function_unknown;
static int hf_ttl_trace_data_entry_meta1;
static int hf_ttl_trace_data_entry_meta1_frame_duplication;
static int hf_ttl_trace_data_entry_meta1_compressed_format;
static int hf_ttl_trace_data_entry_meta1_timestamp_source;
static int hf_ttl_trace_data_entry_src_addr;
static int hf_ttl_trace_data_entry_src_addr_cascade;
static int hf_ttl_trace_data_entry_src_addr_device_logger;
static int hf_ttl_trace_data_entry_src_addr_device_tap;
static int hf_ttl_trace_data_entry_src_addr_function_fpga;
static int hf_ttl_trace_data_entry_src_addr_function_atom;
static int hf_ttl_trace_data_entry_src_addr_function_tricore1;
static int hf_ttl_trace_data_entry_src_addr_function_tricore2;
static int hf_ttl_trace_data_entry_src_addr_function_tricore3;
static int hf_ttl_trace_data_entry_src_addr_function_tda4x;
static int hf_ttl_trace_data_entry_src_addr_function_fpgaa;
static int hf_ttl_trace_data_entry_src_addr_function_fpgab;
static int hf_ttl_trace_data_entry_src_addr_function_pt15_fpga;
static int hf_ttl_trace_data_entry_src_addr_function_pt20_fpga;
static int hf_ttl_trace_data_entry_src_addr_function_pc3_fpga;
static int hf_ttl_trace_data_entry_src_addr_function_pc3_aurix;
static int hf_ttl_trace_data_entry_src_addr_function_zelda_canfd;
static int hf_ttl_trace_data_entry_src_addr_function_zelda_lin;
static int hf_ttl_trace_data_entry_src_addr_function_unknown;
static int hf_ttl_trace_data_entry_meta2;
static int hf_ttl_trace_data_entry_ackmode;

static int hf_ttl_trace_data_entry_status_information;
static int hf_ttl_trace_data_entry_status_info_eth_type;
static int hf_ttl_trace_data_entry_status_info_can_flags;
static int hf_ttl_trace_data_entry_status_info_can_valid_frame;
static int hf_ttl_trace_data_entry_status_info_can_remote_frame;
static int hf_ttl_trace_data_entry_status_info_can_bus_off;
static int hf_ttl_trace_data_entry_status_info_can_matched;
static int hf_ttl_trace_data_entry_status_info_can_error_code;
static int hf_ttl_trace_data_entry_status_info_can_res;
static int hf_ttl_trace_data_entry_status_info_can_dlc;
static int hf_ttl_trace_data_entry_status_info_can_ide;
static int hf_ttl_trace_data_entry_status_info_can_edl;
static int hf_ttl_trace_data_entry_status_info_can_brs;
static int hf_ttl_trace_data_entry_status_info_can_esi;
static int hf_ttl_trace_data_entry_status_info_lin_pid;
static int hf_ttl_trace_data_entry_status_info_lin_id;
static int hf_ttl_trace_data_entry_status_info_lin_parity;
static int hf_ttl_trace_data_entry_status_info_lin_flags;
static int hf_ttl_trace_data_entry_status_info_lin_parity_error;
static int hf_ttl_trace_data_entry_status_info_lin_sync_error;
static int hf_ttl_trace_data_entry_status_info_lin_2_checksum_error;
static int hf_ttl_trace_data_entry_status_info_lin_1_checksum_error;
static int hf_ttl_trace_data_entry_status_info_lin_no_data_error;
static int hf_ttl_trace_data_entry_status_info_lin_abort_error;
static int hf_ttl_trace_data_entry_status_info_lin_unused;
static int hf_ttl_trace_data_entry_status_info_fr_type;
static int hf_ttl_trace_data_entry_status_info_fr_matched;
static int hf_ttl_trace_data_entry_status_info_fr_res1;
static int hf_ttl_trace_data_entry_status_info_fr_error_flags;
static int hf_ttl_trace_data_entry_status_info_fr_fss_error;
static int hf_ttl_trace_data_entry_status_info_fr_bss_error;
static int hf_ttl_trace_data_entry_status_info_fr_fes_error;
static int hf_ttl_trace_data_entry_status_info_fr_frame_crc_error;
static int hf_ttl_trace_data_entry_status_info_fr_header_crc_error;
static int hf_ttl_trace_data_entry_status_info_fr_idle_error;
static int hf_ttl_trace_data_entry_status_info_fr_res2;
static int hf_ttl_trace_data_entry_status_info_fr_res3;
static int hf_ttl_trace_data_entry_status_info_fr_low_phase_exceeded;
static int hf_ttl_trace_data_entry_status_info_fr_res4;
static int hf_ttl_trace_data_entry_status_info_fr_pulse_flags;
static int hf_ttl_trace_data_entry_status_info_fr_cas;
static int hf_ttl_trace_data_entry_status_info_fr_mts;
static int hf_ttl_trace_data_entry_status_info_fr_wup;
static int hf_ttl_trace_data_entry_status_info_fr_res5;

static int hf_ttl_trace_data_entry_timestamp;
static int hf_ttl_trace_data_entry_unparsed;
static int hf_ttl_trace_data_entry_payload;
static int hf_ttl_eth_phy_status;
static int hf_ttl_eth_phy_status_data;
static int hf_ttl_eth_phy_status_reg_addr;
static int hf_ttl_eth_phy_status_unused;
static int hf_ttl_eth_phy_status_res1;
static int hf_ttl_eth_phy_status_phy_addr;
static int hf_ttl_eth_phy_status_res2;
static int hf_ttl_eth_phy_status_valid;
static int hf_ttl_trace_data_entry_eth_unused;
static int hf_ttl_trace_data_entry_can_id;
static int hf_ttl_trace_data_entry_lin_checksum;
static int hf_ttl_trace_data_entry_fr_low_phase_counter;
static int hf_ttl_trace_data_entry_fr_unused;
static int hf_ttl_trace_data_entry_fr_eray_eir_register;
static int hf_ttl_trace_data_entry_fr_eray_stpw1_register;
static int hf_ttl_trace_data_entry_fr_eray_stpw2_register;
static int hf_ttl_trace_data_entry_fr_eray_ccsv_register;
static int hf_ttl_trace_data_entry_fr_eray_ccev_register;
static int hf_ttl_trace_data_entry_fr_eray_swnit_register;
static int hf_ttl_trace_data_entry_fr_eray_acs_register;


static expert_field ei_ttl_block_size_too_short;
static expert_field ei_ttl_header_size_too_short;
static expert_field ei_ttl_header_size_implausible;
static expert_field ei_ttl_header_logfile_info_too_short;
static expert_field ei_ttl_entry_size_too_short;

static int ett_ttl;
static int ett_ttl_header;
static int ett_ttl_header_logfile_info;
static int ett_ttl_header_configuration;
static int ett_ttl_trace_data;
static int ett_ttl_block;
static int ett_ttl_trace_data_entry;
static int ett_ttl_trace_data_entry_dest_addr;
static int ett_ttl_trace_data_entry_src_addr;
static int ett_ttl_trace_data_entry_meta1;
static int ett_ttl_trace_data_entry_status_information;
static int ett_ttl_trace_data_entry_status_info_can_flags;
static int ett_ttl_trace_data_entry_status_info_lin_flags;
static int ett_ttl_trace_data_entry_status_info_lin_pid;
static int ett_ttl_trace_data_entry_status_info_fr_error_flags;
static int ett_ttl_trace_data_entry_status_info_fr_pulse_flags;
static int ett_ttl_trace_data_entry_payload;
static int ett_ttl_eth_phy_status;

static const value_string hf_ttl_header_logfile_info_tracefile_sorted_vals[] = {
    { '0',  "Not Sorted" },
    { '1',  "Sorted" },
    { 0, NULL }
};

static const value_string hf_ttl_trace_data_entry_type_vals[] = {
    { TTL_BUS_DATA_ENTRY,           "Bus Data Entry" },
    { TTL_COMMAND_ENTRY,            "Command Entry" },
    { TTL_BUS_RESERVED1_ENTRY,      "Reserved" },
    { TTL_JOURNAL_ENTRY,            "Journal Entry" },
    { TTL_SEGMENTED_MESSAGE_ENTRY,  "Segmented Message Entry" },
    { TTL_SEND_FRAME_ENTRY,         "Send-Frame Entry" },
    { TTL_PADDING_ENTRY,            "Padding Entry" },
    { TTL_SOFTWARE_DATA_ENTRY,      "Software Data Entry" },
    { TTL_DROPPED_FRAMES_ENTRY,     "Dropped Frames Entry" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_cascade_vals[] = {
    { 0,    "Logger" },
    { 1,    "TAP 1" },
    { 2,    "TAP 2" },
    { 3,    "TAP 3" },
    { 4,    "TAP 4" },
    { 5,    "TAP 5" },
    { 6,    "TAP 6" },
    { 7,    "TAP 7" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_logger_device_vals[] = {
    { TTL_LOGGER_DEVICE_FPGA,       "FPGA" },
    { TTL_LOGGER_DEVICE_ATOM,       "Atom" },
    { TTL_LOGGER_DEVICE_TRICORE1,   "Tricore 1" },
    { TTL_LOGGER_DEVICE_TRICORE2,   "Tricore 2" },
    { TTL_LOGGER_DEVICE_TRICORE3,   "Tricore 3" },
    { TTL_LOGGER_DEVICE_TDA4x,      "TDA 4x" },
    { TTL_LOGGER_DEVICE_FPGAA,      "FPGA A" },
    { TTL_LOGGER_DEVICE_FPGAB,      "FPGA B" },
    { 15,                           "Not allowed" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_tap_device_vals[] = {
    { TTL_TAP_DEVICE_PT15_FPGA,         "PT-15B/PT15-CG FPGA" },
    { TTL_TAP_DEVICE_PT15_HPS_LINUX,    "PT-15B/PT15-CG HPS Linux" },
    { TTL_TAP_DEVICE_PT20_FPGA,         "PT-20MG FPGA" },
    { TTL_TAP_DEVICE_PT20_HPS_LINUX,    "PT-20MG HPS Linux" },
    { TTL_TAP_DEVICE_PC3_FPGA,          "PC-3 FPGA" },
    { TTL_TAP_DEVICE_PC3_HPS_LINUX,     "PC-3 HPS Linux" },
    { TTL_TAP_DEVICE_PC3_AURIX,         "PC-3 Aurix" },
    { TTL_TAP_DEVICE_ZELDA_CANFD,       "Zelda CAN-FD" },
    { TTL_TAP_DEVICE_ZELDA_LIN,         "Zelda LIN" },
    { TTL_TAP_DEVICE_ILLEGAL,           "Not allowed" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_logger_fpga_function_vals[] = {
    { TTL_LOGGER_FPGA_FUNCTION_CORE,            "Core" },
    { TTL_LOGGER_FPGA_FUNCTION_EXT0_MOST25,     "MOST25" },
    { TTL_LOGGER_FPGA_FUNCTION_EXT0_MOST150,    "MOST150" },
    { TTL_LOGGER_FPGA_FUNCTION_ETHA_CH1,        "ETH A (CH1)" },
    { TTL_LOGGER_FPGA_FUNCTION_ETHB_CH1,        "ETH B (CH1)" },
    { TTL_LOGGER_FPGA_FUNCTION_FLEXRAY1A,       "FlexRay 1A" },
    { TTL_LOGGER_FPGA_FUNCTION_FLEXRAY1B,       "FlexRay 1B" },
    { TTL_LOGGER_FPGA_FUNCTION_FLEXRAY2A,       "FlexRay 2A" },
    { TTL_LOGGER_FPGA_FUNCTION_FLEXRAY2B,       "FlexRay 2B" },
    { TTL_LOGGER_FPGA_FUNCTION_FLEXRAY3A,       "FlexRay 3A" },
    { TTL_LOGGER_FPGA_FUNCTION_FLEXRAY3B,       "FlexRay 3B" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN1,            "CAN 1" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN2,            "CAN 2" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN3,            "CAN 3" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN4,            "CAN 4" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN12,           "CAN 12" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN6,            "CAN 6" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN7,            "CAN 7" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN10,           "CAN 10" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN11,           "CAN 11" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN8,            "CAN 8" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN5,            "CAN 5" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN9,            "CAN 9" },
    { TTL_LOGGER_FPGA_FUNCTION_EXT1_MOST25,     "MOST25 (Expansion Slot 1)" },
    { TTL_LOGGER_FPGA_FUNCTION_LIN10,           "LIN 10" },
    { TTL_LOGGER_FPGA_FUNCTION_LIN3,            "LIN 3" },
    { TTL_LOGGER_FPGA_FUNCTION_LIN5,            "LIN 5" },
    { TTL_LOGGER_FPGA_FUNCTION_LIN4,            "LIN 4" },
    { TTL_LOGGER_FPGA_FUNCTION_LIN11,           "LIN 11" },
    { TTL_LOGGER_FPGA_FUNCTION_LIN1,            "LIN 1" },
    { TTL_LOGGER_FPGA_FUNCTION_LIN7,            "LIN 7" },
    { TTL_LOGGER_FPGA_FUNCTION_LIN8,            "LIN 8" },
    { TTL_LOGGER_FPGA_FUNCTION_LIN12,           "LIN 12" },
    { TTL_LOGGER_FPGA_FUNCTION_LIN6,            "LIN 6" },
    { TTL_LOGGER_FPGA_FUNCTION_LIN2,            "LIN 2" },
    { TTL_LOGGER_FPGA_FUNCTION_LIN9,            "LIN 9" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN13,           "CAN 13" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN14,           "CAN 14" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN15,           "CAN 15" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN16,           "CAN 16" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN17,           "CAN 17" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN18,           "CAN 18" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN19,           "CAN 19" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN20,           "CAN 20" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN21,           "CAN 21" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN22,           "CAN 22" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN23,           "CAN 23" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN24,           "CAN 24" },
    { TTL_LOGGER_FPGA_FUNCTION_ETHA_CH2,        "ETH A (CH2)" },
    { TTL_LOGGER_FPGA_FUNCTION_ETHB_CH2,        "ETH B (CH2)" },
    { TTL_LOGGER_FPGA_FUNCTION_ETHA_CH3,        "ETH A (CH3)" },
    { TTL_LOGGER_FPGA_FUNCTION_ETHB_CH3,        "ETH B (CH3)" },
    { TTL_LOGGER_FPGA_FUNCTION_CAN_EXT_BOARD,   "CAN Extension Board" },
    { TTL_LOGGER_FPGA_FUNCTION_RESERVED1,       "Reserved" },
    { TTL_LOGGER_FPGA_FUNCTION_SLOT_CTRL,       "SLOT_CTRL" },
    { TTL_LOGGER_FPGA_FUNCTION_DRAM,            "DRAM" },
    { TTL_LOGGER_FPGA_FUNCTION_SINK,            "Sink" },
    { TTL_LOGGER_FPGA_FUNCTION_POWER_AGENT,     "Power Agent" },
    { TTL_LOGGER_FPGA_FUNCTION_PKT_GENERATOR,   "Packet Generator" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_logger_atom_function_vals[] = {
    { TTL_LOGGER_ATOM_FUNCTION_FRAME_DEVICE,        "Frame Device" },
    { TTL_LOGGER_ATOM_FUNCTION_CHARACTER_DEVICE,    "Character Device" },
    { TTL_LOGGER_ATOM_FUNCTION_ATMEL,               "Atmel" },
    { TTL_LOGGER_ATOM_FUNCTION_ETHA,                "ETH-A" },
    { TTL_LOGGER_ATOM_FUNCTION_ETHB,                "ETH-B" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_logger_tricore1_function_vals[] = {
    { TTL_LOGGER_TRICORE1_FUNCTION_CORE,        "Core" },
    { TTL_LOGGER_TRICORE1_FUNCTION_FLEXRAY1A,   "FlexRay 1A" },
    { TTL_LOGGER_TRICORE1_FUNCTION_FLEXRAY1B,   "FlexRay 1B" },
    { TTL_LOGGER_TRICORE1_FUNCTION_CAN1,        "CAN 1" },
    { TTL_LOGGER_TRICORE1_FUNCTION_CAN2,        "CAN 2" },
    { TTL_LOGGER_TRICORE1_FUNCTION_CAN3,        "CAN 3" },
    { TTL_LOGGER_TRICORE1_FUNCTION_CAN4,        "CAN 4" },
    { TTL_LOGGER_TRICORE1_FUNCTION_ANALOGOUT1,  "Analog Out 1" },
    { TTL_LOGGER_TRICORE1_FUNCTION_DIGITALOUT6, "Digital Out 6" },
    { TTL_LOGGER_TRICORE1_FUNCTION_DIGITALOUT5, "Digital Out 5" },
    { TTL_LOGGER_TRICORE1_FUNCTION_RESERVED1,   "Reserved" },
    { TTL_LOGGER_TRICORE1_FUNCTION_RESERVED2,   "Reserved" },
    { TTL_LOGGER_TRICORE1_FUNCTION_SERIAL1,     "RS232 1" },
    { TTL_LOGGER_TRICORE1_FUNCTION_SERIAL2,     "RS232 2" },
    { TTL_LOGGER_TRICORE1_FUNCTION_ANALOGIN6,   "Analog In 6" },
    { TTL_LOGGER_TRICORE1_FUNCTION_ANALOGIN8,   "Analog In 8" },
    { TTL_LOGGER_TRICORE1_FUNCTION_ANALOGIN14,  "Analog In 14" },
    { TTL_LOGGER_TRICORE1_FUNCTION_ANALOGIN15,  "Analog In 15" },
    { TTL_LOGGER_TRICORE1_FUNCTION_ANALOGIN11,  "Analog In 11" },
    { TTL_LOGGER_TRICORE1_FUNCTION_DIGITALIN8,  "Digital In 8" },
    { TTL_LOGGER_TRICORE1_FUNCTION_DIGITALIN10, "Digital In 10" },
    { TTL_LOGGER_TRICORE1_FUNCTION_DIGITALIN12, "Digital In 12" },
    { TTL_LOGGER_TRICORE1_FUNCTION_DIGITALIN13, "Digital In 13" },
    { TTL_LOGGER_TRICORE1_FUNCTION_DIGITALIN11, "Digital In 11" },
    { TTL_LOGGER_TRICORE1_FUNCTION_KL15IN,      "KL15 Input" },
    { TTL_LOGGER_TRICORE1_FUNCTION_KL30IN,      "KL30 Input" },
    { TTL_LOGGER_TRICORE1_FUNCTION_FLEXRAY1,    "FlexRay 1" },
    { TTL_LOGGER_TRICORE1_FUNCTION_FLEXRAY1AB,  "FlexRay 1AB" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_logger_tricore2_function_vals[] = {
    { TTL_LOGGER_TRICORE2_FUNCTION_CORE,        "Core" },
    { TTL_LOGGER_TRICORE2_FUNCTION_FLEXRAY2A,   "FlexRay 2A" },
    { TTL_LOGGER_TRICORE2_FUNCTION_FLEXRAY2B,   "FlexRay 2B" },
    { TTL_LOGGER_TRICORE2_FUNCTION_CAN12,       "CAN 12" },
    { TTL_LOGGER_TRICORE2_FUNCTION_CAN6,        "CAN 6" },
    { TTL_LOGGER_TRICORE2_FUNCTION_CAN7,        "CAN 7" },
    { TTL_LOGGER_TRICORE2_FUNCTION_CAN10,       "CAN 10" },
    { TTL_LOGGER_TRICORE2_FUNCTION_ANALOGOUT2,  "Analog Out 2" },
    { TTL_LOGGER_TRICORE2_FUNCTION_DIGITALOUT4, "Digital Out 4" },
    { TTL_LOGGER_TRICORE2_FUNCTION_DIGITALOUT3, "Digital Out 3" },
    { TTL_LOGGER_TRICORE2_FUNCTION_RESERVED1,   "Reserved" },
    { TTL_LOGGER_TRICORE2_FUNCTION_RESERVED2,   "Reserved" },
    { TTL_LOGGER_TRICORE2_FUNCTION_SERIAL3,     "RS232 3" },
    { TTL_LOGGER_TRICORE2_FUNCTION_SERIAL4,     "RS232 4" },
    { TTL_LOGGER_TRICORE2_FUNCTION_ANALOGIN4,   "Analog In 4" },
    { TTL_LOGGER_TRICORE2_FUNCTION_ANALOGIN3,   "Analog In 3" },
    { TTL_LOGGER_TRICORE2_FUNCTION_ANALOGIN5,   "Analog In 5" },
    { TTL_LOGGER_TRICORE2_FUNCTION_ANALOGIN9,   "Analog In 9" },
    { TTL_LOGGER_TRICORE2_FUNCTION_ANALOGIN7,   "Analog In 7" },
    { TTL_LOGGER_TRICORE2_FUNCTION_DIGITALIN14, "Digital In 14" },
    { TTL_LOGGER_TRICORE2_FUNCTION_DIGITALIN9,  "Digital In 9" },
    { TTL_LOGGER_TRICORE2_FUNCTION_DIGITALIN15, "Digital In 15" },
    { TTL_LOGGER_TRICORE2_FUNCTION_DIGITALIN7,  "Digital In 7" },
    { TTL_LOGGER_TRICORE2_FUNCTION_DIGITALIN6,  "Digital In 6" },
    { TTL_LOGGER_TRICORE2_FUNCTION_FLEXRAY2,    "FlexRay 2" },
    { TTL_LOGGER_TRICORE2_FUNCTION_FLEXRAY2AB,  "FlexRay 2AB" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_logger_tricore3_function_vals[] = {
    { TTL_LOGGER_TRICORE3_FUNCTION_CORE,        "Core" },
    { TTL_LOGGER_TRICORE3_FUNCTION_FLEXRAY3A,   "FlexRay 3A" },
    { TTL_LOGGER_TRICORE3_FUNCTION_FLEXRAY3B,   "FlexRay 3B" },
    { TTL_LOGGER_TRICORE3_FUNCTION_CAN11,       "CAN 11" },
    { TTL_LOGGER_TRICORE3_FUNCTION_CAN8,        "CAN 8" },
    { TTL_LOGGER_TRICORE3_FUNCTION_CAN5,        "CAN 5" },
    { TTL_LOGGER_TRICORE3_FUNCTION_CAN9,        "CAN 9" },
    { TTL_LOGGER_TRICORE3_FUNCTION_ANALOGOUT3,  "Analog Out 3" },
    { TTL_LOGGER_TRICORE3_FUNCTION_DIGITALOUT2, "Digital Out 2" },
    { TTL_LOGGER_TRICORE3_FUNCTION_DIGITALOUT1, "Digital Out 1" },
    { TTL_LOGGER_TRICORE3_FUNCTION_RESERVED1,   "Reserved" },
    { TTL_LOGGER_TRICORE3_FUNCTION_RESERVED2,   "Reserved" },
    { TTL_LOGGER_TRICORE3_FUNCTION_SERIAL5,     "RS232 5" },
    { TTL_LOGGER_TRICORE3_FUNCTION_SERIAL6,     "RS232 6" },
    { TTL_LOGGER_TRICORE3_FUNCTION_ANALOGIN1,   "Analog In 1" },
    { TTL_LOGGER_TRICORE3_FUNCTION_ANALOGIN2,   "Analog In 2" },
    { TTL_LOGGER_TRICORE3_FUNCTION_ANALOGIN10,  "Analog In 10" },
    { TTL_LOGGER_TRICORE3_FUNCTION_ANALOGIN12,  "Analog In 12" },
    { TTL_LOGGER_TRICORE3_FUNCTION_ANALOGIN13,  "Analog In 13" },
    { TTL_LOGGER_TRICORE3_FUNCTION_DIGITALIN5,  "Digital In 5" },
    { TTL_LOGGER_TRICORE3_FUNCTION_DIGITALIN4,  "Digital In 4" },
    { TTL_LOGGER_TRICORE3_FUNCTION_DIGITALIN3,  "Digital In 3" },
    { TTL_LOGGER_TRICORE3_FUNCTION_DIGITALIN2,  "Digital In 2" },
    { TTL_LOGGER_TRICORE3_FUNCTION_DIGITALIN1,  "Digital In 1" },
    { TTL_LOGGER_TRICORE3_FUNCTION_FLEXRAY3,    "FlexRay 3" },
    { TTL_LOGGER_TRICORE3_FUNCTION_FLEXRAY3AB,  "FlexRay 3AB" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_logger_tda4x_function_vals[] = {
    { TTL_LOGGER_TDA4x_FUNCTION_CORE,               "Core" },
    { TTL_LOGGER_TDA4x_FUNCTION_CHARACTER_DEVICE,   "Character Device" },
    { TTL_LOGGER_TDA4x_FUNCTION_CAN1,               "CAN 1" },
    { TTL_LOGGER_TDA4x_FUNCTION_CAN2,               "CAN 2" },
    { TTL_LOGGER_TDA4x_FUNCTION_CAN3,               "CAN 3" },
    { TTL_LOGGER_TDA4x_FUNCTION_CAN4,               "CAN 4" },
    { TTL_LOGGER_TDA4x_FUNCTION_CAN5,               "CAN 5" },
    { TTL_LOGGER_TDA4x_FUNCTION_CAN6,               "CAN 6" },
    { TTL_LOGGER_TDA4x_FUNCTION_CAN7,               "CAN 7" },
    { TTL_LOGGER_TDA4x_FUNCTION_CAN8,               "CAN 8" },
    { TTL_LOGGER_TDA4x_FUNCTION_CAN9,               "CAN 9" },
    { TTL_LOGGER_TDA4x_FUNCTION_CAN10,              "CAN 10" },
    { TTL_LOGGER_TDA4x_FUNCTION_CAN11,              "CAN 11" },
    { TTL_LOGGER_TDA4x_FUNCTION_SERIAL1,            "RS232 1" },
    { TTL_LOGGER_TDA4x_FUNCTION_SERIAL2,            "RS232 2" },
    { TTL_LOGGER_TDA4x_FUNCTION_SERIAL3,            "RS232 3" },
    { TTL_LOGGER_TDA4x_FUNCTION_SERIAL4,            "RS232 4" },
    { TTL_LOGGER_TDA4x_FUNCTION_SERIAL5,            "RS232 5" },
    { TTL_LOGGER_TDA4x_FUNCTION_SERIAL6,            "RS232 6" },
    { TTL_LOGGER_TDA4x_FUNCTION_ANALOGIN1,          "Analog In 1" },
    { TTL_LOGGER_TDA4x_FUNCTION_ANALOGIN2,          "Analog In 2" },
    { TTL_LOGGER_TDA4x_FUNCTION_ANALOGIN3,          "Analog In 3" },
    { TTL_LOGGER_TDA4x_FUNCTION_ANALOGIN4,          "Analog In 4" },
    { TTL_LOGGER_TDA4x_FUNCTION_ANALOGIN5,          "Analog In 5" },
    { TTL_LOGGER_TDA4x_FUNCTION_ANALOGIN6,          "Analog In 6" },
    { TTL_LOGGER_TDA4x_FUNCTION_ANALOGOUT1,         "Analog Out 1" },
    { TTL_LOGGER_TDA4x_FUNCTION_ANALOGOUT2,         "Analog Out 2" },
    { TTL_LOGGER_TDA4x_FUNCTION_KL15IN,             "KL15 Input" },
    { TTL_LOGGER_TDA4x_FUNCTION_KL30IN,             "KL30 Input" },
    { TTL_LOGGER_TDA4x_FUNCTION_FLEXRAY1A,          "FlexRay 1A" },
    { TTL_LOGGER_TDA4x_FUNCTION_FLEXRAY1B,          "FlexRay 1B" },
    { TTL_LOGGER_TDA4x_FUNCTION_FLEXRAY1AB,         "FlexRay 1AB" },
    { TTL_LOGGER_TDA4x_FUNCTION_CAN12,              "CAN 12" },
    { TTL_LOGGER_TDA4x_FUNCTION_CAN13,              "CAN 13" },
    { TTL_LOGGER_TDA4x_FUNCTION_CAN14,              "CAN 14" },
    { TTL_LOGGER_TDA4x_FUNCTION_SERIAL7,            "RS232 7" },
    { TTL_LOGGER_TDA4x_FUNCTION_SERIAL8,            "RS232 8" },
    { TTL_LOGGER_TDA4x_FUNCTION_SERIAL9,            "RS232 9" },
    { TTL_LOGGER_TDA4x_FUNCTION_SERIAL10,           "RS232 10" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_logger_fpgaa_function_vals[] = {
    { TTL_LOGGER_FPGAA_FUNCTION_CORE,           "Core" },
    { TTL_LOGGER_FPGAA_FUNCTION_CAN1,           "CAN 1" },
    { TTL_LOGGER_FPGAA_FUNCTION_CAN2,           "CAN 2" },
    { TTL_LOGGER_FPGAA_FUNCTION_CAN3,           "CAN 3" },
    { TTL_LOGGER_FPGAA_FUNCTION_CAN4,           "CAN 4" },
    { TTL_LOGGER_FPGAA_FUNCTION_CAN5,           "CAN 5" },
    { TTL_LOGGER_FPGAA_FUNCTION_CAN6,           "CAN 6" },
    { TTL_LOGGER_FPGAA_FUNCTION_CAN7,           "CAN 7" },
    { TTL_LOGGER_FPGAA_FUNCTION_CAN8,           "CAN 8" },
    { TTL_LOGGER_FPGAA_FUNCTION_CAN9,           "CAN 9" },
    { TTL_LOGGER_FPGAA_FUNCTION_CAN10,          "CAN 10" },
    { TTL_LOGGER_FPGAA_FUNCTION_CAN11,          "CAN 11" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN1,           "LIN 1" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN2,           "LIN 2" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN3,           "LIN 3" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN4,           "LIN 4" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN5,           "LIN 5" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN6,           "LIN 6" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN7,           "LIN 7" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN8,           "LIN 8" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN9,           "LIN 9" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN10,          "LIN 10" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN11,          "LIN 11" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN12,          "LIN 12" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN13,          "LIN 13" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN14,          "LIN 14" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN15,          "LIN 15" },
    { TTL_LOGGER_FPGAA_FUNCTION_LIN16,          "LIN 16" },
    { TTL_LOGGER_FPGAA_FUNCTION_FLEXRAY1A,      "FlexRay 1A" },
    { TTL_LOGGER_FPGAA_FUNCTION_FLEXRAY1B,      "FlexRay 1B" },
    { TTL_LOGGER_FPGAA_FUNCTION_SERIAL1,        "RS232 1" },
    { TTL_LOGGER_FPGAA_FUNCTION_SERIAL2,        "RS232 2" },
    { TTL_LOGGER_FPGAA_FUNCTION_SERIAL3,        "RS232 3" },
    { TTL_LOGGER_FPGAA_FUNCTION_SERIAL4,        "RS232 4" },
    { TTL_LOGGER_FPGAA_FUNCTION_SERIAL5,        "RS232 5" },
    { TTL_LOGGER_FPGAA_FUNCTION_SERIAL6,        "RS232 6" },
    { TTL_LOGGER_FPGAA_FUNCTION_SERIAL7,        "RS232 7" },
    { TTL_LOGGER_FPGAA_FUNCTION_SERIAL8,        "RS232 8" },
    { TTL_LOGGER_FPGAA_FUNCTION_SERIAL9,        "RS232 9" },
    { TTL_LOGGER_FPGAA_FUNCTION_SERIAL10,       "RS232 10" },
    { TTL_LOGGER_FPGAA_FUNCTION_CAN12,          "CAN 12" },
    { TTL_LOGGER_FPGAA_FUNCTION_CAN13,          "CAN 13" },
    { TTL_LOGGER_FPGAA_FUNCTION_CAN14,          "CAN 14" },
    { TTL_LOGGER_FPGAA_FUNCTION_SLOT_CTRL,      "SLOT_CTRL" },
    { TTL_LOGGER_FPGAA_FUNCTION_DRAM,           "DRAM" },
    { TTL_LOGGER_FPGAA_FUNCTION_SINK,           "Sink" },
    { TTL_LOGGER_FPGAA_FUNCTION_POWER_AGENT,    "Power Agent" },
    { TTL_LOGGER_FPGAA_FUNCTION_PKT_GENERATOR,  "Packet Generator" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_logger_fpgab_function_vals[] = {
    { TTL_LOGGER_FPGAB_FUNCTION_ETHA_CH1,   "Ethernet A (CH1)" },
    { TTL_LOGGER_FPGAB_FUNCTION_ETHB_CH1,   "Ethernet B (CH1)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH1a_CH1, "Automotive Ethernet 1a (CH1)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH1b_CH1, "Automotive Ethernet 1b (CH1)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH2a_CH1, "Automotive Ethernet 2a (CH1)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH2b_CH1, "Automotive Ethernet 2b (CH1)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH3a_CH1, "Automotive Ethernet 3a (CH1)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH3b_CH1, "Automotive Ethernet 3b (CH1)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH4a_CH1, "Automotive Ethernet 4a (CH1)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH4b_CH1, "Automotive Ethernet 4b (CH1)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH5a_CH1, "Automotive Ethernet 5a (CH1)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH5b_CH1, "Automotive Ethernet 5b (CH1)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH6a_CH1, "Automotive Ethernet 6a (CH1)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH6b_CH1, "Automotive Ethernet 6b (CH1)" },
    { TTL_LOGGER_FPGAB_FUNCTION_ETHA_CH2,   "Ethernet A (CH2)" },
    { TTL_LOGGER_FPGAB_FUNCTION_ETHB_CH2,   "Ethernet B (CH2)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH1a_CH2, "Automotive Ethernet 1a (CH2)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH1b_CH2, "Automotive Ethernet 1b (CH2)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH2a_CH2, "Automotive Ethernet 2a (CH2)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH2b_CH2, "Automotive Ethernet 2b (CH2)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH3a_CH2, "Automotive Ethernet 3a (CH2)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH3b_CH2, "Automotive Ethernet 3b (CH2)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH4a_CH2, "Automotive Ethernet 4a (CH2)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH4b_CH2, "Automotive Ethernet 4b (CH2)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH5a_CH2, "Automotive Ethernet 5a (CH2)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH5b_CH2, "Automotive Ethernet 5b (CH2)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH6a_CH2, "Automotive Ethernet 6a (CH2)" },
    { TTL_LOGGER_FPGAB_FUNCTION_AETH6b_CH2, "Automotive Ethernet 6b (CH2)" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_pt15_fpga_function_vals[] = {
    { TTL_PT15_FPGA_FUNCTION_CORE,      "Core" },
    { TTL_PT15_FPGA_FUNCTION_CAN1,      "CAN 1" },
    { TTL_PT15_FPGA_FUNCTION_CAN2,      "CAN 2" },
    { TTL_PT15_FPGA_FUNCTION_BrdR1a,    "100BASE-T1 1a (Master)" },
    { TTL_PT15_FPGA_FUNCTION_BrdR1b,    "100BASE-T1 1b (Slave)" },
    { TTL_PT15_FPGA_FUNCTION_BrdR2a,    "100BASE-T1 2a (Master)" },
    { TTL_PT15_FPGA_FUNCTION_BrdR2b,    "100BASE-T1 2b (Slave)" },
    { TTL_PT15_FPGA_FUNCTION_BrdR3a,    "100BASE-T1 3a (Master)" },
    { TTL_PT15_FPGA_FUNCTION_BrdR3b,    "100BASE-T1 3b (Slave)" },
    { TTL_PT15_FPGA_FUNCTION_BrdR4a,    "100BASE-T1 4a (Master)" },
    { TTL_PT15_FPGA_FUNCTION_BrdR4b,    "100BASE-T1 4b (Slave)" },
    { TTL_PT15_FPGA_FUNCTION_BrdR5a,    "100BASE-T1 5a (Master)" },
    { TTL_PT15_FPGA_FUNCTION_BrdR5b,    "100BASE-T1 5b (Slave)" },
    { TTL_PT15_FPGA_FUNCTION_BrdR6a,    "100BASE-T1 6a (Master)" },
    { TTL_PT15_FPGA_FUNCTION_BrdR6b,    "100BASE-T1 6b (Slave)" },
    { TTL_PT15_FPGA_FUNCTION_MDIO,      "MDIO" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_pt20_fpga_function_vals[] = {
    { TTL_PT20_FPGA_FUNCTION_CORE,      "Core" },
    { TTL_PT20_FPGA_FUNCTION_CAN1,      "CAN 1" },
    { TTL_PT20_FPGA_FUNCTION_CAN2,      "CAN 2" },
    { TTL_PT20_FPGA_FUNCTION_CAN3,      "CAN 3" },
    { TTL_PT20_FPGA_FUNCTION_CAN4,      "CAN 4" },
    { TTL_PT20_FPGA_FUNCTION_CAN5,      "CAN 5" },
    { TTL_PT20_FPGA_FUNCTION_GbEth1a,   "1000BASE-T1 1a (Master)" },
    { TTL_PT20_FPGA_FUNCTION_GbEth1b,   "1000BASE-T1 1b (Slave)" },
    { TTL_PT20_FPGA_FUNCTION_GbEth2a,   "1000BASE-T1 2a (Master)" },
    { TTL_PT20_FPGA_FUNCTION_GbEth2b,   "1000BASE-T1 2b (Slave)" },
    { TTL_PT20_FPGA_FUNCTION_GbEth3a,   "1000BASE-T1 3a (Master)" },
    { TTL_PT20_FPGA_FUNCTION_GbEth3b,   "1000BASE-T1 3b (Slave)" },
    { TTL_PT20_FPGA_FUNCTION_MDIO,      "MDIO" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_pc3_fpga_function_vals[] = {
    { TTL_PC3_FPGA_FUNCTION_CORE,   "Core" },
    { TTL_PC3_FPGA_FUNCTION_BrdR1a, "BroadR-Reach 1a (Master)" },
    { TTL_PC3_FPGA_FUNCTION_BrdR1b, "BroadR-Reach 1b (Slave)" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_pc3_aurix_function_vals[] = {
    { TTL_PC3_AURIX_FUNCTION_CORE,          "Core" },
    { TTL_PC3_AURIX_FUNCTION_CAN1,          "CAN 1" },
    { TTL_PC3_AURIX_FUNCTION_CAN2,          "CAN 2" },
    { TTL_PC3_AURIX_FUNCTION_CAN3,          "CAN 3" },
    { TTL_PC3_AURIX_FUNCTION_CAN4,          "CAN 4" },
    { TTL_PC3_AURIX_FUNCTION_FLEXRAY1A,     "FlexRay 1A" },
    { TTL_PC3_AURIX_FUNCTION_FLEXRAY1B,     "FlexRay 1B" },
    { TTL_PC3_AURIX_FUNCTION_FLEXRAY2A,     "FlexRay 2A" },
    { TTL_PC3_AURIX_FUNCTION_FLEXRAY2B,     "FlexRay 2B" },
    { TTL_PC3_AURIX_FUNCTION_DIGITALIN1,    "Digital In 1" },
    { TTL_PC3_AURIX_FUNCTION_DIGITALIN2,    "Digital In 2" },
    { TTL_PC3_AURIX_FUNCTION_DIGITALOUT1,   "Digital Out 1" },
    { TTL_PC3_AURIX_FUNCTION_DIGITALOUT2,   "Digital Out 2" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_zelda_canfd_function_vals[] = {
    { TTL_TAP_DEVICE_ZELDA_CORE,    "Core" },
    { TTL_TAP_DEVICE_ZELDA_CANFD1,  "CAN-FD 1" },
    { TTL_TAP_DEVICE_ZELDA_CANFD2,  "CAN-FD 2" },
    { TTL_TAP_DEVICE_ZELDA_CANFD3,  "CAN-FD 3" },
    { TTL_TAP_DEVICE_ZELDA_CANFD4,  "CAN-FD 4" },
    { TTL_TAP_DEVICE_ZELDA_CANFD5,  "CAN-FD 5" },
    { TTL_TAP_DEVICE_ZELDA_CANFD6,  "CAN-FD 6" },
    { TTL_TAP_DEVICE_ZELDA_CANFD7,  "CAN-FD 7" },
    { TTL_TAP_DEVICE_ZELDA_CANFD8,  "CAN-FD 8" },
    { TTL_TAP_DEVICE_ZELDA_CANFD9,  "CAN-FD 9" },
    { TTL_TAP_DEVICE_ZELDA_CANFD10, "CAN-FD 10" },
    { TTL_TAP_DEVICE_ZELDA_CANFD11, "CAN-FD 11" },
    { TTL_TAP_DEVICE_ZELDA_CANFD12, "CAN-FD 12" },
    { TTL_TAP_DEVICE_ZELDA_CANFD13, "CAN-FD 13" },
    { TTL_TAP_DEVICE_ZELDA_CANFD14, "CAN-FD 14" },
    { TTL_TAP_DEVICE_ZELDA_CANFD15, "CAN-FD 15" },
    { 0, NULL }
};

static const value_string hf_ttl_addr_zelda_lin_function_vals[] = {
    { TTL_TAP_DEVICE_ZELDA_CORE,    "Core" },
    { TTL_TAP_DEVICE_ZELDA_LIN1,    "LIN 1" },
    { TTL_TAP_DEVICE_ZELDA_LIN2,    "LIN 2" },
    { TTL_TAP_DEVICE_ZELDA_LIN3,    "LIN 3" },
    { TTL_TAP_DEVICE_ZELDA_LIN4,    "LIN 4" },
    { TTL_TAP_DEVICE_ZELDA_LIN5,    "LIN 5" },
    { TTL_TAP_DEVICE_ZELDA_LIN6,    "LIN 6" },
    { TTL_TAP_DEVICE_ZELDA_LIN7,    "LIN 7" },
    { TTL_TAP_DEVICE_ZELDA_LIN8,    "LIN 8" },
    { TTL_TAP_DEVICE_ZELDA_LIN9,    "LIN 9" },
    { TTL_TAP_DEVICE_ZELDA_LIN10,   "LIN 10" },
    { TTL_TAP_DEVICE_ZELDA_LIN11,   "LIN 11" },
    { TTL_TAP_DEVICE_ZELDA_LIN12,   "LIN 12" },
    { TTL_TAP_DEVICE_ZELDA_LIN13,   "LIN 13" },
    { TTL_TAP_DEVICE_ZELDA_LIN14,   "LIN 14" },
    { TTL_TAP_DEVICE_ZELDA_LIN15,   "LIN 15" },
    { TTL_TAP_DEVICE_ZELDA_LIN16,   "LIN 16" },
    { TTL_TAP_DEVICE_ZELDA_LIN17,   "LIN 17" },
    { TTL_TAP_DEVICE_ZELDA_LIN18,   "LIN 18" },
    { TTL_TAP_DEVICE_ZELDA_LIN19,   "LIN 19" },
    { TTL_TAP_DEVICE_ZELDA_LIN20,   "LIN 20" },
    { TTL_TAP_DEVICE_ZELDA_LIN21,   "LIN 21" },
    { TTL_TAP_DEVICE_ZELDA_LIN22,   "LIN 22" },
    { TTL_TAP_DEVICE_ZELDA_LIN23,   "LIN 23" },
    { TTL_TAP_DEVICE_ZELDA_LIN24,   "LIN 24" },
    { 0, NULL }
};

static const true_false_string hf_ttl_trace_data_entry_meta1_frame_duplication_tfs = {
    "Frame Duplication",
    "No Frame Duplication"
};

static const true_false_string hf_ttl_trace_data_entry_meta1_compressed_format_tfs = {
    "Compressed (32 bit) Timestamp",
    "Normal (64 bit) Timestamp"
};

static const true_false_string hf_ttl_trace_data_entry_meta1_timestamp_source_tfs = {
    "Timestamp comes from Source Address component",
    "Timestamp comes from the FPGA"
};

static const value_string hf_ttl_trace_data_entry_ackmode_vals[] = {
    { 0,    "Acknowledgement not used" },
    { 1,    "Acknowledgement requested" },
    { 2,    "Request finished: Processing successfully finished" },
    { 3,    "Request failed: Processing had errors" },
    { 4,    "Request accepted: Frame received" },
    { 5,    "Request not accepted: Error in the header processing" },
    { 0, NULL }
};

static const value_string hf_ttl_trace_data_entry_status_info_can_error_code_vals[] = {
    { 0,    "No Error" },
    { 1,    "Stuff Error" },
    { 2,    "Form Error" },
    { 3,    "Ack Error" },
    { 4,    "Bit 1 Error" },
    { 5,    "Bit 0 Error" },
    { 6,    "CRC Error" },
    { 7,    "Invalid DLC" },
    { 0, NULL }
};

static const value_string hf_ttl_trace_data_entry_status_info_eth_type_vals[] = {
    { TTL_ETH_STATUS_VALID_FRAME,           "Valid Ethernet Frame" },
    { TTL_ETH_STATUS_CRC_ERROR_FRAME,       "Ethernet CRC Error Frame" },
    { TTL_ETH_STATUS_LENGTH_ERROR_FRAME,    "Ethernet Length Error Frame" },
    { TTL_ETH_STATUS_PHY_ERROR_FRAME,       "Ethernet PHY Error Frame" },
    { TTL_ETH_STATUS_TX_ERROR_FRAME,        "Ethernet TX Error Frame" },
    { TTL_ETH_STATUS_TX_FREEMEM_INFO_FRAME, "Ethernet TX FreeMem Info Frame" },
    { TTL_ETH_STATUS_TX_FRAME,              "Ethernet TX Frame" },
    { TTL_ETH_STATUS_PHY_STATUS,            "Ethernet PHY Status" },
    { 0, NULL }
};

static const value_string hf_ttl_eth_phy_status_phy_addr_vals[] = {
    { 2,    "BroadR-Reach 1a" },
    { 3,    "BroadR-Reach 1b" },
    { 4,    "BroadR-Reach 2a" },
    { 5,    "BroadR-Reach 2b" },
    { 6,    "BroadR-Reach 3a" },
    { 7,    "BroadR-Reach 3b" },
    { 8,    "BroadR-Reach 4a" },
    { 9,    "BroadR-Reach 4b" },
    { 10,   "BroadR-Reach 5a" },
    { 11,   "BroadR-Reach 5b" },
    { 12,   "BroadR-Reach 6a" },
    { 13,   "BroadR-Reach 6b" },
    { 0, NULL }
};

static const value_string hf_ttl_trace_data_entry_status_info_fr_type_vals[] = {
    { TTL_FLEXRAY_ITEM_REGULAR_FRAME,       "Regular Frame" },
    { TTL_FLEXRAY_ITEM_ABORTED_FRAME,       "Aborted Frame" },
    { TTL_FLEXRAY_ITEM_0_PULSE,             "0 Pulse" },
    { TTL_FLEXRAY_ITEM_1_PULSE,             "1 Pulse" },
    { TTL_FLEXRAY_ITEM_ERROR_INFORMATION,   "Error Information" },
    { 0, NULL }
};

static const true_false_string tfs_recognized_not_recognized = {
    "Recognized",
    "Not Recognized"
};

static int* const ttl_trace_data_entry_meta1[] = {
    &hf_ttl_trace_data_entry_meta1_frame_duplication,
    &hf_ttl_trace_data_entry_meta1_compressed_format,
    &hf_ttl_trace_data_entry_meta1_timestamp_source,
    NULL
};

static int* const ttl_trace_data_entry_status_info_can_flags[] = {
    &hf_ttl_trace_data_entry_status_info_can_valid_frame,
    &hf_ttl_trace_data_entry_status_info_can_remote_frame,
    &hf_ttl_trace_data_entry_status_info_can_bus_off,
    &hf_ttl_trace_data_entry_status_info_can_matched,
    &hf_ttl_trace_data_entry_status_info_can_ide,
    &hf_ttl_trace_data_entry_status_info_can_edl,
    &hf_ttl_trace_data_entry_status_info_can_brs,
    &hf_ttl_trace_data_entry_status_info_can_esi,
    NULL
};

static int* const ttl_trace_data_entry_status_info_lin_flags[] = {
    &hf_ttl_trace_data_entry_status_info_lin_parity_error,
    &hf_ttl_trace_data_entry_status_info_lin_sync_error,
    &hf_ttl_trace_data_entry_status_info_lin_2_checksum_error,
    &hf_ttl_trace_data_entry_status_info_lin_1_checksum_error,
    &hf_ttl_trace_data_entry_status_info_lin_no_data_error,
    &hf_ttl_trace_data_entry_status_info_lin_abort_error,
    NULL
};

static int* const ttl_trace_data_entry_status_info_fr_error_flags[] = {
    &hf_ttl_trace_data_entry_status_info_fr_matched,
    &hf_ttl_trace_data_entry_status_info_fr_fss_error,
    &hf_ttl_trace_data_entry_status_info_fr_bss_error,
    &hf_ttl_trace_data_entry_status_info_fr_fes_error,
    &hf_ttl_trace_data_entry_status_info_fr_frame_crc_error,
    &hf_ttl_trace_data_entry_status_info_fr_header_crc_error,
    &hf_ttl_trace_data_entry_status_info_fr_idle_error,
    NULL
};

static int* const ttl_trace_data_entry_status_info_fr_pulse_flags[] = {
    &hf_ttl_trace_data_entry_status_info_fr_matched,
    &hf_ttl_trace_data_entry_status_info_fr_low_phase_exceeded,
    &hf_ttl_trace_data_entry_status_info_fr_cas,
    &hf_ttl_trace_data_entry_status_info_fr_mts,
    &hf_ttl_trace_data_entry_status_info_fr_wup,
    NULL
};


void proto_register_file_ttl(void);
void proto_reg_handoff_file_ttl(void);

#define TTL_MAGIC_SIZE 4
static const uint8_t ttl_magic[TTL_MAGIC_SIZE] = { 'T', 'T', 'L', ' ' };

static proto_item*
dissect_ttl_sw_version(proto_tree* tree, int hf, tvbuff_t* tvb, int offset, int length) {
    uint8_t             major, minor, build, patch;
    header_field_info*  hfinfo;

    major = tvb_get_uint8(tvb, offset);
    minor = tvb_get_uint8(tvb, offset + 1);
    build = tvb_get_uint8(tvb, offset + 2);
    patch = tvb_get_uint8(tvb, offset + 3);

    hfinfo = proto_registrar_get_nth(hf);

    return proto_tree_add_bytes_format(tree, hf, tvb, offset, length, NULL, "%s: %d.%d.%d.%d",
        hfinfo->name, major, minor, build, patch);
}

static proto_item*
dissect_ttl_hw_version(proto_tree* tree, int hf, tvbuff_t* tvb, int offset, int length) {
    uint16_t            major, minor;
    header_field_info*  hfinfo;

    major = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
    minor = tvb_get_uint16(tvb, offset + 2, ENC_LITTLE_ENDIAN);

    hfinfo = proto_registrar_get_nth(hf);

    return proto_tree_add_bytes_format(tree, hf, tvb, offset, length, NULL, "%s: %d.%d",
        hfinfo->name, major, minor);
}

static proto_item*
dissect_ttl_tc_sw_version(proto_tree* tree, int hf, tvbuff_t* tvb, int offset, int length) {
    uint8_t             major, minor;
    header_field_info*  hfinfo;

    major = tvb_get_uint8(tvb, offset);
    minor = tvb_get_uint8(tvb, offset + 1);

    hfinfo = proto_registrar_get_nth(hf);

    return proto_tree_add_bytes_format(tree, hf, tvb, offset, length, NULL, "%s: %d.%d",
        hfinfo->name, major, minor);
}

static int
dissect_ttl_logfile_information(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset) {
    int orig_offset = offset;

    proto_tree_add_item(tree, hf_ttl_header_logfile_info_logger_sn, tvb, offset, 20, ENC_NA);
    offset += 20;
    dissect_ttl_sw_version(tree, hf_ttl_header_logfile_info_logger_sw_version, tvb, offset, 4);
    offset += 4;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_measurement_creation_date, tvb, offset, 20, ENC_NA);
    offset += 20;
    proto_tree_add_time_item(tree, hf_ttl_header_logfile_info_measurement_creation_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_USECS, NULL, NULL, NULL);
    offset += 8;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_supplier_name, tvb, offset, 28, ENC_NA);
    offset += 28;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_description, tvb, offset, 128, ENC_NA);
    offset += 128;
    dissect_ttl_hw_version(tree, hf_ttl_header_logfile_info_hw_version, tvb, offset, 4);
    offset += 4;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_configuration_file_name, tvb, offset, 64, ENC_NA);
    offset += 64;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_tracefile_sorted, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_tracefile_split_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_completion_date, tvb, offset, 20, ENC_NA);
    offset += 20;
    proto_tree_add_time_item(tree, hf_ttl_header_logfile_info_completion_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_USECS, NULL, NULL, NULL);
    offset += 8;
    dissect_ttl_tc_sw_version(tree, hf_ttl_header_logfile_info_tc_sw_bootloader_version, tvb, offset, 2);
    offset += 2;
    dissect_ttl_tc_sw_version(tree, hf_ttl_header_logfile_info_tc_sw_firmware_version, tvb, offset, 2);
    offset += 2;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_most25_fw_version, tvb, offset, 32, ENC_NA);
    offset += 32;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_most150_fw_version, tvb, offset, 32, ENC_NA);
    offset += 32;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_split_file_creation_date, tvb, offset, 20, ENC_NA);
    offset += 20;
    proto_tree_add_time_item(tree, hf_ttl_header_logfile_info_split_file_creation_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_USECS, NULL, NULL, NULL);
    offset += 8;
    proto_tree_add_bytes_item(tree, hf_ttl_header_logfile_info_unused_bytes, tvb, offset, 512, ENC_NA, NULL, NULL, NULL);
    offset += 512;
    proto_tree_add_item(tree, hf_ttl_header_logfile_info_sleep_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bytes_item(tree, hf_ttl_header_logfile_info_reserved_bytes, tvb, offset, 3161, ENC_NA, NULL, NULL, NULL);
    offset += 3161;

    return offset - orig_offset;
}

static int
dissect_ttl_dest_addr_ret(proto_tree* tree, tvbuff_t* tvb, int offset, uint16_t* ret) {
    uint32_t    addr, cascade, device;
    proto_tree* addr_subtree;
    proto_item* ti;

    ti = proto_tree_add_item_ret_uint(tree, hf_ttl_trace_data_entry_dest_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN, &addr);
    addr_subtree = proto_item_add_subtree(ti, ett_ttl_trace_data_entry_dest_addr);
    proto_tree_add_item_ret_uint(addr_subtree, hf_ttl_trace_data_entry_dest_addr_cascade, tvb, offset, 2, ENC_LITTLE_ENDIAN, &cascade);
    if (cascade == 0) {
        proto_tree_add_item_ret_uint(addr_subtree, hf_ttl_trace_data_entry_dest_addr_device_logger, tvb, offset, 2, ENC_LITTLE_ENDIAN, &device);
        switch (device) {
        case TTL_LOGGER_DEVICE_FPGA:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_fpga, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_LOGGER_DEVICE_ATOM:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_atom, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_LOGGER_DEVICE_TRICORE1:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_tricore1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_LOGGER_DEVICE_TRICORE2:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_tricore2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_LOGGER_DEVICE_TRICORE3:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_tricore3, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_LOGGER_DEVICE_TDA4x:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_tda4x, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_LOGGER_DEVICE_FPGAA:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_fpgaa, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_LOGGER_DEVICE_FPGAB:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_fpgab, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        default:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_unknown, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        }
    }
    else {
        proto_tree_add_item_ret_uint(addr_subtree, hf_ttl_trace_data_entry_dest_addr_device_tap, tvb, offset, 2, ENC_LITTLE_ENDIAN, &device);
        switch (device) {
        case TTL_TAP_DEVICE_PT15_FPGA:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_pt15_fpga, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_TAP_DEVICE_PT20_FPGA:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_pt20_fpga, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_TAP_DEVICE_PC3_FPGA:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_pc3_fpga, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_TAP_DEVICE_PC3_AURIX:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_pc3_aurix, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_TAP_DEVICE_ZELDA_CANFD:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_zelda_canfd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_TAP_DEVICE_ZELDA_LIN:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_zelda_lin, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        default:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_dest_addr_function_unknown, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        }
    }

    if (ret) {
        *ret = (uint16_t)addr;
    }
    return 2;
}

static int
dissect_ttl_src_addr_ret(proto_tree* tree, tvbuff_t* tvb, int offset, uint16_t* ret) {
    uint32_t    addr, cascade, device;
    proto_tree* addr_subtree;
    proto_item* ti;

    ti = proto_tree_add_item_ret_uint(tree, hf_ttl_trace_data_entry_src_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN, &addr);
    addr_subtree = proto_item_add_subtree(ti, ett_ttl_trace_data_entry_src_addr);
    proto_tree_add_item_ret_uint(addr_subtree, hf_ttl_trace_data_entry_src_addr_cascade, tvb, offset, 2, ENC_LITTLE_ENDIAN, &cascade);
    if (cascade == 0) {
        proto_tree_add_item_ret_uint(addr_subtree, hf_ttl_trace_data_entry_src_addr_device_logger, tvb, offset, 2, ENC_LITTLE_ENDIAN, &device);
        switch (device) {
        case TTL_LOGGER_DEVICE_FPGA:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_fpga, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_LOGGER_DEVICE_ATOM:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_atom, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_LOGGER_DEVICE_TRICORE1:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_tricore1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_LOGGER_DEVICE_TRICORE2:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_tricore2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_LOGGER_DEVICE_TRICORE3:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_tricore3, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_LOGGER_DEVICE_TDA4x:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_tda4x, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_LOGGER_DEVICE_FPGAA:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_fpgaa, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_LOGGER_DEVICE_FPGAB:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_fpgab, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        default:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_unknown, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        }
    }
    else {
        proto_tree_add_item_ret_uint(addr_subtree, hf_ttl_trace_data_entry_src_addr_device_tap, tvb, offset, 2, ENC_LITTLE_ENDIAN, &device);
        switch (device) {
        case TTL_TAP_DEVICE_PT15_FPGA:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_pt15_fpga, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_TAP_DEVICE_PT20_FPGA:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_pt20_fpga, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_TAP_DEVICE_PC3_FPGA:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_pc3_fpga, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_TAP_DEVICE_PC3_AURIX:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_pc3_aurix, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_TAP_DEVICE_ZELDA_CANFD:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_zelda_canfd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        case TTL_TAP_DEVICE_ZELDA_LIN:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_zelda_lin, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        default:
            proto_tree_add_item(addr_subtree, hf_ttl_trace_data_entry_src_addr_function_unknown, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        }
    }

    if (ret) {
        *ret = (uint16_t)addr;
    }
    return 2;
}

static int
dissect_ttl_eth_bus_data_entry(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int size,
                               proto_tree* status_tree, int status_pos, uint16_t src) {
    proto_item *ti;
    proto_tree *subtree, *payload_subtree;
    int         orig_offset = offset;
    uint16_t    status;
    uint8_t     cascade = (src >> 10) & 0x7;
    bool        valid;

    status = tvb_get_uint16(tvb, status_pos, ENC_LITTLE_ENDIAN);

    if (status != TTL_ETH_STATUS_PHY_STATUS) {
        proto_tree_add_item(tree, hf_ttl_trace_data_entry_eth_unused, tvb, offset, 2, ENC_NA);
        offset += 2;
        size -= 2;
    }

    ti = proto_tree_add_item(tree, hf_ttl_trace_data_entry_payload, tvb, offset, size, ENC_NA);
    payload_subtree = proto_item_add_subtree(ti, ett_ttl_trace_data_entry_payload);
    proto_item_prepend_text(ti, "%s ", val_to_str_const(status, hf_ttl_trace_data_entry_status_info_eth_type_vals, "Unknown"));

    proto_tree_add_item(status_tree, hf_ttl_trace_data_entry_status_info_eth_type, tvb, status_pos, 2, ENC_LITTLE_ENDIAN);

    if (status == TTL_ETH_STATUS_PHY_STATUS) {
        while (size >= 4) {
            ti = proto_tree_add_item(payload_subtree, hf_ttl_eth_phy_status, tvb, offset, 4, ENC_NA);
            subtree = proto_item_add_subtree(ti, ett_ttl_eth_phy_status);
            proto_tree_add_item_ret_boolean(subtree, hf_ttl_eth_phy_status_valid, tvb, offset + 3, 1, ENC_NA, &valid);
            proto_item_append_text(ti, " (%s)", tfs_get_string(valid, &tfs_valid_invalid));
            proto_tree_add_item(subtree, hf_ttl_eth_phy_status_res2, tvb, offset + 3, 1, ENC_NA);
            if (cascade == 0) {
                proto_tree_add_item(subtree, hf_ttl_eth_phy_status_unused, tvb, offset + 3, 1, ENC_NA);
            }
            else {
                proto_tree_add_item(subtree, hf_ttl_eth_phy_status_phy_addr, tvb, offset + 3, 1, ENC_NA);
            }
            proto_tree_add_item(subtree, hf_ttl_eth_phy_status_res1, tvb, offset + 2, 1, ENC_NA);
            proto_tree_add_item(subtree, hf_ttl_eth_phy_status_reg_addr, tvb, offset + 2, 1, ENC_NA);
            proto_tree_add_item(subtree, hf_ttl_eth_phy_status_data, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            offset += 4;
            size -= 4;
        }
    }
    else {
        offset += size;
    }

    return offset - orig_offset;
}

static int
dissect_ttl_can_bus_data_entry(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int size,
                               proto_tree* status_tree, int status_pos) {
    proto_item* ti;
    int         orig_offset = offset;

    proto_tree_add_bitmask(status_tree, tvb, status_pos, hf_ttl_trace_data_entry_status_info_can_flags,
                           ett_ttl_trace_data_entry_status_info_can_flags, ttl_trace_data_entry_status_info_can_flags, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(status_tree, hf_ttl_trace_data_entry_status_info_can_error_code, tvb, status_pos, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(status_tree, hf_ttl_trace_data_entry_status_info_can_res, tvb, status_pos, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(status_tree, hf_ttl_trace_data_entry_status_info_can_dlc, tvb, status_pos, 2, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(tree, hf_ttl_trace_data_entry_can_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    size -= 4;

    ti = proto_tree_add_item(tree, hf_ttl_trace_data_entry_payload, tvb, offset, size, ENC_NA);
    proto_item_prepend_text(ti, "CAN ");
    offset += size;

    return offset - orig_offset;
}

static int
dissect_ttl_lin_bus_data_entry(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int size,
                               proto_tree* status_tree, int status_pos) {
    proto_item* ti;
    proto_tree* subtree;
    int         orig_offset = offset;

    ti = proto_tree_add_item(status_tree, hf_ttl_trace_data_entry_status_info_lin_pid, tvb, status_pos, 1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_ttl_trace_data_entry_status_info_lin_pid);
    proto_tree_add_item(subtree, hf_ttl_trace_data_entry_status_info_lin_parity, tvb, status_pos, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_ttl_trace_data_entry_status_info_lin_id, tvb, status_pos, 1, ENC_NA);
    proto_tree_add_item(status_tree, hf_ttl_trace_data_entry_status_info_lin_unused, tvb, status_pos + 1, 1, ENC_NA);
    proto_tree_add_bitmask(status_tree, tvb, status_pos + 1, hf_ttl_trace_data_entry_status_info_lin_flags,
                           ett_ttl_trace_data_entry_status_info_lin_flags, ttl_trace_data_entry_status_info_lin_flags, ENC_NA);

    if (size > 1) {
        ti = proto_tree_add_item(tree, hf_ttl_trace_data_entry_payload, tvb, offset, size - 1, ENC_NA);
        proto_item_prepend_text(ti, "LIN ");
        offset += (size - 1);

        proto_tree_add_item(tree, hf_ttl_trace_data_entry_lin_checksum, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    return offset - orig_offset;
}

static int
dissect_ttl_flexray_bus_data_entry(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int size,
                                   proto_tree* status_tree, int status_pos) {
    proto_item* ti;
    int         orig_offset = offset;
    uint16_t    status;
    uint8_t     type;

    status = tvb_get_uint16(tvb, status_pos, ENC_LITTLE_ENDIAN);

    type = status & TTL_FLEXRAY_ITEM_MASK;

    proto_tree_add_item(status_tree, hf_ttl_trace_data_entry_status_info_fr_type, tvb, status_pos, 2, ENC_LITTLE_ENDIAN);

    if (type == TTL_FLEXRAY_ITEM_REGULAR_FRAME || type == TTL_FLEXRAY_ITEM_ABORTED_FRAME) {
        proto_tree_add_bitmask(status_tree, tvb, status_pos, hf_ttl_trace_data_entry_status_info_fr_error_flags,
                               ett_ttl_trace_data_entry_status_info_fr_error_flags, ttl_trace_data_entry_status_info_fr_error_flags, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(status_tree, hf_ttl_trace_data_entry_status_info_fr_res1, tvb, status_pos, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(status_tree, hf_ttl_trace_data_entry_status_info_fr_res2, tvb, status_pos, 2, ENC_LITTLE_ENDIAN);
    }
    else if (type == TTL_FLEXRAY_ITEM_0_PULSE || type == TTL_FLEXRAY_ITEM_1_PULSE) {
        proto_tree_add_item(status_tree, hf_ttl_trace_data_entry_status_info_fr_res3, tvb, status_pos, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_bitmask(status_tree, tvb, status_pos, hf_ttl_trace_data_entry_status_info_fr_pulse_flags,
                               ett_ttl_trace_data_entry_status_info_fr_pulse_flags, ttl_trace_data_entry_status_info_fr_pulse_flags, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(status_tree, hf_ttl_trace_data_entry_status_info_fr_res4, tvb, status_pos, 2, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(tree, hf_ttl_trace_data_entry_fr_low_phase_counter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_ttl_trace_data_entry_fr_unused, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }
    else if (type == TTL_FLEXRAY_ITEM_ERROR_INFORMATION) {
        proto_tree_add_item(status_tree, hf_ttl_trace_data_entry_status_info_fr_res5, tvb, status_pos, 2, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(tree, hf_ttl_trace_data_entry_fr_eray_eir_register, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_ttl_trace_data_entry_fr_eray_stpw1_register, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_ttl_trace_data_entry_fr_eray_stpw2_register, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_ttl_trace_data_entry_fr_eray_ccsv_register, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_ttl_trace_data_entry_fr_eray_ccev_register, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_ttl_trace_data_entry_fr_eray_swnit_register, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_ttl_trace_data_entry_fr_eray_acs_register, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    size -= (offset - orig_offset);

    if (size > 0) {
        ti = proto_tree_add_item(tree, hf_ttl_trace_data_entry_payload, tvb, offset, size, ENC_NA);
        proto_item_prepend_text(ti, "FlexRay ");
        offset += size;
    }

    return offset - orig_offset;
}

static int
dissect_ttl_bus_data_entry(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, int size,
                           proto_item* root, proto_tree* status_tree, int status_pos, uint16_t src) {
    int         orig_offset = offset;

    proto_tree_add_item(tree, hf_ttl_trace_data_entry_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_USECS);
    offset += 8;

    switch (ttl_get_address_iface_type(src)) {
    case WTAP_ENCAP_ETHERNET:
        proto_item_append_text(root, " (Ethernet)");
        offset += dissect_ttl_eth_bus_data_entry(tvb, pinfo, tree, offset, size - (offset - orig_offset), status_tree, status_pos, src);
        break;
    case WTAP_ENCAP_SOCKETCAN:
        proto_item_append_text(root, " (CAN)");
        offset += dissect_ttl_can_bus_data_entry(tvb, pinfo, tree, offset, size - (offset - orig_offset), status_tree, status_pos);
        break;
    case WTAP_ENCAP_LIN:
        proto_item_append_text(root, " (LIN)");
        offset += dissect_ttl_lin_bus_data_entry(tvb, pinfo, tree, offset, size - (offset - orig_offset), status_tree, status_pos);
        break;
    case WTAP_ENCAP_FLEXRAY:
        proto_item_append_text(root, " (FlexRay)");
        offset += dissect_ttl_flexray_bus_data_entry(tvb, pinfo, tree, offset, size - (offset - orig_offset), status_tree, status_pos);
        break;
    default:
        proto_item_append_text(root, " (Unsupported)");
        break;
    }

    return offset - orig_offset;
}

static int
dissect_ttl_entry(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset) {
    proto_tree  *entry_subtree, *status_subtree;
    proto_item  *ti, *root_ti;
    int         orig_offset = offset;
    uint32_t    status;
    uint16_t    entry_size_type;
    uint16_t    size;
    uint16_t    src_addr;
    uint8_t     type;

    entry_size_type = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
    type = entry_size_type >> 12;
    size = entry_size_type & TTL_SIZE_MASK;

    root_ti = proto_tree_add_item(tree, hf_ttl_trace_data_entry, tvb, offset, size, ENC_NA);
    proto_item_append_text(root_ti, " - %s", val_to_str_const(type, hf_ttl_trace_data_entry_type_vals, "Unknown Entry"));
    entry_subtree = proto_item_add_subtree(root_ti, ett_ttl_trace_data_entry);

    proto_tree_add_item(entry_subtree, hf_ttl_trace_data_entry_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(entry_subtree, hf_ttl_trace_data_entry_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(entry_subtree, tvb, offset, hf_ttl_trace_data_entry_meta1, ett_ttl_trace_data_entry_meta1, ttl_trace_data_entry_meta1, ENC_LITTLE_ENDIAN);
    offset += dissect_ttl_dest_addr_ret(entry_subtree, tvb, offset, NULL);
    ti = proto_tree_add_item(entry_subtree, hf_ttl_trace_data_entry_meta2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_item_set_hidden(ti);
    proto_tree_add_item(entry_subtree, hf_ttl_trace_data_entry_ackmode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += dissect_ttl_src_addr_ret(entry_subtree, tvb, offset, &src_addr);

    ti = proto_tree_add_item_ret_uint(entry_subtree, hf_ttl_trace_data_entry_status_information, tvb, offset, 2, ENC_LITTLE_ENDIAN, &status);
    status_subtree = proto_item_add_subtree(ti, ett_ttl_trace_data_entry_status_information);
    offset += 2;

    if (size < sizeof(ttl_entryheader_t)) {
        expert_add_info(pinfo, root_ti, &ei_ttl_entry_size_too_short);
    }
    else {
        switch (type) {
        case TTL_BUS_DATA_ENTRY:
            offset += dissect_ttl_bus_data_entry(tvb, pinfo, entry_subtree, offset, (int)size - (offset - orig_offset),
                                                 root_ti, status_subtree, orig_offset + 6, src_addr);
            break;
        case TTL_COMMAND_ENTRY:
        case TTL_JOURNAL_ENTRY:
        case TTL_SEGMENTED_MESSAGE_ENTRY:
        case TTL_SEND_FRAME_ENTRY:
        case TTL_PADDING_ENTRY:
        case TTL_SOFTWARE_DATA_ENTRY:
        case TTL_DROPPED_FRAMES_ENTRY:
        default:
            break;
        }
    }

    if ((offset - orig_offset) < size) {
        proto_tree_add_item(entry_subtree, hf_ttl_trace_data_entry_unparsed, tvb, offset, (int)size - (offset - orig_offset), ENC_NA);
        offset += (int)size - (offset - orig_offset);
    }

    return offset - orig_offset;
}

static int
dissect_ttl_block(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, int size) {
    proto_tree* block_subtree;
    proto_item* ti;
    int orig_offset = offset;
    int dissected;

    if (size > 0) {
        ti = proto_tree_add_item(tree, hf_ttl_block, tvb, offset, size, ENC_NA);
        block_subtree = proto_item_add_subtree(ti, ett_ttl_block);

        while (size >= (int)sizeof(ttl_entryheader_t)) {
            dissected = dissect_ttl_entry(tvb, pinfo, block_subtree, offset);
            offset += dissected;
            size -= dissected;
        }
    }

    return offset - orig_offset;
}

static int
dissect_ttl(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_) {
    unsigned        offset = 0;
    proto_tree     *ttl_tree, *header_subtree, *logfile_info_subtree, *configuration_subtree, *trace_data_subtree;
    proto_item*     ti;
    uint32_t        format_version, header_length, block_size;
    unsigned        logfile_info_length, xml_length, remaining;

    if (tvb_captured_length(tvb) < sizeof(ttl_fileheader_t) || tvb_memeql(tvb, 0, ttl_magic, TTL_MAGIC_SIZE) != 0) {
        return 0;
    }

    ti = proto_tree_add_item(tree, proto_ttl, tvb, offset, -1, ENC_NA);
    ttl_tree = proto_item_add_subtree(ti, ett_ttl);
    header_length = tvb_get_uint32(tvb, 12, ENC_LITTLE_ENDIAN);

    ti = proto_tree_add_item(ttl_tree, hf_ttl_header, tvb, offset, header_length, ENC_NA);
    header_subtree = proto_item_add_subtree(ti, ett_ttl_header);

    proto_tree_add_item(header_subtree, hf_ttl_header_magic, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item_ret_uint(header_subtree, hf_ttl_header_file_format_version, tvb, offset, 4, ENC_LITTLE_ENDIAN, &format_version);
    offset += 4;
    ti = proto_tree_add_item_ret_uint(header_subtree, hf_ttl_header_block_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &block_size);
    offset += 4;
    if (block_size == 0) {
        expert_add_info(pinfo, ti, &ei_ttl_block_size_too_short);
    }
    ti = proto_tree_add_item(header_subtree, hf_ttl_header_header_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (header_length < sizeof(ttl_fileheader_t)) {
        expert_add_info(pinfo, ti, &ei_ttl_header_size_too_short);
    }
    else if (header_length > INT32_MAX) {
        expert_add_info(pinfo, ti, &ei_ttl_header_size_implausible);
    }
    else {
        logfile_info_length = MIN(MIN(tvb_captured_length_remaining(tvb, offset), header_length - offset), TTL_LOGFILE_INFO_SIZE);
        ti = proto_tree_add_item(header_subtree, hf_ttl_header_logfile_info, tvb, offset, logfile_info_length, ENC_NA);
        logfile_info_subtree = proto_item_add_subtree(ti, ett_ttl_header_logfile_info);

        if ((logfile_info_length < TTL_LOGFILE_INFO_SIZE) && format_version >= 10) {
            /* Starting from format version 10, the header is at least TTL_LOGFILE_INFO_SIZE bytes */
            expert_add_info(pinfo, ti, &ei_ttl_header_logfile_info_too_short);
        }

        offset += dissect_ttl_logfile_information(tvb, pinfo, logfile_info_subtree, offset);

        if (format_version >= 10 && header_length > offset) {
            xml_length = MIN(tvb_captured_length_remaining(tvb, offset), header_length - offset);
            ti = proto_tree_add_item(header_subtree, hf_ttl_header_configuration, tvb, offset, xml_length, ENC_NA);

            if (xml_handle) {
                configuration_subtree = proto_item_add_subtree(ti, ett_ttl_header_configuration);
                tvbuff_t* new_tvb = tvb_new_subset_length(tvb, offset, xml_length);
                call_dissector(xml_handle, new_tvb, pinfo, configuration_subtree);
            }
        }

        offset = header_length;

        ti = proto_tree_add_item(ttl_tree, hf_ttl_trace_data, tvb, offset, -1, ENC_NA);
        trace_data_subtree = proto_item_add_subtree(ti, ett_ttl_trace_data);

        if (block_size != 0) {
            while ((remaining = tvb_captured_length_remaining(tvb, offset)) > 0) {
                dissect_ttl_block(tvb, pinfo, trace_data_subtree, offset, MIN(block_size, remaining));
                offset += block_size;
            }
        }

    }

    return offset;
}


static bool
dissect_ttl_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data) {
    return dissect_ttl(tvb, pinfo, tree, data) > 0;
}

void
proto_register_file_ttl(void) {
    expert_module_t* expert_ttl;

    static hf_register_info hf[] = {
        { &hf_ttl_header,
            { "Header Section", "ttl.header", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_magic,
            { "Magic", "ttl.header.magic", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_file_format_version,
            { "File Format Version", "ttl.header.version", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_block_size,
            { "Block Size", "ttl.header.block_size", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_header_size,
            { "Header Size", "ttl.header.header_size", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info,
            { "Logfile Information", "ttl.header.logfile_info", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_ttl_header_logfile_info_logger_sn,
            { "Logger Serial Number", "ttl.header.logfile_info.logger_sn", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_logger_sw_version,
            { "Logger Software Version", "ttl.header.logfile_info.logger_sw_version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_measurement_creation_date,
            { "Measurement Creation Date", "ttl.header.logfile_info.measurement_creation_date", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_measurement_creation_timestamp,
            { "Measurement Creation Timestamp", "ttl.header.logfile_info.measurement_creation_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_supplier_name,
            { "Supplier Name", "ttl.header.logfile_info.supplier_name", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_description,
            { "Description", "ttl.header.logfile_info.description", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_hw_version,
            { "Hardware Version", "ttl.header.logfile_info.hw_version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_configuration_file_name,
            { "Configuration File Name", "ttl.header.logfile_info.config_filename", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_tracefile_sorted,
            { "Tracefile Sorted", "ttl.header.logfile_info.tracefile_sorted", FT_UINT8, BASE_HEX, VALS(hf_ttl_header_logfile_info_tracefile_sorted_vals), 0x0, NULL, HFILL} },
        { &hf_ttl_header_logfile_info_tracefile_split_index,
            { "Tracefile Split Index", "ttl.header.logfile_info.tracefile_split_index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_completion_date,
            { "Completion Date", "ttl.header.logfile_info.completion_date", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_completion_timestamp,
            { "Completion Timestamp", "ttl.header.logfile_info.completion_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_tc_sw_bootloader_version,
            { "TC SW Bootloader Version", "ttl.header.logfile_info.tc_sw_bootloader_version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_tc_sw_firmware_version,
            { "TC SW Firmware Version", "ttl.header.logfile_info.tc_sw_firmware_version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_most25_fw_version,
            { "MOST25 Piggy Firmware Version", "ttl.header.logfile_info.most25_fw_version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_most150_fw_version,
            { "MOST150 Piggy Firmware Version", "ttl.header.logfile_info.most150_fw_version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_split_file_creation_date,
            { "Split File Creation Date", "ttl.header.logfile_info.split_file_creation_date", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_split_file_creation_timestamp,
            { "Split File Creation Timestamp", "ttl.header.logfile_info.split_file_creation_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_unused_bytes,
            { "Unused Bytes", "ttl.header.logfile_info.unused", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_sleep_counter,
            { "Sleep Counter", "ttl.header.logfile_info.sleep_counter", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_logfile_info_reserved_bytes,
            { "Reserved Bytes", "ttl.header.logfile_info.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_header_configuration,
            { "Configuration", "ttl.header.configuration", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_ttl_trace_data,
            { "Trace Data Section", "ttl.trace_data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_block,
            { "Trace Data Block", "ttl.trace_data_block", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry,
            { "Trace Data Entry", "ttl.trace_data.entry", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_size,
            { "Entry Size", "ttl.trace_data.entry.size", FT_UINT16, BASE_DEC_HEX, NULL, 0x0fff, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_type,
            { "Entry Type", "ttl.trace_data.entry.type", FT_UINT16, BASE_DEC, VALS(hf_ttl_trace_data_entry_type_vals), 0xf000, NULL, HFILL} },

        { &hf_ttl_trace_data_entry_dest_addr,
            { "Destination Address", "ttl.trace_data.entry.dst_addr", FT_UINT16, BASE_DEC_HEX, NULL, 0x1fff, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_dest_addr_cascade,
            { "Destination Address Cascade", "ttl.trace_data.entry.dst_addr.cascade", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_cascade_vals), 0x1c00, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_dest_addr_device_logger,
            { "Destination Address Device", "ttl.trace_data.entry.dst_addr.device", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_device_vals), 0x03c0, NULL, HFILL} },
        { &hf_ttl_trace_data_entry_dest_addr_device_tap,
            { "Destination Address Device", "ttl.trace_data.entry.dst_addr.device", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_tap_device_vals), 0x03c0, NULL, HFILL} },
        { &hf_ttl_trace_data_entry_dest_addr_function_fpga,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_fpga_function_vals), 0x003f, NULL, HFILL} },
        { &hf_ttl_trace_data_entry_dest_addr_function_atom,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_atom_function_vals), 0x003f, NULL, HFILL} },
        { &hf_ttl_trace_data_entry_dest_addr_function_tricore1,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_tricore1_function_vals), 0x003f, NULL, HFILL} },
        { &hf_ttl_trace_data_entry_dest_addr_function_tricore2,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_tricore2_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_dest_addr_function_tricore3,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_tricore3_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_dest_addr_function_tda4x,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_tda4x_function_vals), 0x003f, NULL, HFILL} },
        { &hf_ttl_trace_data_entry_dest_addr_function_fpgaa,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_fpgaa_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_dest_addr_function_fpgab,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_fpgab_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_dest_addr_function_pt15_fpga,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_pt15_fpga_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_dest_addr_function_pt20_fpga,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_pt20_fpga_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_dest_addr_function_pc3_fpga,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_pc3_fpga_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_dest_addr_function_pc3_aurix,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_pc3_aurix_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_dest_addr_function_zelda_canfd,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_zelda_canfd_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_dest_addr_function_zelda_lin,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_zelda_lin_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_dest_addr_function_unknown,
            { "Destination Address Function", "ttl.trace_data.entry.dst_addr.function", FT_UINT16, BASE_DEC_HEX, NULL, 0x003f, NULL, HFILL } },

        { &hf_ttl_trace_data_entry_meta1,
            { "Meta 1", "ttl.trace_data.entry.meta1", FT_UINT16, BASE_DEC_HEX, NULL, 0xe000, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_meta1_frame_duplication,
            { "Frame Duplication Marker", "ttl.trace_data.entry.frame_duplication", FT_BOOLEAN, 16, TFS(&hf_ttl_trace_data_entry_meta1_frame_duplication_tfs), 0x8000, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_meta1_compressed_format,
            { "Compressed Format Field", "ttl.trace_data.entry.compressed_format", FT_BOOLEAN, 16, TFS(&hf_ttl_trace_data_entry_meta1_compressed_format_tfs), 0x4000, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_meta1_timestamp_source,
            { "Timestamp Source Field", "ttl.trace_data.entry.timestamp_source", FT_BOOLEAN, 16, TFS(&hf_ttl_trace_data_entry_meta1_timestamp_source_tfs), 0x2000, NULL, HFILL } },

        { &hf_ttl_trace_data_entry_src_addr,
            { "Source Address", "ttl.trace_data.entry.src_addr", FT_UINT16, BASE_DEC_HEX, NULL, 0x1fff, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_src_addr_cascade,
            { "Source Address Cascade", "ttl.trace_data.entry.src_addr.cascade", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_cascade_vals), 0x1c00, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_src_addr_device_logger,
            { "Source Address Device", "ttl.trace_data.entry.src_addr.device", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_device_vals), 0x03c0, NULL, HFILL} },
        { &hf_ttl_trace_data_entry_src_addr_device_tap,
            { "Source Address Device", "ttl.trace_data.entry.src_addr.device", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_tap_device_vals), 0x03c0, NULL, HFILL} },
        { &hf_ttl_trace_data_entry_src_addr_function_fpga,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_fpga_function_vals), 0x003f, NULL, HFILL} },
        { &hf_ttl_trace_data_entry_src_addr_function_atom,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_atom_function_vals), 0x003f, NULL, HFILL} },
        { &hf_ttl_trace_data_entry_src_addr_function_tricore1,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_tricore1_function_vals), 0x003f, NULL, HFILL} },
        { &hf_ttl_trace_data_entry_src_addr_function_tricore2,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_tricore2_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_src_addr_function_tricore3,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_tricore3_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_src_addr_function_tda4x,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_tda4x_function_vals), 0x003f, NULL, HFILL} },
        { &hf_ttl_trace_data_entry_src_addr_function_fpgaa,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_fpgaa_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_src_addr_function_fpgab,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_logger_fpgab_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_src_addr_function_pt15_fpga,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_pt15_fpga_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_src_addr_function_pt20_fpga,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_pt20_fpga_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_src_addr_function_pc3_fpga,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_pc3_fpga_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_src_addr_function_pc3_aurix,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_pc3_aurix_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_src_addr_function_zelda_canfd,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_zelda_canfd_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_src_addr_function_zelda_lin,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, VALS(hf_ttl_addr_zelda_lin_function_vals), 0x003f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_src_addr_function_unknown,
            { "Source Address Function", "ttl.trace_data.entry.src_addr.function", FT_UINT16, BASE_DEC_HEX, NULL, 0x003f, NULL, HFILL } },

        { &hf_ttl_trace_data_entry_meta2,
            { "Meta 2", "ttl.trace_data.entry.meta2", FT_UINT16, BASE_DEC_HEX, NULL, 0xe000, NULL, HFILL }},
        { &hf_ttl_trace_data_entry_ackmode,
            { "Ack Mode", "ttl.trace_data.entry.ackmode", FT_UINT16, BASE_DEC, VALS(hf_ttl_trace_data_entry_ackmode_vals), 0xe000, NULL, HFILL}},

        { &hf_ttl_trace_data_entry_status_information,
            { "Status Information", "ttl.trace_data.entry.status_info", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_ttl_trace_data_entry_status_info_eth_type,
            { "Type", "ttl.trace_data.entry.status_info.eth_type", FT_UINT16, BASE_HEX, VALS(hf_ttl_trace_data_entry_status_info_eth_type_vals), 0x0, NULL, HFILL} },
        { &hf_ttl_trace_data_entry_status_info_can_flags,
            { "CAN Flags", "ttl.trace_data.entry.status_info.can_flags", FT_UINT16, BASE_HEX, NULL, 0xf00f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_can_valid_frame,
            { "Valid Frame", "ttl.trace_data.entry.status_info.can_flags.valid", FT_BOOLEAN, 16, TFS(&tfs_valid_invalid), 0x0001, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_can_remote_frame,
            { "Remote Frame", "ttl.trace_data.entry.status_info.can_flags.rtr", FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_can_bus_off,
            { "Bus Off", "ttl.trace_data.entry.status_info.can_flags.bus_off", FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_can_matched,
            { "Matched", "ttl.trace_data.entry.status_info.can_flags.matched", FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_can_error_code,
            { "CAN Error Code", "ttl.trace_data.entry.status_info.can_error_code", FT_UINT16, BASE_HEX, VALS(hf_ttl_trace_data_entry_status_info_can_error_code_vals), 0x0070, NULL, HFILL}},
        { &hf_ttl_trace_data_entry_status_info_can_res,
            { "Reserved", "ttl.trace_data.entry.status_info.can_res", FT_UINT16, BASE_HEX, NULL, 0x0080, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_can_dlc,
            { "CAN DLC", "ttl.trace_data.entry.status_info.can_dlc", FT_UINT16, BASE_DEC, NULL, 0x0f00, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_can_ide,
            { "Extended Frame", "ttl.trace_data.entry.status_info.can_flags.ide", FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_can_edl,
            { "Extended Data Length", "ttl.trace_data.entry.status_info.can_flags.edl", FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_can_brs,
            { "Bit Rate Switch", "ttl.trace_data.entry.status_info.can_flags.brs", FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_can_esi,
            { "Error State Indicator", "ttl.trace_data.entry.status_info.can_flags.esi", FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_lin_pid,
            { "LIN PID", "ttl.trace_data.entry.status_info.lin_pid", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_lin_parity,
            { "LIN Parity Bits", "ttl.trace_data.entry.status_info.lin_parity", FT_UINT8, BASE_HEX, NULL, 0xc0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_lin_id,
            { "LIN ID", "ttl.trace_data.entry.status_info.lin_id", FT_UINT8, BASE_DEC_HEX, NULL, 0x3f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_lin_flags,
            { "LIN Flags", "ttl.trace_data.entry.status_info.lin_flags", FT_UINT8, BASE_HEX, NULL, 0x3f, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_lin_parity_error,
            { "Parity Error", "ttl.trace_data.entry.status_info.lin_flags.parity_error", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_lin_sync_error,
            { "Sync Error", "ttl.trace_data.entry.status_info.lin_flags.sync_error", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_lin_2_checksum_error,
            { "LIN 2.x Checksum Error", "ttl.trace_data.entry.status_info.lin_flags.lin2_checksum_error", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_lin_1_checksum_error,
            { "LIN 1.x Checksum Error", "ttl.trace_data.entry.status_info.lin_flags.lin1_checksum_error", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_lin_no_data_error,
            { "No Slave Response", "ttl.trace_data.entry.status_info.lin_flags.no_slave_response", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_lin_abort_error,
            { "Abort Error", "ttl.trace_data.entry.status_info.lin_flags.abort_error", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_lin_unused,
            { "Unused", "ttl.trace_data.entry.status_info.lin_unused", FT_UINT8, BASE_HEX, NULL, 0xc0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_type,
            { "Type", "ttl.trace_data.entry.status_info.fr_type", FT_UINT16, BASE_HEX, VALS(hf_ttl_trace_data_entry_status_info_fr_type_vals), 0x0007, NULL, HFILL}},
        { &hf_ttl_trace_data_entry_status_info_fr_error_flags,
            { "FlexRay Flags", "ttl.trace_data.entry.status_info.fr_flags", FT_UINT16, BASE_HEX, NULL, 0x07e8, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_matched,
            { "Matched", "ttl.trace_data.entry.status_info.fr_flags.matched", FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_res1,
            { "Reserved", "ttl.trace_data.entry.status_info.fr_res1", FT_UINT16, BASE_HEX, NULL, 0x0010, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_fss_error,
            { "FSS Error", "ttl.trace_data.entry.status_info.fr_flags.fss_error", FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_bss_error,
            { "BSS Error", "ttl.trace_data.entry.status_info.fr_flags.bss_error", FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_fes_error,
            { "FES Error", "ttl.trace_data.entry.status_info.fr_flags.fes_error", FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_frame_crc_error,
            { "Frame CRC Error", "ttl.trace_data.entry.status_info.fr_flags.frame_crc_error", FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_header_crc_error,
            { "Header CRC Error", "ttl.trace_data.entry.status_info.fr_flags.header_crc_error", FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_idle_error,
            { "Idle Error", "ttl.trace_data.entry.status_info.fr_flags.idle_error", FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_res2,
            { "Reserved", "ttl.trace_data.entry.status_info.fr_res2", FT_UINT16, BASE_HEX, NULL, 0xf800, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_res3,
            { "Reserved", "ttl.trace_data.entry.status_info.fr_res3", FT_UINT16, BASE_HEX, NULL, 0x07f0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_pulse_flags,
            { "FlexRay Flags", "ttl.trace_data.entry.status_info.fr_pulse_flags", FT_UINT16, BASE_HEX, NULL, 0xe808, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_low_phase_exceeded,
            { "Low Phase Exceeded", "ttl.trace_data.entry.status_info.fr_flags.low_phase_exceeded", FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_res4,
            { "Reserved", "ttl.trace_data.entry.status_info.fr_res4", FT_UINT16, BASE_HEX, NULL, 0x1000, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_cas,
            { "Collision Avoidance Symbol", "ttl.trace_data.entry.status_info.fr_flags.cas", FT_BOOLEAN, 16, TFS(&tfs_recognized_not_recognized), 0x2000, NULL, HFILL}},
        { &hf_ttl_trace_data_entry_status_info_fr_mts,
            { "Media Test Symbol", "ttl.trace_data.entry.status_info.fr_flags.mts", FT_BOOLEAN, 16, TFS(&tfs_recognized_not_recognized), 0x4000, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_wup,
            { "Wake-Up Pattern", "ttl.trace_data.entry.status_info.fr_flags.wup", FT_BOOLEAN, 16, TFS(&tfs_recognized_not_recognized), 0x8000, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_status_info_fr_res5,
            { "Reserved", "ttl.trace_data.entry.status_info.fr_res5", FT_UINT16, BASE_HEX, NULL, 0xfff8, NULL, HFILL } },

        { &hf_ttl_trace_data_entry_timestamp,
            { "Timestamp", "ttl.trace_data.entry.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_eth_unused,
            { "Unused", "ttl.trace_data.entry.eth_unused", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_can_id,
            { "CAN Frame ID", "ttl.trace_data.entry.can_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_lin_checksum,
            { "LIN Checksum", "ttl.trace_data.entry.lin_checksum", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_fr_low_phase_counter,
            { "FlexRay Low Phase Counter", "ttl.trace_data.entry.fr_low_phase_counter", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_fr_unused,
            { "Unused", "ttl.trace_data.entry.fr_unused", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_fr_eray_eir_register,
            { "FlexRay Eray EIR Register", "ttl.trace_data.entry.fr_eir", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_fr_eray_stpw1_register,
            { "FlexRay Eray STPW1 Register", "ttl.trace_data.entry.fr_stpw1", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_fr_eray_stpw2_register,
            { "FlexRay Eray STPW2 Register", "ttl.trace_data.entry.fr_stpw2", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_fr_eray_ccsv_register,
            { "FlexRay Eray CCSV Register", "ttl.trace_data.entry.fr_ccsv", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_fr_eray_ccev_register,
            { "FlexRay Eray CCEV Register", "ttl.trace_data.entry.fr_ccev", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_fr_eray_swnit_register,
            { "FlexRay Eray SWNIT Register", "ttl.trace_data.entry.fr_swnit", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_fr_eray_acs_register,
            { "FlexRay Eray ACS Register", "ttl.trace_data.entry.fr_acs", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_ttl_trace_data_entry_unparsed,
            { "Unparsed Data", "ttl.trace_data.entry.unparsed", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_trace_data_entry_payload,
            { "Payload", "ttl.trace_data.entry.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_ttl_eth_phy_status,
            { "Ethernet PHY Status", "ttl.trace_data.entry.eth_phy_status", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ttl_eth_phy_status_valid,
            { "Valid Entry", "ttl.trace_data.entry.eth_phy_status.valid", FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x80, NULL, HFILL } },
        { &hf_ttl_eth_phy_status_res2,
            { "Reserved", "ttl.trace_data.entry.eth_phy_status.res2", FT_UINT8, BASE_HEX, NULL, 0x60, NULL, HFILL } },
        { &hf_ttl_eth_phy_status_phy_addr,
            { "PHY Address", "ttl.trace_data.entry.eth_phy_status.phy_addr", FT_UINT8, BASE_HEX, VALS(hf_ttl_eth_phy_status_phy_addr_vals), 0x1f, NULL, HFILL } },
        { &hf_ttl_eth_phy_status_unused,
            { "Unused", "ttl.trace_data.entry.eth_phy_status.unused", FT_UINT8, BASE_HEX, NULL, 0x1f, NULL, HFILL } },
        { &hf_ttl_eth_phy_status_res1,
            { "Reserved", "ttl.trace_data.entry.eth_phy_status.res1", FT_UINT8, BASE_HEX, NULL, 0xe0, NULL, HFILL } },
        { &hf_ttl_eth_phy_status_reg_addr,
            { "MDIO Register", "ttl.trace_data.entry.eth_phy_status.reg_addr", FT_UINT8, BASE_HEX, NULL, 0x1f, NULL, HFILL } },
        { &hf_ttl_eth_phy_status_data,
            { "MDIO Data", "ttl.trace_data.entry.eth_phy_status.data", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    };

    static ei_register_info ei[] = {
        { &ei_ttl_block_size_too_short,
            { "ttl.block_size_too_short", PI_MALFORMED, PI_ERROR,
                "block size is too short",
                EXPFILL }},
        { &ei_ttl_header_size_too_short,
            { "ttl.header_size_too_short", PI_MALFORMED, PI_ERROR,
                "header size is too short",
                EXPFILL }},
        { &ei_ttl_header_size_implausible,
            { "ttl.header_size_implausible", PI_MALFORMED, PI_ERROR,
                "header size is implausible",
                EXPFILL }},
        { &ei_ttl_header_logfile_info_too_short,
            { "ttl.header.logfile_info_too_short", PI_MALFORMED, PI_ERROR,
                "logfile info is too short",
                EXPFILL }},
        { &ei_ttl_entry_size_too_short,
            { "ttl.trace_data.entry_size_too_short", PI_MALFORMED, PI_ERROR,
                "entry size is too short",
                EXPFILL }},
    };

    static int* ett[] = {
        &ett_ttl,
        &ett_ttl_header,
        &ett_ttl_header_logfile_info,
        &ett_ttl_header_configuration,
        &ett_ttl_trace_data,
        &ett_ttl_block,
        &ett_ttl_trace_data_entry,
        &ett_ttl_trace_data_entry_dest_addr,
        &ett_ttl_trace_data_entry_src_addr,
        &ett_ttl_trace_data_entry_meta1,
        &ett_ttl_trace_data_entry_status_information,
        &ett_ttl_trace_data_entry_status_info_can_flags,
        &ett_ttl_trace_data_entry_status_info_lin_flags,
        &ett_ttl_trace_data_entry_status_info_lin_pid,
        &ett_ttl_trace_data_entry_status_info_fr_error_flags,
        &ett_ttl_trace_data_entry_status_info_fr_pulse_flags,
        &ett_ttl_trace_data_entry_payload,
        &ett_ttl_eth_phy_status,
    };

    proto_ttl = proto_register_protocol("TTL File Format", "File-TTL", "file-ttl");
    expert_ttl = expert_register_protocol(proto_ttl);
    expert_register_field_array(expert_ttl, ei, array_length(ei));

    proto_register_field_array(proto_ttl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("file-ttl", dissect_ttl, proto_ttl);
}

void
proto_reg_handoff_file_ttl(void) {
    heur_dissector_add("wtap_file", dissect_ttl_heur, "TTL File", "ttl_wtap", proto_ttl, HEURISTIC_ENABLE);
    xml_handle = find_dissector_add_dependency("xml", proto_ttl);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
