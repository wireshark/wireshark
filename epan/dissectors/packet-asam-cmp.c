/* packet-asam-cmp.c
 * ASAM Capture Module Protocol dissector.
 * Copyright 2021-2023 Alicia Mediano Schikarski, Technica Engineering GmbH
 * Copyright 2021-2026 Dr. Lars Völker, Technica Engineering GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*
  * This is a dissector for the Capture Module Protocol standardized by the ASAM.
  * ASAM CMP is the standardized successor of TECMP.
  */

#include "config.h"

#include "math.h"

#include <epan/packet.h>
#include <epan/uat.h>
#include <epan/expert.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>

#include "packet-socketcan.h"
#include "packet-flexray.h"
#include "packet-lin.h"

void proto_register_asam_cmp(void);
void proto_reg_handoff_asam_cmp(void);

static int proto_asam_cmp;

static dissector_handle_t eth_handle;

static bool heuristic_first;
static bool old_11bit_canid_encoding;

/* Header fields */
static int hf_cmp_header;
static int hf_cmp_version;
static int hf_cmp_header_res;
static int hf_cmp_device_id;
static int hf_cmp_msg_type;
static int hf_cmp_stream_id;
static int hf_cmp_stream_seq_ctr;

/* Message Fields */
/* Message Header Fields */
static int hf_cmp_msg_header;

static int hf_cmp_common_flag_recal;
static int hf_cmp_common_flag_relative;
static int hf_cmp_common_flag_insync;
static int hf_cmp_common_flag_reserved_0x02;
static int hf_cmp_common_flag_seg;
static int hf_cmp_common_flag_dir_on_if;
static int hf_cmp_common_flag_overflow;
static int hf_cmp_common_flag_err_in_payload;
static int hf_cmp_common_flag_reserved;
static int hf_cmp_common_flag_reserved_0xf0;

static int hf_cmp_msg_timestamp;
static int hf_cmp_msg_timestamp_ns;
static int hf_cmp_msg_deadline;
static int hf_cmp_msg_reserved;
static int hf_cmp_msg_trans_opts;
static int hf_cmp_msg_trans_opts_res;
static int hf_cmp_msg_trans_opts_lin_wup_dura;
static int hf_cmp_msg_trans_opts_lin_res;
static int hf_cmp_msg_trans_opts_fr_op;
static int hf_cmp_msg_trans_opts_fr_cycle_rep;
static int hf_cmp_msg_trans_opts_fr_res;
static int hf_cmp_msg_common_flags;
static int hf_cmp_msg_vendor_id;
static int hf_cmp_msg_payload_length;
static int hf_cmp_msg_payload;

/* Additional Data Message Header Fields */
static int hf_cmp_interface_id;
static int hf_cmp_payload_type;

/* Additional Control Message Header Fields */
static int hf_cmp_ctrl_msg_reserved;
static int hf_cmp_ctrl_msg_payload_type;

/* Additional Status Message Header Fields */
static int hf_cmp_status_msg_payload_type;

/* Additional Status Message Header Fields */
static int hf_cmp_vendor_msg_payload_type;

/* Data Message Payload Fields */
/* CAN */
#define CMP_CAN_FLAGS_ERRORS        0x03ff
#define CMP_CAN_ID_11BIT_MASK       0x1ffc0000
#define CMP_CAN_ID_11BIT_SHIFT      18
#define CMP_CAN_ID_11BIT_MASK_OLD   0x000007ff
#define CMP_CAN_ID_29BIT_MASK       0x1fffffff
#define CMP_CAN_ID_ERR              0x20000000
#define CMP_CAN_ID_RTR              0x40000000
#define CMP_CAN_ID_IDE              0x80000000

#define CMP_CAN_CRC_CRC             0x00007fff
#define CMP_CAN_CRC_RES             0x7fff8000
#define CMP_CAN_CRC_CRC_SUPP        0x80000000

static int hf_cmp_can_flags;

static int hf_cmp_can_flag_crc_err;
static int hf_cmp_can_flag_ack_err;
static int hf_cmp_can_flag_passive_ack_err;
static int hf_cmp_can_flag_reserved_0004;
static int hf_cmp_can_flag_active_ack_err;
static int hf_cmp_can_flag_reserved_0008;
static int hf_cmp_can_flag_ack_del_err;
static int hf_cmp_can_flag_form_err;
static int hf_cmp_can_flag_stuff_err;
static int hf_cmp_can_flag_crc_del_err;
static int hf_cmp_can_flag_eof_err;
static int hf_cmp_can_flag_bit_err;
static int hf_cmp_can_flag_r0;
static int hf_cmp_can_flag_srr_dom;
static int hf_cmp_can_flag_reserved;
static int hf_cmp_can_flag_reserved_1000;
static int hf_cmp_can_flag_reserved_2000;
static int hf_cmp_can_flag_gen_err;
static int hf_cmp_can_flag_reserved_tx;

static int hf_cmp_can_reserved;
static int hf_cmp_can_id;
static int hf_cmp_can_id_11bit;
static int hf_cmp_can_id_11bit_old;
static int hf_cmp_can_id_29bit;
static int hf_cmp_can_id_err;
static int hf_cmp_can_id_rtr;
static int hf_cmp_can_id_ide;
static int hf_cmp_can_crc;
static int hf_cmp_can_crc_crc;
static int hf_cmp_can_crc_res;
static int hf_cmp_can_crc_crc_support;
static int hf_cmp_can_err_pos;
static int hf_cmp_can_dlc;
static int hf_cmp_can_data_len;

/* CAN FD */
#define CMP_CANFD_FLAGS_ERRORS      0x03ff
#define CMP_CANFD_ID_ERR            0x20000000
#define CMP_CANFD_ID_RRS            0x40000000
#define CMP_CANFD_ID_IDE            0x80000000

#define CMP_CANFD_CRC_CRC17         0x0001ffff
#define CMP_CANFD_CRC_CRC21         0x001fffff
#define CMP_CANFD_CRC_SBC           0x00e00000
#define CMP_CANFD_CRC_SBC_PARITY    0x01000000
#define CMP_CANFD_CRC_RES           0x3e000000
#define CMP_CANFD_CRC_SBC_SUPP      0x40000000
#define CMP_CANFD_CRC_CRC_SUPP      0x80000000

static int hf_cmp_canfd_flags;

static int hf_cmp_canfd_flag_crc_err;
static int hf_cmp_canfd_flag_ack_err;
static int hf_cmp_canfd_flag_passive_ack_err;
static int hf_cmp_canfd_flag_reserved_0004;
static int hf_cmp_canfd_flag_active_ack_err;
static int hf_cmp_canfd_flag_reserved_0008;
static int hf_cmp_canfd_flag_ack_del_err;
static int hf_cmp_canfd_flag_form_err;
static int hf_cmp_canfd_flag_stuff_err;
static int hf_cmp_canfd_flag_crc_del_err;
static int hf_cmp_canfd_flag_eof_err;
static int hf_cmp_canfd_flag_bit_err;
static int hf_cmp_canfd_flag_res;
static int hf_cmp_canfd_flag_srr_dom;
static int hf_cmp_canfd_flag_brs;
static int hf_cmp_canfd_flag_esi;
static int hf_cmp_canfd_flag_reserved;
static int hf_cmp_canfd_flag_gen_err;
static int hf_cmp_canfd_flag_reserved_tx;

static int hf_cmp_canfd_reserved;
static int hf_cmp_canfd_id;
static int hf_cmp_canfd_id_11bit;
static int hf_cmp_canfd_id_11bit_old;
static int hf_cmp_canfd_id_29bit;
static int hf_cmp_canfd_id_err;
static int hf_cmp_canfd_id_rrs;
static int hf_cmp_canfd_id_ide;
static int hf_cmp_canfd_crc;
static int hf_cmp_canfd_crc_crc17;
static int hf_cmp_canfd_crc_crc21;
static int hf_cmp_canfd_crc_sbc;
static int hf_cmp_canfd_crc_sbc_parity;
static int hf_cmp_canfd_crc_res;
static int hf_cmp_canfd_crc_sbc_support;
static int hf_cmp_canfd_crc_crc_support;
static int hf_cmp_canfd_err_pos;
static int hf_cmp_canfd_dlc;
static int hf_cmp_canfd_data_len;

/* LIN */
#define CMP_CANFD_PID_PARITY_MASK   0xc0
#define CMP_CANFD_PID_ID_MASK       0x3f

static int hf_cmp_lin_flags;
static int hf_cmp_lin_flag_checksum_err;
static int hf_cmp_lin_flag_col_err;
static int hf_cmp_lin_flag_reserved_0x0002;
static int hf_cmp_lin_flag_parity_err;
static int hf_cmp_lin_flag_no_slave_res;
static int hf_cmp_lin_flag_reserved_0x0008;
static int hf_cmp_lin_flag_sync_err;
static int hf_cmp_lin_flag_framing_err;
static int hf_cmp_lin_flag_short_dom_err;
static int hf_cmp_lin_flag_long_dom_err;
static int hf_cmp_lin_flag_wup;
static int hf_cmp_lin_flag_reserved;

static int hf_cmp_lin_reserved;
static int hf_cmp_lin_pid;
static int hf_cmp_lin_pid_parity;
static int hf_cmp_lin_pid_id;
static int hf_cmp_lin_reserved_2;
static int hf_cmp_lin_checksum;
static int hf_cmp_lin_data_len;

/* FlexRay */
#define CMP_FLEXRAY_FLAGS_NF 0x0004

static int hf_cmp_flexray_flags;

static int hf_cmp_flexray_flag_crc_frame_err;
static int hf_cmp_flexray_flag_crc_header_err;
static int hf_cmp_flexray_flag_nf;
static int hf_cmp_flexray_flag_sf;
static int hf_cmp_flexray_flag_sync;
static int hf_cmp_flexray_flag_wus;
static int hf_cmp_flexray_flag_ppi;
static int hf_cmp_flexray_flag_cas;
static int hf_cmp_flexray_flag_reserved_0x0100;
static int hf_cmp_flexray_flag_leading;
static int hf_cmp_flexray_flag_channel;
static int hf_cmp_flexray_flag_reserved;

static int hf_cmp_flexray_reserved;
static int hf_cmp_flexray_header_crc;
static int hf_cmp_flexray_frame_id;
static int hf_cmp_flexray_cycle;
static int hf_cmp_flexray_frame_crc;
static int hf_cmp_flexray_reserved_2;
static int hf_cmp_flexray_data_len;

/* Digital */
#define CMP_DIGITAL_FLAG_TRIGGER_PRESENT 0x0001
#define CMP_DIGITAL_FLAG_SAMPLE_PRESENT 0x0002

static int hf_cmp_digital_flags;

static int hf_cmp_digital_flag_trig_present;
static int hf_cmp_digital_flag_sampl_present;
static int hf_cmp_digital_flag_reserved;

static int hf_cmp_digital_reserved;
static int hf_cmp_digital_pin_count;

static int hf_cmp_digital_trig_pattern;
static int hf_cmp_digital_trig_pin;
static int hf_cmp_digital_flag_reserved2;

static int hf_cmp_digital_sample_interval;
static int hf_cmp_digital_sample_count;

static int hf_cmp_digital_sample;

/* define 32 Pins for now */
static int hf_cmp_digital_sample_pin_0;
static int hf_cmp_digital_sample_pin_1;
static int hf_cmp_digital_sample_pin_2;
static int hf_cmp_digital_sample_pin_3;
static int hf_cmp_digital_sample_pin_4;
static int hf_cmp_digital_sample_pin_5;
static int hf_cmp_digital_sample_pin_6;
static int hf_cmp_digital_sample_pin_7;

static int hf_cmp_digital_sample_pin_8;
static int hf_cmp_digital_sample_pin_9;
static int hf_cmp_digital_sample_pin_10;
static int hf_cmp_digital_sample_pin_11;
static int hf_cmp_digital_sample_pin_12;
static int hf_cmp_digital_sample_pin_13;
static int hf_cmp_digital_sample_pin_14;
static int hf_cmp_digital_sample_pin_15;

static int hf_cmp_digital_sample_pin_16;
static int hf_cmp_digital_sample_pin_17;
static int hf_cmp_digital_sample_pin_18;
static int hf_cmp_digital_sample_pin_19;
static int hf_cmp_digital_sample_pin_20;
static int hf_cmp_digital_sample_pin_21;
static int hf_cmp_digital_sample_pin_22;
static int hf_cmp_digital_sample_pin_23;

static int hf_cmp_digital_sample_pin_24;
static int hf_cmp_digital_sample_pin_25;
static int hf_cmp_digital_sample_pin_26;
static int hf_cmp_digital_sample_pin_27;
static int hf_cmp_digital_sample_pin_28;
static int hf_cmp_digital_sample_pin_29;
static int hf_cmp_digital_sample_pin_30;
static int hf_cmp_digital_sample_pin_31;

/* UART/RS-232 */
#define CMP_UART_DATA_DATA_MASK     0x01FF

static int hf_cmp_uart_flags;

static int hf_cmp_uart_flag_cl;
static int hf_cmp_uart_flag_reserved;

static int hf_cmp_uart_reserved;
static int hf_cmp_uart_data_len;
static int hf_cmp_uart_data;

static int hf_cmp_uart_data_data;
static int hf_cmp_uart_data_reserved;
static int hf_cmp_uart_data_framing_err;
static int hf_cmp_uart_data_break_condition;
static int hf_cmp_uart_data_parity_err;

/* Analog */
static int hf_cmp_analog_flags;

static int hf_cmp_analog_flag_sample_dt;
static int hf_cmp_analog_flag_reserved;

static int hf_cmp_analog_reserved;
static int hf_cmp_analog_unit;
static int hf_cmp_analog_sample_interval;
static int hf_cmp_analog_sample_offset;
static int hf_cmp_analog_sample_scalar;
static int hf_cmp_analog_sample;
static int hf_cmp_analog_sample_raw;

/* Ethernet */
static int hf_cmp_eth_flags;

static int hf_cmp_eth_flag_fcs_err;
static int hf_cmp_eth_flag_short_err;
static int hf_cmp_eth_flag_tx_down;
static int hf_cmp_eth_flag_collision;
static int hf_cmp_eth_flag_long_err;
static int hf_cmp_eth_flag_phy_err;
static int hf_cmp_eth_flag_truncated;
static int hf_cmp_eth_flag_fcs_supported;
static int hf_cmp_eth_flag_reserved_cap;

static int hf_cmp_eth_flag_reserved_tx;
static int hf_cmp_eth_flag_fcs_sending;
static int hf_cmp_eth_flag_reserved_tx2;

static int hf_cmp_eth_reserved;
static int hf_cmp_eth_payload_length;

/* SPI */
static int hf_cmp_spi_flags;

static int hf_cmp_spi_flag_reserved;

static int hf_cmp_spi_reserved;
static int hf_cmp_spi_cipo_length;
static int hf_cmp_spi_cipo;
static int hf_cmp_spi_copi_length;
static int hf_cmp_spi_copi;

/* I2C */
static int hf_cmp_i2c_flags;
static int hf_cmp_i2c_flag_dir;
static int hf_cmp_i2c_flag_addr_len;
static int hf_cmp_i2c_flag_addr_ack;
static int hf_cmp_i2c_flag_addr_err;
static int hf_cmp_i2c_flag_stop_cond;
static int hf_cmp_i2c_flag_start_cond;
static int hf_cmp_i2c_flag_reserved;

static int hf_cmp_i2c_reserved;
static int hf_cmp_i2c_addr;
static int hf_cmp_i2c_data_entry_count;
static int hf_cmp_i2c_data;
static int hf_cmp_i2c_data_byte;
static int hf_cmp_i2c_data_control_ack;
static int hf_cmp_i2c_data_control_res;

/* GigE Vision */
static int hf_cmp_gige_flags;
static int hf_cmp_gige_flag_reserved;

static int hf_cmp_gige_reserved;
static int hf_cmp_gige_payload_length;
static int hf_cmp_gige_payload;

/* MIPI CSI-2 */
static int hf_cmp_mipi_csi2_flags;
static int hf_cmp_mipi_csi2_flag_crc_err;
static int hf_cmp_mipi_csi2_flag_ecc_err_c;
static int hf_cmp_mipi_csi2_flag_ecc_err_uc;
static int hf_cmp_mipi_csi2_flag_ecc_fmt;
static int hf_cmp_mipi_csi2_flag_frame_ctr_src;
static int hf_cmp_mipi_csi2_flag_line_ctr_src;
static int hf_cmp_mipi_csi2_flag_cs_support;
static int hf_cmp_mipi_csi2_flag_reserved;

static int hf_cmp_mipi_csi2_flag_reserved_tx;

static int hf_cmp_mipi_csi2_reserved;
static int hf_cmp_mipi_csi2_frame_counter;
static int hf_cmp_mipi_csi2_line_counter;
static int hf_cmp_mipi_csi2_dt;
static int hf_cmp_mipi_csi2_dt_res;
static int hf_cmp_mipi_csi2_dt_dt;
static int hf_cmp_mipi_csi2_vci;
static int hf_cmp_mipi_csi2_vci_res;
static int hf_cmp_mipi_csi2_vci_vcx;
static int hf_cmp_mipi_csi2_vci_vci;
static int hf_cmp_mipi_csi2_reserved2;
static int hf_cmp_mipi_csi2_ecc;
static int hf_cmp_mipi_csi2_ecc_res;
static int hf_cmp_mipi_csi2_ecc_ecc;
static int hf_cmp_mipi_csi2_cs;
static int hf_cmp_mipi_csi2_wc;
static int hf_cmp_mipi_csi2_short_packet_data;
static int hf_cmp_mipi_csi2_data;

/* Raw Ethernet */
static int hf_cmp_raw_eth_flags;
static int hf_cmp_raw_eth_flag_reserved;

static int hf_cmp_raw_eth_reserved;
static int hf_cmp_raw_eth_payload_length;
static int hf_cmp_raw_eth_preamble;
static int hf_cmp_raw_eth_sfd;
static int hf_cmp_raw_eth_mpacket;

/* 10BASE-T1S Symbols */
static int hf_cmp_10t1s_symb_flags;
static int hf_cmp_10t1s_symb_flag_decode_err;
static int hf_cmp_10t1s_symb_flag_miss_beacon;
static int hf_cmp_10t1s_symb_flag_res;
static int hf_cmp_10t1s_symb_flag_first_beacon;

static int hf_cmp_10t1s_symb_data_length;
static int hf_cmp_10t1s_symb_data;
static int hf_cmp_10t1s_symb_data_symbol;

/* A2B */
static int hf_cmp_a2b_flags;
static int hf_cmp_a2b_flag_fin;
static int hf_cmp_a2b_flag_fault_err;
static int hf_cmp_a2b_flag_fault_code;
static int hf_cmp_a2b_flag_fault_nloc;
static int hf_cmp_a2b_flag_hdcnt_err;
static int hf_cmp_a2b_flag_dd_err;
static int hf_cmp_a2b_flag_crc_err;
static int hf_cmp_a2b_flag_dp_err;
static int hf_cmp_a2b_flag_pwd_err;
static int hf_cmp_a2b_flag_becovf_err;
static int hf_cmp_a2b_flag_srf_err;
static int hf_cmp_a2b_flag_srfcrc_err;
static int hf_cmp_a2b_flag_icrc_err;
static int hf_cmp_a2b_flag_i2c_err;

static int hf_cmp_a2b_reserved;
static int hf_cmp_a2b_upstream_set;
static int hf_cmp_a2b_upstream_set_upfmt;
static int hf_cmp_a2b_upstream_set_ups;
static int hf_cmp_a2b_upstream_set_upsize;
static int hf_cmp_a2b_upstream_set_upslots;
static int hf_cmp_a2b_upstream_set_upoffset;

static int hf_cmp_a2b_downstream_set;
static int hf_cmp_a2b_downstream_set_dnfmt;
static int hf_cmp_a2b_downstream_set_dns;
static int hf_cmp_a2b_downstream_set_dnsize;
static int hf_cmp_a2b_downstream_set_dnslots;
static int hf_cmp_a2b_downstream_set_dnoffset;

static int hf_cmp_a2b_general_set;
static int hf_cmp_a2b_general_set_mstr;
static int hf_cmp_a2b_general_set_standby;
static int hf_cmp_a2b_general_set_endsniff;
static int hf_cmp_a2b_general_set_discvd;
static int hf_cmp_a2b_general_set_tx2pintl;
static int hf_cmp_a2b_general_set_rx2pintl;
static int hf_cmp_a2b_general_set_tdmmode;
static int hf_cmp_a2b_general_set_tdmss;
static int hf_cmp_a2b_general_set_bmmen;
static int hf_cmp_a2b_general_set_bclkrate;
static int hf_cmp_a2b_general_set_i2srate;
static int hf_cmp_a2b_general_set_txoffset;
static int hf_cmp_a2b_general_set_rxoffset;
static int hf_cmp_a2b_general_set_syncoffset;
static int hf_cmp_a2b_general_set_rrdiv;
static int hf_cmp_a2b_general_set_rrsoffset;
static int hf_cmp_a2b_general_set_reserved;
static int hf_cmp_a2b_general_set_raw_cap;

static int hf_cmp_a2b_data_length;
static int hf_cmp_a2b_data;

/* Link State */
static int hf_cmp_link_state_flags;
static int hf_cmp_link_state_flag_link_err;
static int hf_cmp_link_state_flag_reserved;

static int hf_cmp_link_state_flag_reserved_tx;

static int hf_cmp_link_state_interface_status;
static int hf_cmp_link_state_reserved;

/* Vendor Defined */
static int hf_cmp_vendor_def_vendor_id;
static int hf_cmp_vendor_def_vendor_payload_type;
static int hf_cmp_vendor_def_vendor_payload_data;

/* Control Message Payload Fields */
/* Data Sink Ready */
static int hf_cmp_ctrl_msg_device_id;

/* User Event */
static int hf_cmp_ctrl_msg_event_id;

/* Vendor specific */
static int hf_cmp_ctrl_msg_vendor_id;
static int hf_cmp_ctrl_msg_vendor_payload_type;

/* Status Message Payload Fields */
/* Capture Module Status Message */
static int hf_cmp_status_msg_cm_uptime_ns;
static int hf_cmp_status_msg_cm_uptime_s;
static int hf_cmp_status_msg_gm_identity;
static int hf_cmp_status_msg_gm_clock_quality;
static int hf_cmp_status_msg_current_utc_offset;
static int hf_cmp_status_msg_time_source;
static int hf_cmp_status_msg_domain_num;
static int hf_cmp_status_msg_res;
static int hf_cmp_gptp_flags;

static int hf_cmp_gptp_flags_leap61;
static int hf_cmp_gptp_flags_leap59;
static int hf_cmp_gptp_flags_cur_utco_valid;
static int hf_cmp_gptp_flags_ptp_timescale;
static int hf_cmp_gptp_flags_time_traceable;
static int hf_cmp_gptp_flags_freq_traceable;
static int hf_cmp_gptp_flags_reserved;

static int hf_cmp_status_dev_desc_length;
static int hf_cmp_status_dev_desc;
static int hf_cmp_status_sn_length;
static int hf_cmp_status_sn;
static int hf_cmp_status_hw_ver_length;
static int hf_cmp_status_hw_ver;
static int hf_cmp_status_sw_ver_length;
static int hf_cmp_status_sw_ver;
static int hf_cmp_status_vendor_data_length;
static int hf_cmp_status_vendor_data;

/* Interface Status Message */
static int hf_cmp_iface_interface;
static int hf_cmp_iface_iface_id;
static int hf_cmp_iface_msg_total_rx;
static int hf_cmp_iface_msg_total_tx;
static int hf_cmp_iface_msg_dropped_rx;
static int hf_cmp_iface_msg_dropped_tx;
static int hf_cmp_iface_errs_total_rx;
static int hf_cmp_iface_errs_total_tx;
static int hf_cmp_iface_iface_type;
static int hf_cmp_iface_iface_status;
static int hf_cmp_iface_stream_id_cnt;
static int hf_cmp_iface_reserved;

static int hf_cmp_iface_feat;

static int hf_cmp_iface_feat_can_crr_err;
static int hf_cmp_iface_feat_can_ack_err;
static int hf_cmp_iface_feat_can_pas_ack;
static int hf_cmp_iface_feat_can_act_ack;
static int hf_cmp_iface_feat_can_ack_del_err;
static int hf_cmp_iface_feat_can_form_err;
static int hf_cmp_iface_feat_can_stuff_err;
static int hf_cmp_iface_feat_can_crc_del_err;
static int hf_cmp_iface_feat_can_eof_err;
static int hf_cmp_iface_feat_can_bit_err;
static int hf_cmp_iface_feat_can_r0;
static int hf_cmp_iface_feat_can_srr_dom;
static int hf_cmp_iface_feat_can_gen_err;

static int hf_cmp_iface_feat_canfd_crr_err;
static int hf_cmp_iface_feat_canfd_ack_err;
static int hf_cmp_iface_feat_canfd_pas_ack;
static int hf_cmp_iface_feat_canfd_act_ack;
static int hf_cmp_iface_feat_canfd_ack_del_err;
static int hf_cmp_iface_feat_canfd_form_err;
static int hf_cmp_iface_feat_canfd_stuff_err;
static int hf_cmp_iface_feat_canfd_crc_del_err;
static int hf_cmp_iface_feat_canfd_eof_err;
static int hf_cmp_iface_feat_canfd_bit_err;
static int hf_cmp_iface_feat_canfd_rsvd;
static int hf_cmp_iface_feat_canfd_srr_dom;
static int hf_cmp_iface_feat_canfd_brs;
static int hf_cmp_iface_feat_canfd_esi;
static int hf_cmp_iface_feat_canfd_gen_err;

static int hf_cmp_iface_feat_lin_checksum_err;
static int hf_cmp_iface_feat_lin_coll_err;
static int hf_cmp_iface_feat_lin_parity_err;
static int hf_cmp_iface_feat_lin_no_slave_resp_err;
static int hf_cmp_iface_feat_lin_sync_err;
static int hf_cmp_iface_feat_lin_framing_err;
static int hf_cmp_iface_feat_lin_short_dom_err;
static int hf_cmp_iface_feat_lin_long_dom_err;
static int hf_cmp_iface_feat_lin_wup;

static int hf_cmp_iface_feat_fr_crc_frame_err;
static int hf_cmp_iface_feat_fr_crc_header_err;
static int hf_cmp_iface_feat_fr_nf;
static int hf_cmp_iface_feat_fr_sf;
static int hf_cmp_iface_feat_fr_sync;
static int hf_cmp_iface_feat_fr_wus;
static int hf_cmp_iface_feat_fr_ppi;
static int hf_cmp_iface_feat_fr_cas;
static int hf_cmp_iface_feat_fr_channel;

static int hf_cmp_iface_feat_eth_fcs_err;
static int hf_cmp_iface_feat_eth_too_short;
static int hf_cmp_iface_feat_eth_tx_port_down;
static int hf_cmp_iface_feat_eth_collision;
static int hf_cmp_iface_feat_eth_too_long;
static int hf_cmp_iface_feat_eth_phy_err;
static int hf_cmp_iface_feat_eth_trunc;
static int hf_cmp_iface_feat_eth_fcs;

static int hf_cmp_iface_feat_10t1s_first_beacon;
static int hf_cmp_iface_feat_10t1s_mis_beacon;
static int hf_cmp_iface_feat_10t1s_sym_decode;

static int hf_cmp_iface_feat_link_err;

static int hf_cmp_iface_stream_ids;
static int hf_cmp_iface_stream_id;
static int hf_cmp_iface_vendor_data_len;
static int hf_cmp_iface_vendor_data;

/* Configuration Status Message */
static int hf_cmp_status_msg_config;

/* Data Lost Event Status Message */
static int hf_cmp_dataloss_data_sink_port;
static int hf_cmp_dataloss_device_id;
static int hf_cmp_dataloss_reserved;
static int hf_cmp_dataloss_stream_id;
static int hf_cmp_dataloss_last_ssq_value;
static int hf_cmp_dataloss_current_ssq_value;

/* Time Sync Lost Event Status Message */
static int hf_cmp_timeloss_port_nr;
static int hf_cmp_timeloss_device_id;
static int hf_cmp_timeloss_error_flags;

static int hf_cmp_timeloss_error_flags_ts;
static int hf_cmp_timeloss_error_flags_insync;
static int hf_cmp_timeloss_error_flags_delta;
static int hf_cmp_timeloss_error_flags_reserved;

/* Vendor Specific */
static int hf_cmp_status_msg_vendor_specific;

/* Protocol trees */
static int ett_asam_cmp;
static int ett_asam_cmp_header;
static int ett_asam_cmp_timestamp;
static int ett_asam_cmp_trans_opts;
static int ett_asam_cmp_common_flags;
static int ett_asam_cmp_payload;
static int ett_asam_cmp_payload_flags;
static int ett_asam_cmp_payload_data;
static int ett_asam_cmp_lin_pid;
static int ett_asam_cmp_can_id;
static int ett_asam_cmp_can_crc;
static int ett_asam_cmp_digital_sample;
static int ett_asam_cmp_uart_data;
static int ett_asam_cmp_analog_sample;
static int ett_asam_cmp_i2c_data_entry;
static int ett_asam_cmp_a2b_upstream_settings;
static int ett_asam_cmp_a2b_downstream_settings;
static int ett_asam_cmp_a2b_general_settings;
static int ett_asam_cmp_status_cm_flags;
static int ett_asam_cmp_status_cm_uptime;
static int ett_asam_cmp_status_timeloss_flags;
static int ett_asam_cmp_status_interface;
static int ett_asam_cmp_status_feature_support;
static int ett_asam_cmp_status_stream_ids;

/* General */
#define CMP_HEADER_LEN                         8
#define CMP_MSG_HEADER_LEN                    16
#define CMP_MSG_HEADER_LEN_TX                 24

/* CMP Message Type Names */
#define CMP_MSG_TYPE_CAP_DATA_MSG           0x01
#define CMP_MSG_TYPE_CTRL_MSG               0x02
#define CMP_MSG_TYPE_STATUS_MSG             0x03
#define CMP_MSG_TYPE_TX_DATA_MSG            0x04
#define CMP_MSG_TYPE_VENDOR                 0xFF

/* CMP Segmentation Flag Values */
#define CMP_SEG_UNSEGMENTED                 0x00
#define CMP_SEG_FIRST                       0x01
#define CMP_SEG_INTERMEDIARY                0x02
#define CMP_SEG_LAST                        0x03

/* CMP Data Message Payload Type Names */
#define CMP_DATA_MSG_INVALID                0x00
#define CMP_DATA_MSG_CAN                    0x01
#define CMP_DATA_MSG_CANFD                  0x02
#define CMP_DATA_MSG_LIN                    0x03
#define CMP_DATA_MSG_FLEXRAY                0x04
#define CMP_DATA_MSG_DIGITAL                0x05
#define CMP_DATA_MSG_UART_RS_232            0x06
#define CMP_DATA_MSG_ANALOG                 0x07
#define CMP_DATA_MSG_ETHERNET               0x08
#define CMP_DATA_MSG_SPI                    0x09
#define CMP_DATA_MSG_I2C                    0x0A
#define CMP_DATA_MSG_GIGEVISION             0x0B
#define CMP_DATA_MSG_MIPI_CSI2              0x0C
#define CMP_DATA_MSG_RAW_ETHERNET           0x0D
#define CMP_DATA_MSG_10BASE_T1S_SYMBOL      0x0E
#define CMP_DATA_MSG_A2B                    0x0F
#define CMP_DATA_MSG_LINK_STATE             0xFE
#define CMP_DATA_MSG_VENDOR_DATA_MSG        0xFF

/* CMP Digital Trigger Pattern Values */
#define CMP_T_PATTERN_FALLING               0x00
#define CMP_T_PATTERN_RISING                0x01

/* CMP UART Data Message DL Values */
#define CMP_UART_CL_5                       0x00
#define CMP_UART_CL_6                       0x01
#define CMP_UART_CL_7                       0x02
#define CMP_UART_CL_8                       0x03
#define CMP_UART_CL_9                       0x04

/* CMP Analog Data Message DT Values */
#define CMP_ANALOG_DATA_MSG_DL_16           0x00
#define CMP_ANALOG_DATA_MSG_DL_32           0x01
#define CMP_ANALOG_DATA_MSG_DL_RES1         0x02
#define CMP_ANALOG_DATA_MSG_DL_RES2         0x03

/* CMP Control Message Payload Type Names */
#define CMP_CTRL_MSG_INVALID                0x00
#define CMP_CTRL_MSG_DSR_CTRL_MSG           0x01
#define CMP_CTRL_MSG_USER_EVENT_CTRL_MSG    0xFE
#define CMP_CTRL_MSG_VENDOR_CTRL_MSG        0xFF

/* CMP Status Message Payload Type Names */
#define CMP_STATUS_MSG_INVALID              0x00
#define CMP_STATUS_MSG_CM_STAT_MSG          0x01
#define CMP_STATUS_MSG_IF_STAT_MSG          0x02
#define CMP_STATUS_MSG_CONF_STAT_MSG        0x03
#define CMP_STATUS_MSG_DLE_STAT_MSG         0x04
#define CMP_STATUS_MSG_TSLE_STAT_MSG        0x05
#define CMP_STATUS_MSG_VENDOR_STAT_MSG      0xFF

/* Interface Status Message Names */
#define CMP_STATUS_IFACE_DOWN_EN            0x00
#define CMP_STATUS_IFACE_UP_EN              0x01
#define CMP_STATUS_IFACE_DOWN_DIS           0x02

static const value_string msg_type_names[] = {
    {CMP_MSG_TYPE_CAP_DATA_MSG,             "Capture Data Message"},
    {CMP_MSG_TYPE_CTRL_MSG,                 "Control Message"},
    {CMP_MSG_TYPE_STATUS_MSG,               "Status Message"},
    {CMP_MSG_TYPE_TX_DATA_MSG,              "Transmit Data Message"},
    {CMP_MSG_TYPE_VENDOR,                   "Vendor-defined Message"},
    {0, NULL}
};

static const true_false_string timestamp_rel_abs = {
    "Relative Mode",
    "Absolute Mode"
};

static const value_string seg_flag_names[] = {
    {CMP_SEG_INTERMEDIARY,                  "Intermediary segment"},
    {CMP_SEG_FIRST,                         "First segment"},
    {CMP_SEG_LAST,                          "Last segment"},
    {CMP_SEG_UNSEGMENTED,                   "Unsegmented"},
    {0, NULL}
};

static const true_false_string interface_direction = {
    "Sending",
    "Receive"
};

static const value_string data_msg_type_names[] = {
    {CMP_DATA_MSG_INVALID,                  "Invalid"},
    {CMP_DATA_MSG_CAN,                      "CAN"},
    {CMP_DATA_MSG_CANFD,                    "CAN FD"},
    {CMP_DATA_MSG_LIN,                      "LIN"},
    {CMP_DATA_MSG_FLEXRAY,                  "FlexRay"},
    {CMP_DATA_MSG_DIGITAL,                  "Digital"},
    {CMP_DATA_MSG_UART_RS_232,              "UART/RS-232"},
    {CMP_DATA_MSG_ANALOG,                   "Analog"},
    {CMP_DATA_MSG_ETHERNET,                 "Ethernet"},
    {CMP_DATA_MSG_SPI,                      "SPI"},
    {CMP_DATA_MSG_I2C,                      "I2C"},
    {CMP_DATA_MSG_GIGEVISION,               "Gigevision"},
    {CMP_DATA_MSG_MIPI_CSI2,                "MIPI CSI-2"},
    {CMP_DATA_MSG_RAW_ETHERNET,             "Raw Ethernet"},
    {CMP_DATA_MSG_10BASE_T1S_SYMBOL,        "10BASE-T1S Symbol"},
    {CMP_DATA_MSG_A2B,                      "A2B"},
    {CMP_DATA_MSG_LINK_STATE,               "Link State"},
    {CMP_DATA_MSG_VENDOR_DATA_MSG,          "Vendor-specific"},
    {0, NULL}
};

static const true_false_string cmp_err_noerr = {
    "Error",
    "No Error"
};

static const true_false_string can_dom_rec = {
    "Dominant",
    "Recessive"
};

static const true_false_string can_rec_dom = {
    "Recessive",
    "Dominant"
};

static const true_false_string can_id_ide = {
    "29bit ID",
    "11bit ID"
};

static const true_false_string can_id_rtr = {
    "Remote Frame",
    "Data Frame"
};

static const true_false_string canfd_act_pas = {
    "Error active",
    "Error passive"
};

static const true_false_string flexray_leading_following = {
    "Leading",
    "Following"
};

static const true_false_string flexray_channel_b_a = {
    "B",
    "A"
};

static const value_string flexray_transmission_operations[] = {
    {0x00,                                  "Stop Sending"},
    {0x01,                                  "Send Once"},
    {0x02,                                  "Send Cyclically"},
    {0x08,                                  "Configuration"},
    {0x09,                                  "Start Node"},
    {0x0a,                                  "Stop Node"},
    {0x0b,                                  "Abort Node"},
    {0x00, NULL}
};

static const value_string digital_trigger_pattern[] = {
    {0,                                     "Falling edge"},
    {1,                                     "Rising edge"},
    {0, NULL}
};

static const value_string uart_cl_names[] = {
    {CMP_UART_CL_5,                         "5 Bits"},
    {CMP_UART_CL_6,                         "6 Bits"},
    {CMP_UART_CL_7,                         "7 Bits"},
    {CMP_UART_CL_8,                         "8 Bits"},
    {CMP_UART_CL_9,                         "9 Bits"},
    {0, NULL}
};

static const value_string analog_sample_dt[] = {
    {CMP_ANALOG_DATA_MSG_DL_16,             "A_INT16"},
    {CMP_ANALOG_DATA_MSG_DL_32,             "A_INT32"},
    {CMP_ANALOG_DATA_MSG_DL_RES1,           "Reserved"},
    {CMP_ANALOG_DATA_MSG_DL_RES2,           "Reserved"},
    {0, NULL}
};

/* Also see packet-tecmp.c */
#define CMP_ETH_RAW_PREAMBLE                0x55
#define CMP_ETH_RAW_SFD_ORIG                0xD5
#define CMP_ETH_RAW_SFD_SMD_V               0x07
#define CMP_ETH_RAW_SFD_SMD_R               0x19
#define CMP_ETH_RAW_SFD_SMD_S0              0xE6
#define CMP_ETH_RAW_SFD_SMD_S1              0x4C
#define CMP_ETH_RAW_SFD_SMD_S2              0x7F
#define CMP_ETH_RAW_SFD_SMD_S3              0xB3
#define CMP_ETH_RAW_SFD_SMD_C0              0x61
#define CMP_ETH_RAW_SFD_SMD_C1              0x52
#define CMP_ETH_RAW_SFD_SMD_C2              0x9E
#define CMP_ETH_RAW_SFD_SMD_C3              0x2A

static const value_string eth_raw_sfd[] = {
    {CMP_ETH_RAW_SFD_ORIG,                  "SFD/SMD-E"},
    {CMP_ETH_RAW_SFD_SMD_V,                 "SMD-V"},
    {CMP_ETH_RAW_SFD_SMD_R,                 "SMD-R"},
    {CMP_ETH_RAW_SFD_SMD_S0,                "SMD-S0"},
    {CMP_ETH_RAW_SFD_SMD_S1,                "SMD-S1"},
    {CMP_ETH_RAW_SFD_SMD_S2,                "SMD-S2"},
    {CMP_ETH_RAW_SFD_SMD_S3,                "SMD-S3"},
    {CMP_ETH_RAW_SFD_SMD_C0,                "SMD-C0"},
    {CMP_ETH_RAW_SFD_SMD_C1,                "SMD-C1"},
    {CMP_ETH_RAW_SFD_SMD_C2,                "SMD-C2"},
    {CMP_ETH_RAW_SFD_SMD_C3,                "SMD-C3"},
    {0, NULL}
};

static const true_false_string i2c_read_write = {
    "Read",
    "Write"
};

static const true_false_string i2c_addr_length = {
    "10 Bit Address",
    "7 Bit Address"
};

static const true_false_string i2c_nack_ack = {
    "NACK",
    "ACK"
};

static const true_false_string i2c_stop_repeated_start = {
    "Stop",
    "Repeated-Start"
};

static const true_false_string i2c_repeated_start_start = {
    "Repeated-Start",
    "Start"
};

static const true_false_string mipi_csi2_ecc_noecc = {
    "6-bit ECC",
    "No ECC"
};

static const true_false_string mipi_csi2_cmcounter_csicounter = {
    "Counter generated by Capture Module",
    "Counter extracted from MIPI CSI-2 data"
};

/*
 * Based on what is publicly available:
 *   https://elixir.bootlin.com/linux/v5.19.17/source/include/media/mipi-csi2.h
 *   https://www.nxp.com/docs/en/application-note/AN5305.pdf
 *   https://www.efinixinc.com/docs/mipi-csi2-rx-core-ug-v3.2.pdf
 *   https://introspect.ca/blog/mipi-cse-and-csi-2/
 *   https://www.macnica.co.jp/en/business/semiconductor/articles/lattice/142604/
 *   https://www.design-reuse.com/article/60991-generating-high-speed-csi2-video-by-an-fpga/
 *   https://www.ti.com/lit/ds/symlink/ds90ub954-q1.pdf
 *   https://bitsimnow.se/wp-content/uploads/2021/04/Data_Sheet_bitcsi2rx_rH.pdf
 */

#define MIPI_CSI2_DT_BITS           0x3F
#define MIPI_CSI2_DT_SHORT_START    0x00
#define MIPI_CSI2_DT_SHORT_END      0x0F

static const value_string mipi_csi2_data_type_names[] = {
    /* 0x00 - 0x07 Sync Short Packets */
    {MIPI_CSI2_DT_SHORT_START,              "Frame Start Code"},
    {0x01,                                  "Frame End Code"},
    {0x02,                                  "Line Start Code"},
    {0x03,                                  "Line End Code"},
    /* 0x08 - 0x0F Generic Short Packets */
    /* 0x10 - 0x17 Generic Long Packets */
    {0x10,                                  "Null"},
    {0x11,                                  "Blanking Data"},
    {0x12,                                  "Embedded 8-bit non-Image Data"},
    /* 0x18 - 0x1F YUV Data Long Packets */
    {0x18,                                  "YUV420 8-bit"},
    {0x19,                                  "YUV420 10-bit"},
    {0x1A,                                  "Legacy YUV420 8-bit"},
    {0x1C,                                  "YUV420 8-bit (CSPS)"},
    {0x1D,                                  "YUV420 10-bit (CSPS)"},
    {0x1E,                                  "YUV422 8-bit"},
    {0x1F,                                  "YUV422 10-bit"},
    /* 0x20 - 0x27 RGB Data Long Packets */
    {0x20,                                  "RGB444"},
    {0x21,                                  "RGB555"},
    {0x22,                                  "RGB565"},
    {0x23,                                  "RGB666"},
    {0x24,                                  "RGB888"},
    /* 0x28 - 0x2F RAW Data Long Packets */
    {0x26,                                  "RAW24"},
    {0x27,                                  "RAW28"},
    {0x28,                                  "RAW6"},
    {0x29,                                  "RAW7"},
    {0x2A,                                  "RAW8"},
    {0x2B,                                  "RAW10"},
    {0x2C,                                  "RAW12"},
    {0x2D,                                  "RAW14"},
    {0x2E,                                  "RAW16"},
    {0x2F,                                  "RAW20"},
    /* 0x30 - 0x37 User Defined Long Packets */
    {0x30,                                  "User Defined 8-bit Data Type 1"},
    {0x31,                                  "User Defined 8-bit Data Type 2"},
    {0x32,                                  "User Defined 8-bit Data Type 3"},
    {0x33,                                  "User Defined 8-bit Data Type 4"},
    {0x34,                                  "User Defined 8-bit Data Type 5"},
    {0x35,                                  "User Defined 8-bit Data Type 6"},
    {0x36,                                  "User Defined 8-bit Data Type 7"},
    {0x37,                                  "User Defined 8-bit Data Type 8"},
    /* 0x38 - 0x3F Reserved */
    {0x3E,                                  "SEP (MIPI CSE)"},
    {0, NULL}
};

static const true_false_string eth_10baset1s_firstbeacon_notfirstbeacon = {
    "First Beacon",
    "Not First Beacon"
};

/* IEEE 802.3-2022 Table 147-1: 4B/5B Encoding */
static const value_string eth_10baset1s_symbol_names[] = {
    {0x1F,                                  "SILENCE"},         /* I: 11111 */
    {0x18,                                  "SYNC / COMMIT"},   /* J: 11000 */
    {0x11,                                  "ESDERR"},          /* K: 10001 */
    {0x0D,                                  "ESD / HB"},        /* T: 01101 */
    {0x07,                                  "ESDOK / ESDBRS"},  /* R: 00111 */
    {0x04,                                  "SSD"},             /* H: 00100 */
    {0x08,                                  "BEACON"},          /* N: 01000 */
    {0x19,                                  "ESDJAB"},          /* I: 11001 */
    {0, NULL}
};

static const true_false_string a2b_switch_closed_open = {
    "Switch completed closing",
    "Switch is open or has not finished closing"
};

static const true_false_string a2b_cable_fault_no_fault = {
    "Cable fault detected",
    "Cable fault not detected"
};

static const value_string a2b_fault_code_names[] = {
    {0x0,                                   "No fault detected"},
    {0x1,                                   "Cable terminal shorted to GND"},
    {0x2,                                   "Cable terminal shorted to VBAT"},
    {0x3,                                   "Cable terminals shorted together"},
    {0x4,                                   "Cable disconnected or open circuit"},
    {0x5,                                   "Cable is reverse connected"},
    {0x6,                                   "Reserved"},
    {0x7,                                   "Undetermined fault"},
    {0, NULL}
};

static const true_false_string a2b_cable_fault_not_localized_localized = {
    "Cable fault not localized",
    "Cable fault localized"
};

static const true_false_string a2b_data_decode_error_no_error = {
    "Data decoding error detected",
    "No data decoding error"
};

static const true_false_string a2b_crc_error_no_error = {
    "CRC error detected",
    "No CRC error"
};

static const true_false_string a2b_data_parity_error_no_error = {
    "Data parity error detected",
    "No data parity error"
};

static const true_false_string a2b_downstream_power_switch_error_no_error = {
    "Downstream power switch error",
    "No power error"
};

static const true_false_string a2b_bit_error_count_error_no_error = {
    "BEC error pending",
    "No BEC error pending"
};

static const true_false_string a2b_srf_miss_error_no_error = {
    "SRF miss error detected",
    "No SRF miss error"
};

static const true_false_string a2b_srf_crc_error_no_error = {
    "SRF CRC error detected",
    "No SRF CRC error"
};

static const true_false_string a2b_iocrc_error_no_error = {
    "Interrupt Frame CRC error detected",
    "No error"
};

static const true_false_string a2b_i2c_transaction_error_no_error = {
    "An I2C access error occurred",
    "No error"
};

static const true_false_string a2b_fmt_alternate_normal = {
    "Alternate data slot format",
    "Normal data slot format"
};

static const value_string a2b_slot_sizes[] = {
    {0x00,                                  "8 bits"},
    {0x01,                                  "12 bits"},
    {0x02,                                  "16 bits"},
    {0x03,                                  "20 bits"},
    {0x04,                                  "24 bits"},
    {0x05,                                  "28 bits"},
    {0x06,                                  "32 bits"},
    {0x07,                                  "Reserved"},
    {0, NULL}
};

static const val64_string a2b_tdmmode_values[] = {
    {0x00,                                  "TDM2"},
    {0x01,                                  "TDM4"},
    {0x02,                                  "TDM8"},
    {0x03,                                  "TDM12"},
    {0x04,                                  "TDM16"},
    {0x05,                                  "TDM20"},
    {0x06,                                  "TDM24"},
    {0x07,                                  "TDM32"},
    {0, NULL}
};

static const true_false_string a2b_tdmss_16_32 = {
    "32bit",
    "16bit"
};

static const val64_string a2b_blckrate_values[] = {
    {0x00,                                  "BCLK frequency as configured in A2B_I2SGCFG"},
    {0x01,                                  "SYNC frequency x 2048"},
    {0x02,                                  "SYNC frequency x 4096"},
    {0x04,                                  "SFF frequency x 64"},
    {0x05,                                  "SFF frequency x 128"},
    {0x06,                                  "SFF frequency x 256"},
    {0, NULL}
};

static const val64_string a2b_i2srate_values[] = {
    {0x00,                                  "SFF x 1"},
    {0x01,                                  "SFF / 2"},
    {0x02,                                  "SFF / 4"},
    {0x03,                                  "SFF / A2B_I2SRRATE.RRDIV"},
    {0x05,                                  "SFF x 2"},
    {0x06,                                  "SFF x 4"},
    {0, NULL}
};

static const val64_string a2b_rrdiv_values[] = {
    {1,                                     "Superframe frequency (SFF)"},
    {2,                                     "SFF / 2"},
    {4,                                     "SFF / 4"},
    {8,                                     "SFF / 8"},
    {12,                                    "SFF / 12"},
    {16,                                    "SFF / 16"},
    {20,                                    "SFF / 20"},
    {24,                                    "SFF / 24"},
    {28,                                    "SFF / 28"},
    {32,                                    "SFF / 32"},
    {0, NULL}
};

static const val64_string a2b_rrsoffset_values[] = {
    {0,                                     "No Offset"},
    {1,                                     "1 Superframe Earlier"},
    {2,                                     "2 Superframes Earlier"},
    {3,                                     "3 Superframes Earlier"},
    {0, NULL}
};

static const true_false_string a2b_raw_capturing = {
    "Raw A2B Busline was captured",
    "I²S/TDM representation was captured"
};

static const value_string link_state_names[] = {
    {0x00,                                  "Down"},
    {0x01,                                  "Up"},
    {0x02,                                  "Disabled"},
    {0x03,                                  "Testing"},
    {0x04,                                  "Unknown"},
    {0x05,                                  "Dormant"},
    {0x06,                                  "NotPresent"},
    {0, NULL}
};

static const value_string ctrl_msg_type_names[] = {
    {CMP_CTRL_MSG_INVALID,                  "Invalid"},
    {CMP_CTRL_MSG_DSR_CTRL_MSG,             "Data Sink ready to receive Control Message"},
    {CMP_CTRL_MSG_USER_EVENT_CTRL_MSG,      "User Event Message"},
    {CMP_CTRL_MSG_VENDOR_CTRL_MSG,          "Vendor-specific Control Message"},
    {0, NULL}
};

static const value_string status_msg_type_names[] = {
    {CMP_STATUS_MSG_INVALID,                "Invalid"},
    {CMP_STATUS_MSG_CM_STAT_MSG,            "Capture Module Status"},
    {CMP_STATUS_MSG_IF_STAT_MSG,            "Interface Status"},
    {CMP_STATUS_MSG_CONF_STAT_MSG,          "Configuration Status"},
    {CMP_STATUS_MSG_DLE_STAT_MSG,           "Data Lost Status"},
    {CMP_STATUS_MSG_TSLE_STAT_MSG,          "Time Sync Lost Status"},
    {CMP_STATUS_MSG_VENDOR_STAT_MSG,        "Vendor-specific Status Message"},
    {0, NULL}
};

static const value_string interface_status_names[] = {
    {CMP_STATUS_IFACE_DOWN_EN,              "Down and enabled"},
    {CMP_STATUS_IFACE_UP_EN,                "Up and enabled"},
    {CMP_STATUS_IFACE_DOWN_DIS,             "Down and disabled"},
    {0, NULL}
};

/* As defined by the ASAM Vendor ID registry for POD and CMP */
#define CMP_VENDOR_ID_AVL_LIST              0x0006
#define CMP_VENDOR_DSPACE                   0x000b
#define CMP_VENDOR_ETAS                     0x000c
#define CMP_VENDOR_BOSCH                    0x0027
#define CMP_VENDOR_VECTOR                   0x002d
#define CMP_VENDOR_CONTINENTAL              0x003c
#define CMP_VENDOR_MK                       0x003e
#define CMP_VENDOR_ID_ACCURATE              0x004a
#define CMP_VENDOR_RA                       0x006c
#define CMP_VENDOR_X2E                      0x00ca
#define CMP_VENDOR_INTREPIDCS               0x00f0
#define CMP_VENDOR_ID_BPLUS                 0x010f
#define CMP_VENDOR_VIGEM                    0x012a
#define CMP_VENDOR_TECHNICA                 0x019c
#define CMP_VENDOR_ID_AED_ENG               0x0241

/* As defined by the ASAM Vendor ID registry for POD and CMP */
static const value_string vendor_ids[] = {
    {CMP_VENDOR_ID_ACCURATE,                "Accurate Technologies Inc."},
    {CMP_VENDOR_ID_AED_ENG,                 "AED Engineering GmbH"},
    {CMP_VENDOR_ID_AVL_LIST,                "AVL List GmbH"},
    {CMP_VENDOR_ID_BPLUS,                   "b-plus GmbH"},
    {CMP_VENDOR_CONTINENTAL,                "Continental AG"},
    {CMP_VENDOR_DSPACE,                     "dSPACE GmbH"},
    {CMP_VENDOR_ETAS,                       "ETAS GmbH"},
    {CMP_VENDOR_INTREPIDCS,                 "Intrepid Control Systems, Inc."},
    {CMP_VENDOR_MK,                         "M&K Meß- und Kommunikationstechnik GmbH"},
    {CMP_VENDOR_RA,                         "RA Consulting GmbH"},
    {CMP_VENDOR_BOSCH,                      "Robert Bosch GmbH"},
    {CMP_VENDOR_TECHNICA,                   "Technica Engineering GmbH"},
    {CMP_VENDOR_VECTOR,                     "Vector Informatik GmbH"},
    {CMP_VENDOR_VIGEM,                      "ViGEM GmbH"},
    {CMP_VENDOR_X2E,                        "X2E GmbH"},
    {0, NULL}
};

static const value_string analog_units[] = {
    {0x01, "s"},
    {0x02, "m"},
    {0x03, "kg"},
    {0x04, "A"},
    {0x05, "K"},
    {0x06, "mol"},
    {0x07, "cd"},
    {0x08, "Hz"},
    {0x09, "rad"},
    {0x0a, "sr"},
    {0x0b, "N"},
    {0x0c, "Pa"},
    {0x0d, "J"},
    {0x0e, "W"},
    {0x0f, "C"},
    {0x10, "V"},
    {0x11, "F"},
    {0x12, "Ω"},
    {0x13, "S"},
    {0x14, "Wb"},
    {0x15, "T"},
    {0x16, "H"},
    {0x17, "°C"},
    {0x18, "lm"},
    {0x19, "lx"},
    {0x1A, "Bq"},
    {0x1B, "Gy"},
    {0x1C, "Sv"},
    {0x1D, "kat"},
    {0x1E, "m/s"},
    {0x1F, "m/s2"},
    {0x20, "m/s3"},
    {0x21, "m/s4"},
    {0x22, "rad/s"},
    {0x23, "rad/s2"},
    {0x24, "Hz/s"},
    {0x25, "m3/s"},
    {0x26, "m2"},
    {0x27, "m3"},
    {0x28, "N s"},
    {0x29, "N m s"},
    {0x2A, "N m"},
    {0x2B, "kg/m2"},
    {0x2C, "kg/m3"},
    {0x2D, "m3/kg"},
    {0x2E, "J s"},
    {0x2F, "J/kg"},
    {0x30, "J/m3"},
    {0x31, "N/m"},
    {0x32, "W/m2"},
    {0x33, "m2/s"},
    {0x34, "Pa s"},
    {0x35, "kg/s"},
    {0x36, "W/(sr m2)"},
    {0x37, "Gy/s"},
    {0x38, "m/m3"},
    {0x39, "W/m3"},
    {0x3A, "J/(m2 s)"},
    {0x3B, "kg m2"},
    {0x3C, "W/sr"},
    {0x3D, "mol/m3"},
    {0x3E, "m3/mol"},
    {0x3F, "J/(mol K)"},
    {0x40, "J/mol"},
    {0x41, "mol/kg"},
    {0x42, "kg/mol"},
    {0x45, "C/m3"},
    {0x46, "A/m2"},
    {0x47, "S/m"},
    {0x48, "F/m"},
    {0x49, "H/m"},
    {0x4A, "V/m"},
    {0x4B, "A/m"},
    {0x4C, "C/Kg"},
    {0x4D, "J/T"},
    {0x4E, "lm s"},
    {0x4F, "lx s"},
    {0x50, "cd/m2"},
    {0x51, "lm/W"},
    {0x52, "J/K"},
    {0x53, "J/(K kg)"},
    {0x54, "W/(m K)"},
    {0, NULL}
};

/********* UATs *********/

typedef struct _generic_one_id_string {
    unsigned   id;
    char   *name;
} generic_one_id_string_t;

/* Interface UAT */
typedef struct _interface_config {
    unsigned  id;
    unsigned  bus_id;
    char     *name;
} interface_config_t;

/* Devices */
#define DATAFILE_ASAM_CMP_DEVICES_IDS "ASAM_CMP_devices"

static GHashTable *data_asam_cmp_devices;
static generic_one_id_string_t *asam_cmp_devices;
static unsigned asam_cmp_devices_num;

UAT_HEX_CB_DEF(asam_cmp_devices, id, generic_one_id_string_t)
UAT_CSTRING_CB_DEF(asam_cmp_devices, name, generic_one_id_string_t)

/* Interfaces */
#define DATAFILE_ASAM_CMP_IFACE_IDS "ASAM_CMP_interfaces"

static GHashTable *data_asam_cmp_interfaces;
static interface_config_t *asam_cmp_interfaces;
static unsigned asam_cmp_interface_num;

UAT_HEX_CB_DEF(asam_cmp_interfaces, id, interface_config_t)
UAT_CSTRING_CB_DEF(asam_cmp_interfaces, name, interface_config_t)
UAT_HEX_CB_DEF(asam_cmp_interfaces, bus_id, interface_config_t)

/*** expert info items ***/
static expert_field ei_asam_cmp_length_mismatch;
static expert_field ei_asam_cmp_unsupported_crc_not_zero;

/* ID -> Name */
static void *
copy_generic_one_id_string_cb(void *n, const void *o, size_t size _U_) {
    generic_one_id_string_t *new_rec = (generic_one_id_string_t *)n;
    const generic_one_id_string_t *old_rec = (const generic_one_id_string_t *)o;

    new_rec->name = g_strdup(old_rec->name);
    new_rec->id = old_rec->id;
    return new_rec;
}

static bool
update_generic_one_identifier_16bit(void *r, char **err) {
    generic_one_id_string_t *rec = (generic_one_id_string_t *)r;

    if (rec->id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit identifiers (ID: %i  Name: %s)", rec->id, rec->name);
        return false;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return false;
    }

    return true;
}

static void
free_generic_one_id_string_cb(void *r) {
    generic_one_id_string_t *rec = (generic_one_id_string_t *)r;
    /* freeing result of g_strdup */
    g_free(rec->name);
    rec->name = NULL;
}

static char *
ht_lookup_device_name(uint16_t device_id) {
    if (data_asam_cmp_devices == NULL) {
        return NULL;
    }

    return g_hash_table_lookup(data_asam_cmp_devices, GUINT_TO_POINTER(device_id));
}

/* ID -> ID, Name */
static void *
copy_interface_config_cb(void *n, const void *o, size_t size _U_) {
    interface_config_t *new_rec = (interface_config_t *)n;
    const interface_config_t *old_rec = (const interface_config_t *)o;

    new_rec->id = old_rec->id;
    new_rec->name = g_strdup(old_rec->name);
    new_rec->bus_id = old_rec->bus_id;
    return new_rec;
}

static bool
update_interface_config(void *r, char **err) {
    interface_config_t *rec = (interface_config_t *)r;

    if (rec->id > 0xffffffff) {
        *err = ws_strdup_printf("We currently only support 32 bit identifiers (ID: %i  Name: %s)", rec->id, rec->name);
        return false;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return false;
    }

    if (rec->bus_id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit bus identifiers (ID: %i  Name: %s  Bus-ID: %i)", rec->id, rec->name, rec->bus_id);
        return false;
    }

    return true;
}

static void
free_interface_config_cb(void *r) {
    interface_config_t *rec = (interface_config_t *)r;
    /* freeing result of g_strdup */
    g_free(rec->name);
    rec->name = NULL;
}

static interface_config_t *
ht_lookup_interface(unsigned int identifier) {
    if (data_asam_cmp_interfaces == NULL) {
        return NULL;
    }

    return g_hash_table_lookup(data_asam_cmp_interfaces, GUINT_TO_POINTER(identifier));
}


static char *
ht_interface_config_to_string(unsigned int identifier) {
    interface_config_t *tmp = ht_lookup_interface(identifier);
    if (tmp == NULL) {
        return NULL;
    }

    return tmp->name;
}

static uint16_t
ht_interface_config_to_bus_id(unsigned int identifier) {
    interface_config_t *tmp = ht_lookup_interface(identifier);
    if (tmp == NULL) {
        /* 0 means basically any or none */
        return 0;
    }

    return (uint16_t)tmp->bus_id;
}

static void
reset_asam_cmp_devices_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_asam_cmp_devices) {
        g_hash_table_destroy(data_asam_cmp_devices);
        data_asam_cmp_devices = NULL;
    }
}

static void
post_update_asam_cmp_devices_cb(void) {
    /* destroy old hash table, if it exists */
    reset_asam_cmp_devices_cb();

    /* create new hash table */
    data_asam_cmp_devices = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    for (unsigned i = 0; i < asam_cmp_devices_num; i++) {
        g_hash_table_insert(data_asam_cmp_devices, GUINT_TO_POINTER(asam_cmp_devices[i].id), asam_cmp_devices[i].name);
    }
}

static void
reset_interface_config_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_asam_cmp_interfaces) {
        g_hash_table_destroy(data_asam_cmp_interfaces);
        data_asam_cmp_interfaces = NULL;
    }
}

static void
post_update_interface_config_cb(void) {
    /* destroy old hash table, if it exists */
    reset_interface_config_cb();

    /* create new hash table */
    data_asam_cmp_interfaces = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    for (unsigned i = 0; i < asam_cmp_interface_num; i++) {
        g_hash_table_insert(data_asam_cmp_interfaces, GUINT_TO_POINTER(asam_cmp_interfaces[i].id), &asam_cmp_interfaces[i]);
    }
}

static void
add_device_id_text(proto_item *ti, uint16_t device_id) {
    const char *descr = ht_lookup_device_name(device_id);

    if (descr != NULL) {
        proto_item_append_text(ti, " (%s)", descr);
    }
}

static void
add_interface_id_text(proto_item *ti, uint32_t interface_id) {
    const char *descr = ht_interface_config_to_string(interface_id);

    if (descr != NULL) {
        proto_item_append_text(ti, " (%s)", descr);
    }
}

static uint32_t
dissect_asam_cmp_data_msg_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned interface_id, bool tx) {
    uint32_t offset = 0;

    static int * const asam_cmp_can_flags_cap[] = {
        &hf_cmp_can_flag_reserved,
        &hf_cmp_can_flag_srr_dom,
        &hf_cmp_can_flag_r0,
        &hf_cmp_can_flag_bit_err,
        &hf_cmp_can_flag_eof_err,
        &hf_cmp_can_flag_crc_del_err,
        &hf_cmp_can_flag_stuff_err,
        &hf_cmp_can_flag_form_err,
        &hf_cmp_can_flag_ack_del_err,
        &hf_cmp_can_flag_active_ack_err,
        &hf_cmp_can_flag_passive_ack_err,
        &hf_cmp_can_flag_ack_err,
        &hf_cmp_can_flag_crc_err,
        NULL
    };

    static int * const asam_cmp_can_flags_tx[] = {
        &hf_cmp_can_flag_reserved_tx,
        &hf_cmp_can_flag_gen_err,
        &hf_cmp_can_flag_reserved_2000,
        &hf_cmp_can_flag_reserved_1000,
        &hf_cmp_can_flag_srr_dom,
        &hf_cmp_can_flag_r0,
        &hf_cmp_can_flag_bit_err,
        &hf_cmp_can_flag_eof_err,
        &hf_cmp_can_flag_crc_del_err,
        &hf_cmp_can_flag_stuff_err,
        &hf_cmp_can_flag_form_err,
        &hf_cmp_can_flag_ack_del_err,
        &hf_cmp_can_flag_reserved_0008,
        &hf_cmp_can_flag_reserved_0004,
        &hf_cmp_can_flag_ack_err,
        &hf_cmp_can_flag_crc_err,
        NULL
    };

    static int * const asam_cmp_can_id_field_11bit[] = {
        &hf_cmp_can_id_ide,
        &hf_cmp_can_id_rtr,
        &hf_cmp_can_id_err,
        &hf_cmp_can_id_11bit,
        NULL
    };

    static int * const asam_cmp_can_id_field_11bit_old[] = {
        &hf_cmp_can_id_ide,
        &hf_cmp_can_id_rtr,
        &hf_cmp_can_id_err,
        &hf_cmp_can_id_11bit_old,
        NULL
    };

    static int * const asam_cmp_can_id_field_29bit[] = {
        &hf_cmp_can_id_ide,
        &hf_cmp_can_id_rtr,
        &hf_cmp_can_id_err,
        &hf_cmp_can_id_29bit,
        NULL
    };

    static int * const asam_cmp_can_crc_field[] = {
        &hf_cmp_can_crc_crc_support,
        &hf_cmp_can_crc_res,
        &hf_cmp_can_crc_crc,
        NULL
    };

    uint16_t can_flags = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    if (tx) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_can_flags, ett_asam_cmp_payload_flags, asam_cmp_can_flags_tx, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_can_flags, ett_asam_cmp_payload_flags, asam_cmp_can_flags_cap, ENC_BIG_ENDIAN);
    }
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_can_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    uint32_t can_id_field = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    bool can_id_29bit = (can_id_field & CMP_CAN_ID_IDE) == CMP_CAN_ID_IDE;
    uint32_t can_id = 0;
    if (can_id_29bit) {
        proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_cmp_can_id, ett_asam_cmp_can_id, asam_cmp_can_id_field_29bit, ENC_BIG_ENDIAN, BMT_NO_FALSE);
        can_id = can_id_field & (CMP_CAN_ID_29BIT_MASK | CMP_CAN_ID_RTR | CMP_CAN_ID_IDE);
    } else {
        if (old_11bit_canid_encoding) {
            proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_cmp_can_id, ett_asam_cmp_can_id, asam_cmp_can_id_field_11bit_old, ENC_BIG_ENDIAN, BMT_NO_FALSE);
            can_id = can_id_field & (CMP_CAN_ID_RTR | CMP_CAN_ID_IDE | CMP_CAN_ID_11BIT_MASK_OLD);
        } else {
            proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_cmp_can_id, ett_asam_cmp_can_id, asam_cmp_can_id_field_11bit, ENC_BIG_ENDIAN, BMT_NO_FALSE);
            can_id = (can_id_field & (CMP_CAN_ID_RTR | CMP_CAN_ID_IDE)) + ((can_id_field & CMP_CAN_ID_11BIT_MASK) >> CMP_CAN_ID_11BIT_SHIFT);
        }
    }
    offset += 4;

    uint64_t tmp64;
    proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_cmp_can_crc, ett_asam_cmp_can_crc, asam_cmp_can_crc_field, ENC_BIG_ENDIAN, BMT_NO_FALSE, &tmp64);
    if ((tmp64 & CMP_CAN_CRC_CRC_SUPP) == 0 && (tmp64 & CMP_CAN_CRC_CRC) != 0) {
        proto_tree_add_expert(tree, pinfo, &ei_asam_cmp_unsupported_crc_not_zero, tvb, offset, 4);
    }
    offset += 4;

    uint32_t err_pos = 0;
    proto_tree_add_item_ret_uint(tree, hf_cmp_can_err_pos, tvb, offset, 2, ENC_BIG_ENDIAN, &err_pos);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_can_dlc, tvb, offset, 1, ENC_NA);
    offset += 1;

    uint32_t msg_payload_type_length;
    proto_tree_add_item_ret_uint(tree, hf_cmp_can_data_len, tvb, offset, 1, ENC_NA, &msg_payload_type_length);
    offset += 1;

    if (msg_payload_type_length > 0) {
        tvbuff_t *sub_tvb = tvb_new_subset_length(tvb, offset, msg_payload_type_length);

        if ((can_flags & CMP_CAN_FLAGS_ERRORS) != 0) {
            can_id = can_id | CAN_ERR_FLAG;
        }

        struct can_info can_info = { .id = can_id, .len = msg_payload_type_length, .fd = CAN_TYPE_CAN_CLASSIC, .bus_id = ht_interface_config_to_bus_id(interface_id) };
        if (!socketcan_call_subdissectors(sub_tvb, pinfo, tree, &can_info, heuristic_first)) {
            call_data_dissector(sub_tvb, pinfo, tree);
        }

        offset += msg_payload_type_length;
    }

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_canfd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned interface_id, bool tx) {
    uint32_t offset = 0;

    static int * const asam_cmp_canfd_flags_cap[] = {
        &hf_cmp_canfd_flag_reserved,
        &hf_cmp_canfd_flag_esi,
        &hf_cmp_canfd_flag_brs,
        &hf_cmp_canfd_flag_srr_dom,
        &hf_cmp_canfd_flag_res,
        &hf_cmp_canfd_flag_bit_err,
        &hf_cmp_canfd_flag_eof_err,
        &hf_cmp_canfd_flag_crc_del_err,
        &hf_cmp_canfd_flag_stuff_err,
        &hf_cmp_canfd_flag_form_err,
        &hf_cmp_canfd_flag_ack_del_err,
        &hf_cmp_canfd_flag_active_ack_err,
        &hf_cmp_canfd_flag_passive_ack_err,
        &hf_cmp_canfd_flag_ack_err,
        &hf_cmp_canfd_flag_crc_err,
        NULL
    };

    static int * const asam_cmp_canfd_flags_tx[] = {
        &hf_cmp_canfd_flag_reserved_tx,
        &hf_cmp_canfd_flag_gen_err,
        &hf_cmp_canfd_flag_esi,
        &hf_cmp_canfd_flag_brs,
        &hf_cmp_canfd_flag_srr_dom,
        &hf_cmp_canfd_flag_res,
        &hf_cmp_canfd_flag_bit_err,
        &hf_cmp_canfd_flag_eof_err,
        &hf_cmp_canfd_flag_crc_del_err,
        &hf_cmp_canfd_flag_stuff_err,
        &hf_cmp_canfd_flag_form_err,
        &hf_cmp_canfd_flag_ack_del_err,
        &hf_cmp_canfd_flag_reserved_0008,
        &hf_cmp_canfd_flag_reserved_0004,
        &hf_cmp_canfd_flag_ack_err,
        &hf_cmp_canfd_flag_crc_err,
        NULL
    };

    static int * const asam_cmp_canfd_id_field_11bit[] = {
        &hf_cmp_canfd_id_ide,
        &hf_cmp_canfd_id_rrs,
        &hf_cmp_canfd_id_err,
        &hf_cmp_canfd_id_11bit,
        NULL
    };

    static int * const asam_cmp_canfd_id_field_11bit_old[] = {
        &hf_cmp_canfd_id_ide,
        &hf_cmp_canfd_id_rrs,
        &hf_cmp_canfd_id_err,
        &hf_cmp_canfd_id_11bit_old,
        NULL
    };

    static int * const asam_cmp_canfd_id_field_29bit[] = {
        &hf_cmp_canfd_id_ide,
        &hf_cmp_canfd_id_rrs,
        &hf_cmp_canfd_id_err,
        &hf_cmp_canfd_id_29bit,
        NULL
    };

    static int * const asam_cmp_canfd_crc_field_17bit[] = {
        &hf_cmp_canfd_crc_crc_support,
        &hf_cmp_canfd_crc_sbc_support,
        &hf_cmp_canfd_crc_res,
        &hf_cmp_canfd_crc_sbc_parity,
        &hf_cmp_canfd_crc_sbc,
        &hf_cmp_canfd_crc_crc17,
        NULL
    };

    static int * const asam_cmp_canfd_crc_field_21bit[] = {
        &hf_cmp_canfd_crc_crc_support,
        &hf_cmp_canfd_crc_sbc_support,
        &hf_cmp_canfd_crc_res,
        &hf_cmp_canfd_crc_sbc_parity,
        &hf_cmp_canfd_crc_sbc,
        &hf_cmp_canfd_crc_crc21,
        NULL
    };

    uint16_t canfd_flags = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    if (tx) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_canfd_flags, ett_asam_cmp_payload_flags, asam_cmp_canfd_flags_tx, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_canfd_flags, ett_asam_cmp_payload_flags, asam_cmp_canfd_flags_cap, ENC_BIG_ENDIAN);
    }
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_canfd_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    uint32_t can_id_field = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    bool can_id_29bit = (can_id_field & CMP_CANFD_ID_IDE) == CMP_CANFD_ID_IDE;
    uint32_t can_id = 0;
    if (can_id_29bit) {
        proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_cmp_canfd_id, ett_asam_cmp_can_id, asam_cmp_canfd_id_field_29bit, ENC_BIG_ENDIAN, BMT_NO_FALSE);
        can_id = can_id_field & (CMP_CAN_ID_29BIT_MASK | CMP_CANFD_ID_IDE);
    } else {
        if (old_11bit_canid_encoding) {
            proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_cmp_canfd_id, ett_asam_cmp_can_id, asam_cmp_canfd_id_field_11bit_old, ENC_BIG_ENDIAN, BMT_NO_FALSE);
            can_id = can_id_field & (CMP_CANFD_ID_IDE | CMP_CAN_ID_11BIT_MASK_OLD);
        } else {
            proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_cmp_canfd_id, ett_asam_cmp_can_id, asam_cmp_canfd_id_field_11bit, ENC_BIG_ENDIAN, BMT_NO_FALSE);
            can_id = (can_id_field & CMP_CANFD_ID_IDE) + ((can_id_field & CMP_CAN_ID_11BIT_MASK) >> CMP_CAN_ID_11BIT_SHIFT);
        }
    }
    offset += 4;

    /* We peek ahead to find out the DLC. 0..10: 17bit CRC, 11..15: 21bit CRC. */
    if (tvb_get_uint8(tvb, offset + 6) <= 10) {
        proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_cmp_canfd_crc, ett_asam_cmp_can_crc, asam_cmp_canfd_crc_field_17bit, ENC_BIG_ENDIAN, BMT_NO_FALSE);
    } else {
        proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_cmp_canfd_crc, ett_asam_cmp_can_crc, asam_cmp_canfd_crc_field_21bit, ENC_BIG_ENDIAN, BMT_NO_FALSE);
    }
    offset += 4;

    proto_tree_add_item(tree, hf_cmp_canfd_err_pos, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_canfd_dlc, tvb, offset, 1, ENC_NA);
    offset += 1;

    uint32_t msg_payload_type_length;
    proto_tree_add_item_ret_uint(tree, hf_cmp_canfd_data_len, tvb, offset, 1, ENC_NA, &msg_payload_type_length);
    offset += 1;

    if (msg_payload_type_length > 0) {
        tvbuff_t *sub_tvb = tvb_new_subset_length(tvb, offset, msg_payload_type_length);

        if ((canfd_flags & CMP_CANFD_FLAGS_ERRORS) != 0) {
            can_id = can_id | CAN_ERR_FLAG;
        }

        struct can_info can_info = { .id = can_id, .len = msg_payload_type_length, .fd = CAN_TYPE_CAN_FD, .bus_id = ht_interface_config_to_bus_id(interface_id) };
        if (!socketcan_call_subdissectors(sub_tvb, pinfo, tree, &can_info, heuristic_first)) {
            call_data_dissector(sub_tvb, pinfo, tree);
        }

        offset += msg_payload_type_length;
    }

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_lin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned interface_id, bool tx) {
    uint32_t offset = 0;

    lin_info_t lin_info = { 0, 0, 0 };

    static int * const asam_cmp_lin_pid[] = {
        &hf_cmp_lin_pid_parity,
        &hf_cmp_lin_pid_id,
        NULL
    };

    static int * const asam_cmp_lin_flags_cap[] = {
        &hf_cmp_lin_flag_reserved,
        &hf_cmp_lin_flag_wup,
        &hf_cmp_lin_flag_long_dom_err,
        &hf_cmp_lin_flag_short_dom_err,
        &hf_cmp_lin_flag_framing_err,
        &hf_cmp_lin_flag_sync_err,
        &hf_cmp_lin_flag_no_slave_res,
        &hf_cmp_lin_flag_parity_err,
        &hf_cmp_lin_flag_col_err,
        &hf_cmp_lin_flag_checksum_err,
        NULL
    };

    static int * const asam_cmp_lin_flags_tx[] = {
        &hf_cmp_lin_flag_reserved,
        &hf_cmp_lin_flag_wup,
        &hf_cmp_lin_flag_long_dom_err,
        &hf_cmp_lin_flag_short_dom_err,
        &hf_cmp_lin_flag_framing_err,
        &hf_cmp_lin_flag_sync_err,
        &hf_cmp_lin_flag_reserved_0x0008,
        &hf_cmp_lin_flag_parity_err,
        &hf_cmp_lin_flag_reserved_0x0002,
        &hf_cmp_lin_flag_checksum_err,
        NULL
    };

    if (tx) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_lin_flags, ett_asam_cmp_payload_flags, asam_cmp_lin_flags_tx, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_lin_flags, ett_asam_cmp_payload_flags, asam_cmp_lin_flags_cap, ENC_BIG_ENDIAN);
    }
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_lin_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    lin_info.id = tvb_get_uint8(tvb, offset) & CMP_CANFD_PID_ID_MASK;
    proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_lin_pid, ett_asam_cmp_lin_pid, asam_cmp_lin_pid, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_cmp_lin_reserved_2, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_cmp_lin_checksum, tvb, offset, 1, ENC_NA);
    offset += 1;

    uint32_t msg_payload_type_length;
    proto_tree_add_item_ret_uint(tree, hf_cmp_lin_data_len, tvb, offset, 1, ENC_NA, &msg_payload_type_length);
    offset += 1;

    if (msg_payload_type_length > 0) {
        lin_info.bus_id = ht_interface_config_to_bus_id(interface_id);
        lin_info.len = (uint16_t)msg_payload_type_length;

        tvbuff_t *sub_tvb = tvb_new_subset_length(tvb, offset, msg_payload_type_length);
        dissect_lin_message(sub_tvb, pinfo, tree, &lin_info);
        offset += msg_payload_type_length;
    }

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_flexray(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned interface_id, bool tx) {
    uint32_t offset = 0;

    flexray_info_t fr_info = { 0, 0, 0, 0 };
    uint32_t tmp;

    static int * const asam_cmp_flexray_flags_cap[] = {
        &hf_cmp_flexray_flag_reserved,
        &hf_cmp_flexray_flag_channel,
        &hf_cmp_flexray_flag_reserved_0x0100,
        &hf_cmp_flexray_flag_cas,
        &hf_cmp_flexray_flag_ppi,
        &hf_cmp_flexray_flag_wus,
        &hf_cmp_flexray_flag_sync,
        &hf_cmp_flexray_flag_sf,
        &hf_cmp_flexray_flag_nf,
        &hf_cmp_flexray_flag_crc_header_err,
        &hf_cmp_flexray_flag_crc_frame_err,
        NULL
    };

    static int * const asam_cmp_flexray_flags_tx[] = {
        &hf_cmp_flexray_flag_reserved,
        &hf_cmp_flexray_flag_channel,
        &hf_cmp_flexray_flag_leading,
        &hf_cmp_flexray_flag_cas,
        &hf_cmp_flexray_flag_ppi,
        &hf_cmp_flexray_flag_wus,
        &hf_cmp_flexray_flag_sync,
        &hf_cmp_flexray_flag_sf,
        &hf_cmp_flexray_flag_nf,
        &hf_cmp_flexray_flag_crc_header_err,
        &hf_cmp_flexray_flag_crc_frame_err,
        NULL
    };

    uint16_t flags = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    if (tx) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_flexray_flags, ett_asam_cmp_payload_flags, asam_cmp_flexray_flags_tx, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_flexray_flags, ett_asam_cmp_payload_flags, asam_cmp_flexray_flags_cap, ENC_BIG_ENDIAN);
    }
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_flexray_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_flexray_header_crc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item_ret_uint(tree, hf_cmp_flexray_frame_id, tvb, offset, 2, ENC_BIG_ENDIAN, &tmp);
    fr_info.id = (uint16_t)tmp;
    offset += 2;

    proto_tree_add_item_ret_uint(tree, hf_cmp_flexray_cycle, tvb, offset, 1, ENC_NA, &tmp);
    fr_info.cc = (uint8_t)tmp;
    offset += 1;

    proto_tree_add_item(tree, hf_cmp_flexray_frame_crc, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(tree, hf_cmp_flexray_reserved_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    uint32_t msg_payload_type_length;
    proto_tree_add_item_ret_uint(tree, hf_cmp_flexray_data_len, tvb, offset, 1, ENC_NA, &msg_payload_type_length);
    offset += 1;

    if (msg_payload_type_length > 0 && (flags & CMP_FLEXRAY_FLAGS_NF) == 0) {
        fr_info.bus_id = ht_interface_config_to_bus_id(interface_id);
        fr_info.ch = 0; /* Assuming A! Could this be B? */

        tvbuff_t *sub_tvb = tvb_new_subset_length(tvb, offset, msg_payload_type_length);
        if (!flexray_call_subdissectors(sub_tvb, pinfo, tree, &fr_info, heuristic_first)) {
            call_data_dissector(sub_tvb, pinfo, tree);
        }
    }

    offset += msg_payload_type_length;

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_digital(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    uint32_t offset = 0;

    static int * const asam_cmp_digital_flags[] = {
        &hf_cmp_digital_flag_reserved,
        &hf_cmp_digital_flag_sampl_present,
        &hf_cmp_digital_flag_trig_present,
        NULL
    };

    uint64_t flags;
    proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_cmp_digital_flags, ett_asam_cmp_payload_flags, asam_cmp_digital_flags, ENC_BIG_ENDIAN, &flags);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_digital_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    uint32_t pin_count;
    proto_tree_add_item_ret_uint(tree, hf_cmp_digital_pin_count, tvb, offset, 1, ENC_NA, &pin_count);
    offset += 1;

    if ((flags & CMP_DIGITAL_FLAG_TRIGGER_PRESENT) == CMP_DIGITAL_FLAG_TRIGGER_PRESENT) {
        proto_tree_add_item(tree, hf_cmp_digital_trig_pattern, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_cmp_digital_trig_pin, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_cmp_digital_flag_reserved2, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    if ((flags & CMP_DIGITAL_FLAG_SAMPLE_PRESENT) == CMP_DIGITAL_FLAG_SAMPLE_PRESENT) {
        proto_tree_add_item(tree, hf_cmp_digital_sample_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        uint32_t sample_count;
        proto_tree_add_item_ret_uint(tree, hf_cmp_digital_sample_count, tvb, offset, 1, ENC_NA, &sample_count);
        offset += 1;

        uint32_t sample_byte_count = (uint32_t)floor((pin_count + 7) / 8);

        for (uint32_t i = 0; i < sample_count; i++) {

            proto_item *ti = proto_tree_add_item(tree, hf_cmp_digital_sample, tvb, offset, sample_byte_count, ENC_NA);
            proto_item_append_text(ti, " [%d] ", i);
            proto_tree *sample_tree = proto_item_add_subtree(ti, ett_asam_cmp_digital_sample);

            /* we are supporting 32 pins for the beginning */
            if (4 < sample_byte_count) {
                /* skip unsupported pins */
                offset += sample_byte_count - 4;
            }
            if (4 <= sample_byte_count) {
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_31, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_30, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_29, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_28, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_27, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_26, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_25, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_24, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x", tvb_get_uint8(tvb, offset));
                offset += 1;
            }

            if (3 <= sample_byte_count) {
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_23, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_22, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_21, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_20, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_19, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_18, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_17, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_16, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x", tvb_get_uint8(tvb, offset));
                offset += 1;
            }

            if (2 <= sample_byte_count) {
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_15, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_14, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_13, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_12, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_11, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_10, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_9, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_8, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x", tvb_get_uint8(tvb, offset));
                offset += 1;
            }

            if (1 <= sample_byte_count) {
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_7, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_6, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_5, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_4, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_3, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_2, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_1, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sample_tree, hf_cmp_digital_sample_pin_0, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%02x", tvb_get_uint8(tvb, offset));
                offset += 1;
            }
        }
    }

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_uart(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    uint32_t offset = 0;

    static int * const asam_cmp_uart_flags[] = {
        &hf_cmp_uart_flag_reserved,
        &hf_cmp_uart_flag_cl,
        NULL
    };

    static int * const asam_cmp_uart_data[] = {
        &hf_cmp_uart_data_parity_err,
        &hf_cmp_uart_data_break_condition,
        &hf_cmp_uart_data_framing_err,
        &hf_cmp_uart_data_reserved,
        &hf_cmp_uart_data_data,
        NULL
    };

    uint64_t char_len;
    proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_cmp_uart_flags, ett_asam_cmp_payload_flags, asam_cmp_uart_flags, ENC_BIG_ENDIAN, &char_len);
    char_len = char_len & 0x07;
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_uart_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    uint32_t msg_payload_type_length;
    proto_tree_add_item_ret_uint(tree, hf_cmp_uart_data_len, tvb, offset, 2, ENC_BIG_ENDIAN, &msg_payload_type_length);
    offset += 2;

    for (unsigned i = 0; i < msg_payload_type_length; i++) {
        uint8_t *buf = NULL;
        proto_item *ti = proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_uart_data, ett_asam_cmp_uart_data, asam_cmp_uart_data, ENC_BIG_ENDIAN);
        if (char_len == CMP_UART_CL_7 || char_len == CMP_UART_CL_8) {
            buf = tvb_get_string_enc(pinfo->pool, tvb, offset + 1, 1, ENC_ASCII | ENC_NA);

            /* sanitizing buffer */
            if (buf[0] > 0x00 && buf[0] < 0x20) {
                buf[0] = 0x20;
            } else {
                proto_item_append_text(ti, ": %s", buf);
            }
        }
        offset += 2;
    }

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_analog(tvbuff_t *tvb, proto_tree *tree) {
    uint32_t offset = 0;

    static int * const asam_cmp_analog_flags[] = {
        &hf_cmp_analog_flag_reserved,
        &hf_cmp_analog_flag_sample_dt,
        NULL
    };

    uint64_t flags;
    proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_cmp_analog_flags, ett_asam_cmp_payload_flags, asam_cmp_analog_flags, ENC_BIG_ENDIAN, &flags);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_analog_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    unsigned analog_unit;
    proto_tree_add_item_ret_uint(tree, hf_cmp_analog_unit, tvb, offset, 1, ENC_NA, &analog_unit);
    const char *unit_symbol;
    unit_symbol = try_val_to_str(analog_unit, analog_units);
    offset += 1;

    proto_tree_add_item(tree, hf_cmp_analog_sample_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    float sample_offset;
    proto_tree_add_item(tree, hf_cmp_analog_sample_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
    sample_offset = tvb_get_ieee_float(tvb, offset, ENC_BIG_ENDIAN);
    offset += 4;

    float sample_scalar;
    proto_tree_add_item(tree, hf_cmp_analog_sample_scalar, tvb, offset, 4, ENC_BIG_ENDIAN);
    sample_scalar = tvb_get_ieee_float(tvb, offset, ENC_BIG_ENDIAN);
    offset += 4;

    int data_width;
    switch (flags & 0x03) {
    case 0: /* INT16 */
        data_width = 2;
        break;
    case 1: /* INT32 */
        data_width = 4;
        break;
    default:
        data_width = 0;
    }

    int data_left = tvb_captured_length(tvb) - offset;

    while (data_width != 0 && data_left > data_width) {
        switch (flags & 0x03) {
        case 0: {
            /* INT16 */
            double sample_value = ((double)tvb_get_int16(tvb, offset, ENC_BIG_ENDIAN) * sample_scalar + sample_offset);
            proto_item *ti = proto_tree_add_double(tree, hf_cmp_analog_sample, tvb, offset, 2, sample_value);
            if (unit_symbol == NULL) {
                proto_item_append_text(ti, " (%.9f)", sample_value);
            } else {
                proto_item_append_text(ti, "%s (%.9f%s)", unit_symbol, sample_value, unit_symbol);
            }
            PROTO_ITEM_SET_GENERATED(ti);

            proto_tree *sample_tree = proto_item_add_subtree(ti, ett_asam_cmp_analog_sample);
            ti = proto_tree_add_item(sample_tree, hf_cmp_analog_sample_raw, tvb, offset, 2, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_HIDDEN(ti);

            data_left -= 2;
            offset += 2;
            break;
        }
        case 1: { /* INT32 */
            double sample_value = ((double)tvb_get_int32(tvb, offset, ENC_BIG_ENDIAN) * sample_scalar + sample_offset);
            proto_item *ti = proto_tree_add_double(tree, hf_cmp_analog_sample, tvb, offset, 4, sample_value);
            if (unit_symbol == NULL) {
                proto_item_append_text(ti, " (%.9f)", sample_value);
            } else {
                proto_item_append_text(ti, "%s (%.9f%s)", unit_symbol, sample_value, unit_symbol);
            }
            PROTO_ITEM_SET_GENERATED(ti);

            proto_tree *sample_tree = proto_item_add_subtree(ti, ett_asam_cmp_analog_sample);
            ti = proto_tree_add_item(sample_tree, hf_cmp_analog_sample_raw, tvb, offset, 4, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_HIDDEN(ti);

            data_left -= 4;
            offset += 4;
            break;
        }
        default:
            /* Other types are reserved as of now, so we do not know how to parse them. Just ignore. */
            break;
        }
    }

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_ethernet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *root_tree, bool tx) {
    uint32_t offset = 0;

    static int * const asam_cmp_ethernet_flags_cap[] = {
        &hf_cmp_eth_flag_reserved_cap,
        &hf_cmp_eth_flag_fcs_supported,
        &hf_cmp_eth_flag_truncated,
        &hf_cmp_eth_flag_phy_err,
        &hf_cmp_eth_flag_long_err,
        &hf_cmp_eth_flag_collision,
        &hf_cmp_eth_flag_tx_down,
        &hf_cmp_eth_flag_short_err,
        &hf_cmp_eth_flag_fcs_err,
        NULL
    };

    static int * const asam_cmp_ethernet_flags_tx[] = {
        &hf_cmp_eth_flag_reserved_tx2,
        &hf_cmp_eth_flag_fcs_sending,
        &hf_cmp_eth_flag_reserved_tx,
        NULL
    };

    if (tx) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_eth_flags, ett_asam_cmp_payload_flags, asam_cmp_ethernet_flags_tx, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_eth_flags, ett_asam_cmp_payload_flags, asam_cmp_ethernet_flags_cap, ENC_BIG_ENDIAN);
    }
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_eth_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    uint32_t msg_payload_type_length;
    proto_tree_add_item_ret_uint(tree, hf_cmp_eth_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN, &msg_payload_type_length);
    offset += 2;

    if (msg_payload_type_length > 0) {
        tvbuff_t *sub_tvb = tvb_new_subset_length(tvb, offset, (int)msg_payload_type_length);
        call_dissector(eth_handle, sub_tvb, pinfo, root_tree);
        offset += msg_payload_type_length;
    }

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_spi(tvbuff_t *tvb, proto_tree *tree) {
    uint32_t offset = 0;

    static int * const asam_cmp_spi_flags[] = {
        &hf_cmp_spi_flag_reserved,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_spi_flags, ett_asam_cmp_payload_flags, asam_cmp_spi_flags, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_spi_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    uint32_t cipo_length;
    proto_tree_add_item_ret_uint(tree, hf_cmp_spi_cipo_length, tvb, offset, 2, ENC_BIG_ENDIAN, &cipo_length);
    offset += 2;

    if (cipo_length > 0) {
        proto_tree_add_item(tree, hf_cmp_spi_cipo, tvb, offset, cipo_length, ENC_NA);
        offset += cipo_length;
    }

    uint32_t copi_length;
    proto_tree_add_item_ret_uint(tree, hf_cmp_spi_copi_length, tvb, offset, 2, ENC_BIG_ENDIAN, &copi_length);
    offset += 2;

    if (copi_length > 0) {
        proto_tree_add_item(tree, hf_cmp_spi_copi, tvb, offset, copi_length, ENC_NA);
        offset += copi_length;
    }

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_i2c(tvbuff_t *tvb, proto_tree *tree) {
    uint32_t offset = 0;

    static int * const asam_cmp_i2c_flags[] = {
        &hf_cmp_i2c_flag_reserved,
        &hf_cmp_i2c_flag_start_cond,
        &hf_cmp_i2c_flag_stop_cond,
        &hf_cmp_i2c_flag_addr_err,
        &hf_cmp_i2c_flag_addr_ack,
        &hf_cmp_i2c_flag_addr_len,
        &hf_cmp_i2c_flag_dir,
        NULL
    };

    proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_cmp_i2c_flags, ett_asam_cmp_payload_flags, asam_cmp_i2c_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_i2c_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_i2c_addr, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    uint32_t data_entry_count;
    proto_tree_add_item_ret_uint(tree, hf_cmp_i2c_data_entry_count, tvb, offset, 2, ENC_BIG_ENDIAN, &data_entry_count);
    offset += 2;

    static int * const asam_cmp_i2c_data[] = {
        &hf_cmp_i2c_data_control_res,
        &hf_cmp_i2c_data_control_ack,
        &hf_cmp_i2c_data_byte,
        NULL
    };

    for (uint32_t i = 0; i < data_entry_count; i++) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_i2c_data, ett_asam_cmp_i2c_data_entry, asam_cmp_i2c_data, ENC_BIG_ENDIAN);
        offset += 2;
    }

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_gige_vision(tvbuff_t *tvb, proto_tree *tree) {
    uint32_t offset = 0;

    static int * const asam_cmp_gige_flags[] = {
        &hf_cmp_gige_flag_reserved,
        NULL
    };

    proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_cmp_gige_flags, ett_asam_cmp_payload_flags, asam_cmp_gige_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_gige_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    uint32_t msg_payload_type_length;
    proto_tree_add_item_ret_uint(tree, hf_cmp_gige_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN, &msg_payload_type_length);
    offset += 2;

    if (msg_payload_type_length > 0) {
        proto_tree_add_item(tree, hf_cmp_gige_payload, tvb, offset, msg_payload_type_length, ENC_NA);
        offset += msg_payload_type_length;
    }

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_mipi_csi2(tvbuff_t *tvb, proto_tree *tree, bool tx) {
    uint32_t offset = 0;

    static int * const asam_cmp_mipi_csi2_flags_cap[] = {
        &hf_cmp_mipi_csi2_flag_reserved,
        &hf_cmp_mipi_csi2_flag_cs_support,
        &hf_cmp_mipi_csi2_flag_line_ctr_src,
        &hf_cmp_mipi_csi2_flag_frame_ctr_src,
        &hf_cmp_mipi_csi2_flag_ecc_fmt,
        &hf_cmp_mipi_csi2_flag_ecc_err_uc,
        &hf_cmp_mipi_csi2_flag_ecc_err_c,
        &hf_cmp_mipi_csi2_flag_crc_err,
        NULL
    };

    static int * const asam_cmp_mipi_csi2_flags_tx[] = {
        &hf_cmp_mipi_csi2_flag_reserved_tx,
        NULL
    };

    if (tx) {
        proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_cmp_mipi_csi2_flags, ett_asam_cmp_payload_flags, asam_cmp_mipi_csi2_flags_tx, ENC_BIG_ENDIAN, BMT_NO_APPEND);
    } else {
        proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_cmp_mipi_csi2_flags, ett_asam_cmp_payload_flags, asam_cmp_mipi_csi2_flags_cap, ENC_BIG_ENDIAN, BMT_NO_APPEND);
    }
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_mipi_csi2_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_mipi_csi2_frame_counter, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_mipi_csi2_line_counter, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    static int * const asam_cmp_mipi_dt[] = {
        &hf_cmp_mipi_csi2_dt_res,
        &hf_cmp_mipi_csi2_dt_dt,
        NULL
    };

    uint64_t mipi_csi2_dt_flags;
    proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_cmp_mipi_csi2_dt, ett_asam_cmp_payload_flags, asam_cmp_mipi_dt, ENC_NA, BMT_NO_APPEND, &mipi_csi2_dt_flags);
    offset += 1;

    bool asam_cmp_mipi_csi_short_packet = (mipi_csi2_dt_flags & MIPI_CSI2_DT_BITS) <= MIPI_CSI2_DT_SHORT_END;

    static int * const asam_cmp_mipi_vci[] = {
        &hf_cmp_mipi_csi2_vci_res,
        &hf_cmp_mipi_csi2_vci_vcx,
        &hf_cmp_mipi_csi2_vci_vci,
        NULL
    };

    proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_cmp_mipi_csi2_vci, ett_asam_cmp_payload_flags, asam_cmp_mipi_vci, ENC_NA, BMT_NO_APPEND);
    offset += 1;

    proto_tree_add_item(tree, hf_cmp_mipi_csi2_reserved2, tvb, offset, 1, ENC_NA);
    offset += 1;

    static int * const asam_cmp_mipi_ecc[] = {
        &hf_cmp_mipi_csi2_ecc_res,
        &hf_cmp_mipi_csi2_ecc_ecc,
        NULL
    };

    proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_cmp_mipi_csi2_ecc, ett_asam_cmp_payload_flags, asam_cmp_mipi_ecc, ENC_NA, BMT_NO_APPEND);
    offset += 1;

    proto_tree_add_item(tree, hf_cmp_mipi_csi2_cs, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (asam_cmp_mipi_csi_short_packet) {
        proto_tree_add_item(tree, hf_cmp_mipi_csi2_short_packet_data, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    } else {
        uint32_t word_count;
        proto_tree_add_item_ret_uint(tree, hf_cmp_mipi_csi2_wc, tvb, offset, 2, ENC_BIG_ENDIAN, &word_count);
        offset += 2;

        proto_tree_add_item(tree, hf_cmp_mipi_csi2_data, tvb, offset, word_count, ENC_NA);
        offset += word_count;
    }

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_raw_ethernet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *root_tree) {
    uint32_t offset = 0;

    static int * const asam_cmp_raw_ethernet_flags[] = {
        &hf_cmp_raw_eth_flag_reserved,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_eth_flags, ett_asam_cmp_payload_flags, asam_cmp_raw_ethernet_flags, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_eth_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    uint32_t msg_payload_type_length;
    proto_tree_add_item_ret_uint(tree, hf_cmp_eth_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN, &msg_payload_type_length);
    offset += 2;

    uint32_t payload_end = offset + msg_payload_type_length;

    uint32_t preamble_length = 0;
    while ((preamble_length < msg_payload_type_length) && (CMP_ETH_RAW_PREAMBLE == tvb_get_uint8(tvb, offset + preamble_length))) {
        preamble_length += 1;
    }

    if (preamble_length > 0) {
        proto_tree_add_item(tree, hf_cmp_raw_eth_preamble, tvb, offset, preamble_length, ENC_NA);
        offset += preamble_length;

        if (offset < payload_end) {
            uint8_t sfd_candidate = tvb_get_uint8(tvb, offset);

            if (try_val_to_str(sfd_candidate, eth_raw_sfd) != NULL) {
                proto_tree_add_item(tree, hf_cmp_raw_eth_sfd, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                if (offset < payload_end) {
                    uint32_t bytes_left = msg_payload_type_length - preamble_length - 1;

                    if (bytes_left > 0) {
                        if (sfd_candidate == CMP_ETH_RAW_SFD_ORIG) {
                            call_dissector(eth_handle, tvb_new_subset_length(tvb, offset, bytes_left), pinfo, root_tree);
                        } else {
                            proto_tree_add_item(tree, hf_cmp_raw_eth_mpacket, tvb, offset, bytes_left, ENC_NA);
                        }
                        offset += (int)bytes_left;
                    }
                }
            }
        }
    }

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_10baset1s_symbols(tvbuff_t *tvb, proto_tree *tree) {
    uint32_t offset = 0;

    static int * const asam_cmp_10baset1s_flags[] = {
        &hf_cmp_10t1s_symb_flag_first_beacon,
        &hf_cmp_10t1s_symb_flag_res,
        &hf_cmp_10t1s_symb_flag_miss_beacon,
        &hf_cmp_10t1s_symb_flag_decode_err,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_10t1s_symb_flags, ett_asam_cmp_payload_flags, asam_cmp_10baset1s_flags, ENC_BIG_ENDIAN);
    offset += 2;

    uint32_t msg_payload_type_length;
    proto_tree_add_item_ret_uint(tree, hf_cmp_10t1s_symb_data_length, tvb, offset, 2, ENC_BIG_ENDIAN, &msg_payload_type_length);
    offset += 2;

    proto_item *ti = proto_tree_add_item(tree, hf_cmp_10t1s_symb_data, tvb, offset, msg_payload_type_length, ENC_NA);
    proto_tree *data_tree = proto_item_add_subtree(ti, ett_asam_cmp_payload_data);
    for (uint32_t i = 0; i < msg_payload_type_length; i++) {
        proto_tree_add_item(data_tree, hf_cmp_10t1s_symb_data_symbol, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_a2b(tvbuff_t *tvb, proto_tree *tree) {
    uint32_t offset = 0;

    static int * const asam_cmp_a2b_flags[] = {
        &hf_cmp_a2b_flag_i2c_err,
        &hf_cmp_a2b_flag_icrc_err,
        &hf_cmp_a2b_flag_srfcrc_err,
        &hf_cmp_a2b_flag_srf_err,
        &hf_cmp_a2b_flag_becovf_err,
        &hf_cmp_a2b_flag_pwd_err,
        &hf_cmp_a2b_flag_dp_err,
        &hf_cmp_a2b_flag_crc_err,
        &hf_cmp_a2b_flag_dd_err,
        &hf_cmp_a2b_flag_hdcnt_err,
        &hf_cmp_a2b_flag_fault_nloc,
        &hf_cmp_a2b_flag_fault_code,
        &hf_cmp_a2b_flag_fault_err,
        &hf_cmp_a2b_flag_fin,
        NULL
    };

    static int * const asam_cmp_a2b_upstream_settings[] = {
        &hf_cmp_a2b_upstream_set_upoffset,
        &hf_cmp_a2b_upstream_set_upslots,
        &hf_cmp_a2b_upstream_set_upsize,
        &hf_cmp_a2b_upstream_set_ups,
        &hf_cmp_a2b_upstream_set_upfmt,
        NULL
    };

    static int * const asam_cmp_a2b_downstream_settings[] = {
        &hf_cmp_a2b_downstream_set_dnoffset,
        &hf_cmp_a2b_downstream_set_dnslots,
        &hf_cmp_a2b_downstream_set_dnsize,
        &hf_cmp_a2b_downstream_set_dns,
        &hf_cmp_a2b_downstream_set_dnfmt,
        NULL
    };

    static int * const asam_cmp_a2b_general_settings[] = {
        &hf_cmp_a2b_general_set_raw_cap,
        &hf_cmp_a2b_general_set_reserved,
        &hf_cmp_a2b_general_set_rrsoffset,
        &hf_cmp_a2b_general_set_rrdiv,
        &hf_cmp_a2b_general_set_syncoffset,
        &hf_cmp_a2b_general_set_rxoffset,
        &hf_cmp_a2b_general_set_txoffset,
        &hf_cmp_a2b_general_set_i2srate,
        &hf_cmp_a2b_general_set_bclkrate,
        &hf_cmp_a2b_general_set_bmmen,
        &hf_cmp_a2b_general_set_tdmss,
        &hf_cmp_a2b_general_set_tdmmode,
        &hf_cmp_a2b_general_set_rx2pintl,
        &hf_cmp_a2b_general_set_tx2pintl,
        &hf_cmp_a2b_general_set_discvd,
        &hf_cmp_a2b_general_set_endsniff,
        &hf_cmp_a2b_general_set_standby,
        &hf_cmp_a2b_general_set_mstr,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_a2b_flags, ett_asam_cmp_payload_flags, asam_cmp_a2b_flags, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_a2b_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_a2b_upstream_set, ett_asam_cmp_a2b_upstream_settings, asam_cmp_a2b_upstream_settings, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_a2b_downstream_set, ett_asam_cmp_a2b_downstream_settings, asam_cmp_a2b_downstream_settings, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_a2b_general_set, ett_asam_cmp_a2b_general_settings, asam_cmp_a2b_general_settings, ENC_BIG_ENDIAN);
    offset += 8;

    uint32_t msg_payload_type_length;
    proto_tree_add_item_ret_uint(tree, hf_cmp_a2b_data_length, tvb, offset, 2, ENC_BIG_ENDIAN, &msg_payload_type_length);
    offset += 2;

    if (msg_payload_type_length > 0) {
        proto_tree_add_item(tree, hf_cmp_a2b_data, tvb, offset, msg_payload_type_length, ENC_NA);
        offset += msg_payload_type_length;
    }

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_link_state(tvbuff_t *tvb, proto_tree *tree, bool tx) {
    uint32_t offset = 0;

    static int * const asam_cmp_link_state_flags_cap[] = {
        &hf_cmp_link_state_flag_reserved,
        &hf_cmp_link_state_flag_link_err,
        NULL
    };

    static int * const asam_cmp_link_state_flags_tx[] = {
        &hf_cmp_link_state_flag_reserved_tx,
        NULL
    };

    if (tx) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_link_state_flags, ett_asam_cmp_payload_flags, asam_cmp_link_state_flags_tx, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_bitmask(tree, tvb, offset, hf_cmp_link_state_flags, ett_asam_cmp_payload_flags, asam_cmp_link_state_flags_cap, ENC_BIG_ENDIAN);
    }
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_link_state_interface_status, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_cmp_link_state_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;


    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_user_defined(tvbuff_t *tvb, proto_tree *tree) {
    uint32_t offset = 0;

    proto_tree_add_item(tree, hf_cmp_vendor_def_vendor_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_vendor_def_vendor_payload_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_cmp_vendor_def_vendor_payload_data, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
    offset += tvb_captured_length_remaining(tvb, offset);

    return offset;
}

static uint32_t
dissect_asam_cmp_data_msg_payload(tvbuff_t *payload_tvb, packet_info *pinfo, proto_tree *tree, proto_tree *root_tree, uint32_t msg_payload_type, uint32_t interface_id, bool tx) {
    uint32_t offset = 0;
    uint32_t msg_payload_length = tvb_captured_length(payload_tvb);

    switch (msg_payload_type) {
    case CMP_DATA_MSG_INVALID:
        if (msg_payload_length > 0) {
            call_data_dissector(payload_tvb, pinfo, tree);
            offset += tvb_captured_length(payload_tvb);
        }
        break;

    case CMP_DATA_MSG_CAN:
        offset += dissect_asam_cmp_data_msg_can(payload_tvb, pinfo, tree, interface_id, tx);
        break;

    case CMP_DATA_MSG_CANFD:
        offset += dissect_asam_cmp_data_msg_canfd(payload_tvb, pinfo, tree, interface_id, tx);
        break;

    case CMP_DATA_MSG_LIN:
        offset += dissect_asam_cmp_data_msg_lin(payload_tvb, pinfo, tree, interface_id, tx);
        break;

    case CMP_DATA_MSG_FLEXRAY:
        offset += dissect_asam_cmp_data_msg_flexray(payload_tvb, pinfo, tree, interface_id, tx);
        break;

    case CMP_DATA_MSG_DIGITAL:
        offset += dissect_asam_cmp_data_msg_digital(payload_tvb, pinfo, tree);
        break;

    case CMP_DATA_MSG_UART_RS_232:
        offset += dissect_asam_cmp_data_msg_uart(payload_tvb, pinfo, tree);
        break;

    case CMP_DATA_MSG_ANALOG:
        offset += dissect_asam_cmp_data_msg_analog(payload_tvb, tree);
        break;

    case CMP_DATA_MSG_ETHERNET:
        offset += dissect_asam_cmp_data_msg_ethernet(payload_tvb, pinfo, tree, root_tree, tx);
        break;

    case CMP_DATA_MSG_SPI:
        offset += dissect_asam_cmp_data_msg_spi(payload_tvb, tree);
        break;

    case CMP_DATA_MSG_I2C:
        offset += dissect_asam_cmp_data_msg_i2c(payload_tvb, tree);
        break;

    case CMP_DATA_MSG_GIGEVISION:
        offset += dissect_asam_cmp_data_msg_gige_vision(payload_tvb, tree);
        break;

    case CMP_DATA_MSG_MIPI_CSI2:
        offset += dissect_asam_cmp_data_msg_mipi_csi2(payload_tvb, tree, tx);
        break;

    case CMP_DATA_MSG_RAW_ETHERNET:
        offset += dissect_asam_cmp_data_msg_raw_ethernet(payload_tvb, pinfo, tree, root_tree);
        break;

    case CMP_DATA_MSG_10BASE_T1S_SYMBOL:
        offset += dissect_asam_cmp_data_msg_10baset1s_symbols(payload_tvb, tree);
        break;

    case CMP_DATA_MSG_A2B:
        offset += dissect_asam_cmp_data_msg_a2b(payload_tvb, tree);
        break;

    case CMP_DATA_MSG_LINK_STATE:
        offset += dissect_asam_cmp_data_msg_link_state(payload_tvb, tree, tx);
        break;

    case CMP_DATA_MSG_VENDOR_DATA_MSG:
        offset += dissect_asam_cmp_data_msg_user_defined(payload_tvb, tree);
        break;

    default:
        offset += tvb_captured_length(payload_tvb);
        break;
    }

    return offset;
}

static void
dissect_asam_cmp_data_msg_transmission_options(tvbuff_t *tvb, proto_tree *tree, uint8_t payload_type) {

    static int * const trans_opts_default[] = {
        &hf_cmp_msg_trans_opts_res,
        NULL
    };

    static int * const trans_opts_lin[] = {
        &hf_cmp_msg_trans_opts_lin_wup_dura,
        &hf_cmp_msg_trans_opts_lin_res,
        NULL
    };

    static int * const trans_opts_flexray[] = {
        &hf_cmp_msg_trans_opts_fr_op,
        &hf_cmp_msg_trans_opts_fr_cycle_rep,
        &hf_cmp_msg_trans_opts_fr_res,
        NULL
    };

    switch (payload_type) {
    case CMP_DATA_MSG_LIN:
        proto_tree_add_bitmask(tree, tvb, 0, hf_cmp_msg_trans_opts, ett_asam_cmp_trans_opts, trans_opts_lin, ENC_BIG_ENDIAN);
        break;

    case CMP_DATA_MSG_FLEXRAY:
        proto_tree_add_bitmask(tree, tvb, 0, hf_cmp_msg_trans_opts, ett_asam_cmp_trans_opts, trans_opts_flexray, ENC_BIG_ENDIAN);
        break;

    default:
        proto_tree_add_bitmask(tree, tvb, 0, hf_cmp_msg_trans_opts, ett_asam_cmp_trans_opts, trans_opts_default, ENC_BIG_ENDIAN);
    }
}

static int
dissect_asam_cmp_data_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *root_tree, proto_tree *tree, unsigned offset_orig, bool tx) {
    proto_item *ti = NULL;
    proto_item *ti_msg_header = NULL;
    proto_item *ti_msg_payload = NULL;
    proto_tree *asam_cmp_data_msg_header_tree = NULL;
    proto_tree *asam_cmp_data_msg_payload_tree = NULL;
    proto_tree *subtree = NULL;
    unsigned offset = offset_orig;

    unsigned msg_payload_type = 0;
    unsigned msg_payload_length = 0;
    unsigned interface_id = 0;

    static int * const asam_cmp_common_flags_cap[] = {
        &hf_cmp_common_flag_reserved,
        &hf_cmp_common_flag_err_in_payload,
        &hf_cmp_common_flag_overflow,
        &hf_cmp_common_flag_dir_on_if,
        &hf_cmp_common_flag_seg,
        &hf_cmp_common_flag_insync,
        &hf_cmp_common_flag_recal,
        NULL
    };

    static int * const asam_cmp_common_flags_tx[] = {
        &hf_cmp_common_flag_reserved_0xf0,
        &hf_cmp_common_flag_seg,
        &hf_cmp_common_flag_reserved_0x02,
        &hf_cmp_common_flag_relative,
        NULL
    };

    /* Testing for Ethernet Padding */
    if (tvb_get_uint8(tvb, offset + 13) == 0) {
        return 0;
    }

    ti_msg_header = proto_tree_add_item(tree, hf_cmp_msg_header, tvb, offset, 8, ENC_BIG_ENDIAN);
    asam_cmp_data_msg_header_tree = proto_item_add_subtree(ti_msg_header, ett_asam_cmp_header);
    proto_item_append_text(ti_msg_header, " %s", "- Data Message");

    uint64_t ns = tvb_get_uint64(tvb, offset, ENC_BIG_ENDIAN);
    nstime_t timestamp = { .secs = (time_t)(ns / 1000000000), .nsecs = (int)(ns % 1000000000) };

    ti = proto_tree_add_time(asam_cmp_data_msg_header_tree, hf_cmp_msg_timestamp, tvb, offset, 8, &timestamp);
    subtree = proto_item_add_subtree(ti, ett_asam_cmp_timestamp);
    proto_tree_add_item(subtree, hf_cmp_msg_timestamp_ns, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    if (tx) {
        /* Deadline */
        proto_tree_add_item(asam_cmp_data_msg_header_tree, hf_cmp_msg_deadline, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    ti = proto_tree_add_item_ret_uint(asam_cmp_data_msg_header_tree, hf_cmp_interface_id, tvb, offset, 4, ENC_BIG_ENDIAN, &interface_id);
    add_interface_id_text(ti, interface_id);
    offset += 4;

    if (tx) {
        /* Transmission Options */
        // peek into msg_payload_type
        dissect_asam_cmp_data_msg_transmission_options(tvb_new_subset_length(tvb, offset, 4), asam_cmp_data_msg_header_tree, tvb_get_uint8(tvb, offset + 5));
        offset += 4;

        proto_tree_add_bitmask(asam_cmp_data_msg_header_tree, tvb, offset, hf_cmp_msg_common_flags, ett_asam_cmp_common_flags, asam_cmp_common_flags_tx, ENC_BIG_ENDIAN);
        offset += 1;
    } else {
        proto_tree_add_bitmask(asam_cmp_data_msg_header_tree, tvb, offset, hf_cmp_msg_common_flags, ett_asam_cmp_common_flags, asam_cmp_common_flags_cap, ENC_BIG_ENDIAN);
        offset += 1;
    }

    proto_tree_add_item_ret_uint(asam_cmp_data_msg_header_tree, hf_cmp_payload_type, tvb, offset, 1, ENC_NA, &msg_payload_type);
    offset += 1;

    proto_tree_add_item_ret_uint(asam_cmp_data_msg_header_tree, hf_cmp_msg_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN, &msg_payload_length);
    offset += 2;

    proto_item_set_end(ti_msg_header, tvb, offset);

    ti_msg_payload = proto_tree_add_item(tree, hf_cmp_msg_payload, tvb, offset, msg_payload_length, ENC_BIG_ENDIAN);
    asam_cmp_data_msg_payload_tree = proto_item_add_subtree(ti_msg_payload, ett_asam_cmp_header);
    proto_item_append_text(ti_msg_payload, " %s", "- Data Message");

    const char *msg_payload_name = try_val_to_str(msg_payload_type, data_msg_type_names);
    if (msg_payload_name != NULL) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", msg_payload_name);
        proto_item_append_text(ti_msg_payload, " (%s)", msg_payload_name);
    }

    tvbuff_t *payload_tvb = tvb_new_subset_length(tvb, offset, msg_payload_length);

    offset += dissect_asam_cmp_data_msg_payload(payload_tvb, pinfo, asam_cmp_data_msg_payload_tree, root_tree, msg_payload_type, interface_id, tx);

    uint8_t header_len = tx ? CMP_MSG_HEADER_LEN_TX : CMP_MSG_HEADER_LEN;
    if ((header_len + msg_payload_length) < (offset - offset_orig)) {
        proto_tree_add_expert(tree, pinfo, &ei_asam_cmp_length_mismatch, tvb, offset_orig + header_len, msg_payload_length);
        proto_item_set_end(ti_msg_payload, tvb, offset);
    }

    return header_len + msg_payload_length;
}

static int
dissect_asam_cmp_ctrl_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset_orig) {

    proto_item *ti = NULL;
    proto_item *ti_msg_header = NULL;
    proto_item *ti_msg_payload = NULL;
    proto_tree *asam_cmp_ctrl_msg_header_tree = NULL;
    proto_tree *asam_cmp_ctrl_msg_payload_tree = NULL;
    proto_tree *subtree = NULL;
    unsigned asam_cmp_ctrl_msg_payload_type = 0;
    unsigned asam_cmp_ctrl_msg_payload_length = 0;
    unsigned offset = offset_orig;

    static int * const asam_cmp_common_flags[] = {
        &hf_cmp_common_flag_reserved_0xf0,
        &hf_cmp_common_flag_seg,
        &hf_cmp_common_flag_insync,
        &hf_cmp_common_flag_recal,
        NULL
    };

    /* Testing for Ethernet Padding */
    if (tvb_get_uint8(tvb, offset + 13) == 0) {
        return 0;
    }

    ti_msg_header = proto_tree_add_item(tree, hf_cmp_msg_header, tvb, offset, 8, ENC_BIG_ENDIAN);
    asam_cmp_ctrl_msg_header_tree = proto_item_add_subtree(ti_msg_header, ett_asam_cmp_header);
    proto_item_append_text(ti_msg_header, " %s", "- Control Message");

    uint64_t ns = tvb_get_uint64(tvb, offset, ENC_BIG_ENDIAN);
    nstime_t timestamp = { .secs = (time_t)(ns / 1000000000), .nsecs = (int)(ns % 1000000000) };

    ti = proto_tree_add_time(asam_cmp_ctrl_msg_header_tree, hf_cmp_msg_timestamp, tvb, offset, 8, &timestamp);

    subtree = proto_item_add_subtree(ti, ett_asam_cmp_timestamp);
    proto_tree_add_item(subtree, hf_cmp_msg_timestamp_ns, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(asam_cmp_ctrl_msg_header_tree, hf_cmp_ctrl_msg_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_bitmask(asam_cmp_ctrl_msg_header_tree, tvb, offset, hf_cmp_msg_common_flags, ett_asam_cmp_common_flags, asam_cmp_common_flags, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item_ret_uint(asam_cmp_ctrl_msg_header_tree, hf_cmp_ctrl_msg_payload_type, tvb, offset, 1, ENC_NA, &asam_cmp_ctrl_msg_payload_type);
    offset += 1;

    proto_tree_add_item_ret_uint(asam_cmp_ctrl_msg_header_tree, hf_cmp_msg_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN, &asam_cmp_ctrl_msg_payload_length);
    offset += 2;

    proto_item_set_end(ti_msg_header, tvb, offset);

    ti_msg_payload = proto_tree_add_item(tree, hf_cmp_msg_payload, tvb, offset, asam_cmp_ctrl_msg_payload_length, ENC_BIG_ENDIAN);
    asam_cmp_ctrl_msg_payload_tree = proto_item_add_subtree(ti_msg_payload, ett_asam_cmp_header);
    proto_item_append_text(ti_msg_payload, " %s", "- Control Message");

    switch (asam_cmp_ctrl_msg_payload_type) {
    case CMP_CTRL_MSG_INVALID:
        col_append_str(pinfo->cinfo, COL_INFO, " (Invalid/Padding)");
        proto_item_append_text(ti_msg_payload, " %s", "(Invalid/Padding)");
        proto_item_set_end(ti_msg_payload, tvb, offset + asam_cmp_ctrl_msg_payload_length);

        return tvb_reported_length_remaining(tvb, offset_orig);

    case CMP_CTRL_MSG_DSR_CTRL_MSG:
        col_append_str(pinfo->cinfo, COL_INFO, " (Data Sink Ready)");
        proto_item_append_text(ti_msg_payload, " %s", "(Data Sink Ready)");

        proto_tree_add_item(asam_cmp_ctrl_msg_payload_tree, hf_cmp_ctrl_msg_device_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        break;

    case CMP_CTRL_MSG_USER_EVENT_CTRL_MSG:
        col_append_str(pinfo->cinfo, COL_INFO, " (User Event)");
        proto_item_append_text(ti_msg_payload, " %s", "(User Event)");

        proto_tree_add_item(asam_cmp_ctrl_msg_payload_tree, hf_cmp_ctrl_msg_event_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        break;

    case CMP_CTRL_MSG_VENDOR_CTRL_MSG:
        col_append_str(pinfo->cinfo, COL_INFO, " (Vendor specific)");
        proto_item_append_text(ti_msg_payload, " %s", "(Vendor specific)");

        proto_tree_add_item(asam_cmp_ctrl_msg_payload_tree, hf_cmp_ctrl_msg_vendor_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        asam_cmp_ctrl_msg_payload_length -= 2;

        proto_tree_add_item(asam_cmp_ctrl_msg_payload_tree, hf_cmp_ctrl_msg_vendor_payload_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        asam_cmp_ctrl_msg_payload_length -= 2;

        if (asam_cmp_ctrl_msg_payload_length > 0) {
            tvbuff_t *sub_tvb = tvb_new_subset_length(tvb, offset, asam_cmp_ctrl_msg_payload_length);
            call_data_dissector(sub_tvb, pinfo, tree);
            offset += (int)asam_cmp_ctrl_msg_payload_length;
        }

        /* we changed the payload length, so lets skip the length check by leaving */
        return (offset + asam_cmp_ctrl_msg_payload_length) - offset_orig;

    default:
        if (asam_cmp_ctrl_msg_payload_length > 0) {
            offset += (int)asam_cmp_ctrl_msg_payload_length;
        }

        proto_item_set_end(ti_msg_payload, tvb, offset);
        break;
    }

    if ((CMP_MSG_HEADER_LEN + asam_cmp_ctrl_msg_payload_length) < (offset - offset_orig)) {
        proto_tree_add_expert(tree, pinfo, &ei_asam_cmp_length_mismatch, tvb, offset_orig + CMP_MSG_HEADER_LEN, asam_cmp_ctrl_msg_payload_length);
        proto_item_set_end(ti_msg_payload, tvb, offset);
    }

    return CMP_MSG_HEADER_LEN + asam_cmp_ctrl_msg_payload_length;
}

static int
dissect_asam_cmp_status_interface_support_mask(tvbuff_t *tvb, proto_tree *tree, unsigned offset_orig, uint8_t interface_type) {
    unsigned offset = offset_orig;
    uint64_t temp = 0;

    static int *const can_feature_support[] = {
        &hf_cmp_iface_feat_can_gen_err,
        &hf_cmp_iface_feat_can_srr_dom,
        &hf_cmp_iface_feat_can_r0,
        &hf_cmp_iface_feat_can_bit_err,
        &hf_cmp_iface_feat_can_eof_err,
        &hf_cmp_iface_feat_can_crc_del_err,
        &hf_cmp_iface_feat_can_stuff_err,
        &hf_cmp_iface_feat_can_form_err,
        &hf_cmp_iface_feat_can_ack_del_err,
        &hf_cmp_iface_feat_can_act_ack,
        &hf_cmp_iface_feat_can_pas_ack,
        &hf_cmp_iface_feat_can_ack_err,
        &hf_cmp_iface_feat_can_crr_err,
        NULL
    };

    static int *const canfd_feature_support[] = {
        &hf_cmp_iface_feat_canfd_gen_err,
        &hf_cmp_iface_feat_canfd_esi,
        &hf_cmp_iface_feat_canfd_brs,
        &hf_cmp_iface_feat_canfd_srr_dom,
        &hf_cmp_iface_feat_canfd_rsvd,
        &hf_cmp_iface_feat_canfd_bit_err,
        &hf_cmp_iface_feat_canfd_eof_err,
        &hf_cmp_iface_feat_canfd_crc_del_err,
        &hf_cmp_iface_feat_canfd_stuff_err,
        &hf_cmp_iface_feat_canfd_form_err,
        &hf_cmp_iface_feat_canfd_ack_del_err,
        &hf_cmp_iface_feat_canfd_act_ack,
        &hf_cmp_iface_feat_canfd_pas_ack,
        &hf_cmp_iface_feat_canfd_ack_err,
        &hf_cmp_iface_feat_canfd_crr_err,
        NULL
    };

    static int *const lin_feature_support[] = {
        &hf_cmp_iface_feat_lin_wup,
        &hf_cmp_iface_feat_lin_long_dom_err,
        &hf_cmp_iface_feat_lin_short_dom_err,
        &hf_cmp_iface_feat_lin_framing_err,
        &hf_cmp_iface_feat_lin_sync_err,
        &hf_cmp_iface_feat_lin_no_slave_resp_err,
        &hf_cmp_iface_feat_lin_parity_err,
        &hf_cmp_iface_feat_lin_coll_err,
        &hf_cmp_iface_feat_lin_checksum_err,
        NULL
    };

    static int *const flexray_feature_support[] = {
        &hf_cmp_iface_feat_fr_channel,
        &hf_cmp_iface_feat_fr_cas,
        &hf_cmp_iface_feat_fr_ppi,
        &hf_cmp_iface_feat_fr_wus,
        &hf_cmp_iface_feat_fr_sync,
        &hf_cmp_iface_feat_fr_sf,
        &hf_cmp_iface_feat_fr_nf,
        &hf_cmp_iface_feat_fr_crc_header_err,
        &hf_cmp_iface_feat_fr_crc_frame_err,
        NULL
    };

    static int *const eth_feature_support[] = {
        &hf_cmp_iface_feat_eth_fcs,
        &hf_cmp_iface_feat_eth_trunc,
        &hf_cmp_iface_feat_eth_phy_err,
        &hf_cmp_iface_feat_eth_too_long,
        &hf_cmp_iface_feat_eth_collision,
        &hf_cmp_iface_feat_eth_tx_port_down,
        &hf_cmp_iface_feat_eth_too_short,
        &hf_cmp_iface_feat_eth_fcs_err,
        NULL
    };

    static int *const eth_10baset1s_feature_support[] = {
        &hf_cmp_iface_feat_10t1s_first_beacon,
        &hf_cmp_iface_feat_10t1s_mis_beacon,
        &hf_cmp_iface_feat_10t1s_sym_decode,
        NULL
    };

    static int *const link_state_feature_support[] = {
        &hf_cmp_iface_feat_link_err,
        NULL
    };

    switch (interface_type) {
    case CMP_DATA_MSG_CAN:
        proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_cmp_iface_feat, ett_asam_cmp_status_feature_support, can_feature_support, ENC_BIG_ENDIAN, &temp);
        break;

    case CMP_DATA_MSG_CANFD:
        proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_cmp_iface_feat, ett_asam_cmp_status_feature_support, canfd_feature_support, ENC_BIG_ENDIAN, &temp);
        break;

    case CMP_DATA_MSG_LIN:
        proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_cmp_iface_feat, ett_asam_cmp_status_feature_support, lin_feature_support, ENC_BIG_ENDIAN, &temp);
        break;

    case CMP_DATA_MSG_FLEXRAY:
        proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_cmp_iface_feat, ett_asam_cmp_status_feature_support, flexray_feature_support, ENC_BIG_ENDIAN, &temp);
        break;

    case CMP_DATA_MSG_ETHERNET:
        proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_cmp_iface_feat, ett_asam_cmp_status_feature_support, eth_feature_support, ENC_BIG_ENDIAN, &temp);
        break;

    case CMP_DATA_MSG_RAW_ETHERNET:
        proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_cmp_iface_feat, ett_asam_cmp_status_feature_support, eth_feature_support, ENC_BIG_ENDIAN, &temp);
        break;

    case CMP_DATA_MSG_10BASE_T1S_SYMBOL:
        proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_cmp_iface_feat, ett_asam_cmp_status_feature_support, eth_10baset1s_feature_support, ENC_BIG_ENDIAN, &temp);
        break;

    case CMP_DATA_MSG_LINK_STATE:
        proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_cmp_iface_feat, ett_asam_cmp_status_feature_support, link_state_feature_support, ENC_BIG_ENDIAN, &temp);
        break;

    default:
        proto_tree_add_item(tree, hf_cmp_iface_feat, tvb, offset, 4, ENC_BIG_ENDIAN);
    }

    offset += 4;

    return offset - offset_orig;
}

static int
dissect_asam_cmp_status_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset_orig) {
    proto_item *ti = NULL;
    proto_item *ti_msg_header = NULL;
    proto_item *ti_msg_payload = NULL;
    proto_item *ti_interface = NULL;
    proto_item *ti_stream_ids = NULL;
    proto_tree *asam_cmp_status_msg_header_tree = NULL;
    proto_tree *asam_cmp_status_msg_payload_tree = NULL;
    proto_tree *subtree = NULL;
    proto_tree *stream_ids_subtree = NULL;
    unsigned offset = offset_orig;

    unsigned asam_cmp_status_msg_payload_type = 0;
    unsigned asam_cmp_status_msg_payload_length = 0;
    unsigned asam_cmp_status_msg_cm_dev_desc_length = 0;
    unsigned asam_cmp_status_msg_cm_sn_length = 0;
    unsigned asam_cmp_status_msg_cm_hw_ver_length = 0;
    unsigned asam_cmp_status_msg_cm_sw_ver_length = 0;
    unsigned asam_cmp_status_msg_vendor_data_length = 0;
    unsigned asam_cmp_status_msg_iface_stream_id_count = 0;
    uint64_t uptime = 0;
    const char *descr = NULL;

    static int * const asam_cmp_common_flags[] = {
        &hf_cmp_common_flag_reserved_0xf0,
        &hf_cmp_common_flag_seg,
        &hf_cmp_common_flag_insync,
        &hf_cmp_common_flag_recal,
        NULL
    };

    static int * const asam_cmp_status_cm_flags[] = {
        &hf_cmp_gptp_flags_reserved,
        &hf_cmp_gptp_flags_freq_traceable,
        &hf_cmp_gptp_flags_time_traceable,
        &hf_cmp_gptp_flags_ptp_timescale,
        &hf_cmp_gptp_flags_cur_utco_valid,
        &hf_cmp_gptp_flags_leap59,
        &hf_cmp_gptp_flags_leap61,
        NULL
    };

    static int * const asam_cmp_status_timeloss_error_flags[] = {
        &hf_cmp_timeloss_error_flags_reserved,
        &hf_cmp_timeloss_error_flags_delta,
        &hf_cmp_timeloss_error_flags_insync,
        &hf_cmp_timeloss_error_flags_ts,
        NULL
    };

    /* Testing for Ethernet Padding */
    if (tvb_get_uint8(tvb, offset + 13) == 0) {
        return 0;
    }

    ti_msg_header = proto_tree_add_item(tree, hf_cmp_msg_header, tvb, offset, 16, ENC_BIG_ENDIAN);
    asam_cmp_status_msg_header_tree = proto_item_add_subtree(ti_msg_header, ett_asam_cmp_header);
    proto_item_append_text(ti_msg_header, " %s", "- Status Message");

    uint64_t ns = tvb_get_uint64(tvb, offset, ENC_BIG_ENDIAN);
    nstime_t timestamp = { .secs = (time_t)(ns / 1000000000), .nsecs = (int)(ns % 1000000000) };

    ti = proto_tree_add_time(asam_cmp_status_msg_header_tree, hf_cmp_msg_timestamp, tvb, offset, 8, &timestamp);
    subtree = proto_item_add_subtree(ti, ett_asam_cmp_timestamp);
    proto_tree_add_item(subtree, hf_cmp_msg_timestamp_ns, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(asam_cmp_status_msg_header_tree, hf_cmp_msg_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(asam_cmp_status_msg_header_tree, hf_cmp_msg_vendor_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_bitmask(asam_cmp_status_msg_header_tree, tvb, offset, hf_cmp_msg_common_flags, ett_asam_cmp_common_flags, asam_cmp_common_flags, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item_ret_uint(asam_cmp_status_msg_header_tree, hf_cmp_status_msg_payload_type, tvb, offset, 1, ENC_NA, &asam_cmp_status_msg_payload_type);
    offset += 1;

    proto_tree_add_item_ret_uint(asam_cmp_status_msg_header_tree, hf_cmp_msg_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN, &asam_cmp_status_msg_payload_length);
    offset += 2;

    proto_item_set_end(ti_msg_header, tvb, offset);

    ti_msg_payload = proto_tree_add_item(tree, hf_cmp_msg_payload, tvb, offset, asam_cmp_status_msg_payload_length, ENC_BIG_ENDIAN);
    asam_cmp_status_msg_payload_tree = proto_item_add_subtree(ti_msg_payload, ett_asam_cmp_header);
    proto_item_append_text(ti_msg_payload, " %s", "- Status Message");

    switch (asam_cmp_status_msg_payload_type) {
    case CMP_STATUS_MSG_INVALID:
        col_append_str(pinfo->cinfo, COL_INFO, " (Invalid/Padding)");
        proto_item_append_text(ti_msg_payload, " %s", "(Invalid/Padding)");
        proto_item_set_end(ti_msg_payload, tvb, offset + asam_cmp_status_msg_payload_length);

        return tvb_reported_length_remaining(tvb, offset_orig);

    case CMP_STATUS_MSG_CM_STAT_MSG:
        col_append_str(pinfo->cinfo, COL_INFO, " (CM)");
        proto_item_append_text(ti_msg_payload, " %s", "(CM)");

        ti = proto_tree_add_item_ret_uint64(asam_cmp_status_msg_payload_tree, hf_cmp_status_msg_cm_uptime_ns, tvb, offset, 8, ENC_BIG_ENDIAN, &uptime);

        subtree = proto_item_add_subtree(ti, ett_asam_cmp_status_cm_uptime);
        proto_tree_add_uint64(subtree, hf_cmp_status_msg_cm_uptime_s, tvb, offset, 8, uptime / 1000000000);
        offset += 8;

        proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_status_msg_gm_identity, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_status_msg_gm_clock_quality, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_status_msg_current_utc_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_status_msg_time_source, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_status_msg_domain_num, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_status_msg_res, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_bitmask(asam_cmp_status_msg_payload_tree, tvb, offset, hf_cmp_gptp_flags, ett_asam_cmp_status_cm_flags, asam_cmp_status_cm_flags, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item_ret_uint(asam_cmp_status_msg_payload_tree, hf_cmp_status_dev_desc_length, tvb, offset, 2, ENC_BIG_ENDIAN, &asam_cmp_status_msg_cm_dev_desc_length);
        offset += 2;

        if (asam_cmp_status_msg_cm_dev_desc_length > 0) {
            asam_cmp_status_msg_cm_dev_desc_length += (asam_cmp_status_msg_cm_dev_desc_length % 2); /* padding to 16bit */
            proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_status_dev_desc, tvb, offset, asam_cmp_status_msg_cm_dev_desc_length, ENC_UTF_8);
            offset += (int)asam_cmp_status_msg_cm_dev_desc_length;
        }

        proto_tree_add_item_ret_uint(asam_cmp_status_msg_payload_tree, hf_cmp_status_sn_length, tvb, offset, 2, ENC_BIG_ENDIAN, &asam_cmp_status_msg_cm_sn_length);
        offset += 2;

        if (asam_cmp_status_msg_cm_sn_length > 0) {
            asam_cmp_status_msg_cm_sn_length += (asam_cmp_status_msg_cm_sn_length % 2); /* padding to 16bit */
            proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_status_sn, tvb, offset, asam_cmp_status_msg_cm_sn_length, ENC_UTF_8);
            offset += (int)asam_cmp_status_msg_cm_sn_length;
        }

        proto_tree_add_item_ret_uint(asam_cmp_status_msg_payload_tree, hf_cmp_status_hw_ver_length, tvb, offset, 2, ENC_BIG_ENDIAN, &asam_cmp_status_msg_cm_hw_ver_length);
        offset += 2;

        if (asam_cmp_status_msg_cm_hw_ver_length > 0) {
            asam_cmp_status_msg_cm_hw_ver_length += (asam_cmp_status_msg_cm_hw_ver_length % 2); /* padding to 16bit */
            proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_status_hw_ver, tvb, offset, asam_cmp_status_msg_cm_hw_ver_length, ENC_UTF_8);
            offset += (int)asam_cmp_status_msg_cm_hw_ver_length;
        }

        proto_tree_add_item_ret_uint(asam_cmp_status_msg_payload_tree, hf_cmp_status_sw_ver_length, tvb, offset, 2, ENC_BIG_ENDIAN, &asam_cmp_status_msg_cm_sw_ver_length);
        offset += 2;

        if (asam_cmp_status_msg_cm_sw_ver_length > 0) {
            asam_cmp_status_msg_cm_sw_ver_length += (asam_cmp_status_msg_cm_sw_ver_length % 2); /* padding to 16bit */
            proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_status_sw_ver, tvb, offset, asam_cmp_status_msg_cm_sw_ver_length, ENC_UTF_8);
            offset += (int)asam_cmp_status_msg_cm_sw_ver_length;
        }

        proto_tree_add_item_ret_uint(asam_cmp_status_msg_payload_tree, hf_cmp_status_vendor_data_length, tvb, offset, 2, ENC_BIG_ENDIAN, &asam_cmp_status_msg_vendor_data_length);
        offset += 2;

        if (asam_cmp_status_msg_vendor_data_length > 0) {
            proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_status_vendor_data, tvb, offset, asam_cmp_status_msg_vendor_data_length, ENC_NA);
            offset += (int)asam_cmp_status_msg_vendor_data_length;
        }
        break;

    case CMP_STATUS_MSG_IF_STAT_MSG:
        col_append_str(pinfo->cinfo, COL_INFO, " (Interface)");
        proto_item_append_text(ti_msg_payload, " %s", "(Interface)");

        /* each entry is 40 bytes, header is 16 bytes */
        while (tvb_reported_length_remaining(tvb, offset) >= 40 && offset - offset_orig + 40 <= 16 + asam_cmp_status_msg_payload_length) {
            uint32_t ifaceid;
            uint32_t ifacetype;

            ti_interface = proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_iface_interface, tvb, offset, 34, ENC_NA);
            subtree = proto_item_add_subtree(ti_interface, ett_asam_cmp_status_interface);

            ti = proto_tree_add_item_ret_uint(subtree, hf_cmp_iface_iface_id, tvb, offset, 4, ENC_BIG_ENDIAN, &ifaceid);
            descr = ht_interface_config_to_string(ifaceid);
            if (descr != NULL) {
                proto_item_append_text(ti, " (%s)", descr);
            }
            offset += 4;

            proto_tree_add_item(subtree, hf_cmp_iface_msg_total_rx, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(subtree, hf_cmp_iface_msg_total_tx, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(subtree, hf_cmp_iface_msg_dropped_rx, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(subtree, hf_cmp_iface_msg_dropped_tx, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(subtree, hf_cmp_iface_errs_total_rx, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item(subtree, hf_cmp_iface_errs_total_tx, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_tree_add_item_ret_uint(subtree, hf_cmp_iface_iface_type, tvb, offset, 1, ENC_NA, &ifacetype);
            offset += 1;

            if (descr != NULL) {
                proto_item_append_text(ti_interface, " %s, Type: %s", descr, val_to_str(pinfo->pool, ifacetype, data_msg_type_names, "Unknown (0x%x)"));
            } else {
                proto_item_append_text(ti_interface, " 0x%x, Type: %s", ifaceid, val_to_str(pinfo->pool, ifacetype, data_msg_type_names, "Unknown (0x%x)"));
            }

            proto_tree_add_item(subtree, hf_cmp_iface_iface_status, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(subtree, hf_cmp_iface_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            offset += dissect_asam_cmp_status_interface_support_mask(tvb, subtree, offset, (uint8_t)ifacetype);

            proto_tree_add_item_ret_uint(subtree, hf_cmp_iface_stream_id_cnt, tvb, offset, 2, ENC_BIG_ENDIAN, &asam_cmp_status_msg_iface_stream_id_count);
            offset += 2;

            if (asam_cmp_status_msg_iface_stream_id_count > 0) {
                ti_stream_ids = proto_tree_add_item(subtree, hf_cmp_iface_stream_ids, tvb, offset, asam_cmp_status_msg_iface_stream_id_count, ENC_NA);
                stream_ids_subtree = proto_item_add_subtree(ti_stream_ids, ett_asam_cmp_status_stream_ids);

                for (unsigned i = 0; i < asam_cmp_status_msg_iface_stream_id_count; i++) {
                    proto_tree_add_item(stream_ids_subtree, hf_cmp_iface_stream_id, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }
                offset += (asam_cmp_status_msg_iface_stream_id_count % 2); /* padding to 16bit */
            }

            proto_tree_add_item_ret_uint(subtree, hf_cmp_iface_vendor_data_len, tvb, offset, 2, ENC_BIG_ENDIAN, &asam_cmp_status_msg_vendor_data_length);
            offset += 2;

            if (asam_cmp_status_msg_vendor_data_length > 0) {
                proto_tree_add_item(subtree, hf_cmp_iface_vendor_data, tvb, offset, asam_cmp_status_msg_vendor_data_length, ENC_NA);
                offset += (int)asam_cmp_status_msg_vendor_data_length;
            }

            proto_item_set_end(ti_interface, tvb, offset);
        }
        break;

    case CMP_STATUS_MSG_CONF_STAT_MSG:
        col_append_str(pinfo->cinfo, COL_INFO, " (Configuration)");
        proto_item_append_text(ti_msg_payload, " %s", "(Configuration)");

        if (asam_cmp_status_msg_payload_length > 0) {
            proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_status_msg_config, tvb, offset, asam_cmp_status_msg_payload_length, ENC_NA);
            offset += (int)asam_cmp_status_msg_payload_length;
        }
        break;

    case CMP_STATUS_MSG_DLE_STAT_MSG:
        col_append_str(pinfo->cinfo, COL_INFO, " (Data Lost Event)");
        proto_item_append_text(ti_msg_payload, " %s", "(Data Lost Event)");

        proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_dataloss_data_sink_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_dataloss_device_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_dataloss_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_dataloss_stream_id, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_dataloss_last_ssq_value, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_dataloss_current_ssq_value, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        break;

    case CMP_STATUS_MSG_TSLE_STAT_MSG:
        col_append_str(pinfo->cinfo, COL_INFO, " (Time Sync Lost Event)");
        proto_item_append_text(ti_msg_payload, " %s", "(Time Sync Lost Event)");

        proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_timeloss_port_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_timeloss_device_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_bitmask(asam_cmp_status_msg_payload_tree, tvb, offset, hf_cmp_timeloss_error_flags, ett_asam_cmp_status_timeloss_flags, asam_cmp_status_timeloss_error_flags, ENC_BIG_ENDIAN);
        offset += 1;
        break;

    case CMP_STATUS_MSG_VENDOR_STAT_MSG:
        col_append_str(pinfo->cinfo, COL_INFO, " (Vendor specific)");
        proto_item_append_text(ti_msg_payload, " %s", "(Vendor specific)");

        if (asam_cmp_status_msg_payload_length > 0) {
            proto_tree_add_item(asam_cmp_status_msg_payload_tree, hf_cmp_status_msg_vendor_specific, tvb, offset, asam_cmp_status_msg_payload_length, ENC_NA);
            offset += (int)asam_cmp_status_msg_payload_length;
        }
        break;

    default:
        if (asam_cmp_status_msg_payload_length > 0) {
            offset += (int)asam_cmp_status_msg_payload_length;
        }

        proto_item_set_end(ti_msg_payload, tvb, offset);
        break;
    }

    if ((CMP_MSG_HEADER_LEN + asam_cmp_status_msg_payload_length) < (offset - offset_orig)) {
        proto_tree_add_expert(tree, pinfo, &ei_asam_cmp_length_mismatch, tvb, offset_orig + CMP_MSG_HEADER_LEN, asam_cmp_status_msg_payload_length);
        proto_item_set_end(ti_msg_payload, tvb, offset);
    }

    return CMP_MSG_HEADER_LEN + asam_cmp_status_msg_payload_length;
}

static int
dissect_asam_cmp_vendor_msg(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset_orig) {
    proto_item *ti = NULL;
    proto_item *ti_msg_header = NULL;
    proto_item *ti_msg_payload = NULL;
    proto_tree *asam_cmp_vendor_msg_header_tree = NULL;
    proto_tree *subtree = NULL;
    unsigned asam_cmp_vendor_msg_payload_type = 0;
    unsigned asam_cmp_vendor_msg_payload_length = 0;
    unsigned offset = offset_orig;

    static int * const asam_cmp_common_flags[] = {
        &hf_cmp_common_flag_reserved_0xf0,
        &hf_cmp_common_flag_seg,
        &hf_cmp_common_flag_insync,
        &hf_cmp_common_flag_recal,
        NULL
    };

    ti_msg_header = proto_tree_add_item(tree, hf_cmp_msg_header, tvb, offset, 8, ENC_BIG_ENDIAN);
    asam_cmp_vendor_msg_header_tree = proto_item_add_subtree(ti_msg_header, ett_asam_cmp_header);
    proto_item_append_text(ti_msg_header, " %s", "- Vendor-Defined Message");

    uint64_t ns = tvb_get_uint64(tvb, offset, ENC_BIG_ENDIAN);
    nstime_t timestamp = { .secs = (time_t)(ns / 1000000000), .nsecs = (int)(ns % 1000000000) };

    ti = proto_tree_add_time(asam_cmp_vendor_msg_header_tree, hf_cmp_msg_timestamp, tvb, offset, 8, &timestamp);

    subtree = proto_item_add_subtree(ti, ett_asam_cmp_timestamp);
    proto_tree_add_item(subtree, hf_cmp_msg_timestamp_ns, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(asam_cmp_vendor_msg_header_tree, hf_cmp_msg_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(asam_cmp_vendor_msg_header_tree, hf_cmp_msg_vendor_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_bitmask(asam_cmp_vendor_msg_header_tree, tvb, offset, hf_cmp_msg_common_flags, ett_asam_cmp_common_flags, asam_cmp_common_flags, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item_ret_uint(asam_cmp_vendor_msg_header_tree, hf_cmp_vendor_msg_payload_type, tvb, offset, 1, ENC_NA, &asam_cmp_vendor_msg_payload_type);
    offset += 1;

    proto_tree_add_item_ret_uint(asam_cmp_vendor_msg_header_tree, hf_cmp_msg_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN, &asam_cmp_vendor_msg_payload_length);
    offset += 2;

    proto_item_set_end(ti_msg_header, tvb, offset);

    ti_msg_payload = proto_tree_add_item(tree, hf_cmp_msg_payload, tvb, offset, asam_cmp_vendor_msg_payload_length, ENC_BIG_ENDIAN);
    proto_item_append_text(ti_msg_payload, " %s", "- Vendor-Defined Message");

    if (asam_cmp_vendor_msg_payload_length > 0) {
        offset += (int)asam_cmp_vendor_msg_payload_length;
        proto_item_set_end(ti_msg_payload, tvb, offset);
    }

    return CMP_MSG_HEADER_LEN + asam_cmp_vendor_msg_payload_length;
}

static int
dissect_asam_cmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_item *ti_root = NULL;
    proto_item *ti_header = NULL;
    proto_item *ti = NULL;
    proto_tree *asam_cmp_tree = NULL;
    proto_tree *asam_cmp_header_tree = NULL;
    unsigned msg_type = 0;
    unsigned device_id = 0;
    unsigned offset = 0;

    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_INFO, "ASAM-CMP");
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ASAM-CMP");

    ti_root = proto_tree_add_item(tree, proto_asam_cmp, tvb, 0, -1, ENC_NA);
    asam_cmp_tree = proto_item_add_subtree(ti_root, ett_asam_cmp);

    ti_header = proto_tree_add_item(asam_cmp_tree, hf_cmp_header, tvb, offset, CMP_HEADER_LEN, ENC_BIG_ENDIAN);
    asam_cmp_header_tree = proto_item_add_subtree(ti_header, ett_asam_cmp_header);

    proto_tree_add_item(asam_cmp_header_tree, hf_cmp_version, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(asam_cmp_header_tree, hf_cmp_header_res, tvb, offset, 1, ENC_NA);
    offset += 1;

    ti = proto_tree_add_item_ret_uint(asam_cmp_header_tree, hf_cmp_device_id, tvb, offset, 2, ENC_BIG_ENDIAN, &device_id);
    add_device_id_text(ti, (uint16_t)device_id);
    offset += 2;

    proto_tree_add_item_ret_uint(asam_cmp_header_tree, hf_cmp_msg_type, tvb, offset, 1, ENC_NA, &msg_type);
    offset += 1;

    proto_tree_add_item(asam_cmp_header_tree, hf_cmp_stream_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(asam_cmp_header_tree, hf_cmp_stream_seq_ctr, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_item_append_text(ti_root, ", Device: 0x%04x, Type: %s", (uint16_t)device_id, val_to_str(pinfo->pool, msg_type, msg_type_names, "Unknown (0x%x)"));

    while (tvb_reported_length_remaining(tvb, offset) >= 16) {
        unsigned bytes_parsed = 0;

        switch (msg_type) {
        case CMP_MSG_TYPE_CAP_DATA_MSG:
            col_append_str(pinfo->cinfo, COL_INFO, ", Data Msg (Capturing)");
            bytes_parsed += dissect_asam_cmp_data_msg(tvb, pinfo, tree, asam_cmp_tree, offset, false);
            break;
        case CMP_MSG_TYPE_CTRL_MSG:
            col_append_str(pinfo->cinfo, COL_INFO, ", Control Msg");
            bytes_parsed = dissect_asam_cmp_ctrl_msg(tvb, pinfo, asam_cmp_tree, offset);
            break;
        case CMP_MSG_TYPE_STATUS_MSG:
            col_append_str(pinfo->cinfo, COL_INFO, ", Status Msg");
            bytes_parsed = dissect_asam_cmp_status_msg(tvb, pinfo, asam_cmp_tree, offset);
            break;
        case CMP_MSG_TYPE_TX_DATA_MSG:
            col_append_str(pinfo->cinfo, COL_INFO, ", Data Msg (Transmit)");
            bytes_parsed += dissect_asam_cmp_data_msg(tvb, pinfo, tree, asam_cmp_tree, offset, true);
            break;
        case CMP_MSG_TYPE_VENDOR:
            col_append_str(pinfo->cinfo, COL_INFO, ", Vendor Msg");
            bytes_parsed = dissect_asam_cmp_vendor_msg(tvb, pinfo, asam_cmp_tree, offset);
            break;
        default:
            proto_item_set_end(ti_root, tvb, offset);
            return offset;
        }

        offset += bytes_parsed;

        /* Bytes are not being parsed, if detected as Ethernet padding, so we need to bail out. */
        if (bytes_parsed == 0) {
            proto_item_set_end(ti_root, tvb, offset);
            return offset;
        }

    }

    proto_item_set_end(ti_root, tvb, offset);
    return offset;
}

void
proto_register_asam_cmp(void) {
    module_t *asam_cmp_module = NULL;
    expert_module_t *expert_module_asam_cmp;
    uat_t *asam_cmp_deviceid_uat = NULL;
    uat_t *asam_cmp_interfaceid_uat = NULL;

    static hf_register_info hf[] = {
        /* Header */
        { &hf_cmp_header,                           { "ASAM CMP Header", "asam-cmp.hdr", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_cmp_version,                          { "Version", "asam-cmp.hdr.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_header_res,                       { "Reserved", "asam-cmp.hdr.res", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_device_id,                        { "Device ID", "asam-cmp.hdr.device_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_msg_type,                         { "Message Type", "asam-cmp.hdr.msg_type", FT_UINT8, BASE_HEX, VALS(msg_type_names), 0x0, NULL, HFILL }},
        { &hf_cmp_stream_id,                        { "Stream ID", "asam-cmp.hdr.stream_id", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_stream_seq_ctr,                   { "Stream Sequence Counter", "asam-cmp.hdr.stream_seq_cnt", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* Message Header*/
        { &hf_cmp_msg_header,                       { "ASAM CMP Msg Header", "asam-cmp.msg_hdr", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_cmp_msg_timestamp,                    { "Timestamp", "asam-cmp.msg_hdr.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_msg_timestamp_ns,                 { "Timestamp (ns)", "asam-cmp.msg_hdr.timestamp_ns", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_msg_deadline,                     { "Deadline", "asam-cmp.msg_hdr.deadline", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_nanoseconds), 0x0, NULL, HFILL }},
        { &hf_cmp_msg_reserved,                     { "Reserved", "asam-cmp.msg_hdr.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_cmp_msg_trans_opts,                   { "Transmission Options", "asam-cmp.msg_hdr.trans_opts", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_msg_trans_opts_res,               { "Reserved", "asam-cmp.msg_hdr.trans_opts.res", FT_UINT32, BASE_HEX, NULL, 0xFFFFFFFF, NULL, HFILL } },
        { &hf_cmp_msg_trans_opts_lin_wup_dura,      { "Wake Up Duration", "asam-cmp.msg_hdr.trans_opts.lin.wup_duration", FT_UINT32, BASE_DEC, NULL, 0xFFFF0000, NULL, HFILL } },
        { &hf_cmp_msg_trans_opts_lin_res,           { "Reserved", "asam-cmp.msg_hdr.trans_opts.lin.reserved", FT_UINT32, BASE_HEX, NULL, 0x0000FFFF, NULL, HFILL } },
        { &hf_cmp_msg_trans_opts_fr_op,             { "Operation", "asam-cmp.msg_hdr.trans_opts.flexray.operation", FT_UINT32, BASE_HEX,  VALS(flexray_transmission_operations), 0xFF000000, NULL, HFILL}},
        { &hf_cmp_msg_trans_opts_fr_cycle_rep,      { "Cycle Repetition", "asam-cmp.msg_hdr.trans_opts.flexray.cycle_repetition", FT_UINT32, BASE_DEC, NULL, 0x00FF0000, NULL, HFILL } },
        { &hf_cmp_msg_trans_opts_fr_res,            { "Reserved", "asam-cmp.msg_hdr.trans_opts.flexray.reserved", FT_UINT32, BASE_HEX, NULL, 0x0000FFFF, NULL, HFILL } },

        { &hf_cmp_msg_common_flags,                 { "Common Flags", "asam-cmp.msg_hdr.common_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_common_flag_recal,                { "Timestamp recalculated", "asam-cmp.msg_hdr.recalculated", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
        { &hf_cmp_common_flag_relative,             { "Relative", "asam-cmp.msg_hdr.timestamp_relative", FT_BOOLEAN, 8, TFS(&timestamp_rel_abs), 0x01, NULL, HFILL}},
        { &hf_cmp_common_flag_insync,               { "Synchronized", "asam-cmp.msg_hdr.sync", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_cmp_common_flag_reserved_0x02,        { "Reserved", "asam-cmp.msg_hdr.res3", FT_UINT8, BASE_HEX, NULL, 0x02, NULL, HFILL } },
        { &hf_cmp_common_flag_seg,                  { "Segmentation", "asam-cmp.msg_hdr.seg", FT_UINT8, BASE_HEX, VALS(seg_flag_names), 0x0C, NULL, HFILL } },
        { &hf_cmp_common_flag_dir_on_if,            { "Direction", "asam-cmp.msg_hdr.dir_on_if", FT_BOOLEAN, 8, TFS(&interface_direction), 0x10, NULL, HFILL } },
        { &hf_cmp_common_flag_overflow,             { "Overflow", "asam-cmp.msg_hdr.overflow", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL } },
        { &hf_cmp_common_flag_err_in_payload,       { "Error in payload", "asam-cmp.msg_hdr.error_in_payload", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL } },
        { &hf_cmp_common_flag_reserved,             { "Reserved", "asam-cmp.msg_hdr.res", FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL } },
        { &hf_cmp_common_flag_reserved_0xf0,        { "Reserved", "asam-cmp.msg_hdr.res2", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL } },

        { &hf_cmp_msg_vendor_id,                    { "Vendor ID", "asam-cmp.msg_hdr.vendor_id", FT_UINT16, BASE_HEX, VALS(vendor_ids), 0x0, NULL, HFILL }},
        { &hf_cmp_msg_payload_length,               { "Payload Length", "asam-cmp.msg_hdr.payload_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_msg_payload,                      { "Payload", "asam-cmp.msg_payload", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        /* Data Message Header */
        { &hf_cmp_interface_id,                     { "Interface ID", "asam-cmp.msg_hdr.interface_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_payload_type,                     { "Payload Type", "asam-cmp.msg_hdr.payload_type", FT_UINT8, BASE_HEX, VALS(data_msg_type_names), 0x0, NULL, HFILL }},

        /* Additional Control Message Header */
        { &hf_cmp_ctrl_msg_reserved,                { "Reserved", "asam-cmp.msg_hdr.reserved", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_ctrl_msg_payload_type,            { "Payload Type", "asam-cmp.msg_hdr.payload_type", FT_UINT8, BASE_HEX, VALS(ctrl_msg_type_names), 0x0, NULL, HFILL }},

        /* Additional Status Message Header */
        { &hf_cmp_status_msg_payload_type,          { "Payload Type", "asam-cmp.msg_hdr.payload_type", FT_UINT8, BASE_HEX, VALS(status_msg_type_names), 0x0, NULL, HFILL }},

        /* Additional Vendor Message Header */
        { &hf_cmp_vendor_msg_payload_type,          { "Payload Type", "asam-cmp.msg_hdr.payload_type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        /* Data Message Payloads */
        /* CAN Data */
        { &hf_cmp_can_flags,                        { "Flags", "asam-cmp.msg.can.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_can_flag_crc_err,                 { "CRC Error", "asam-cmp.msg.can.flags.crc_err", FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }},
        { &hf_cmp_can_flag_ack_err,                 { "ACK Error", "asam-cmp.msg.can.flags.ack_err", FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
        { &hf_cmp_can_flag_passive_ack_err,         { "Passive ACK Error", "asam-cmp.msg.can.flags.passive_ack_err", FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
        { &hf_cmp_can_flag_reserved_0004,           { "Reserved", "asam-cmp.msg.can.flags.reserved_0x0004", FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
        { &hf_cmp_can_flag_active_ack_err,          { "Active ACK Error", "asam-cmp.msg.can.flags.active_ack_err", FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },
        { &hf_cmp_can_flag_reserved_0008,           { "Reserved", "asam-cmp.msg.can.flags.reserved_0x0008", FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },
        { &hf_cmp_can_flag_ack_del_err,             { "ACK DEL Error", "asam-cmp.msg.can.flags.ack_del_err", FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },
        { &hf_cmp_can_flag_form_err,                { "Form Error", "asam-cmp.msg.can.flags.form_err", FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },
        { &hf_cmp_can_flag_stuff_err,               { "Stuff Error", "asam-cmp.msg.can.flags.stuff_err", FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },
        { &hf_cmp_can_flag_crc_del_err,             { "CRC DEL Error", "asam-cmp.msg.can.flags.crc_del_err", FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },
        { &hf_cmp_can_flag_eof_err,                 { "EOF Error", "asam-cmp.msg.can.flags.eof_err", FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },
        { &hf_cmp_can_flag_bit_err,                 { "Bit Error", "asam-cmp.msg.can.flags.bit_err", FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },
        { &hf_cmp_can_flag_r0,                      { "R0", "asam-cmp.msg.can.flags.r0", FT_BOOLEAN, 16, TFS(&can_rec_dom), 0x0400, NULL, HFILL } },
        { &hf_cmp_can_flag_srr_dom,                 { "Substitute Remote Request (SRR)", "asam-cmp.msg.can.flags.srr", FT_BOOLEAN, 16, TFS(&can_dom_rec), 0x0800, NULL, HFILL } },
        { &hf_cmp_can_flag_reserved,                { "Reserved", "asam-cmp.msg.can.flags.reserved", FT_UINT16, BASE_HEX, NULL, 0xF000, NULL, HFILL } },
        { &hf_cmp_can_flag_reserved_1000,           { "Reserved", "asam-cmp.msg.can.flags.reserved_0x1000", FT_UINT16, BASE_HEX, NULL, 0x1000, NULL, HFILL } },
        { &hf_cmp_can_flag_reserved_2000,           { "Reserved", "asam-cmp.msg.can.flags.reserved_0x2000", FT_UINT16, BASE_HEX, NULL, 0x2000, NULL, HFILL } },
        { &hf_cmp_can_flag_gen_err,                 { "Generic Error", "asam-cmp.msg.can.flags.gen_err", FT_UINT16, BASE_HEX, NULL, 0x4000, NULL, HFILL } },
        { &hf_cmp_can_flag_reserved_tx,             { "Reserved", "asam-cmp.msg.can.flags.reserved_tx", FT_UINT16, BASE_HEX, NULL, 0x8000, NULL, HFILL } },

        { &hf_cmp_can_reserved,                     { "Reserved", "asam-cmp.msg.can.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_cmp_can_id,                           { "ID", "asam-cmp.msg.can.id_field", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_can_id_11bit,                     { "ID (11bit)", "asam-cmp.msg.can.id_11bit", FT_UINT32, BASE_HEX_DEC, NULL, CMP_CAN_ID_11BIT_MASK, NULL, HFILL }},
        { &hf_cmp_can_id_11bit_old,                 { "ID (11bit)", "asam-cmp.msg.can.id_11bit", FT_UINT32, BASE_HEX_DEC, NULL, CMP_CAN_ID_11BIT_MASK_OLD, NULL, HFILL }},
        { &hf_cmp_can_id_29bit,                     { "ID (29bit)", "asam-cmp.msg.can.id_29bit", FT_UINT32, BASE_HEX_DEC, NULL, CMP_CAN_ID_29BIT_MASK, NULL, HFILL }},
        { &hf_cmp_can_id_err,                       { "ID_ERR", "asam-cmp.msg.can.id_err", FT_BOOLEAN, 32, TFS(&tfs_invalid_valid), CMP_CAN_ID_ERR, NULL, HFILL}},
        { &hf_cmp_can_id_rtr,                       { "RTR", "asam-cmp.msg.can.rtr", FT_BOOLEAN, 32, TFS(&can_id_rtr), CMP_CAN_ID_RTR, NULL, HFILL }},
        { &hf_cmp_can_id_ide,                       { "IDE", "asam-cmp.msg.can.ide", FT_BOOLEAN, 32, TFS(&can_id_ide), CMP_CAN_ID_IDE, NULL, HFILL }},

        { &hf_cmp_can_crc,                          { "CRC", "asam-cmp.msg.can.crc_field", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_can_crc_crc,                      { "CRC", "asam-cmp.msg.can.crc", FT_UINT32, BASE_HEX_DEC, NULL, CMP_CAN_CRC_CRC, NULL, HFILL }},
        { &hf_cmp_can_crc_res,                      { "Reserved", "asam-cmp.msg.can.crc_res", FT_UINT32, BASE_HEX_DEC, NULL, CMP_CAN_CRC_RES, NULL, HFILL }},
        { &hf_cmp_can_crc_crc_support,              { "CRC Supported", "asam-cmp.msg.can.crc_support", FT_BOOLEAN, 32, NULL, CMP_CAN_CRC_CRC_SUPP, NULL, HFILL }},

        { &hf_cmp_can_err_pos,                      { "Error Position", "asam-cmp.msg.can.err_pos", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_can_dlc,                          { "DLC", "asam-cmp.msg.can.dlc", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_can_data_len,                     { "Data length", "asam-cmp.msg.can.data_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* CAN-FD Data */
        { &hf_cmp_canfd_flags,                      { "Flags", "asam-cmp.msg.canfd.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_canfd_flag_crc_err,               { "CRC Error", "asam-cmp.msg.canfd.flags.crc_err", FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }},
        { &hf_cmp_canfd_flag_ack_err,               { "ACK Error", "asam-cmp.msg.canfd.flags.ack_err", FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
        { &hf_cmp_canfd_flag_passive_ack_err,       { "Passive ACK Error", "asam-cmp.msg.canfd.flags.passive_ack_err", FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
        { &hf_cmp_canfd_flag_reserved_0004,         { "Reserved", "asam-cmp.msg.canfd.flags.reserved_0x0004", FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
        { &hf_cmp_canfd_flag_active_ack_err,        { "Active ACK Error", "asam-cmp.msg.canfd.flags.active_ack_err", FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },
        { &hf_cmp_canfd_flag_reserved_0008,         { "Reserved", "asam-cmp.msg.canfd.flags.reserved_0x0008", FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },
        { &hf_cmp_canfd_flag_ack_del_err,           { "ACK DEL Error", "asam-cmp.msg.canfd.flags.ack_del_err", FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },
        { &hf_cmp_canfd_flag_form_err,              { "Form Error", "asam-cmp.msg.canfd.flags.form_err", FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },
        { &hf_cmp_canfd_flag_stuff_err,             { "Stuff Error", "asam-cmp.msg.canfd.flags.stuff_err", FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },
        { &hf_cmp_canfd_flag_crc_del_err,           { "CRC DEL Error", "asam-cmp.msg.canfd.flags.crc_del_err", FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },
        { &hf_cmp_canfd_flag_eof_err,               { "EOF Error", "asam-cmp.msg.canfd.flags.eof_err", FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },
        { &hf_cmp_canfd_flag_bit_err,               { "Bit Error", "asam-cmp.msg.canfd.flags.bit_err", FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },
        { &hf_cmp_canfd_flag_res,                   { "Reserved Bit", "asam-cmp.msg.canfd.flags.res", FT_BOOLEAN, 16, TFS(&can_rec_dom), 0x0400, NULL, HFILL } },
        { &hf_cmp_canfd_flag_srr_dom,               { "Substitute Remote Request (SRR)", "asam-cmp.msg.canfd.flags.srr", FT_BOOLEAN, 16, TFS(&can_dom_rec), 0x0800, NULL, HFILL } },
        { &hf_cmp_canfd_flag_brs,                   { "BRS", "asam-cmp.msg.canfd.flags.brs", FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL } },
        { &hf_cmp_canfd_flag_esi,                   { "ESI", "asam-cmp.msg.canfd.flags.esi",  FT_BOOLEAN, 16, TFS(&canfd_act_pas), 0x2000, NULL, HFILL } },
        { &hf_cmp_canfd_flag_reserved,              { "Reserved", "asam-cmp.msg.canfd.flags.reserved",  FT_UINT16, BASE_HEX, NULL, 0xC000, NULL, HFILL } },

        { &hf_cmp_canfd_flag_gen_err,               { "Generic Error", "asam-cmp.msg.canfd.flags.gen_err", FT_UINT16, BASE_HEX, NULL, 0x4000, NULL, HFILL } },
        { &hf_cmp_canfd_flag_reserved_tx,           { "Reserved", "asam-cmp.msg.canfd.flags.reserved_tx",  FT_UINT16, BASE_HEX, NULL, 0x8000, NULL, HFILL } },

        { &hf_cmp_canfd_reserved,                   { "Reserved", "asam-cmp.msg.canfd.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_cmp_canfd_id,                         { "ID", "asam-cmp.msg.canfd.id_field", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_canfd_id_11bit,                   { "ID (11bit)", "asam-cmp.msg.canfd.id_11bit", FT_UINT32, BASE_HEX_DEC, NULL, CMP_CAN_ID_11BIT_MASK, NULL, HFILL }},
        { &hf_cmp_canfd_id_11bit_old,               { "ID (11bit)", "asam-cmp.msg.canfd.id_11bit", FT_UINT32, BASE_HEX_DEC, NULL, CMP_CAN_ID_11BIT_MASK_OLD, NULL, HFILL }},
        { &hf_cmp_canfd_id_29bit,                   { "ID (29bit)", "asam-cmp.msg.canfd.id_29bit", FT_UINT32, BASE_HEX_DEC, NULL, CMP_CAN_ID_29BIT_MASK, NULL, HFILL }},
        { &hf_cmp_canfd_id_err,                     { "ID_ERR", "asam-cmp.msg.canfd.id_err", FT_BOOLEAN, 32, TFS(&tfs_invalid_valid), CMP_CANFD_ID_ERR, NULL, HFILL}},
        { &hf_cmp_canfd_id_rrs,                     { "RRS", "asam-cmp.msg.canfd.rrs", FT_BOOLEAN, 32, NULL, CMP_CANFD_ID_RRS, NULL, HFILL }},
        { &hf_cmp_canfd_id_ide,                     { "IDE", "asam-cmp.msg.canfd.ide", FT_BOOLEAN, 32, NULL, CMP_CANFD_ID_IDE, NULL, HFILL }},

        { &hf_cmp_canfd_crc,                        { "CRC SBC", "asam-cmp.msg.canfd.crc_field", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_canfd_crc_crc17,                  { "CRC (17bit)", "asam-cmp.msg.canfd.crc17", FT_UINT32, BASE_HEX_DEC, NULL, CMP_CANFD_CRC_CRC17, NULL, HFILL }},
        { &hf_cmp_canfd_crc_crc21,                  { "CRC (21bit)", "asam-cmp.msg.canfd.crc21", FT_UINT32, BASE_HEX_DEC, NULL, CMP_CANFD_CRC_CRC21, NULL, HFILL }},
        { &hf_cmp_canfd_crc_sbc,                    { "SBC", "asam-cmp.msg.canfd.sbc", FT_UINT32, BASE_HEX_DEC, NULL, CMP_CANFD_CRC_SBC, NULL, HFILL }},
        { &hf_cmp_canfd_crc_sbc_parity,             { "SBC Parity", "asam-cmp.msg.canfd.sbc_parity", FT_BOOLEAN, 32, NULL, CMP_CANFD_CRC_SBC_PARITY, NULL, HFILL }},
        { &hf_cmp_canfd_crc_res,                    { "Reserved", "asam-cmp.msg.canfd.crc_res", FT_UINT32, BASE_HEX_DEC, NULL, CMP_CANFD_CRC_RES, NULL, HFILL }},
        { &hf_cmp_canfd_crc_sbc_support,            { "SBC Supported", "asam-cmp.msg.canfd.sbc_support", FT_BOOLEAN, 32, NULL, CMP_CANFD_CRC_SBC_SUPP, NULL, HFILL }},
        { &hf_cmp_canfd_crc_crc_support,            { "CRC Supported", "asam-cmp.msg.canfd.crc_support", FT_BOOLEAN, 32, NULL, CMP_CANFD_CRC_CRC_SUPP, NULL, HFILL }},

        { &hf_cmp_canfd_err_pos,                    { "Error Position", "asam-cmp.msg.canfd.err_pos", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_canfd_dlc,                        { "DLC", "asam-cmp.msg.canfd.dlc", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_canfd_data_len,                   { "Data length", "asam-cmp.msg.canfd.data_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* LIN */
        { &hf_cmp_lin_flags,                        { "Flags", "asam-cmp.msg.lin.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_lin_flag_checksum_err,            { "Checksum Error", "asam-cmp.msg.lin.flags.checksum_err", FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
        { &hf_cmp_lin_flag_col_err,                 { "Collision Error", "asam-cmp.msg.lin.flags.col_err", FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
        { &hf_cmp_lin_flag_reserved_0x0002,         { "Reserved", "asam-cmp.msg.lin.flags.reserved_0x0002", FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
        { &hf_cmp_lin_flag_parity_err,              { "Parity Error", "asam-cmp.msg.lin.flags.parity_err", FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
        { &hf_cmp_lin_flag_no_slave_res,            { "No Slave Response", "asam-cmp.msg.lin.flags.no_slave_response", FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },
        { &hf_cmp_lin_flag_reserved_0x0008,         { "Reserved", "asam-cmp.msg.lin.flags.reserved_0x0008", FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },
        { &hf_cmp_lin_flag_sync_err,                { "Sync Error", "asam-cmp.msg.lin.flags.sync_err", FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },
        { &hf_cmp_lin_flag_framing_err,             { "Framing Error", "asam-cmp.msg.lin.flags.framing_err", FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },
        { &hf_cmp_lin_flag_short_dom_err,           { "Short Dominant Error", "asam-cmp.msg.lin.flags.short_dom_err", FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },
        { &hf_cmp_lin_flag_long_dom_err,            { "Long Dominant Error", "asam-cmp.msg.lin.flags.long_dom_err", FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },
        { &hf_cmp_lin_flag_wup,                     { "Wake Up Request Detection (WUP)", "asam-cmp.msg.lin.flags.wup", FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },
        { &hf_cmp_lin_flag_reserved,                { "Reserved", "asam-cmp.msg.lin.flags.reserved", FT_UINT16, BASE_HEX, NULL, 0xFE00, NULL, HFILL } },

        { &hf_cmp_lin_reserved,                     { "Reserved", "asam-cmp.msg.lin.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_lin_pid,                          { "PID", "asam-cmp.msg.lin.pid", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_lin_pid_id,                       { "ID", "asam-cmp.msg.lin.pid.id", FT_UINT8, BASE_HEX, NULL, CMP_CANFD_PID_ID_MASK, NULL, HFILL } },
        { &hf_cmp_lin_pid_parity,                   { "Parity", "asam-cmp.msg.lin.pid.parity", FT_UINT8, BASE_HEX, NULL, CMP_CANFD_PID_PARITY_MASK, NULL, HFILL } },
        { &hf_cmp_lin_reserved_2,                   { "Reserved", "asam-cmp.msg.lin.res_2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_lin_checksum,                     { "Checksum", "asam-cmp.msg.lin.checksum", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_lin_data_len,                     { "Data length", "asam-cmp.msg.lin.data_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* FlexRay */
        { &hf_cmp_flexray_flags,                    { "Flags", "asam-cmp.msg.flexray.flags.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_flexray_flag_crc_frame_err,       { "Frame CRC Error", "asam-cmp.msg.flexray.flags.crc_frame_err", FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
        { &hf_cmp_flexray_flag_crc_header_err,      { "Header CRC Error", "asam-cmp.msg.flexray.flags.crc_header_err", FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
        { &hf_cmp_flexray_flag_nf,                  { "Null Frame", "asam-cmp.msg.flexray.flags.nf", FT_BOOLEAN, 16, NULL, CMP_FLEXRAY_FLAGS_NF, NULL, HFILL } },
        { &hf_cmp_flexray_flag_sf,                  { "Startup Frame", "asam-cmp.msg.flexray.flags.sf", FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },
        { &hf_cmp_flexray_flag_sync,                { "Sync Frame", "asam-cmp.msg.flexray.flags.sync", FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },
        { &hf_cmp_flexray_flag_wus,                 { "Wake Up Symbol", "asam-cmp.msg.flexray.flags.wus", FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },
        { &hf_cmp_flexray_flag_ppi,                 { "Preamble Indicator", "asam-cmp.msg.flexray.flags.ppi", FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },
        { &hf_cmp_flexray_flag_cas,                 { "Collision avoidance Symbol (CAS)", "asam-cmp.msg.flexray.flags.cas", FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },
        { &hf_cmp_flexray_flag_leading,             { "Leading", "asam-cmp.msg.flexray.flags.leading", FT_BOOLEAN, 16, TFS(&flexray_leading_following), 0x0100, NULL, HFILL}},
        { &hf_cmp_flexray_flag_reserved_0x0100,     { "Reserved", "asam-cmp.msg.flexray.flags.reserved_0x0100", FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL}},
        { &hf_cmp_flexray_flag_channel,             { "Channel", "asam-cmp.msg.flexray.flags.channel", FT_BOOLEAN, 16, TFS(&flexray_channel_b_a), 0x0200, NULL, HFILL}},
        { &hf_cmp_flexray_flag_reserved,            { "Reserved", "asam-cmp.msg.flexray.flags.reserved", FT_UINT16, BASE_HEX, NULL, 0xFC00, NULL, HFILL } },

        { &hf_cmp_flexray_reserved,                 { "Reserved", "asam-cmp.msg.flexray.flags.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_flexray_header_crc,               { "Header CRC", "asam-cmp.msg.flexray.flags.header_crc", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_flexray_frame_id,                 { "Frame ID", "asam-cmp.msg.flexray.flags.frame_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_flexray_cycle,                    { "Cycle", "asam-cmp.msg.flexray.flags.cycle", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_flexray_frame_crc,                { "Frame CRC", "asam-cmp.msg.flexray.flags.frame_crc", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_flexray_reserved_2,               { "Reserved", "asam-cmp.msg.flexray.flags.res_2", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_flexray_data_len,                 { "Data length", "asam-cmp.msg.flexray.flags.data_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        /* Digital */
        { &hf_cmp_digital_flags,                    { "Flags", "asam-cmp.msg.digital.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_digital_flag_trig_present,        { "Trigger Information Present", "asam-cmp.msg.digital.flags.trigger_present",  FT_UINT16, BASE_HEX, NULL, 0x0001, NULL, HFILL } },
        { &hf_cmp_digital_flag_sampl_present,       { "Sampling Information Present", "asam-cmp.msg.digital.flags.sampling_present",  FT_UINT16, BASE_HEX, NULL, 0x0002, NULL, HFILL } },
        { &hf_cmp_digital_flag_reserved,            { "Reserved", "asam-cmp.msg.digital.flags.reserved", FT_UINT16, BASE_HEX, NULL, 0xFFFC, NULL, HFILL } },

        { &hf_cmp_digital_reserved,                 { "Reserved", "asam-cmp.msg.digital.res", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_digital_pin_count,                { "Pin Count", "asam-cmp.msg.digital.pin_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_cmp_digital_trig_pattern,             { "Trigger Pattern", "asam-cmp.msg.digital.trigger.pattern", FT_UINT8, BASE_DEC, VALS(digital_trigger_pattern), 0x0, NULL, HFILL}},
        { &hf_cmp_digital_trig_pin,                 { "Trigger Pin", "asam-cmp.msg.digital.trigger.pin", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_cmp_digital_flag_reserved2,           { "Reserved", "asam-cmp.msg.digital.trigger.reserved2", FT_UINT16, BASE_HEX, NULL, 0x0 , NULL, HFILL } },

        { &hf_cmp_digital_sample_interval,          { "Sample Interval", "asam-cmp.msg.digital.sample.interval", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_digital_sample_count,             { "Sample Count", "asam-cmp.msg.digital.sample.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_digital_sample,                   { "Sample", "asam-cmp.msg.digital.sample", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_cmp_digital_sample_pin_0,             { "GPIO 0", "asam-cmp.msg.digital.sample.pin_0", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x01, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_1,             { "GPIO 1", "asam-cmp.msg.digital.sample.pin_1", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x02, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_2,             { "GPIO 2", "asam-cmp.msg.digital.sample.pin_2", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x04, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_3,             { "GPIO 3", "asam-cmp.msg.digital.sample.pin_3", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x08, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_4,             { "GPIO 4", "asam-cmp.msg.digital.sample.pin_4", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x10, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_5,             { "GPIO 5", "asam-cmp.msg.digital.sample.pin_5", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x20, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_6,             { "GPIO 6", "asam-cmp.msg.digital.sample.pin_6", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x40, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_7,             { "GPIO 7", "asam-cmp.msg.digital.sample.pin_7", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x80, NULL, HFILL } },

        { &hf_cmp_digital_sample_pin_8,             { "GPIO 8", "asam-cmp.msg.digital.sample.pin_8", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x01, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_9,             { "GPIO 9", "asam-cmp.msg.digital.sample.pin_9", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x02, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_10,            { "GPIO 10", "asam-cmp.msg.digital.sample.pin_10", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x04, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_11,            { "GPIO 11", "asam-cmp.msg.digital.sample.pin_11", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x08, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_12,            { "GPIO 12", "asam-cmp.msg.digital.sample.pin_12", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x10, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_13,            { "GPIO 13", "asam-cmp.msg.digital.sample.pin_13", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x20, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_14,            { "GPIO 14", "asam-cmp.msg.digital.sample.pin_14", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x40, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_15,            { "GPIO 15", "asam-cmp.msg.digital.sample.pin_15", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x80, NULL, HFILL } },

        { &hf_cmp_digital_sample_pin_16,            { "GPIO 16", "asam-cmp.msg.digital.sample.pin_16", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x01, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_17,            { "GPIO 17", "asam-cmp.msg.digital.sample.pin_17", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x02, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_18,            { "GPIO 18", "asam-cmp.msg.digital.sample.pin_18", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x04, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_19,            { "GPIO 19", "asam-cmp.msg.digital.sample.pin_19", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x08, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_20,            { "GPIO 20", "asam-cmp.msg.digital.sample.pin_20", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x10, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_21,            { "GPIO 21", "asam-cmp.msg.digital.sample.pin_21", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x20, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_22,            { "GPIO 22", "asam-cmp.msg.digital.sample.pin_22", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x40, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_23,            { "GPIO 23", "asam-cmp.msg.digital.sample.pin_23", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x80, NULL, HFILL } },

        { &hf_cmp_digital_sample_pin_24,            { "GPIO 24", "asam-cmp.msg.digital.sample.pin_24", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x01, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_25,            { "GPIO 25", "asam-cmp.msg.digital.sample.pin_25", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x02, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_26,            { "GPIO 26", "asam-cmp.msg.digital.sample.pin_26", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x04, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_27,            { "GPIO 27", "asam-cmp.msg.digital.sample.pin_27", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x08, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_28,            { "GPIO 28", "asam-cmp.msg.digital.sample.pin_28", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x10, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_29,            { "GPIO 29", "asam-cmp.msg.digital.sample.pin_29", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x20, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_30,            { "GPIO 30", "asam-cmp.msg.digital.sample.pin_30", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x40, NULL, HFILL } },
        { &hf_cmp_digital_sample_pin_31,            { "GPIO 31", "asam-cmp.msg.digital.sample.pin_31", FT_BOOLEAN, 8, TFS(&tfs_high_low), 0x80, NULL, HFILL } },

        /* UART/RS-232 */
        { &hf_cmp_uart_flags,                       { "Flags", "asam-cmp.msg.uart.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_uart_flag_cl,                     { "CL", "asam-cmp.msg.uart.flags.cl",  FT_UINT16, BASE_HEX, VALS(uart_cl_names), 0x0007, NULL, HFILL } },
        { &hf_cmp_uart_flag_reserved,               { "Reserved", "asam-cmp.msg.uart.flags.reserved", FT_UINT16, BASE_HEX, NULL, 0xFFF8, NULL, HFILL } },

        { &hf_cmp_uart_reserved,                    { "Reserved", "asam-cmp.msg.uart.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_uart_data_len,                    { "Data entry count", "asam-cmp.msg.uart.data_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_uart_data,                        { "Data", "asam-cmp.msg.uart.data", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_uart_data_data,                   { "Data", "asam-cmp.msg.uart.data.data", FT_UINT16, BASE_HEX, NULL, CMP_UART_DATA_DATA_MASK, NULL, HFILL }},
        { &hf_cmp_uart_data_reserved,               { "Reserved", "asam-cmp.msg.uart.data.reserved", FT_UINT16, BASE_HEX, NULL, 0x1E00, NULL, HFILL }},
        { &hf_cmp_uart_data_framing_err,            { "Framing Error", "asam-cmp.msg.uart.flags.framing_err", FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL }},
        { &hf_cmp_uart_data_break_condition,        { "Break Condition", "asam-cmp.msg.uart.flags.break_condition", FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL }},
        { &hf_cmp_uart_data_parity_err,             { "Parity Error", "asam-cmp.msg.uart.data.parity_err", FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL }},

        /* Analog */
        { &hf_cmp_analog_flags,                     { "Flags", "asam-cmp.msg.analog.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_analog_flag_sample_dt,            { "Sample Datatype", "asam-cmp.msg.analog.flags.sample_dt", FT_UINT16, BASE_HEX, VALS(analog_sample_dt), 0x0003, NULL, HFILL } },
        { &hf_cmp_analog_flag_reserved,             { "Reserved", "asam-cmp.msg.analog.flags.reserved", FT_UINT16, BASE_HEX, NULL, 0xfffc, NULL, HFILL } },

        { &hf_cmp_analog_reserved,                  { "Reserved", "asam-cmp.msg.analog.reserved",  FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_analog_unit,                      { "Unit", "asam-cmp.msg.analog.unit", FT_UINT8, BASE_HEX, VALS(analog_units), 0x0, NULL, HFILL } },
        { &hf_cmp_analog_sample_interval,           { "Sample Interval", "asam-cmp.msg.analog.sample_interval", FT_FLOAT, BASE_NONE|BASE_UNIT_STRING, UNS(&units_seconds), 0x0, NULL, HFILL } },
        { &hf_cmp_analog_sample_offset,             { "Sample Offset", "asam-cmp.msg.analog.sample_offset", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_analog_sample_scalar,             { "Sample Scalar", "asam-cmp.msg.analog.sample_scalar", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_analog_sample,                    { "Sample", "asam-cmp.msg.analog.sample", FT_DOUBLE, BASE_EXP, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_analog_sample_raw,                { "Sample Raw", "asam-cmp.msg.analog.sample_raw", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* Ethernet */
        { &hf_cmp_eth_flags,                        { "Flags", "asam-cmp.msg.eth.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_cmp_eth_flag_fcs_err,                 { "FCS Error", "asam-cmp.msg.eth.flags.crc_err", FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
        { &hf_cmp_eth_flag_short_err,               { "Short Frame Error", "asam-cmp.msg.eth.flags.short_err", FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
        { &hf_cmp_eth_flag_tx_down,                 { "TX Port Down", "asam-cmp.msg.eth.flags.tx_down", FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
        { &hf_cmp_eth_flag_collision,               { "Collision detected", "asam-cmp.msg.eth.flags.collision", FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },
        { &hf_cmp_eth_flag_long_err,                { "Long Frame Error", "asam-cmp.msg.eth.flags.long_err", FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },
        { &hf_cmp_eth_flag_phy_err,                 { "PHY Error", "asam-cmp.msg.eth.flags.phy_err", FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },
        { &hf_cmp_eth_flag_truncated,               { "Frame truncated", "asam-cmp.msg.eth.flags.truncated", FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },
        { &hf_cmp_eth_flag_fcs_supported,           { "FCS supported", "asam-cmp.msg.eth.flags.fcs_supported", FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },
        { &hf_cmp_eth_flag_reserved_cap,            { "Reserved", "asam-cmp.msg.eth.flags.reserved", FT_UINT16, BASE_HEX, NULL, 0xFF00, NULL, HFILL } },

        { &hf_cmp_eth_flag_reserved_tx,             { "Reserved", "asam-cmp.msg.eth.flags.reserved_tx", FT_UINT16, BASE_HEX, NULL, 0x00FF, NULL, HFILL } },
        { &hf_cmp_eth_flag_fcs_sending,             { "FCS sending", "asam-cmp.msg.eth.flags.fcs_sending", FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },
        { &hf_cmp_eth_flag_reserved_tx2,            { "Reserved", "asam-cmp.msg.eth.flags.reserved_tx2", FT_UINT16, BASE_HEX, NULL, 0xFE00, NULL, HFILL } },

        { &hf_cmp_eth_reserved,                     { "Reserved", "asam-cmp.msg.eth.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_eth_payload_length,               { "Data length", "asam-cmp.msg.eth.data_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* SPI */
        { &hf_cmp_spi_flags,                        { "Flags", "asam-cmp.msg.spi.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_spi_flag_reserved,                { "Reserved", "asam-cmp.msg.spi.flags.reserved", FT_UINT16, BASE_HEX, NULL, 0xFFFF, NULL, HFILL } },

        { &hf_cmp_spi_reserved,                     { "Reserved", "asam-cmp.msg.spi.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_spi_cipo_length,                  { "Controller In Peripheral Out Length", "asam-cmp.msg.spi.cipo_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_spi_cipo,                         { "Controller In Peripheral Out (CIPO)", "asam-cmp.msg.spi.cipo", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_spi_copi_length,                  { "Controller Out Peripheral In Length", "asam-cmp.msg.spi.copi_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_spi_copi,                         { "Controller Out Peripheral In (COPI)", "asam-cmp.msg.spi.copi", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        /* I2C */
        { &hf_cmp_i2c_flags,                        { "Flags", "asam-cmp.msg.i2c.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_i2c_flag_dir,                     { "Direction", "asam-cmp.msg.i2c.flags.dir", FT_BOOLEAN, 16, TFS(&i2c_read_write), 0x0001, NULL, HFILL} },
        { &hf_cmp_i2c_flag_addr_len,                { "Address Length", "asam-cmp.msg.i2c.flags.addr_len", FT_BOOLEAN, 16, TFS(&i2c_addr_length), 0x0002, NULL, HFILL } },
        { &hf_cmp_i2c_flag_addr_ack,                { "Address Ack", "asam-cmp.msg.i2c.flags.addr_ack", FT_BOOLEAN, 16, TFS(&i2c_nack_ack), 0x0004, NULL, HFILL } },
        { &hf_cmp_i2c_flag_addr_err,                { "Ack Error", "asam-cmp.msg.i2c.flags.ack_err", FT_BOOLEAN, 16, TFS(&cmp_err_noerr), 0x0008, NULL, HFILL } },
        { &hf_cmp_i2c_flag_stop_cond,               { "Stop Condition", "asam-cmp.msg.i2c.flags.stop_cond", FT_BOOLEAN, 16, TFS(&i2c_stop_repeated_start), 0x0010, NULL, HFILL } },
        { &hf_cmp_i2c_flag_start_cond,              { "Start Condition", "asam-cmp.msg.i2c.flags.start_cond", FT_BOOLEAN, 16, TFS(&i2c_repeated_start_start), 0x0020, NULL, HFILL } },
        { &hf_cmp_i2c_flag_reserved,                { "Reserved", "asam-cmp.msg.i2c.flags.reserved", FT_UINT16, BASE_HEX, NULL, 0xFFC0, NULL, HFILL } },

        { &hf_cmp_i2c_reserved,                     { "Reserved", "asam-cmp.msg.i2c.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_i2c_addr,                         { "Address", "asam-cmp.msg.i2c.addr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_i2c_data_entry_count,             { "Data Entry Count", "asam-cmp.msg.i2c.data_entry_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_i2c_data,                         { "Data Entry", "asam-cmp.msg.i2c.data_entry", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_i2c_data_byte,                    { "Data Byte", "asam-cmp.msg.i2c.data_entry.data", FT_UINT16, BASE_HEX, NULL, 0x00FF, NULL, HFILL } },
        { &hf_cmp_i2c_data_control_ack,             { "Ack", "asam-cmp.msg.i2c.data_entry.control.ack", FT_BOOLEAN, 16, TFS(&i2c_nack_ack), 0x0100, NULL, HFILL } },
        { &hf_cmp_i2c_data_control_res,             { "Reserved", "asam-cmp.msg.i2c.data_entry.control.reserved", FT_UINT16, BASE_HEX, NULL, 0xFE00, NULL, HFILL } },

        /* GigE Vision */
        { &hf_cmp_gige_flags,                       { "Flags", "asam-cmp.msg.gige.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_gige_flag_reserved,               { "Reserved", "asam-cmp.msg.gige.flags.reserved", FT_UINT16, BASE_HEX, NULL, 0xFFFF, NULL, HFILL } },

        { &hf_cmp_gige_reserved,                    { "Reserved", "asam-cmp.msg.gige.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_gige_payload_length,              { "Data length", "asam-cmp.msg.gige.data_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_gige_payload,                     { "Data", "asam-cmp.msg.gige.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        /* MIPI CSI-2 */
        { &hf_cmp_mipi_csi2_flags,                  { "Flags", "asam-cmp.msg.mipi_csi2.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_flag_crc_err,           { "CRC Error", "asam-cmp.msg.mipi_csi2.flags.crc_err", FT_BOOLEAN, 16, TFS(&cmp_err_noerr), 0x0001, NULL, HFILL} },
        { &hf_cmp_mipi_csi2_flag_ecc_err_c,         { "Correctable ECC Error", "asam-cmp.msg.mipi_csi2.flags.ecc_err_c", FT_BOOLEAN, 16, TFS(&cmp_err_noerr), 0x0002, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_flag_ecc_err_uc,        { "Uncorrectable ECC Error", "asam-cmp.msg.mipi_csi2.flags.ecc_err_uc", FT_BOOLEAN, 16, TFS(&cmp_err_noerr), 0x0004, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_flag_ecc_fmt,           { "ECC Format", "asam-cmp.msg.mipi_csi2.flags.ecc_fmt", FT_BOOLEAN, 16, TFS(&mipi_csi2_ecc_noecc), 0x0008, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_flag_frame_ctr_src,     { "Frame Counter Source", "asam-cmp.msg.mipi_csi2.flags.frame_counter_source", FT_BOOLEAN, 16, TFS(&mipi_csi2_cmcounter_csicounter), 0x0010, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_flag_line_ctr_src,      { "Line Counter Source", "asam-cmp.msg.mipi_csi2.flags.line_counter_source", FT_BOOLEAN, 16, TFS(&mipi_csi2_cmcounter_csicounter), 0x0020, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_flag_cs_support,        { "Checksum Support", "asam-cmp.msg.mipi_csi2.flags.checksum_support", FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0040, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_flag_reserved,          { "Reserved", "asam-cmp.msg.mipi_csi2.flags.reserved", FT_UINT16, BASE_HEX, NULL, 0xFF80, NULL, HFILL } },

        { &hf_cmp_mipi_csi2_flag_reserved_tx,       { "Reserved", "asam-cmp.msg.mipi_csi2.flags.reserved_tx", FT_UINT16, BASE_HEX, NULL, 0xFFFF, NULL, HFILL } },

        { &hf_cmp_mipi_csi2_reserved,               { "Reserved", "asam-cmp.msg.mipi_csi2.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_frame_counter,          { "Frame Counter", "asam-cmp.msg.mipi_csi2.frame_counter", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_line_counter,           { "Line Counter", "asam-cmp.msg.mipi_csi2.line_counter", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_dt,                     { "Data Type", "asam-cmp.msg.mipi_csi2.data_type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_dt_res,                 { "Reserved", "asam-cmp.msg.mipi_csi2.data_type.res", FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_dt_dt,                  { "Data Type", "asam-cmp.msg.mipi_csi2.data_type.data_type", FT_UINT8, BASE_HEX, VALS(mipi_csi2_data_type_names), MIPI_CSI2_DT_BITS, NULL, HFILL}},
        { &hf_cmp_mipi_csi2_vci,                    { "Virtual Channel Identifier", "asam-cmp.msg.mipi_csi2.vci", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_vci_res,                { "Reserved", "asam-cmp.msg.mipi_csi2.vci.res", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_vci_vcx,                { "Virtual Channel Exctension", "asam-cmp.msg.mipi_csi2.vci.vcx", FT_UINT8, BASE_HEX, NULL, 0x0C, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_vci_vci,                { "Virtual Channel Identifier", "asam-cmp.msg.mipi_csi2.vci.vci", FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_reserved2,              { "Reserved", "asam-cmp.msg.mipi_csi2.res2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_ecc,                    { "ECC", "asam-cmp.msg.mipi_csi2.ecc", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_ecc_res,                { "Reserved", "asam-cmp.msg.mipi_csi2.ecc.res", FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_ecc_ecc,                { "ECC", "asam-cmp.msg.mipi_csi2.ecc.ecc", FT_UINT8, BASE_HEX, NULL, 0x3F, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_cs,                     { "Checksum", "asam-cmp.msg.mipi_csi2.checksum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_wc,                     { "Word Count", "asam-cmp.msg.mipi_csi2.word_count", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_short_packet_data,      { "Short Packet Data Field", "asam-cmp.msg.mipi_csi2.short_packet_data_field", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_mipi_csi2_data,                   { "Data", "asam-cmp.msg.mipi_csi2.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        /* Ethernet Raw */
        { &hf_cmp_raw_eth_flags,                    { "Flags", "asam-cmp.msg.raw_eth.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_raw_eth_flag_reserved,            { "Reserved", "asam-cmp.msg.raw_eth.flags.reserved", FT_UINT16, BASE_HEX, NULL, 0xFFFF, NULL, HFILL } },

        { &hf_cmp_raw_eth_reserved,                 { "Reserved", "asam-cmp.msg.raw_eth.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_raw_eth_payload_length,           { "Data length", "asam-cmp.msg.raw_eth.data_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_raw_eth_preamble,                 { "Preamble", "asam-cmp.msg.raw_eth.preamble", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_raw_eth_sfd,                      { "SFD", "asam-cmp.msg.raw_eth.sfd", FT_UINT8, BASE_HEX, VALS(eth_raw_sfd), 0x0, NULL, HFILL } },
        { &hf_cmp_raw_eth_mpacket,                  { "mPacket", "asam-cmp.msg.raw_eth.mpacket", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        /* 10BASE-T1S Symbols */
        { &hf_cmp_10t1s_symb_flags,                 { "Flags", "asam-cmp.msg.10baset1s_symbols.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_10t1s_symb_flag_decode_err,       { "Decode Error", "asam-cmp.msg.10baset1s_symbols.flags.decode_error", FT_BOOLEAN, 16, TFS(&cmp_err_noerr), 0x0001, NULL, HFILL} },
        { &hf_cmp_10t1s_symb_flag_miss_beacon,      { "Missing Beacon Error", "asam-cmp.msg.10baset1s_symbols.flags.missing_beacon", FT_BOOLEAN, 16, TFS(&cmp_err_noerr), 0x0002, NULL, HFILL} },
        { &hf_cmp_10t1s_symb_flag_res,              { "Reserved", "asam-cmp.msg.10baset1s_symbols.flags.reserved", FT_BOOLEAN, 16, NULL, 0x7FFC, NULL, HFILL } },
        { &hf_cmp_10t1s_symb_flag_first_beacon,     { "First Beacon", "asam-cmp.msg.10baset1s_symbols.flags.first_beacon", FT_BOOLEAN, 16, TFS(&eth_10baset1s_firstbeacon_notfirstbeacon), 0x8000, NULL, HFILL} },

        { &hf_cmp_10t1s_symb_data_length,           { "Data length", "asam-cmp.msg.10baset1s_symbols.data_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_10t1s_symb_data,                  { "Data", "asam-cmp.msg.10baset1s_symbols.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_10t1s_symb_data_symbol,           { "Symbol", "asam-cmp.msg.10baset1s_symbols.data.symbol", FT_UINT8, BASE_HEX, VALS(eth_10baset1s_symbol_names), 0x0, NULL, HFILL}},

        /* A2B */
        { &hf_cmp_a2b_flags,                        { "Flags", "asam-cmp.msg.a2b.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_cmp_a2b_flag_fin,                     { "Switch Activation Finished", "asam-cmp.msg.a2b.flags.fin", FT_BOOLEAN, 16, TFS(&a2b_switch_closed_open), 00001, NULL, HFILL} },
        { &hf_cmp_a2b_flag_fault_err,               { "Cable Fault (FAULT)", "asam-cmp.msg.a2b.flags.fault_err", FT_BOOLEAN, 16, TFS(&a2b_cable_fault_no_fault), 0x0002, NULL, HFILL}},
        { &hf_cmp_a2b_flag_fault_code,              { "Cable Fault Code (FAULT_CODE)", "asam-cmp.msg.a2b.flags.fault_code", FT_UINT16, BASE_DEC, VALS(a2b_fault_code_names), 0x001c, NULL, HFILL}},
        { &hf_cmp_a2b_flag_fault_nloc,              { "Cable Fault Not Localized (FAULT_NLOC)", "asam-cmp.msg.a2b.flags.fault_nloc", FT_BOOLEAN, 16, TFS(&a2b_cable_fault_not_localized_localized), 0x0020, NULL, HFILL} },
        { &hf_cmp_a2b_flag_hdcnt_err,               { "Header Count Error (HDCNTERR)", "asam-cmp.msg.a2b.flags.hdcnt_err", FT_BOOLEAN, 16, TFS(&tfs_enabled_disabled), 0x0040, NULL, HFILL} },
        { &hf_cmp_a2b_flag_dd_err,                  { "Data Decoding Error (DDERR)", "asam-cmp.msg.a2b.flags.dd_err", FT_BOOLEAN, 16, TFS(&a2b_data_decode_error_no_error), 0x0080, NULL, HFILL} },
        { &hf_cmp_a2b_flag_crc_err,                 { "CRC Error (CRCERR)", "asam-cmp.msg.a2b.flags.crc_err", FT_BOOLEAN, 16, TFS(&a2b_crc_error_no_error), 0x0100, NULL, HFILL} },
        { &hf_cmp_a2b_flag_dp_err,                  { "Data Parity Error (DPERR)", "asam-cmp.msg.a2b.flags.dp_err", FT_BOOLEAN, 16, TFS(&a2b_data_parity_error_no_error), 0x0200, NULL, HFILL} },
        { &hf_cmp_a2b_flag_pwd_err,                 { "Downstream Power Switch Error (PWRERR)", "asam-cmp.msg.a2b.flags.pwr_err", FT_BOOLEAN, 16, TFS(&a2b_downstream_power_switch_error_no_error), 0x0400, NULL, HFILL} },
        { &hf_cmp_a2b_flag_becovf_err,              { "Bit Error Count Error (BECOVFERR)", "asam-cmp.msg.a2b.flags.becovf_err", FT_BOOLEAN, 16, TFS(&a2b_bit_error_count_error_no_error), 0x0800, NULL, HFILL} },
        { &hf_cmp_a2b_flag_srf_err,                 { "SRF Miss Error (SRFERR)", "asam-cmp.msg.a2b.flags.srf_err", FT_BOOLEAN, 16, TFS(&a2b_srf_miss_error_no_error), 0x1000, NULL, HFILL} },
        { &hf_cmp_a2b_flag_srfcrc_err,              { "SRF CRC Error (SRFCRCERR Subordinate Node Only)", "asam-cmp.msg.a2b.flags.srf_err", FT_BOOLEAN, 16, TFS(&a2b_srf_crc_error_no_error), 0x2000, NULL, HFILL} },
        { &hf_cmp_a2b_flag_icrc_err,                { "Interrupt Frame CRC Error (ICRCERR)", "asam-cmp.msg.a2b.flags.srf_err", FT_BOOLEAN, 16, TFS(&a2b_iocrc_error_no_error), 0x4000, NULL, HFILL} },
        { &hf_cmp_a2b_flag_i2c_err,                 { "I2C Transaction Error (I2CERR)", "asam-cmp.msg.a2b.flags.srf_err", FT_BOOLEAN, 16, TFS(&a2b_i2c_transaction_error_no_error), 0x8000, NULL, HFILL} },

        { &hf_cmp_a2b_reserved,                     { "Reserved", "asam-cmp.msg.a2b.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_a2b_upstream_set,                 { "Upstream Settings", "asam-cmp.msg.a2b.upstream_settings", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL} },
        { &hf_cmp_a2b_upstream_set_upfmt,           { "Upstream Format", "asam-cmp.msg.a2b.upstream_settings.upfmt", FT_BOOLEAN, 16, TFS(&a2b_fmt_alternate_normal), 0x0001, NULL, HFILL} },
        { &hf_cmp_a2b_upstream_set_ups,             { "Upstream Slots Enabled", "asam-cmp.msg.a2b.upstream_settings.ups", FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL} },
        { &hf_cmp_a2b_upstream_set_upsize,          { "Upstream Slot Size", "asam-cmp.msg.a2b.upstream_settings.upsize", FT_UINT16, BASE_HEX, VALS(a2b_slot_sizes), 0x001C, NULL, HFILL} },
        { &hf_cmp_a2b_upstream_set_upslots,         { "Number of Upstream Slots", "asam-cmp.msg.a2b.upstream_settings.upslots", FT_UINT16, BASE_DEC, NULL, 0x07E0, NULL, HFILL} },
        { &hf_cmp_a2b_upstream_set_upoffset,        { "Upstream Channel Offset", "asam-cmp.msg.a2b.upstream_settings.upoffset", FT_UINT16, BASE_DEC, NULL, 0xF800, NULL, HFILL} },

        { &hf_cmp_a2b_downstream_set,               { "Downstream Settings", "asam-cmp.msg.a2b.downstream_settings", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL} },
        { &hf_cmp_a2b_downstream_set_dnfmt,         { "Downstream Format", "asam-cmp.msg.a2b.downstream_settings.dnfmt", FT_BOOLEAN, 16, TFS(&a2b_fmt_alternate_normal), 0x0001, NULL, HFILL} },
        { &hf_cmp_a2b_downstream_set_dns,           { "Downstream Slots Enabled", "asam-cmp.msg.a2b.downstream_settings.dns", FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL} },
        { &hf_cmp_a2b_downstream_set_dnsize,        { "Downstream Slot Size", "asam-cmp.msg.a2b.downstream_settings.dnsize", FT_UINT16, BASE_HEX, VALS(a2b_slot_sizes), 0x001C, NULL, HFILL} },
        { &hf_cmp_a2b_downstream_set_dnslots,       { "Number of Downstream Slots", "asam-cmp.msg.a2b.downstream_settings.dnslots", FT_UINT16, BASE_DEC, NULL, 0x07E0, NULL, HFILL} },
        { &hf_cmp_a2b_downstream_set_dnoffset,      { "Downstream Channel Offset", "asam-cmp.msg.a2b.downstream_settings.dnoffset", FT_UINT16, BASE_DEC, NULL, 0xF800, NULL, HFILL} },

        { &hf_cmp_a2b_general_set,                  { "General Settings", "asam-cmp.msg.a2b.general_settings", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_mstr,             { "Main Node Enable", "asam-cmp.msg.a2b.general_settings.mstr", FT_BOOLEAN, 64, NULL, 0x0000000000000001, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_standby,          { "Standby Mode Enable", "asam-cmp.msg.a2b.general_settings.standby", FT_BOOLEAN, 64, NULL, 0x0000000000000002, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_endsniff,         { "Bus Monitor Node Data Output Enable", "asam-cmp.msg.a2b.general_settings.endsniff", FT_BOOLEAN, 64, NULL, 0x0000000000000004, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_discvd,           { "Node Discovered", "asam-cmp.msg.a2b.general_settings.discvd", FT_BOOLEAN, 64, NULL, 0x0000000000000008, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_tx2pintl,         { "TX 2 Pin Interleave", "asam-cmp.msg.a2b.general_settings.tx2pintl", FT_BOOLEAN, 64, NULL, 0x0000000000000010, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_rx2pintl,         { "RX 2 Pin Interleave", "asam-cmp.msg.a2b.general_settings.rx2pintl", FT_BOOLEAN, 64, NULL, 0x0000000000000020, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_tdmmode,          { "TDM Mode", "asam-cmp.msg.a2b.general_settings.tdmmode", FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(a2b_tdmmode_values), 0x00000000000001C0, NULL, HFILL}},
        { &hf_cmp_a2b_general_set_tdmss,            { "TDM Channel Size", "asam-cmp.msg.a2b.general_settings.tdmss", FT_BOOLEAN, 64, TFS(&a2b_tdmss_16_32), 0x0000000000000200, NULL, HFILL}},
        { &hf_cmp_a2b_general_set_bmmen,            { "Bus Monitor Mode Enable", "asam-cmp.msg.a2b.general_settings.bmmen", FT_BOOLEAN, 64, NULL, 0x0000000000000400, NULL, HFILL}},
        { &hf_cmp_a2b_general_set_bclkrate,         { "BCLK Frequency Select", "asam-cmp.msg.a2b.general_settings.bclkrate", FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(a2b_blckrate_values), 0x0000000000003800, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_i2srate,          { "I2S Rate Select", "asam-cmp.msg.a2b.general_settings.i2srate", FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(a2b_i2srate_values), 0x000000000001C000, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_txoffset,         { "TX Offset", "asam-cmp.msg.a2b.general_settings.txoffset", FT_UINT64, BASE_HEX, NULL, 0x00000000007E0000, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_rxoffset,         { "RX Offset", "asam-cmp.msg.a2b.general_settings.rxoffset", FT_UINT64, BASE_HEX, NULL, 0x000000001F800000, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_syncoffset,       { "SYNC Offset", "asam-cmp.msg.a2b.general_settings.syncoffset", FT_UINT64, BASE_HEX, NULL, 0x0000001FE0000000, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_rrdiv,            { "Reduced Rate Divide Select", "asam-cmp.msg.a2b.general_settings.rrdiv", FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(a2b_rrdiv_values), 0x000007E000000000, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_rrsoffset,        { "Reduced Rate SYNC Offset Select", "asam-cmp.msg.a2b.general_settings.rrsoffset", FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(a2b_rrsoffset_values), 0x0000180000000000, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_reserved,         { "Reserved", "asam-cmp.msg.a2b.general_settings.reserved", FT_UINT64, BASE_HEX, NULL, 0x7FFFE00000000000, NULL, HFILL} },
        { &hf_cmp_a2b_general_set_raw_cap,          { "Raw Capturing", "asam-cmp.msg.a2b.general_settings.raw_capturing", FT_BOOLEAN, 64, TFS(&a2b_raw_capturing), 0x8000000000000000, NULL, HFILL}},

        { &hf_cmp_a2b_data_length,                  { "Data Length", "asam-cmp.msg.a2b.data_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL} },
        { &hf_cmp_a2b_data,                         { "Data", "asam-cmp.msg.a2b.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL} },

        /* Link State */
        { &hf_cmp_link_state_flags,                 { "Flags", "asam-cmp.msg.link_state.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_link_state_flag_link_err,         { "Link Error", "asam-cmp.msg.link_state.flags.link_err", FT_BOOLEAN, 16, TFS(&cmp_err_noerr), 0x01, NULL, HFILL} },
        { &hf_cmp_link_state_flag_reserved,         { "Reserved", "asam-cmp.msg.link_state.flags.reserved", FT_BOOLEAN, 16, NULL, 0xFFFE, NULL, HFILL } },

        { &hf_cmp_link_state_flag_reserved_tx,      { "Reserved", "asam-cmp.msg.link_state.flags.reserved_tx", FT_BOOLEAN, 16, NULL, 0xFFFF, NULL, HFILL } },

        { &hf_cmp_link_state_interface_status,      { "Interface Status", "asam-cmp.msg.link_state.interface_status", FT_UINT8, BASE_HEX, VALS(link_state_names), 0x0, NULL, HFILL} },
        { &hf_cmp_link_state_reserved,              { "Reserved", "asam-cmp.msg.link_state.reserved", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        /* User-Defined */
        { &hf_cmp_vendor_def_vendor_id,             { "Vendor ID", "asam-cmp.msg.vendor_def.vendor_id", FT_UINT16, BASE_HEX, VALS(vendor_ids), 0x0, NULL, HFILL } },
        { &hf_cmp_vendor_def_vendor_payload_type,   { "Vendor Payload Type", "asam-cmp.msg.vendor_def.payload_type", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_vendor_def_vendor_payload_data,   { "Vendor Payload", "asam-cmp.msg.vendor_def.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        /* Control Message Payloads */
        /* Data Sink Ready */
        { &hf_cmp_ctrl_msg_device_id,               { "Device ID", "asam-cmp.msg.dsr.device_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

         /* User Event */
        { &hf_cmp_ctrl_msg_event_id,                { "Event ID", "asam-cmp.msg.ue.event_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

         /* Vendor specific */
        { &hf_cmp_ctrl_msg_vendor_id,               { "Vendor ID", "asam-cmp.msg.vs.vendor_id", FT_UINT16, BASE_HEX, VALS(vendor_ids), 0x0, NULL, HFILL } },
        { &hf_cmp_ctrl_msg_vendor_payload_type,     { "Payload Type", "asam-cmp.msg.vs.payload_type", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        /* Status Message Payloads */
        /* Capture Module Status Message */
        { &hf_cmp_status_msg_cm_uptime_ns,          { "Uptime (ns)", "asam-cmp.msg.cm.uptime_ns", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_msg_cm_uptime_s,           { "Uptime (s)", "asam-cmp.msg.cm.uptime_s", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_msg_gm_identity,           { "gPTP grandmasterIdentity", "asam-cmp.msg.cm.gm_identity", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_msg_gm_clock_quality,      { "gPTP grandmasterClockQuality", "asam-cmp.msg.cm.gm_clock_quality", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_msg_current_utc_offset,    { "gPTP currentUtcOffset", "asam-cmp.msg.cm.current_utc_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_msg_time_source,           { "gPTP timeSource", "asam-cmp.msg.cm.time_source", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_msg_domain_num,            { "gPTP domainNumber", "asam-cmp.msg.cm.domain_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_msg_res,                   { "Reserved", "asam-cmp.msg.cm.res", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_gptp_flags,                       { "gPTP Flags", "asam-cmp.msg.cm.gptp_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_cmp_gptp_flags_leap61,                { "Leap61", "asam-cmp.msg.cm.gptp_flags.leap61", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_cmp_gptp_flags_leap59,                { "Leap59", "asam-cmp.msg.cm.gptp_flags.leap59", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_cmp_gptp_flags_cur_utco_valid,        { "Current UTC Offset Valid", "asam-cmp.msg.cm.gptp_flags.current_utco_valid", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
        { &hf_cmp_gptp_flags_ptp_timescale,         { "PTP Timescale", "asam-cmp.msg.cm.gptp_flags.ptp_timescale", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL } },
        { &hf_cmp_gptp_flags_time_traceable,        { "Time Traceable", "asam-cmp.msg.cm.gptp_flags.time_traceable", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL } },
        { &hf_cmp_gptp_flags_freq_traceable,        { "Frequency Traceable", "asam-cmp.msg.cm.gptp_flags.freq_traceable", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL } },
        { &hf_cmp_gptp_flags_reserved,              { "Reserved", "asam-cmp.msg.cm.gptp_flags.res", FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL } },

        { &hf_cmp_status_dev_desc_length,           { "Length of Device Description", "asam-cmp.msg.cm.dev_desc_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_dev_desc,                  { "Device Description", "asam-cmp.msg.cm.dev_desc", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_sn_length,                 { "Length of Serial Number", "asam-cmp.msg.cm.sn_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_sn,                        { "Serial Number (SN)", "asam-cmp.msg.cm.sn", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_hw_ver_length,             { "Length of Hardware Version", "asam-cmp.msg.cm.hw_ver_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_hw_ver,                    { "HW version", "asam-cmp.msg.cm.hw_ver", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_sw_ver_length,             { "Length of Software Version", "asam-cmp.msg.cm.sw_ver_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_sw_ver,                    { "SW version", "asam-cmp.msg.cm.sw_ver", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_vendor_data_length,        { "Length of Vendor Data", "asam-cmp.msg.cm.vendor_data_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_status_vendor_data,               { "Vendor Data", "asam-cmp.msg.cm.vendor_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        /* Interface Status Message */
        { &hf_cmp_iface_interface,                  { "Interface", "asam-cmp.msg.iface", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_iface_iface_id,                   { "Interface ID", "asam-cmp.msg.iface.iface_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_iface_msg_total_rx,               { "Messages Total RX", "asam-cmp.msg.iface.msg_total_rx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_iface_msg_total_tx,               { "Messages Total TX", "asam-cmp.msg.iface.msg_total_tx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_iface_msg_dropped_rx,             { "Messages Dropped RX", "asam-cmp.msg.iface.msg_drop_rx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_iface_msg_dropped_tx,             { "Messages Dropped TX", "asam-cmp.msg.iface.msg_drop_tx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_iface_errs_total_rx,              { "Errors Total RX", "asam-cmp.msg.iface.errors_total_rx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_iface_errs_total_tx,              { "Errors Total TX", "asam-cmp.msg.iface.errors_total_tx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_iface_iface_type,                 { "Interface Type", "asam-cmp.msg.iface.interface_type", FT_UINT8, BASE_HEX, VALS(data_msg_type_names), 0x0, NULL, HFILL } },
        { &hf_cmp_iface_iface_status,               { "Interface Status", "asam-cmp.msg.iface.interface_status", FT_UINT8, BASE_HEX, VALS(interface_status_names), 0x0, NULL, HFILL } },
        { &hf_cmp_iface_stream_id_cnt,              { "Stream ID count", "asam-cmp.msg.iface.stream_id_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_iface_reserved,                   { "Reserved", "asam-cmp.msg.iface.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        /* TODO: Update to CMP 1.1!!! */
        { &hf_cmp_iface_feat,                       { "Feature Support Bitmask", "asam-cmp.msg.iface.feat_supp", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_cmp_iface_feat_can_crr_err,           { "CRC Error Supported", "asam-cmp.msg.iface.feat_supp.can.crc_err", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_cmp_iface_feat_can_ack_err,           { "Ack Error Supported", "asam-cmp.msg.iface.feat_supp.can.ack_err", FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
        { &hf_cmp_iface_feat_can_pas_ack,           { "Passive Ack Supported", "asam-cmp.msg.iface.feat_supp.can.pas_ack", FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL } },
        { &hf_cmp_iface_feat_can_act_ack,           { "Active Ack Supported", "asam-cmp.msg.iface.feat_supp.can.act_ack", FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL } },
        { &hf_cmp_iface_feat_can_ack_del_err,       { "Ack Del Error Supported", "asam-cmp.msg.iface.feat_supp.can.ack_del_err", FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL } },
        { &hf_cmp_iface_feat_can_form_err,          { "Form Error Supported", "asam-cmp.msg.iface.feat_supp.can.form_err", FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL } },
        { &hf_cmp_iface_feat_can_stuff_err,         { "Stuff Error Supported", "asam-cmp.msg.iface.feat_supp.can.stuff_err", FT_BOOLEAN, 32, NULL, 0x00000040, NULL, HFILL } },
        { &hf_cmp_iface_feat_can_crc_del_err,       { "CRC Del Error Supported", "asam-cmp.msg.iface.feat_supp.can.crc_del_err", FT_BOOLEAN, 32, NULL, 0x00000080, NULL, HFILL } },
        { &hf_cmp_iface_feat_can_eof_err,           { "EOF Error Supported", "asam-cmp.msg.iface.feat_supp.can.eof_err", FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL } },
        { &hf_cmp_iface_feat_can_bit_err,           { "Bit Error Supported", "asam-cmp.msg.iface.feat_supp.can.bit_err", FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL } },
        { &hf_cmp_iface_feat_can_r0,                { "R0 Supported", "asam-cmp.msg.iface.feat_supp.can.r0", FT_BOOLEAN, 32, NULL, 0x00000400, NULL, HFILL } },
        { &hf_cmp_iface_feat_can_srr_dom,           { "SRR Dom Supported", "asam-cmp.msg.iface.feat_supp.can.srr_dom", FT_BOOLEAN, 32, NULL, 0x00000800, NULL, HFILL } },
        { &hf_cmp_iface_feat_can_gen_err,           { "Generic Error Supported", "asam-cmp.msg.iface.feat_supp.can.gen_err", FT_BOOLEAN, 32, NULL, 0x00004000, NULL, HFILL } },

        { &hf_cmp_iface_feat_canfd_crr_err,         { "CRC Error Supported", "asam-cmp.msg.iface.feat_supp.canfd.crc_err", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_cmp_iface_feat_canfd_ack_err,         { "Ack Error Supported", "asam-cmp.msg.iface.feat_supp.canfd.ack_err", FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
        { &hf_cmp_iface_feat_canfd_pas_ack,         { "Passive Ack Supported", "asam-cmp.msg.iface.feat_supp.canfd.pas_ack", FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL } },
        { &hf_cmp_iface_feat_canfd_act_ack,         { "Active Ack Supported", "asam-cmp.msg.iface.feat_supp.canfd.act_ack", FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL } },
        { &hf_cmp_iface_feat_canfd_ack_del_err,     { "Ack Del Error Supported", "asam-cmp.msg.iface.feat_supp.canfd.ack_del_err", FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL } },
        { &hf_cmp_iface_feat_canfd_form_err,        { "Form Error Supported", "asam-cmp.msg.iface.feat_supp.canfd.form_err", FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL } },
        { &hf_cmp_iface_feat_canfd_stuff_err,       { "Stuff Error Supported", "asam-cmp.msg.iface.feat_supp.canfd.stuff_err", FT_BOOLEAN, 32, NULL, 0x00000040, NULL, HFILL } },
        { &hf_cmp_iface_feat_canfd_crc_del_err,     { "CRC Del Error Supported", "asam-cmp.msg.iface.feat_supp.canfd.crc_del_err", FT_BOOLEAN, 32, NULL, 0x00000080, NULL, HFILL } },
        { &hf_cmp_iface_feat_canfd_eof_err,         { "EOF Error Supported", "asam-cmp.msg.iface.feat_supp.canfd.eof_err", FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL } },
        { &hf_cmp_iface_feat_canfd_bit_err,         { "Bit Error Supported", "asam-cmp.msg.iface.feat_supp.canfd.bit_err", FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL } },
        { &hf_cmp_iface_feat_canfd_rsvd,            { "RRSV Supported", "asam-cmp.msg.iface.feat_supp.canfd.rsvd", FT_BOOLEAN, 32, NULL, 0x00000400, NULL, HFILL } },
        { &hf_cmp_iface_feat_canfd_srr_dom,         { "SRR Dom Supported", "asam-cmp.msg.iface.feat_supp.canfd.srr_dom", FT_BOOLEAN, 32, NULL, 0x00000800, NULL, HFILL } },
        { &hf_cmp_iface_feat_canfd_brs,             { "BRS Supported", "asam-cmp.msg.iface.feat_supp.canfd.brs", FT_BOOLEAN, 32, NULL, 0x00001000, NULL, HFILL } },
        { &hf_cmp_iface_feat_canfd_esi,             { "ESI Supported", "asam-cmp.msg.iface.feat_supp.canfd.esi", FT_BOOLEAN, 32, NULL, 0x00002000, NULL, HFILL } },
        { &hf_cmp_iface_feat_canfd_gen_err,         { "Generic Error Supported", "asam-cmp.msg.iface.feat_supp.canfd.gen_err", FT_BOOLEAN, 32, NULL, 0x00004000, NULL, HFILL } },

        { &hf_cmp_iface_feat_lin_checksum_err,      { "Checksum Error Supported", "asam-cmp.msg.iface.feat_supp.lin.checksum_err", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_cmp_iface_feat_lin_coll_err,          { "Collision Error Supported", "asam-cmp.msg.iface.feat_supp.lin.coll_err", FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
        { &hf_cmp_iface_feat_lin_parity_err,        { "Parity Error Supported", "asam-cmp.msg.iface.feat_supp.lin.parity_err", FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL } },
        { &hf_cmp_iface_feat_lin_no_slave_resp_err, { "No Slave Response Error Supported", "asam-cmp.msg.iface.feat_supp.lin.no_slave_resp_err", FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL } },
        { &hf_cmp_iface_feat_lin_sync_err,          { "Sync Error Supported", "asam-cmp.msg.iface.feat_supp.lin.sync_err", FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL } },
        { &hf_cmp_iface_feat_lin_framing_err,       { "Framing Error Supported", "asam-cmp.msg.iface.feat_supp.lin.framing_err", FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL } },
        { &hf_cmp_iface_feat_lin_short_dom_err,     { "Short Dom Error Supported", "asam-cmp.msg.iface.feat_supp.lin.short_dom_err", FT_BOOLEAN, 32, NULL, 0x00000040, NULL, HFILL } },
        { &hf_cmp_iface_feat_lin_long_dom_err,      { "Long Dom Error Supported", "asam-cmp.msg.iface.feat_supp.lin.long_dom_err", FT_BOOLEAN, 32, NULL, 0x00000080, NULL, HFILL } },
        { &hf_cmp_iface_feat_lin_wup,               { "WUP Supported", "asam-cmp.msg.iface.feat_supp.lin.wup", FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL } },

        { &hf_cmp_iface_feat_fr_crc_frame_err,      { "CRC Frame Error Supported", "asam-cmp.msg.iface.feat_supp.fr.crc_frame_err", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_cmp_iface_feat_fr_crc_header_err,     { "CRC Header Error Supported", "asam-cmp.msg.iface.feat_supp.fr.crc_header_err", FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
        { &hf_cmp_iface_feat_fr_nf,                 { "Null Frame Supported", "asam-cmp.msg.iface.feat_supp.fr.nf", FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL } },
        { &hf_cmp_iface_feat_fr_sf,                 { "Startup Frame Supported", "asam-cmp.msg.iface.feat_supp.fr.sf", FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL } },
        { &hf_cmp_iface_feat_fr_sync,               { "Sync Supported", "asam-cmp.msg.iface.feat_supp.fr.sync", FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL } },
        { &hf_cmp_iface_feat_fr_wus,                { "Wake Up Symbol Supported", "asam-cmp.msg.iface.feat_supp.fr.wus", FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL } },
        { &hf_cmp_iface_feat_fr_ppi,                { "Preamble Indicator Supported", "asam-cmp.msg.iface.feat_supp.fr.ppi", FT_BOOLEAN, 32, NULL, 0x00000040, NULL, HFILL } },
        { &hf_cmp_iface_feat_fr_cas,                { "Collision Avoidance Symbol Supported", "asam-cmp.msg.iface.feat_supp.fr.cas", FT_BOOLEAN, 32, NULL, 0x00000080, NULL, HFILL } },
        { &hf_cmp_iface_feat_fr_channel,            { "Channel Supported", "asam-cmp.msg.iface.feat_supp.fr.channel", FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL } },

        { &hf_cmp_iface_feat_eth_fcs_err,           { "FCS Error Supported", "asam-cmp.msg.iface.feat_supp.eth.fcs_err", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_cmp_iface_feat_eth_too_short,         { "Frame too short Supported", "asam-cmp.msg.iface.feat_supp.eth.frame_too_short", FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
        { &hf_cmp_iface_feat_eth_tx_port_down,      { "TX Port Down Supported", "asam-cmp.msg.iface.feat_supp.eth.tx_port_down", FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL } },
        { &hf_cmp_iface_feat_eth_collision,         { "Collision Supported", "asam-cmp.msg.iface.feat_supp.eth.collision", FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL } },
        { &hf_cmp_iface_feat_eth_too_long,          { "Frame too long Supported", "asam-cmp.msg.iface.feat_supp.eth.frame_too_long", FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL } },
        { &hf_cmp_iface_feat_eth_phy_err,           { "PHY Error Supported", "asam-cmp.msg.iface.feat_supp.eth.phy_err", FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL } },
        { &hf_cmp_iface_feat_eth_trunc,             { "Truncated Frames Supported", "asam-cmp.msg.iface.feat_supp.eth.truncated_frames", FT_BOOLEAN, 32, NULL, 0x00000040, NULL, HFILL } },
        { &hf_cmp_iface_feat_eth_fcs,               { "FCS Supported", "asam-cmp.msg.iface.feat_supp.eth.fcs", FT_BOOLEAN, 32, NULL, 0x00000080, NULL, HFILL } },

        { &hf_cmp_iface_feat_10t1s_sym_decode,      { "Decode Error Supported", "asam-cmp.msg.iface.feat_supp.10baset1s_symbols.decode_err", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_cmp_iface_feat_10t1s_mis_beacon,      { "Missing Beacon Error Supported", "asam-cmp.msg.iface.feat_supp.10baset1s_symbols.missing_beacon_err", FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
        { &hf_cmp_iface_feat_10t1s_first_beacon,    { "First Beacon Supported", "asam-cmp.msg.iface.feat_supp.10baset1s_symbols.first_beacon", FT_BOOLEAN, 32, NULL, 0x80000000, NULL, HFILL } },

        { &hf_cmp_iface_feat_link_err,              { "Link Error Supported", "asam-cmp.msg.iface.feat_supp.link_state.link_err", FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },

        { &hf_cmp_iface_stream_ids,                 { "Stream IDs", "asam-cmp.msg.iface.stream_ids", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_iface_stream_id,                  { "Stream ID", "asam-cmp.msg.iface.stream_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_iface_vendor_data_len,            { "Vendor Data Length", "asam-cmp.msg.iface.vendor_data_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_iface_vendor_data,                { "Vendor Data", "asam-cmp.msg.iface.vendor_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        /* Configuration Status Message */
        { &hf_cmp_status_msg_config,                { "Data", "asam-cmp.msg.config.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        /* Data Lost Event Status Message */
        { &hf_cmp_dataloss_data_sink_port,          { "Data Sink Port", "asam-cmp.msg.dataloss.data_sink_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_dataloss_device_id,               { "Device ID", "asam-cmp.msg.dataloss.device_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_dataloss_reserved,                { "Reserved", "asam-cmp.msg.dataloss.res", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_dataloss_stream_id,               { "Stream ID", "asam-cmp.msg.dataloss.stream_id", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_dataloss_last_ssq_value,          { "Last Stream Sequence Counter Value", "asam-cmp.msg.dataloss.last_ssqc", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_dataloss_current_ssq_value,       { "Current Stream Sequence Counter Value", "asam-cmp.msg.dataloss.current_ssqc", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        /* Time Sync Lost Event Status Message */
        { &hf_cmp_timeloss_port_nr,                 { "Port Number", "asam-cmp.msg.timesyncloss.port_nr", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_timeloss_device_id,               { "Device ID", "asam-cmp.msg.timesyncloss.device_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_cmp_timeloss_error_flags,             { "Time Sync Loss Error Flags", "asam-cmp.msg.timesyncloss.err_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_cmp_timeloss_error_flags_ts,          { "Was Time Synced before", "asam-cmp.msg.timesyncloss.err_flags.ts", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_cmp_timeloss_error_flags_insync,      { "Original CMP Message had at least one INSYNC=0", "asam-cmp.msg.timesyncloss.err_flags.insync", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_cmp_timeloss_error_flags_delta,       { "Configured Time Delta was exceeded", "asam-cmp.msg.timesyncloss.err_flags.delta", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
        { &hf_cmp_timeloss_error_flags_reserved,    { "Reserved", "asam-cmp.msg.timesyncloss.err_flags.res", FT_UINT8, BASE_HEX, NULL, 0xF8, NULL, HFILL } },

        /* Vendor Specific Status Message */
        { &hf_cmp_status_msg_vendor_specific,       { "Vendor Specific", "asam-cmp.msg.vendor_specific", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    static int *ett[] = {
        &ett_asam_cmp,
        &ett_asam_cmp_header,
        &ett_asam_cmp_timestamp,
        &ett_asam_cmp_common_flags,
        &ett_asam_cmp_trans_opts,
        &ett_asam_cmp_payload,
        &ett_asam_cmp_payload_flags,
        &ett_asam_cmp_payload_data,
        &ett_asam_cmp_lin_pid,
        &ett_asam_cmp_can_id,
        &ett_asam_cmp_can_crc,
        &ett_asam_cmp_digital_sample,
        &ett_asam_cmp_uart_data,
        &ett_asam_cmp_analog_sample,
        &ett_asam_cmp_i2c_data_entry,
        &ett_asam_cmp_a2b_upstream_settings,
        &ett_asam_cmp_a2b_downstream_settings,
        &ett_asam_cmp_a2b_general_settings,
        &ett_asam_cmp_status_cm_flags,
        &ett_asam_cmp_status_cm_uptime,
        &ett_asam_cmp_status_timeloss_flags,
        &ett_asam_cmp_status_interface,
        &ett_asam_cmp_status_feature_support,
        &ett_asam_cmp_status_stream_ids
    };

    static ei_register_info ei[] = {
        { &ei_asam_cmp_length_mismatch, {"asam-cmp.expert.length_mismatch", PI_MALFORMED, PI_WARN, "Malformed message, length mismatch!", EXPFILL } },
        { &ei_asam_cmp_unsupported_crc_not_zero, {"asam-cmp.export.deactivated_crc_not_zero", PI_MALFORMED, PI_WARN, "Unsupported CRC is not zero!", EXPFILL } },
    };

    /* UATs for user_data fields */
    static uat_field_t asam_cmp_device_id_uat_fields[] = {
        UAT_FLD_HEX(asam_cmp_devices, id, "Device ID", "Device ID (hex uint16 without leading 0x)"),
        UAT_FLD_CSTRING(asam_cmp_devices, name, "Device Name", "Device Name (string)"),
        UAT_END_FIELDS
    };

    static uat_field_t asam_cmp_interface_id_uat_fields[] = {
        UAT_FLD_HEX(asam_cmp_interfaces, id, "Interface ID", "Interface ID (hex uint32 without leading 0x)"),
        UAT_FLD_CSTRING(asam_cmp_interfaces, name, "Interface Name", "Interface Name (string)"),
        UAT_FLD_HEX(asam_cmp_interfaces, bus_id, "Bus ID", "Bus ID of the Interface (hex uint16 without leading 0x)"),
        UAT_END_FIELDS
    };

    proto_asam_cmp = proto_register_protocol("ASAM Capture Module Protocol", "ASAM CMP", "asam-cmp");
    proto_register_field_array(proto_asam_cmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    asam_cmp_module = prefs_register_protocol(proto_asam_cmp, NULL);

    expert_module_asam_cmp = expert_register_protocol(proto_asam_cmp);
    expert_register_field_array(expert_module_asam_cmp, ei, array_length(ei));

    /* Configuration Items */
    asam_cmp_deviceid_uat = uat_new("ASAM CMP Devices",
        sizeof(generic_one_id_string_t),        /* record size           */
        DATAFILE_ASAM_CMP_DEVICES_IDS,          /* filename              */
        true,                                   /* from profile          */
        (void**)&asam_cmp_devices,              /* data_ptr              */
        &asam_cmp_devices_num,                  /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                 /* but not fields        */
        NULL,                                   /* help                  */
        copy_generic_one_id_string_cb,          /* copy callback         */
        update_generic_one_identifier_16bit,    /* update callback       */
        free_generic_one_id_string_cb,          /* free callback         */
        post_update_asam_cmp_devices_cb,        /* post update callback  */
        reset_asam_cmp_devices_cb,              /* reset callback        */
        asam_cmp_device_id_uat_fields           /* UAT field definitions */
    );

    prefs_register_uat_preference(asam_cmp_module, "_udf_asam_cmp_devices", "Devices",
        "A table to define names of Devices.", asam_cmp_deviceid_uat);

    asam_cmp_interfaceid_uat = uat_new("ASAM CMP Interfaces",
        sizeof(interface_config_t),             /* record size           */
        DATAFILE_ASAM_CMP_IFACE_IDS,            /* filename              */
        true,                                   /* from profile          */
        (void**)&asam_cmp_interfaces,           /* data_ptr              */
        &asam_cmp_interface_num,                /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                 /* but not fields        */
        NULL,                                   /* help                  */
        copy_interface_config_cb,               /* copy callback         */
        update_interface_config,                /* update callback       */
        free_interface_config_cb,               /* free callback         */
        post_update_interface_config_cb,        /* post update callback  */
        reset_interface_config_cb,              /* reset callback        */
        asam_cmp_interface_id_uat_fields        /* UAT field definitions */
    );

    prefs_register_uat_preference(asam_cmp_module, "_udf_asam_cmp_interfaces", "Interfaces",
        "A table to define names and mappings of Interfaces.", asam_cmp_interfaceid_uat);

    prefs_register_bool_preference(asam_cmp_module, "try_heuristic_first",
        "Try heuristic sub-dissectors first",
        "Try to decode a packet using an heuristic sub-dissector"
        " before using a sub-dissector registered to \"decode as\"",
        &heuristic_first);

    prefs_register_bool_preference(asam_cmp_module, "use_old_canid_11bit_format",
        "Use old encoding of 11bit CAN/CAN-FD IDs",
        "Use the old encoding of 11bit CAN/CAN-FD IDs",
        &old_11bit_canid_encoding);
}

void
proto_reg_handoff_asam_cmp(void) {
    dissector_handle_t asam_cmp_handle;

    asam_cmp_handle = register_dissector("asam-cmp", dissect_asam_cmp, proto_asam_cmp);
    eth_handle = find_dissector("eth_maybefcs");

    dissector_add_for_decode_as("ethertype", asam_cmp_handle);
    dissector_add_for_decode_as_with_preference("udp.port", asam_cmp_handle);
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
