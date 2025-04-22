/* packet-ebhscr.c
 * Routines for EBHSCR dissection
 * Copyright 2019, Ana Pantar <ana.pantar@gmail.com> for Elektrobit
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * For more information on this protocol see:
 * https://www.elektrobit.com/ebhscr
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/decode_as.h>
#include <epan/prefs.h>
#include <wiretap/wtap.h>
#include <epan/expert.h>
#include <epan/tfs.h>

/* Custom EBHSCR packet types */
#define EBHSCR_USER_FIRST 0x43
#define EBHSCR_USER_LAST 0x4F

/* EBHSCR packet types */
#define ETHERNET_FRAME 0x50
#define NMEA_FRAME 0x51
#define TIME_STATE_FRAME 0x52
#define CAN_FRAME 0x53
#define LIN_FRAME 0x55
#define DIO_FRAME 0x56
#define FLEXRAY_FRAME 0x57
#define MIPI_CSI2 0x59
#define DSI3_FRAME 0x5C
#define CSI2_FRAME 0x5E

/* Protocol specific definitions */
#define FLEXRAY_FRAME_PACKET 0x00
#define FLEXRAY_SYMBOL_PACKET 0x01
#define FLEXRAY_SLOT_STATUS_PACKET 0x02
#define FLEXRAY_START_OF_CYCLE_PACKET 0x03
#define FLEXRAY_CHANNEL_B_MASK 0x02
#define FLEXRAY_TSSVIOL_MASK 0x0020
#define FLEXRAY_CODERR_MASK 0x0010
#define FLEXRAY_FESERR_MASK 0x0100
#define FLEXRAY_HCRCERR_MASK 0x0040
#define FLEXRAY_FCRCERR_MASK 0x0080
#define MIPI_CSI2_PKT_HDR_LEN 8U
#define CSI2_FRAME_NUM_SECTIONS 8U
#define CSI2_FRAME_SECTION_SIZE_BYTES 16U
#define CSI2_FRAME_PKT_HDR_LEN 128U
#define DSI3_CHANNEL_SLAVE 0x00
#define DSI3_CHANNEL_MASTER 0x01
#define EBHSCR_HEADER_LENGTH 32U

void proto_reg_handoff_ebhscr(void);
void proto_register_ebhscr(void);

static int proto_ebhscr;

static int hf_ebhscr_packet_header;
static int hf_ebhscr_major_number;
static int hf_ebhscr_slot;
static int hf_ebhscr_channel;
static int hf_ebhscr_status;
static int hf_ebhscr_status_unused;

static int hf_can_proto_type;
static int hf_can_status_available;
static int hf_can_status_overflow;
static int hf_can_LEC;
static int hf_can_ERRP;
static int hf_can_ERRW;
static int hf_can_BOFF;
static int hf_can_DLEC;
static int hf_can_TEC;
static int hf_can_REC;
static int hf_can_CEL;
static int hf_can_reserved_bytes;

static int hf_eth_reserved_bytes;
static int hf_eth_tx_trunc;
static int hf_eth_trans_undrun;
static int hf_eth_retrans_limit;
static int hf_eth_late_collision;
static int hf_eth_link_up_down;
static int hf_eth_master_slave;
static int hf_eth_fcs_unavailable;
static int hf_eth_rsvd_bit;
static int hf_eth_speed;

static int hf_eth_crc_error;
static int hf_eth_mii_foe;
static int hf_eth_payload_foe;
static int hf_eth_hdr_foe;
static int hf_eth_rcv_dec_err;
static int hf_eth_sym_error;
static int hf_eth_jabber_event;
static int hf_eth_pol_ch_event;
static int hf_eth_fls_carrier_event;
static int hf_eth_rx_trunc;
static int hf_eth_transmission_disc_err;
static int hf_eth_wait_frame_sep_bit;

static int hf_ts_time_offset_valid;
static int hf_ts_last_offset_change_valid;
static int hf_ts_nano_seconds_last_jump_valid;
static int hf_ts_UTC_leap_seconds_valid;
static int hf_ts_sync_state_valid;
static int hf_ts_time_source;

static int hf_ts_time_offset_ns;
static int hf_ts_last_offset_ns;
static int hf_ts_last_jump_ns;
static int hf_ts_utc_leap_sec;
static int hf_ts_sync_state;

static int hf_lin_1_3_classic_chksum;
static int hf_lin_1_2_enhanced_chksum;
static int hf_lin_wakeup;
static int hf_lin_time_jump;

static int hf_lin_reserved_bytes;
static int hf_lin_wakeup_length;
static int hf_lin_sts_reserved;
static int hf_lin_sts_syn;
static int hf_lin_sts_par;
static int hf_lin_sts_res;
static int hf_lin_sts_dat;
static int hf_lin_sts_chk;
static int hf_lin_sts_sta;
static int hf_lin_sts_sto;
static int hf_lin_sts_emp;
static int hf_lin_payload;
static int hf_lin_payload_pid;
static int hf_lin_payload_id_parity_0;
static int hf_lin_payload_id_parity_1;
static int hf_lin_payload_id;
static int hf_lin_payload_data;
static int hf_lin_payload_checksum;

static int hf_dio_overflow_mon_unit;
static int hf_dio_jump_occurred;
static int hf_dio_value_type;
static int hf_dio_channel_ref;
static int hf_dio_gpio_id;
static int hf_dio_reserved_bytes;

static int hf_flexray_ch_a;
static int hf_flexray_ch_b;
static int hf_flexray_ctrl_id;
static int hf_flexray_monitoring_bit;
static int hf_flexray_sync_bit;
static int hf_flexray_packet_type;
static int hf_flexray_CODERR;
static int hf_flexray_TSSVIOL;
static int hf_flexray_HCRCERR;
static int hf_flexray_FCRCERR;
static int hf_flexray_FESERR;
static int hf_flexray_FSSERR;
static int hf_flexray_BSSERR;
static int hf_flexray_jump_occurred;
static int hf_flexray_overflow_err;
static int hf_flexray_slot_information;
static int hf_flexray_SBV;
static int hf_flexray_ACI;
static int hf_flexray_CED;
static int hf_flexray_SED;
static int hf_flexray_VFR;
static int hf_flexray_SID;
static int hf_flexray_frame_status;
static int hf_flexray_SPLERR;
static int hf_flexray_CCERR;
static int hf_flexray_FIDERR;
static int hf_flexray_SSERR;
static int hf_flexray_NERR;
static int hf_flexray_SOVERR;
static int hf_flexray_SWVIOL;
static int hf_flexray_NITVIOL;
static int hf_flexray_BVIOL;
static int hf_flexray_PCD;
static int hf_flexray_SYNCERR;
static int hf_flexray_CP;
static int hf_flexray_BRC;
static int hf_flexray_symbol_length_and_status;
static int hf_flexray_SYERR;
static int hf_flexray_SL;
static int hf_flexray_POC_state;
static int hf_flexray_following_cycle_counter;
static int hf_flexray_supercycle_counter;

static int hf_dsi3_status_crc_error;
static int hf_dsi3_status_transition_error;
static int hf_dsi3_status_packet_truncated_error;
static int hf_dsi3_status_packet_dropped_error;
static int hf_dsi3_mjr_hdr_st0_command_type;
static int hf_dsi3_mjr_hdr_slave_st0_bit_count;
static int hf_dsi3_mjr_hdr_slave_st2_blnk_err;
static int hf_dsi3_mjr_hdr_slave_st2_no_trans_err;
static int hf_dsi3_mjr_hdr_slave_st3_crc_err;
static int hf_dsi3_mjr_hdr_slave_st3_cnt_overflow;
static int hf_dsi3_mjr_hdr_slave_st3_disabled_err;
static int hf_dsi3_mjr_hdr_slave_st3_trunc_data;
static int hf_dsi3_mjr_hdr_slave_st3_drop_data;
static int hf_dsi3_mjr_hdr_master_st0_nibble_count;
static int hf_dsi3_mjr_hdr_master_st2_blnk_err;
static int hf_dsi3_mjr_hdr_master_st2_bad_trans_err;
static int hf_dsi3_mjr_hdr_master_st2_bad_chip_err;
static int hf_dsi3_mjr_hdr_master_st2_no_trans_err;
static int hf_dsi3_mjr_hdr_master_st3_crc_err;
static int hf_dsi3_mjr_hdr_master_st3_bad_decode_err;
static int hf_dsi3_mjr_hdr_master_st3_cnt_overflow;
static int hf_dsi3_mjr_hdr_master_st3_disable_err;
static int hf_dsi3_mjr_hdr_master_st3_trunc_data;
static int hf_dsi3_mjr_hdr_master_st3_drop_data;

static int hf_mipi_csi2_status_packet_checksum_err;
static int hf_mipi_csi2_status_ecc_err;
static int hf_mipi_csi2_status_payload_fifo_overflow;
static int hf_mipi_csi2_status_header_fifo_overflow;
static int hf_mipi_csi2_status_rcv_decoder_err;
static int hf_mipi_csi2_status_payload_trunc_err;
static int hf_mipi_csi2_status_trans_rejected;

static int hf_mipi_csi2_mjr_hdr_flags_packet_checksum_err;
static int hf_mipi_csi2_mjr_hdr_flags_correctable_ecc_err;
static int hf_mipi_csi2_mjr_hdr_flags_uncorrectable_ecc_err;
static int hf_mipi_csi2_mjr_hdr_flags_mipi_phy_type;
static int hf_mipi_csi2_mjr_hdr_flags_first_line_of_frame;
static int hf_mipi_csi2_mjr_hdr_frame_counter;
static int hf_mipi_csi2_mjr_hdr_line_counter;

static int hf_mipi_csi2_payload_pkt_hdr;
static int hf_mipi_csi2_payload_pkt_hdr_dt;
static int hf_mipi_csi2_payload_pkt_hdr_vc;
static int hf_mipi_csi2_payload_pkt_hdr_ecc;
static int hf_mipi_csi2_payload_pkt_hdr_crc;
static int hf_mipi_csi2_payload_pkt_hdr_wc_lsb;
static int hf_mipi_csi2_payload_pkt_hdr_wc_msb;

static int hf_csi2_frame_status_packet_checksum_err;
static int hf_csi2_frame_status_ecc_err;
static int hf_csi2_frame_status_rcv_decoder_err;
static int hf_csi2_frame_status_section_err;
static int hf_csi2_frame_status_fifo_overflow;
static int hf_csi2_frame_status_payload_trunc_err;
static int hf_csi2_frame_status_trans_rejected;

static int hf_csi2_frame_mjr_hdr_flags_proc;
static int hf_csi2_frame_mjr_hdr_flags_pad_align;
static int hf_csi2_frame_mjr_hdr_flags_mipi_phy_type;
static int hf_csi2_frame_mjr_hdr_vc;
static int hf_csi2_frame_mjr_hdr_imhv;

static int hf_csi2_frame_header;
static int hf_csi2_frame_header_payload_byte_offset;
static int hf_csi2_frame_header_bytes_total;
static int hf_csi2_frame_header_bytes_per_line;
static int hf_csi2_frame_header_number_lines;
static int hf_csi2_frame_header_error_bits_field;
static int hf_csi2_frame_header_mipi_data_type;
static int hf_csi2_frame_sections[CSI2_FRAME_NUM_SECTIONS];

static int hf_csi2_frame_header_error_bits_packet_checksum_err;
static int hf_csi2_frame_header_error_bits_correctable_ecc_err;
static int hf_csi2_frame_header_error_bits_uncorrectable_ecc_err;
static int hf_csi2_frame_header_error_bits_rcv_dec_err;

static int hf_ebhscr_version;
static int hf_ebhscr_length;
static int hf_ebhscr_start_timestamp;
static int hf_ebhscr_stop_timestamp;
static int hf_ebhscr_mjr_hdr;
static int hf_ebhscr_mjr_hdr_unused;

static int ett_ebhscr;
static int ett_ebhscr_channel;
static int ett_ebhscr_packet_header;
static int ett_ebhscr_status;
static int ett_ebhscr_mjr_hdr;

static int ett_lin_payload;

static int * const can_status_bits[] = {
	&hf_can_proto_type,
	&hf_can_status_available,
	&hf_can_status_overflow,
	NULL
};

static int * const can_mjr_hdr_bits[] = {
	& hf_can_reserved_bytes,
	& hf_can_LEC,
	& hf_can_ERRP,
	& hf_can_ERRW,
	& hf_can_BOFF,
	& hf_can_DLEC,
	& hf_can_TEC,
	& hf_can_REC,
	& hf_can_CEL,
	NULL
};

static const value_string can_proto_type_strings[] = {
	{ 0,	"Classical CAN" },
	{ 1,	"CAN FD data frame" },
	{ 0, NULL },
};

static const value_string can_status_available_strings[] = {
	{ 0,	"CAN protocol status not available" },
	{ 1,	"CAN protocol status available" },
	{ 0, NULL },
};

static const value_string can_status_overflow_strings[] = {
	{ 0,	"No FIFO overflow detected" },
	{ 1,	"FIFO overflow detected, data were lost" },
	{ 0, NULL },
};

static const val64_string can_last_err_code_strings[] = {
	{ 0,	"No Error" },
	{ 1,	"Stuff Error" },
	{ 2,	"Form Error" },
	{ 3,	"Ack Error" },
	{ 4,	"Bit1 Error" },
	{ 5,	"Bit0 Error" },
	{ 6,	"CRC Error" },
	{ 7,	"No Change" },
	{ 0, NULL },
};

static const val64_string can_ERRP_strings[] = {
	{ 0,	"Error counters are below the error passive limit (128)" },
	{ 1,	"One of the error counters has reached the error passive limit (128)" },
	{ 0, NULL },
};

static const val64_string can_ERRW_strings[] = {
	{ 0,	"Error counters are below the error warning limit (96)" },
	{ 1,	"One of the error counters has reached the error warning limit (96)" },
	{ 0, NULL },
};
static const val64_string can_BOFF_strings[] = {
	{ 0,	"Not in Bus Off state" },
	{ 1,	"In Bus Off state." },
	{ 0, NULL },
};


static int * const  eth_rx_error_bits[] = {
	&hf_eth_crc_error,
	&hf_eth_mii_foe,
	&hf_eth_payload_foe,
	&hf_eth_hdr_foe,
	&hf_eth_rcv_dec_err,
	&hf_eth_sym_error,
	&hf_eth_jabber_event,
	&hf_eth_pol_ch_event,
	&hf_eth_fls_carrier_event,
	&hf_eth_rx_trunc,
	&hf_eth_transmission_disc_err,
	&hf_eth_wait_frame_sep_bit,
	NULL
};

static int * const eth_mjr_hdr_bits[] = {
	&hf_eth_reserved_bytes,
	&hf_eth_tx_trunc,
	&hf_eth_trans_undrun,
	&hf_eth_retrans_limit,
	&hf_eth_late_collision,
	&hf_eth_link_up_down,
	&hf_eth_master_slave,
	&hf_eth_fcs_unavailable,
	&hf_eth_rsvd_bit,
	&hf_eth_speed,
	NULL
};

static const val64_string eth_link_strings[] = {
	{ 0,	"Link Down" },
	{ 1,	"Link Up" },
	{ 0, NULL },
};

static const val64_string eth_master_strings[] = {
	{ 0,	"Slave" },
	{ 1,	"Master" },
	{ 0, NULL },
};

static const val64_string eth_fcs_strings[] = {
	{ 0,	"FCS appended to payload" },
	{ 1,	"FCS not appended to payload." },
	{ 0, NULL },
};

static const val64_string eth_speed_strings[] = {
	{ 0,	"Speed 10M" },
	{ 1,	"Speed 100M" },
	{ 2,	"Speed 1000M" },
	{ 3,	"Speed 2.5G" },
	{ 4,	"Speed 5G" },
	{ 5,	"Speed 10G" },
	{ 6,	"Speed 25G" },
	{ 7,	"Speed 40G" },
	{ 8,	"Speed 100G" },
	{ 9,	"Reserved" },
	{ 10,	"Reserved" },
	{ 11,	"Reserved" },
	{ 12,	"Reserved" },
	{ 13,	"Reserved" },
	{ 14,	"Reserved" },
	{ 15,	"Speed unknown. This value can be used when the speed could not be detected." },
	{ 0, NULL },
};

static int * const ts_status_bits[] = {
	&hf_ts_time_offset_valid,
	&hf_ts_last_offset_change_valid,
	&hf_ts_nano_seconds_last_jump_valid,
	&hf_ts_UTC_leap_seconds_valid,
	&hf_ts_sync_state_valid,
	NULL
};

static const val64_string ts_time_source_strings[] = {
	{ 0x00,	"TimeSourceNone" },
	{ 0x01,	"TimeSourceEBTimesyncHard" },
	{ 0x02,	"TimeSourceXTSS" },
	{ 0x03,	"TimeSourcePTPHW" },
	{ 0x10,	"TimeSourcePTPSW" },
	{ 0x20,	"TimeSourceGPS" },
	{ 0x30,	"TimeSourceEBTimesyncSoft" },
	{ 0x40,	"TimeSourceCAN" },
	{ 0x50,	"TimeSourceEBVirt" },
	{ 0, NULL },
};
static const value_string ts_sync_state_strings[] = {
	{ 0,	"Free running" },
	{ 1,	"Locked to master" },
	{ 0, NULL },
};

static int * const lin_status_bits[] = {
	&hf_lin_time_jump,
	&hf_lin_wakeup,
	&hf_lin_1_2_enhanced_chksum,
	&hf_lin_1_3_classic_chksum,
	NULL
};

static int * const lin_mjr_hdr_bits[] = {

	&hf_lin_wakeup_length,
	&hf_lin_sts_emp,
	&hf_lin_sts_sto,
	&hf_lin_sts_sta,
	&hf_lin_sts_chk,
	&hf_lin_sts_dat,
	&hf_lin_sts_res,
	&hf_lin_sts_par,
	&hf_lin_sts_syn,
	&hf_lin_sts_reserved,
	&hf_lin_reserved_bytes,
	NULL
};

static int * const lin_payload_pid_bits[] = {
	&hf_lin_payload_id,
	&hf_lin_payload_id_parity_0,
	&hf_lin_payload_id_parity_1,
	NULL
};

static int * const dio_status_bits[] = {
	&hf_dio_overflow_mon_unit,
	&hf_dio_jump_occurred,
	NULL
};

static int * const dio_mjr_hdr_bits[] = {
	&hf_dio_value_type,
	&hf_dio_channel_ref,
	&hf_dio_gpio_id,
	&hf_dio_reserved_bytes,
	NULL
};

static const val64_string dio_val_type_strings[] = {
	{ 0,	"Event triggered falling edge" },
	{ 1,	"Event triggered rising edge" },
	{ 2,	"GPIO is in low state (No state change)" },
	{ 3,	"GPIO is in high state (No state change)" },
	{ 0, NULL },
};

static const val64_string dio_channel_ref_strings[] = {
	{ 0,	"The EBHSCR header 'Channel' field refers to the Digital IO line number (zero based). EB 2200 /"
			"EB 5200 provides four input lines for DETI with the values 0-3" },
	{ 1,	"The EBHSCR header 'Channel' field refers to a accumulated GPIO data channel and the GPIO-"
			"ID field is used for further identification of the GPIO" },
	{ 0, NULL },
};

static int * const flexray_channel_bits[] = {
	&hf_flexray_ch_a,
	&hf_flexray_ch_b,
	&hf_flexray_ctrl_id,
	NULL
};

static int * const flexray_status_bits[] = {
	&hf_flexray_monitoring_bit,
	&hf_flexray_sync_bit,
	&hf_flexray_packet_type,
	&hf_flexray_jump_occurred,
	NULL
};

static int * const flexray_frame_status_bits[] = {
	&hf_flexray_monitoring_bit,
	&hf_flexray_sync_bit,
	&hf_flexray_packet_type,
	&hf_flexray_CODERR,
	&hf_flexray_TSSVIOL,
	&hf_flexray_HCRCERR,
	&hf_flexray_FCRCERR,
	&hf_flexray_FESERR,
	&hf_flexray_FSSERR,
	&hf_flexray_BSSERR,
	&hf_flexray_jump_occurred,
	NULL
};

static int * const flexray_slot_status_bits[] = {
	&hf_flexray_monitoring_bit,
	&hf_flexray_sync_bit,
	&hf_flexray_packet_type,
	&hf_flexray_overflow_err,
	&hf_flexray_jump_occurred,
	NULL
};

static int * const flexray_mhdr_slot_information_bits[] = {
	&hf_flexray_SBV,
	&hf_flexray_ACI,
	&hf_flexray_CED,
	&hf_flexray_SED,
	&hf_flexray_VFR,
	&hf_flexray_SID,
	NULL
};

static int * const flexray_mhdr_frame_status_bits[] = {
	&hf_flexray_SPLERR,
	&hf_flexray_CCERR,
	&hf_flexray_FIDERR,
	&hf_flexray_SSERR,
	&hf_flexray_NERR,
	&hf_flexray_SOVERR,
	&hf_flexray_SWVIOL,
	&hf_flexray_NITVIOL,
	&hf_flexray_BVIOL,
	&hf_flexray_PCD,
	&hf_flexray_SYNCERR,
	&hf_flexray_CP,
	&hf_flexray_BRC,
	NULL
};

static int * const flexray_mhdr_symbol_length_and_status_bits[] = {
	&hf_flexray_SYERR,
	&hf_flexray_SL,
	NULL
};

static const value_string flexray_monitoring_bit_strings[] = {
	{ 0x00, "Packet was generated by asynchronous monitoring" },
	{ 0x01, "Packet was generated by FlexRay synchronous monitoring" },
	{ 0, NULL },
};

static const value_string flexray_packet_type_strings[] = {
	{ FLEXRAY_FRAME_PACKET, "Frame" },
	{ FLEXRAY_SYMBOL_PACKET, "Symbol" },
	{ FLEXRAY_SLOT_STATUS_PACKET, "Slot status" },
	{ FLEXRAY_START_OF_CYCLE_PACKET, "Start of cycle" },
	{ 0, NULL },
};

static const value_string flexray_CP_strings[] = {
	{ 0x00, "Static part" },
	{ 0x01, "Dynamic part" },
	{ 0x02, "Symbol window" },
	{ 0x03, "NIT" },
	{ 0, NULL },
};

static const value_string flexray_POC_state_strings[] = {
	{ 0x00, "DEFAULT_CONFIG state" },
	{ 0x01, "READY state" },
	{ 0x02, "NORMAL_ACTIVE state" },
	{ 0x03, "NORMAL_PASSIVE state" },
	{ 0x04, "HALT state" },
	{ 0x05, "MONITOR_MODE state" },
	{ 0x0F, "CONFIG state" },
	{ 0x10, "WAKEUP_STANDBY state" },
	{ 0x11, "WAKEUP_LISTEN state" },
	{ 0x12, "WAKEUP_SEND state" },
	{ 0x13, "WAKEUP_DETECT state" },
	{ 0x20, "STARTUP_PREPARE state" },
	{ 0x21, "COLDSTART_LISTEN state" },
	{ 0x22, "COLDSTART_COLLISION_RESOLUTION state" },
	{ 0x23, "COLDSTART_CONSISTENCY_CHECK state" },
	{ 0x24, "COLDSTART_GAP state" },
	{ 0x25, "COLDSTART_JOIN state" },
	{ 0x26, "INTEGRATION_COLDSTART_CHECK state" },
	{ 0x27, "INTEGRATION_LISTEN state" },
	{ 0x28, "INTEGRATION_CONSISTENCY_CHECK state" },
	{ 0x29, "INITIALIZE_SCHEDULE state" },
	{ 0x2A, "ABORT_STARTUP state" },
	{ 0x2B, "STARTUP_SUCCESS state" },
	{ 0, NULL },
};

static int * const dsi3_status_bits[] = {
	&hf_dsi3_status_crc_error,
	&hf_dsi3_status_transition_error,
	&hf_dsi3_status_packet_truncated_error,
	&hf_dsi3_status_packet_dropped_error,
	NULL
};

static int * const dis3_mjr_hdr_slave_status_bits[] = {
	&hf_dsi3_mjr_hdr_st0_command_type,
	&hf_dsi3_mjr_hdr_slave_st0_bit_count,
	&hf_dsi3_mjr_hdr_slave_st2_blnk_err,
	&hf_dsi3_mjr_hdr_slave_st2_no_trans_err,
	&hf_dsi3_mjr_hdr_slave_st3_crc_err,
	&hf_dsi3_mjr_hdr_slave_st3_cnt_overflow,
	&hf_dsi3_mjr_hdr_slave_st3_disabled_err,
	&hf_dsi3_mjr_hdr_slave_st3_trunc_data,
	&hf_dsi3_mjr_hdr_slave_st3_drop_data,
	NULL
};

static int * const dis3_mjr_hdr_master_status_bits[] = {
	&hf_dsi3_mjr_hdr_st0_command_type,
	&hf_dsi3_mjr_hdr_master_st0_nibble_count,
	&hf_dsi3_mjr_hdr_master_st2_blnk_err,
	&hf_dsi3_mjr_hdr_master_st2_bad_trans_err,
	&hf_dsi3_mjr_hdr_master_st2_bad_chip_err,
	&hf_dsi3_mjr_hdr_master_st2_no_trans_err,
	&hf_dsi3_mjr_hdr_master_st3_crc_err,
	&hf_dsi3_mjr_hdr_master_st3_bad_decode_err,
	&hf_dsi3_mjr_hdr_master_st3_cnt_overflow,
	&hf_dsi3_mjr_hdr_master_st3_disable_err,
	&hf_dsi3_mjr_hdr_master_st3_trunc_data,
	&hf_dsi3_mjr_hdr_master_st3_drop_data,
	NULL
};

static const true_false_string dsi3_status_err_CRC_strings = {
	"CRC error occurred",
	"No CRC error occurred"
};

static const true_false_string dsi3_status_err_trans_strings = {
	"An unexpected transition was detected during reception or an unexpected transition was detected",
	"No transition error occurred"
};

static const true_false_string dsi3_status_err_trunc_strings = {
	"An associated data packet has been truncated",
	"No packet truncation error occurred"
};

static const true_false_string dsi3_status_err_drop_strings = {
	"An associated packet or an undefined number of them were dropped since last successful data reception",
	"No packet drop error occurred"
};

static const true_false_string dsi3_mjr_hdr_st0_command_type_strings = {
	"Periodic Data Collection Mode (PDCM) command",
	"Command and Response Mode (CRM) command"
};

static int * const mipi_csi2_status_bits[] = {
	&hf_mipi_csi2_status_packet_checksum_err,
	&hf_mipi_csi2_status_ecc_err,
	&hf_mipi_csi2_status_payload_fifo_overflow,
	&hf_mipi_csi2_status_header_fifo_overflow,
	&hf_mipi_csi2_status_rcv_decoder_err,
	&hf_mipi_csi2_status_payload_trunc_err,
	&hf_mipi_csi2_status_trans_rejected,
	NULL
};

static int * const mipi_csi2_mjr_hdr_flags_bits[] = {
	&hf_mipi_csi2_mjr_hdr_flags_packet_checksum_err,
	&hf_mipi_csi2_mjr_hdr_flags_correctable_ecc_err,
	&hf_mipi_csi2_mjr_hdr_flags_uncorrectable_ecc_err,
	&hf_mipi_csi2_mjr_hdr_flags_mipi_phy_type,
	&hf_mipi_csi2_mjr_hdr_flags_first_line_of_frame,
	NULL
};

static const true_false_string hf_mipi_csi2_mjr_hdr_flags_mipi_phy_type_string = {
	"CPHY",
	"DPHY"
};

static int * const csi2_frame_status_bits[] = {
	&hf_csi2_frame_status_packet_checksum_err,
	&hf_csi2_frame_status_ecc_err,
	&hf_csi2_frame_status_rcv_decoder_err,
	&hf_csi2_frame_status_section_err,
	&hf_csi2_frame_status_fifo_overflow,
	&hf_csi2_frame_status_payload_trunc_err,
	&hf_csi2_frame_status_trans_rejected,
	NULL
};

static int * const csi2_frame_mjr_hdr_bits[] = {
	&hf_csi2_frame_mjr_hdr_flags_proc,
	&hf_csi2_frame_mjr_hdr_flags_pad_align,
	&hf_csi2_frame_mjr_hdr_flags_mipi_phy_type,
	&hf_csi2_frame_mjr_hdr_vc,
	&hf_csi2_frame_mjr_hdr_imhv,
	NULL
};

static int * const csi2_frame_header_error_bits[] = {
	&hf_csi2_frame_header_error_bits_packet_checksum_err,
	&hf_csi2_frame_header_error_bits_correctable_ecc_err,
	&hf_csi2_frame_header_error_bits_uncorrectable_ecc_err,
	&hf_csi2_frame_header_error_bits_rcv_dec_err,
	NULL
};

static expert_field ei_ebhscr_frame_header;
static expert_field ei_ebhscr_err_status_flag;
static expert_field ei_ebhscr_info_status_flag;
static expert_field ei_ebhscr_err_channel_flag;
static expert_field ei_ebhscr_warn_mjr_hdr_status_flag;
static expert_field ei_ebhscr_warn_csi2_hdr_error_flag;

static dissector_handle_t ebhscr_handle;

static dissector_handle_t can_handle;
static dissector_handle_t can_fd_handle;
static dissector_handle_t eth_withfcs_handle;
static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t flexray_handle;
static dissector_handle_t ebhscr_user_handle;

static dissector_table_t subdissector_table;

static int dissect_ebhscr_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
								proto_tree *ebhscr_packet_header_tree, uint16_t ebhscr_status,
								uint32_t ebhscr_frame_length)
{
	uint16_t can_proto_status, can_type;
	uint32_t ebhscr_current_payload_length;
	tvbuff_t* next_tvb;
	proto_item *ti;

	ti = proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 2, hf_ebhscr_status, ett_ebhscr_status,
								can_status_bits, ENC_BIG_ENDIAN);

	can_proto_status = (ebhscr_status & 0x0002);
	if (can_proto_status) {
		proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 24, hf_ebhscr_mjr_hdr, ett_ebhscr_mjr_hdr,
								can_mjr_hdr_bits, ENC_BIG_ENDIAN);
		expert_add_info(pinfo, ti, &ei_ebhscr_info_status_flag);
	}
	else {
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
	}

	/* received hdr only and no data */
	if (ebhscr_frame_length == EBHSCR_HEADER_LENGTH) {
		return tvb_captured_length(tvb);
	}
	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;
	/* payload is CAN or CAN FD frame */
	next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);

	can_type = (ebhscr_status & 0x0001);

	if (can_type) {
		call_dissector(can_fd_handle, next_tvb, pinfo, tree);
	}
	else {
		call_dissector(can_handle, next_tvb, pinfo, tree);
	}
	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_eth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
								proto_tree *ebhscr_packet_header_tree, uint16_t ebhscr_status,
								uint32_t ebhscr_frame_length)
{
	tvbuff_t* next_tvb;
	proto_item *ti;
	uint8_t channel;
	uint32_t ebhscr_current_payload_length;
	uint64_t major_hrd, fsc_not_present, link_up, link_speed;
	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;

	ti = proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 2, hf_ebhscr_status,
								ett_ebhscr_status, eth_rx_error_bits, ENC_BIG_ENDIAN);

	if (ebhscr_status) {
		expert_add_info(pinfo, ti, &ei_ebhscr_err_status_flag);
	}

	channel = (tvb_get_uint8(tvb, 1) & 0x1C) >> 2;
	major_hrd = tvb_get_uint64(tvb, 24, ENC_BIG_ENDIAN);

	proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 24, hf_ebhscr_mjr_hdr, ett_ebhscr_mjr_hdr,
							eth_mjr_hdr_bits, ENC_BIG_ENDIAN);

	fsc_not_present = (major_hrd & 0x0000000400000000);
	link_up = (major_hrd & 0x0000000100000000) ? 1 : 0;
	link_speed = (major_hrd & 0x00000000F0000000) >> 28U;
	/* received hdr only and no data */
	if (ebhscr_frame_length == EBHSCR_HEADER_LENGTH) {
		col_append_fstr(pinfo->cinfo, COL_INFO, "Ethernet controller %d %s", channel, val64_to_str_const(link_up, eth_link_strings, ""));
		if (link_up)
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val64_to_str_const(link_speed, eth_speed_strings, "Speed unknown"));
		}
		return tvb_captured_length(tvb);
	}
	/* payload is 802.3 Ethernet frame */
	next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
	if (fsc_not_present) {
		call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
	}
	else {
		call_dissector(eth_withfcs_handle, next_tvb, pinfo, tree);
	}
	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_nmea(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
								proto_tree *ebhscr_packet_header_tree, uint32_t ebhscr_frame_length,
								uint32_t ebhscr_length)
{
	tvbuff_t* next_tvb;
	uint8_t *nmea_str;
	uint32_t ebhscr_current_payload_length;

	if (ebhscr_frame_length == EBHSCR_HEADER_LENGTH) {
		return tvb_captured_length(tvb);
	}

	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;

	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_status_unused, tvb, 2, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr_unused, tvb, 24, 8, ENC_BIG_ENDIAN);

	next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
	call_data_dissector(next_tvb, pinfo, tree);
	nmea_str = tvb_get_string_enc(pinfo->pool, tvb, 32, ebhscr_length, ENC_UTF_8);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", "NMEA:", nmea_str);
	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_ts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
								proto_tree *ebhscr_packet_header_tree, uint16_t ebhscr_status,
								uint32_t ebhscr_frame_length)
{
	tvbuff_t* next_tvb;
	uint32_t ebhscr_current_payload_length;
	uint64_t time_source = 0;
	proto_item *ti;

	col_set_str(pinfo->cinfo, COL_INFO, "TimeState:");
	ti = proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 2, hf_ebhscr_status, ett_ebhscr_status,
								ts_status_bits, ENC_BIG_ENDIAN);

	if (ebhscr_status) {
		expert_add_info(pinfo, ti, &ei_ebhscr_info_status_flag);
	}
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_uint64(ebhscr_packet_header_tree, hf_ts_time_source, tvb, 24, 8, ENC_BIG_ENDIAN, &time_source);
	col_append_str(pinfo->cinfo, COL_INFO, val64_to_str_const(time_source, ts_time_source_strings, "Unknown Time Source"));

	if (ebhscr_frame_length == EBHSCR_HEADER_LENGTH) {
		return tvb_captured_length(tvb);
	}

	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;
	if (ebhscr_current_payload_length < 28) {
		return tvb_captured_length(tvb);
	}

	/* display params only if the appropriate valid bit is set */
	if ((ebhscr_status & 0x001) != 0) {
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ts_time_offset_ns, tvb, 32, 8, ENC_BIG_ENDIAN);
	}
	if ((ebhscr_status & 0x002) != 0) {
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ts_last_offset_ns, tvb, 40, 8, ENC_BIG_ENDIAN);
	}
	if ((ebhscr_status & 0x004) != 0) {
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ts_last_jump_ns, tvb, 48, 8, ENC_BIG_ENDIAN);
	}
	if ((ebhscr_status & 0x008) != 0) {
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ts_utc_leap_sec, tvb, 56, 2, ENC_BIG_ENDIAN);
	}
	if ((ebhscr_status & 0x010) != 0) {
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ts_sync_state, tvb, 58, 2, ENC_BIG_ENDIAN);
	}

	next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
	call_data_dissector(next_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_lin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ebhscr_tree,
					proto_tree *ebhscr_packet_header_tree, uint16_t ebhscr_status, uint32_t ebhscr_frame_length)
{
	proto_item* ti;
	proto_tree *lin_payload_tree, *lin_pid_tree;
	uint32_t ebhscr_current_payload_length;

	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;

	ti = proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 2, hf_ebhscr_status,
								ett_ebhscr_status, lin_status_bits, ENC_BIG_ENDIAN);

	if (ebhscr_status) {
		expert_add_info(pinfo, ti, &ei_ebhscr_info_status_flag);
	}

	if ((ebhscr_status & 0x0010) != 0) {
		col_set_str(pinfo->cinfo, COL_INFO, "LIN Wake-Up Packet");
	}
	else {
		col_set_str(pinfo->cinfo, COL_INFO, "LIN Frame");
	}

	proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 24, hf_ebhscr_mjr_hdr, ett_ebhscr_mjr_hdr,
							lin_mjr_hdr_bits, ENC_BIG_ENDIAN);

	/* received hdr only and no data */
	if (ebhscr_frame_length == EBHSCR_HEADER_LENGTH) {
		return tvb_captured_length(tvb);
	}

	ti = proto_tree_add_item(ebhscr_tree, hf_lin_payload, tvb, 32, ebhscr_current_payload_length, ENC_NA);
	lin_payload_tree = proto_item_add_subtree(ti, ett_lin_payload);

	ti = proto_tree_add_item(lin_payload_tree, hf_lin_payload_pid, tvb, 32, 1, ENC_BIG_ENDIAN);
	lin_pid_tree = proto_item_add_subtree(ti, ett_lin_payload);
	proto_tree_add_bitmask_list(lin_pid_tree, tvb, 32, 1, lin_payload_pid_bits, ENC_BIG_ENDIAN);

	proto_tree_add_item(lin_payload_tree, hf_lin_payload_data, tvb, EBHSCR_HEADER_LENGTH + 1, ebhscr_current_payload_length - 2, ENC_NA);
	proto_tree_add_item(lin_payload_tree, hf_lin_payload_checksum, tvb, EBHSCR_HEADER_LENGTH + ebhscr_current_payload_length - 1, 1, ENC_BIG_ENDIAN);

	return tvb_captured_length(tvb);
}

static int
dissect_ebhscr_dio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
					proto_tree *ebhscr_packet_header_tree, uint16_t ebhscr_status, uint32_t ebhscr_frame_length)
{
	tvbuff_t* next_tvb;
	proto_item *ti;
	uint32_t ebhscr_current_payload_length;

	col_set_str(pinfo->cinfo, COL_INFO, "DIO:");
	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;

	ti = proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 2, hf_ebhscr_status,
								ett_ebhscr_status, dio_status_bits, ENC_BIG_ENDIAN);

	if (ebhscr_status) {
		expert_add_info(pinfo, ti, &ei_ebhscr_err_status_flag);
	}
	proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 24, hf_ebhscr_mjr_hdr, ett_ebhscr_mjr_hdr,
							dio_mjr_hdr_bits, ENC_BIG_ENDIAN);

	if (ebhscr_frame_length == EBHSCR_HEADER_LENGTH) {
		return tvb_captured_length(tvb);
	}

	next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
	call_data_dissector(next_tvb, pinfo, tree);
	col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, 32, ebhscr_current_payload_length, ' '));

	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_flexray_frame_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
												proto_tree *ebhscr_packet_header_tree, uint16_t ebhscr_status,
												uint32_t ebhscr_current_payload_length)
{
	proto_item *ti;
	proto_tree *flexray_mhdr_tree, *flexray_mhdr_sub_tree, *flexray_status_tree;
	tvbuff_t *fr_tvb, *hdr_tvb;
	uint8_t channel;
	uint8_t header_data[2U];

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_status, tvb, 2, 2, ENC_BIG_ENDIAN);
	flexray_status_tree = proto_item_add_subtree(ti, ett_ebhscr_status);
	proto_tree_add_bitmask_list(flexray_status_tree, tvb, 2, 2, flexray_frame_status_bits, ENC_BIG_ENDIAN);

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
	flexray_mhdr_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);

	ti = proto_tree_add_item(flexray_mhdr_tree, hf_flexray_slot_information, tvb, 24, 2, ENC_BIG_ENDIAN);
	flexray_mhdr_sub_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);
	proto_tree_add_bitmask_list(flexray_mhdr_sub_tree, tvb, 24, 2, flexray_mhdr_slot_information_bits, ENC_BIG_ENDIAN);

	ti = proto_tree_add_item(flexray_mhdr_tree, hf_flexray_frame_status, tvb, 26, 2, ENC_BIG_ENDIAN);
	flexray_mhdr_sub_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);
	proto_tree_add_bitmask_list(flexray_mhdr_sub_tree, tvb, 26, 2, flexray_mhdr_frame_status_bits, ENC_BIG_ENDIAN);

	proto_tree_add_item(flexray_mhdr_tree, hf_flexray_supercycle_counter, tvb, 28, 4, ENC_BIG_ENDIAN);

	fr_tvb = tvb_new_composite();

	header_data[0] = 0x01;
	channel = tvb_get_uint8(tvb, 1);

	if ((channel & FLEXRAY_CHANNEL_B_MASK) != 0) {
		header_data[0] |= 0x80;
	}

	header_data[1] = 0x00;

	if ((ebhscr_status & FLEXRAY_TSSVIOL_MASK) != 0) {
		header_data[1] |= 0x01;
	}
	if ((ebhscr_status & FLEXRAY_CODERR_MASK) != 0) {
		header_data[1] |= 0x02;
	}
	if ((ebhscr_status & FLEXRAY_FESERR_MASK) != 0) {
		header_data[1] |= 0x04;
	}
	if ((ebhscr_status & FLEXRAY_HCRCERR_MASK) != 0) {
		header_data[1] |= 0x08;
	}
	if ((ebhscr_status & FLEXRAY_FCRCERR_MASK) != 0) {
		header_data[1] |= 0x10;
	}

	hdr_tvb = tvb_new_real_data(header_data, 2U, 2U);

	tvb_composite_append(fr_tvb, hdr_tvb);
	tvb_composite_append(fr_tvb, tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length));

	tvb_composite_finalize(fr_tvb);
	call_dissector(flexray_handle, fr_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_flexray_symbol_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
												proto_tree *ebhscr_packet_header_tree)
{
	tvbuff_t* symbol_tvb;
	proto_item *ti;
	proto_tree *flexray_mhdr_tree, *flexray_mhdr_sub_tree, *flexray_status_tree;
	uint8_t symbol_length, channel;
	uint8_t flexray_symbol_packet[2U];

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_status, tvb, 2, 2, ENC_BIG_ENDIAN);
	flexray_status_tree = proto_item_add_subtree(ti, ett_ebhscr_status);
	proto_tree_add_bitmask_list(flexray_status_tree, tvb, 2, 2, flexray_status_bits, ENC_BIG_ENDIAN);

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
	flexray_mhdr_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);

	ti = proto_tree_add_item(flexray_mhdr_tree, hf_flexray_slot_information, tvb, 24, 2, ENC_BIG_ENDIAN);
	flexray_mhdr_sub_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);
	proto_tree_add_bitmask_list(flexray_mhdr_sub_tree, tvb, 24, 2, flexray_mhdr_slot_information_bits, ENC_BIG_ENDIAN);

	ti = proto_tree_add_item(flexray_mhdr_tree, hf_flexray_frame_status, tvb, 26, 2, ENC_BIG_ENDIAN);
	flexray_mhdr_sub_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);
	proto_tree_add_bitmask_list(flexray_mhdr_sub_tree, tvb, 26, 2, flexray_mhdr_frame_status_bits, ENC_BIG_ENDIAN);

	ti = proto_tree_add_item(flexray_mhdr_tree, hf_flexray_symbol_length_and_status, tvb, 28, 1, ENC_BIG_ENDIAN);
	flexray_mhdr_sub_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);
	proto_tree_add_bitmask_list(flexray_mhdr_sub_tree, tvb, 28, 1, flexray_mhdr_symbol_length_and_status_bits, ENC_BIG_ENDIAN);

	symbol_length = tvb_get_uint8(tvb, 28) & 0x7F;

	flexray_symbol_packet[0] = 0x02;

	channel = tvb_get_uint8(tvb, 1);

	if ((channel & FLEXRAY_CHANNEL_B_MASK) != 0) {
		flexray_symbol_packet[0] |= 0x80;
	}

	flexray_symbol_packet[1] = symbol_length;

	symbol_tvb = tvb_new_real_data(flexray_symbol_packet, 2U, 2U);
	call_dissector(flexray_handle, symbol_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_flexray_slot_status_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ebhscr_packet_header_tree)
{
	uint32_t supercycle_counter;
	proto_item *ti;
	proto_tree *flexray_mhdr_tree, *flexray_mhdr_sub_tree, *flexray_status_tree;

	supercycle_counter = tvb_get_uint32(tvb, 28, ENC_BIG_ENDIAN);
	col_append_fstr(pinfo->cinfo, COL_INFO, " SLSTS: SCC %d", supercycle_counter);

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_status, tvb, 2, 2, ENC_BIG_ENDIAN);
	flexray_status_tree = proto_item_add_subtree(ti, ett_ebhscr_status);
	proto_tree_add_bitmask_list(flexray_status_tree, tvb, 2, 2, flexray_slot_status_bits, ENC_BIG_ENDIAN);

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
	flexray_mhdr_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);

	ti = proto_tree_add_item(flexray_mhdr_tree, hf_flexray_slot_information, tvb, 24, 2, ENC_BIG_ENDIAN);
	flexray_mhdr_sub_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);
	proto_tree_add_bitmask_list(flexray_mhdr_sub_tree, tvb, 24, 2, flexray_mhdr_slot_information_bits, ENC_BIG_ENDIAN);

	ti = proto_tree_add_item(flexray_mhdr_tree, hf_flexray_frame_status, tvb, 26, 2, ENC_BIG_ENDIAN);
	flexray_mhdr_sub_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);
	proto_tree_add_bitmask_list(flexray_mhdr_sub_tree, tvb, 26, 2, flexray_mhdr_frame_status_bits, ENC_BIG_ENDIAN);

	proto_tree_add_item(flexray_mhdr_tree, hf_flexray_supercycle_counter, tvb, 28, 4, ENC_BIG_ENDIAN);

	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_flexray_start_of_cycle_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ebhscr_packet_header_tree)
{
	uint8_t cycle_counter;
	uint32_t supercycle_counter;
	proto_item *ti;
	proto_tree *flexray_mhdr_tree, *flexray_status_tree;

	cycle_counter = tvb_get_uint8(tvb, 25);
	supercycle_counter = tvb_get_uint32(tvb, 28, ENC_BIG_ENDIAN);

	col_append_fstr(pinfo->cinfo, COL_INFO, " SOC: CC %2d SCC %d", cycle_counter, supercycle_counter);

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_status, tvb, 2, 2, ENC_BIG_ENDIAN);
	flexray_status_tree = proto_item_add_subtree(ti, ett_ebhscr_status);
	proto_tree_add_bitmask_list(flexray_status_tree, tvb, 2, 2, flexray_status_bits, ENC_BIG_ENDIAN);

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
	flexray_mhdr_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);

	proto_tree_add_item(flexray_mhdr_tree, hf_flexray_POC_state, tvb, 24, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(flexray_mhdr_tree, hf_flexray_following_cycle_counter, tvb, 25, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(flexray_mhdr_tree, hf_flexray_supercycle_counter, tvb, 28, 4, ENC_BIG_ENDIAN);

	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_flexray(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
									proto_tree *ebhscr_packet_header_tree, proto_item *ebhscr_channel,
									uint16_t ebhscr_status, uint32_t ebhscr_frame_length)
{
	proto_tree *flexray_channel_tree;
	uint32_t flexray_packet_type;
	uint32_t ebhscr_current_payload_length;

	col_set_str(pinfo->cinfo, COL_INFO, "FLEXRAY:");
	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;

	flexray_channel_tree = proto_item_add_subtree(ebhscr_channel, ett_ebhscr_channel);
	proto_tree_add_bitmask_list(flexray_channel_tree, tvb, 1, 1, flexray_channel_bits, ENC_BIG_ENDIAN);

	flexray_packet_type = (ebhscr_status & 0xC) >> 2U;

	if (flexray_packet_type == FLEXRAY_FRAME_PACKET) {
		dissect_ebhscr_flexray_frame_packet(tvb, pinfo, tree, ebhscr_packet_header_tree, ebhscr_status, ebhscr_current_payload_length);
	}
	else if (flexray_packet_type == FLEXRAY_SYMBOL_PACKET) {
		dissect_ebhscr_flexray_symbol_packet(tvb, pinfo, tree, ebhscr_packet_header_tree);
	}
	else if (flexray_packet_type == FLEXRAY_SLOT_STATUS_PACKET) {
		dissect_ebhscr_flexray_slot_status_packet(tvb, pinfo, ebhscr_packet_header_tree);
	}
	else if (flexray_packet_type == FLEXRAY_START_OF_CYCLE_PACKET) {
		dissect_ebhscr_flexray_start_of_cycle_packet(tvb, pinfo, ebhscr_packet_header_tree);
	}

	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_dsi3_slave_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ebhscr_packet_header_tree)
{
	proto_item *ti;
	proto_tree *dsi3_mhdr_tree;
	uint8_t mjr_hdr_st2_flags;
	uint8_t mjr_hdr_st3_flags;

	col_append_str(pinfo->cinfo, COL_INFO, "SLAVE:");

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
	dsi3_mhdr_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);
	proto_tree_add_bitmask_list(dsi3_mhdr_tree, tvb, 24, 4, dis3_mjr_hdr_slave_status_bits, ENC_BIG_ENDIAN);

	mjr_hdr_st2_flags = tvb_get_uint8(tvb, 26) & 0x03;
	if (mjr_hdr_st2_flags) {
		expert_add_info(pinfo, ti, &ei_ebhscr_warn_mjr_hdr_status_flag);
	}

	mjr_hdr_st3_flags = tvb_get_uint8(tvb, 27) & 0x1F;
	if (mjr_hdr_st3_flags) {
		expert_add_info(pinfo, ti, &ei_ebhscr_warn_mjr_hdr_status_flag);
	}

	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_dsi3_master_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ebhscr_packet_header_tree)
{
	proto_item *ti;
	proto_tree *dsi3_mhdr_tree;
	uint8_t mjr_hdr_st2_flags;
	uint8_t mjr_hdr_st3_flags;

	col_append_str(pinfo->cinfo, COL_INFO, "MASTER:");

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
	dsi3_mhdr_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);
	proto_tree_add_bitmask_list(dsi3_mhdr_tree, tvb, 24, 4, dis3_mjr_hdr_master_status_bits, ENC_BIG_ENDIAN);

	mjr_hdr_st2_flags = tvb_get_uint8(tvb, 26) & 0x0F;
	if (mjr_hdr_st2_flags) {
		expert_add_info(pinfo, ti, &ei_ebhscr_warn_mjr_hdr_status_flag);
	}

	mjr_hdr_st3_flags = tvb_get_uint8(tvb, 27) & 0x3F;
	if (mjr_hdr_st3_flags) {
		expert_add_info(pinfo, ti, &ei_ebhscr_warn_mjr_hdr_status_flag);
	}

	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_dsi3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *ebhscr_packet_header_tree,
								proto_item *ebhscr_channel, uint16_t ebhscr_status, uint32_t ebhscr_frame_length)
{
	proto_item *ti;
	tvbuff_t *next_tvb;
	proto_tree *dsi3_status_tree;
	proto_tree *dsi3_channel_tree;
	uint16_t dsi3_channel_val;
	uint32_t ebhscr_current_payload_length;

	col_set_str(pinfo->cinfo, COL_INFO, "DSI3_");
	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;

	dsi3_channel_val = tvb_get_uint16(tvb, 0, ENC_BIG_ENDIAN) & 0x3F;
	dsi3_channel_tree = proto_item_add_subtree(ebhscr_channel, ett_ebhscr_channel);

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_status, tvb, 2, 2, ENC_BIG_ENDIAN);
	dsi3_status_tree = proto_item_add_subtree(ti, ett_ebhscr_status);
	proto_tree_add_bitmask_list(dsi3_status_tree, tvb, 2, 2, dsi3_status_bits, ENC_BIG_ENDIAN);

	if (ebhscr_status) {
		expert_add_info(pinfo, ti, &ei_ebhscr_err_status_flag);
	}

	if (dsi3_channel_val == DSI3_CHANNEL_SLAVE) {
		dissect_ebhscr_dsi3_slave_packet(tvb, pinfo, ebhscr_packet_header_tree);
	}
	else if (dsi3_channel_val == DSI3_CHANNEL_MASTER) {
		dissect_ebhscr_dsi3_master_packet(tvb, pinfo, ebhscr_packet_header_tree);
	}
	else
	{
		col_append_str(pinfo->cinfo, COL_INFO, "CH_ERR:");
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr_unused, tvb, 24, 8, ENC_BIG_ENDIAN);
		expert_add_info(pinfo, dsi3_channel_tree, &ei_ebhscr_err_channel_flag);
	}

	if (ebhscr_frame_length == EBHSCR_HEADER_LENGTH) {
		return tvb_captured_length(tvb);
	}

	next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
	call_data_dissector(next_tvb, pinfo, tree);
	col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, 32, ebhscr_current_payload_length, ' '));

	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_mipi_csi2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	proto_tree *ebhscr_packet_header_tree, uint16_t ebhscr_status, uint32_t ebhscr_frame_length)
{
	proto_item * ti;
	tvbuff_t* next_tvb;
	proto_tree *mipi_csi2_status_tree;
	proto_tree *mipi_csi2_mhdr_tree;
	proto_tree *mipi_csi2_payload_pkt_header_subtree;
	uint8_t mjr_hdr_flags;
	uint32_t ebhscr_current_payload_length;

	col_set_str(pinfo->cinfo, COL_INFO, "MIPI_CSI2:");
	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_status, tvb, 2, 2, ENC_BIG_ENDIAN);
	mipi_csi2_status_tree = proto_item_add_subtree(ti, ett_ebhscr_status);
	proto_tree_add_bitmask_list(mipi_csi2_status_tree, tvb, 2, 2, mipi_csi2_status_bits, ENC_BIG_ENDIAN);

	if (ebhscr_status) {
		expert_add_info(pinfo, ti, &ei_ebhscr_err_status_flag);
	}

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
	mipi_csi2_mhdr_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);
	proto_tree_add_bitmask_list(mipi_csi2_mhdr_tree, tvb, 24, 4, mipi_csi2_mjr_hdr_flags_bits, ENC_BIG_ENDIAN);
	mjr_hdr_flags = tvb_get_uint8(tvb, 24) & 0x07;
	if (mjr_hdr_flags) {
		expert_add_info(pinfo, ti, &ei_ebhscr_warn_mjr_hdr_status_flag);
	}

	ti = proto_tree_add_item(mipi_csi2_mhdr_tree, hf_mipi_csi2_mjr_hdr_frame_counter, tvb, 28, 2, ENC_BIG_ENDIAN);
	ti = proto_tree_add_item(mipi_csi2_mhdr_tree, hf_mipi_csi2_mjr_hdr_line_counter, tvb, 30, 2, ENC_BIG_ENDIAN);

	if (ebhscr_current_payload_length < MIPI_CSI2_PKT_HDR_LEN) {
		return tvb_captured_length(tvb);
	}

	ti = proto_tree_add_item(tree, hf_mipi_csi2_payload_pkt_hdr, tvb, 32, 8, ENC_BIG_ENDIAN);
	mipi_csi2_payload_pkt_header_subtree = proto_item_add_subtree(ti, ett_ebhscr_status);

	ti = proto_tree_add_item(mipi_csi2_payload_pkt_header_subtree, hf_mipi_csi2_payload_pkt_hdr_dt, tvb, 32, 1, ENC_BIG_ENDIAN);
	ti = proto_tree_add_item(mipi_csi2_payload_pkt_header_subtree, hf_mipi_csi2_payload_pkt_hdr_vc, tvb, 33, 1, ENC_BIG_ENDIAN);
	ti = proto_tree_add_item(mipi_csi2_payload_pkt_header_subtree, hf_mipi_csi2_payload_pkt_hdr_ecc, tvb, 35, 1, ENC_BIG_ENDIAN);
	ti = proto_tree_add_item(mipi_csi2_payload_pkt_header_subtree, hf_mipi_csi2_payload_pkt_hdr_crc, tvb, 36, 2, ENC_LITTLE_ENDIAN);
	ti = proto_tree_add_item(mipi_csi2_payload_pkt_header_subtree, hf_mipi_csi2_payload_pkt_hdr_wc_lsb, tvb, 38, 2, ENC_LITTLE_ENDIAN);
	ti = proto_tree_add_item(mipi_csi2_payload_pkt_header_subtree, hf_mipi_csi2_payload_pkt_hdr_wc_msb, tvb, 38, 2, ENC_LITTLE_ENDIAN);

	ebhscr_current_payload_length -= MIPI_CSI2_PKT_HDR_LEN;
	uint32_t const headers_length = EBHSCR_HEADER_LENGTH + MIPI_CSI2_PKT_HDR_LEN;

	if (ebhscr_current_payload_length > 0) {
		next_tvb = tvb_new_subset_length(tvb, headers_length, ebhscr_current_payload_length);
		call_data_dissector(next_tvb, pinfo, tree);
		col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, headers_length, ebhscr_current_payload_length, ' '));
	}

	return tvb_captured_length(tvb);
}

static int dissect_ebhscr_csi2_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	proto_tree *ebhscr_packet_header_tree, uint16_t ebhscr_status, uint32_t ebhscr_frame_length)
{
	proto_item *ti;
	tvbuff_t* next_tvb;
	proto_tree *csi2_frame_status_tree;
	proto_tree *csi2_frame_mhdr_tree;
	proto_tree *csi2_frame_header_subtree;
	proto_tree *csi2_frame_header_sections_subtree[CSI2_FRAME_NUM_SECTIONS];
	proto_tree *csi2_frame_header_sections_err_bits_subtree;
	uint32_t ebhscr_current_payload_length;
	uint8_t csi2_frame_header_error_flags;

	col_set_str(pinfo->cinfo, COL_INFO, "CSI2_FRAME:");
	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_status, tvb, 2, 2, ENC_BIG_ENDIAN);
	csi2_frame_status_tree = proto_item_add_subtree(ti, ett_ebhscr_status);
	proto_tree_add_bitmask_list(csi2_frame_status_tree, tvb, 2, 2, csi2_frame_status_bits, ENC_BIG_ENDIAN);

	if (ebhscr_status) {
		expert_add_info(pinfo, ti, &ei_ebhscr_err_status_flag);
	}

	ti = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
	csi2_frame_mhdr_tree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);
	proto_tree_add_bitmask_list(csi2_frame_mhdr_tree, tvb, 24, 4, csi2_frame_mjr_hdr_bits, ENC_BIG_ENDIAN);

	if (ebhscr_current_payload_length < CSI2_FRAME_PKT_HDR_LEN) {
		return tvb_captured_length(tvb);
	}

	ti = proto_tree_add_item(tree, hf_csi2_frame_header, tvb, 32, 128, ENC_NA);
	csi2_frame_header_subtree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);

	for (unsigned int i = 0, section_offset = EBHSCR_HEADER_LENGTH; i < CSI2_FRAME_NUM_SECTIONS; ++i) {
		int field_offset = section_offset;
		int current_section = hf_csi2_frame_sections[i];
		ti = proto_tree_add_item(csi2_frame_header_subtree, current_section, tvb, section_offset, CSI2_FRAME_SECTION_SIZE_BYTES, ENC_NA);
		section_offset += CSI2_FRAME_SECTION_SIZE_BYTES;

		csi2_frame_header_sections_subtree[i] = proto_item_add_subtree(ti, ett_ebhscr_status);

		ti = proto_tree_add_item(csi2_frame_header_sections_subtree[i], hf_csi2_frame_header_payload_byte_offset, tvb, field_offset, 4, ENC_BIG_ENDIAN);
		field_offset += 4;

		ti = proto_tree_add_item(csi2_frame_header_sections_subtree[i], hf_csi2_frame_header_bytes_total, tvb, field_offset, 4, ENC_BIG_ENDIAN);
		field_offset += 4;

		ti = proto_tree_add_item(csi2_frame_header_sections_subtree[i], hf_csi2_frame_header_bytes_per_line, tvb, field_offset, 2, ENC_BIG_ENDIAN);
		field_offset += 2;

		ti = proto_tree_add_item(csi2_frame_header_sections_subtree[i], hf_csi2_frame_header_number_lines, tvb, field_offset, 2, ENC_BIG_ENDIAN);
		field_offset += 2;

		/* Next 2 bytes are reserved */
		field_offset += 2;

		ti = proto_tree_add_item(csi2_frame_header_sections_subtree[i], hf_csi2_frame_header_error_bits_field, tvb, field_offset, 1, ENC_BIG_ENDIAN);
		csi2_frame_header_sections_err_bits_subtree = proto_item_add_subtree(ti, ett_ebhscr_mjr_hdr);
		proto_tree_add_bitmask_list(csi2_frame_header_sections_err_bits_subtree, tvb, field_offset, 1, csi2_frame_header_error_bits, ENC_BIG_ENDIAN);
		csi2_frame_header_error_flags = tvb_get_uint8(tvb, field_offset) & 0x0F;
		if (csi2_frame_header_error_flags) {
			expert_add_info(pinfo, ti, &ei_ebhscr_warn_csi2_hdr_error_flag);
		}
		field_offset += 1;

		ti = proto_tree_add_item(csi2_frame_header_sections_subtree[i], hf_csi2_frame_header_mipi_data_type, tvb, field_offset, 1, ENC_BIG_ENDIAN);
		/* field_offset += 1; */

		ebhscr_current_payload_length -= CSI2_FRAME_SECTION_SIZE_BYTES;
	}

	uint32_t const headers_length = EBHSCR_HEADER_LENGTH + (CSI2_FRAME_NUM_SECTIONS * CSI2_FRAME_SECTION_SIZE_BYTES);

	if (ebhscr_current_payload_length > 0) {
		next_tvb = tvb_new_subset_length(tvb, headers_length, ebhscr_current_payload_length);
		call_data_dissector(next_tvb, pinfo, tree);
		col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, headers_length, ebhscr_current_payload_length, ' '));
	}

	return tvb_captured_length(tvb);
}

static int
dissect_ebhscr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *ebhscr_packet_header_tree;
	proto_tree *ebhscr_tree;
	proto_tree *proto_ebhscr_channel;
	tvbuff_t* next_tvb;
	uint32_t ebhscr_frame_length, ebhscr_length;
	int ebhscr_current_payload_length;
	uint8_t ebhscr_major_num;
	uint16_t ebhscr_status = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EBHSCR");
	col_clear(pinfo->cinfo, COL_INFO);

	ebhscr_frame_length = tvb_captured_length(tvb);

	ti = proto_tree_add_item(tree, proto_ebhscr, tvb, 0, -1, ENC_NA);
	ebhscr_tree = proto_item_add_subtree(ti, ett_ebhscr);

	if (ebhscr_frame_length < EBHSCR_HEADER_LENGTH) {
		expert_add_info(pinfo, ebhscr_tree, &ei_ebhscr_frame_header);
		return tvb_captured_length(tvb);
	}

	ebhscr_major_num = tvb_get_uint8(tvb, 0);
	ebhscr_status = tvb_get_uint16(tvb, 2, ENC_BIG_ENDIAN) & 0x0FFF;

	ti = proto_tree_add_item(ebhscr_tree, hf_ebhscr_packet_header, tvb, 0, 32, ENC_NA);
	ebhscr_packet_header_tree = proto_item_add_subtree(ti, ett_ebhscr_packet_header);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_major_number, tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_slot, tvb, 1, 1, ENC_BIG_ENDIAN);
	proto_ebhscr_channel = proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_channel, tvb, 1, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_version, tvb, 2, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_uint(ebhscr_packet_header_tree, hf_ebhscr_length, tvb, 4, 4, ENC_BIG_ENDIAN, &ebhscr_length);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_start_timestamp, tvb, 8, 8, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_stop_timestamp, tvb, 16, 8, ENC_BIG_ENDIAN);

	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;

	if ((ebhscr_major_num >= EBHSCR_USER_FIRST) && (ebhscr_major_num <= EBHSCR_USER_LAST)) {
		if (ebhscr_user_handle != NULL) {
			next_tvb = tvb_new_subset_length(tvb, 0, ebhscr_frame_length);
			call_dissector(ebhscr_user_handle, next_tvb, pinfo, ebhscr_tree);
		}
		else {
			proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_status, tvb, 2, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
			next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
			call_data_dissector(next_tvb, pinfo, tree);
			if (ebhscr_current_payload_length > 0) {
				col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, 32,
								ebhscr_current_payload_length, ' '));
			}
		}
		return tvb_captured_length(tvb);
	}

	/* each dissect function handles Status and Major number specific header bits */
	if (ebhscr_major_num == CAN_FRAME) {
		dissect_ebhscr_can(tvb, pinfo, tree, ebhscr_packet_header_tree, ebhscr_status, ebhscr_frame_length);
	}

	else if (ebhscr_major_num == ETHERNET_FRAME) {
		dissect_ebhscr_eth(tvb, pinfo, tree, ebhscr_packet_header_tree, ebhscr_status, ebhscr_frame_length);
	}

	else if (ebhscr_major_num == NMEA_FRAME)
	{
		dissect_ebhscr_nmea(tvb, pinfo, tree, ebhscr_packet_header_tree, ebhscr_frame_length, ebhscr_length);
	}

	else if (ebhscr_major_num == TIME_STATE_FRAME) {
		dissect_ebhscr_ts(tvb, pinfo, tree, ebhscr_packet_header_tree, ebhscr_status, ebhscr_frame_length);
	}

	else if (ebhscr_major_num == LIN_FRAME) {
		dissect_ebhscr_lin(tvb, pinfo, ebhscr_tree, ebhscr_packet_header_tree, ebhscr_status, ebhscr_frame_length);
	}

	else if (ebhscr_major_num == DIO_FRAME) {
		dissect_ebhscr_dio(tvb, pinfo, tree, ebhscr_packet_header_tree, ebhscr_status, ebhscr_frame_length);
	}

	else if (ebhscr_major_num == FLEXRAY_FRAME) {
		dissect_ebhscr_flexray(tvb, pinfo, tree, ebhscr_packet_header_tree, proto_ebhscr_channel, ebhscr_status, ebhscr_frame_length);
	}

	else if (ebhscr_major_num == DSI3_FRAME) {
		dissect_ebhscr_dsi3(tvb, pinfo, tree, ebhscr_packet_header_tree, proto_ebhscr_channel, ebhscr_status, ebhscr_frame_length);
	}

	else if (ebhscr_major_num == MIPI_CSI2) {
		dissect_ebhscr_mipi_csi2(tvb, pinfo, tree, ebhscr_packet_header_tree, ebhscr_status, ebhscr_frame_length);
	}

	else if (ebhscr_major_num == CSI2_FRAME) {
		dissect_ebhscr_csi2_frame(tvb, pinfo, tree, ebhscr_packet_header_tree, ebhscr_status, ebhscr_frame_length);
	}

	else {
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_status, tvb, 2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);
		next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
		call_data_dissector(next_tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

void
proto_register_ebhscr(void)
{
	expert_module_t *expert_ebhscr;

	static hf_register_info hf[] = {
		{ &hf_ebhscr_packet_header,
			{ "Packet header", "ebhscr.hdr",
			FT_BYTES, BASE_NO_DISPLAY_VALUE,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_major_number,
			{ "Major number", "ebhscr.mjr",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_slot,
			{ "Slot", "ebhscr.slot",
			FT_UINT8, BASE_HEX,
			NULL, 0xc0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_channel,
			{ "Channel", "ebhscr.channel",
			FT_UINT8, BASE_HEX,
			NULL, 0x3f,
			NULL, HFILL }
		},
		{ &hf_ebhscr_status,
			{ "Status", "ebhscr.sts",
			FT_UINT16, BASE_HEX,
			NULL, 0x0FFF,
			NULL, HFILL }
		},
		{ &hf_ebhscr_status_unused,{
			"Status [Unused]", "ebhscr.sts.unused",
			FT_UINT32,	BASE_HEX,
			NULL, 0x0FFF,
			NULL, HFILL }
		},
		{ &hf_ebhscr_version,
			{ "Version", "ebhscr.ver",
			FT_UINT16, BASE_HEX,
			NULL, 0xF000,
			NULL, HFILL }
		},
		{ &hf_ebhscr_length,
			{ "Length", "ebhscr.len",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_start_timestamp,
			{ "Start timestamp", "ebhscr.strt",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_stop_timestamp,
			{ "Stop timestamp", "ebhscr.stpt",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_mjr_hdr,
			{ "Major number specific header", "ebhscr.mjrhdr",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_mjr_hdr_unused,
			{ "Major number specific header [Unused]", "ebhscr.mjrhdr.unused",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_can_proto_type,
			{ "CAN FD flag", "ebhscr.can.type",
			FT_UINT16, BASE_HEX,
			VALS(can_proto_type_strings), 0x0001,
			NULL, HFILL }
		},
		{ &hf_can_status_available,
			{ "CAN protocol status availability", "ebhscr.can.asts",
			FT_UINT16, BASE_HEX,
			VALS(can_status_available_strings), 0x0002,
			NULL, HFILL }
		},
		{ &hf_can_status_overflow,
			{ "Overflow flag", "ebhscr.can.overflow",
			FT_UINT16, BASE_HEX,
			VALS(can_status_overflow_strings), 0x0004,
			NULL, HFILL }
		},
		{ &hf_can_LEC,
			{ "CAN Last error code", "ebhscr.can.LEC",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			VALS64(can_last_err_code_strings), 0x0000000700000000,
			NULL, HFILL }
		},
		{ &hf_can_ERRP,
			{ "CAN Counters reached Error passive limit", "ebhscr.can.errp",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			VALS64(can_ERRP_strings), 0x0000002000000000,
			NULL, HFILL }
		},
		{ &hf_can_ERRW,
			{ "CAN Counters reached Error warning limit", "ebhscr.can.errw",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			VALS64(can_ERRW_strings), 0x0000004000000000,
			NULL, HFILL }
		},
		{ &hf_can_BOFF,
			{ "CAN Bus Off state", "ebhscr.can.boff",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			VALS64(can_BOFF_strings), 0x0000008000000000,
			NULL, HFILL }
		},
		{ &hf_can_DLEC,
			{ "CAN Data phase of CAN FD frame (with BRS flag set) last error code.", "ebhscr.can.dlec",
			FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
			VALS64(can_last_err_code_strings), 0x0000070000000000,
			NULL, HFILL }
		},
		{ &hf_can_TEC,
			{ "CAN Transmit Error Counter", "ebhscr.can.tec",
			FT_UINT64, BASE_HEX,
			NULL, 0x00FF000000000000,
			NULL, HFILL }
		},
		{ &hf_can_REC,
			{ "CAN Receive Error Counter", "ebhscr.can.rec",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			NULL, 0x7F00000000000000,
			NULL, HFILL }
		},
		{ &hf_can_CEL,
			{ "Can Error Logging Counter", "ebhscr.can.cel",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			NULL, 0x00000000000000FF,
			NULL, HFILL }
		},
		{ &hf_can_reserved_bytes,
			{ "Reserved Flags", "ebhscr.can.rsv",
			FT_BOOLEAN, 64, NULL,
			0x00000000FFFFFF00,
			NULL, HFILL }
		},
		{ &hf_eth_reserved_bytes,
			{ "Reserved Flags", "ebhscr.eth.rsv",
			FT_BOOLEAN, 64, NULL,
			0xFFF0FF00FFFFFFFF,
			NULL, HFILL }
		},
		{ &hf_eth_link_up_down,
			{ "Link Up or Down", "ebhscr.eth.lud",
			FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
			VALS64(eth_link_strings), 0x0000000100000000,
			NULL, HFILL }
		},
		{ &hf_eth_master_slave,
			{ "Master or Slave (if supported)", "ebhscr.eth.ms",
			FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
			VALS64(eth_master_strings), 0x0000000200000000,
			NULL, HFILL }
		},
		{ &hf_eth_fcs_unavailable,
		{ "FCS unavailable", "ebhscr.eth.fcsua",
			FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
			VALS64(eth_fcs_strings), 0x0000000400000000,
			NULL, HFILL }
		},
		{ &hf_eth_rsvd_bit,
		{ "Reserved", "ebhscr.eth.rsvd",
			FT_BOOLEAN, 64, NULL,
			0x0000000800000000,
			NULL, HFILL }
		},
		{ &hf_eth_speed,
			{ "Ethernet speed", "ebhscr.eth.spd",
			FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
			VALS64(eth_speed_strings), 0x000000F000000000,
			NULL, HFILL }
		},
		{ &hf_eth_crc_error,
			{ "Ethernet CRC Error", "ebhscr.eth.crc",
			FT_BOOLEAN, 16,
			NULL, 0x0001,
			NULL, HFILL }
		},
		{ &hf_eth_mii_foe,
			{ "Media-independent interface FIFO Overflow Error", "ebhscr.eth.miifoe",
			FT_BOOLEAN, 16,
			NULL, 0x0002,
			NULL, HFILL }
		},
		{ &hf_eth_payload_foe,
			{ "Payload FIFO Overflow Error", "ebhscr.eth.pfoe",
			FT_BOOLEAN, 16,
			NULL, 0x0004,
			NULL, HFILL }
		},
		{ &hf_eth_hdr_foe,
			{ "Header FIFO Overflow Error", "ebhscr.eth.hfoe",
			FT_BOOLEAN, 16,
			NULL, 0x0008,
			NULL, HFILL }
		},
		{ &hf_eth_rcv_dec_err,
			{ "Receiver Decoder Error", "ebhscr.eth.rde",
			FT_BOOLEAN, 16,
			NULL, 0x0010,
			NULL, HFILL }
		},
		{ &hf_eth_sym_error,
			{ "Symbol Error", "ebhscr.eth.se",
			FT_BOOLEAN, 16,
			NULL, 0x0020,
			NULL, HFILL }
		},
		{ &hf_eth_jabber_event,
			{ "Jabber", "ebhscr.eth.jbr",
			FT_BOOLEAN, 16,
			NULL, 0x0040,
			NULL, HFILL }
		},
		{ &hf_eth_pol_ch_event,
			{ "Polarity Change", "ebhscr.eth.pche",
			FT_BOOLEAN, 16,
			NULL, 0x0080,
			NULL, HFILL }
		},
		{ &hf_eth_fls_carrier_event,
			{ "False Carrier", "ebhscr.eth.flsc",
			FT_BOOLEAN, 16,
			NULL, 0x0100,
			NULL, HFILL }
		},
		{ &hf_eth_rx_trunc,
			{ "Truncation", "ebhscr.eth.rxtrc",
			FT_BOOLEAN, 16,
			NULL, 0x0200,
			NULL, HFILL }
		},
		{ &hf_eth_transmission_disc_err,
			{ "Capture: Transmission Discarded Error, Replay: Start Frame Separation Bit", "ebhscr.eth.trdis",
			FT_BOOLEAN, 16,
			NULL, 0x0400,
			NULL, HFILL }
		},
		{ &hf_eth_wait_frame_sep_bit,
			{ "Wait Frame Separation Bit", "ebhscr.eth.wfsb",
			FT_BOOLEAN, 16,
			NULL, 0x0800,
			NULL, HFILL }
		},
		{ &hf_eth_tx_trunc,
			{ "If value 1 then a Truncation occurred. The frame is sent truncated.", "ebhscr.eth.trc",
			FT_BOOLEAN, 64, NULL,
			0x0001000000000000,
			NULL, HFILL }
		},
		{ &hf_eth_trans_undrun,
			{ "If value 1 then a Transmitter Underrun occurred.", "ebhscr.eth.trudr",
			FT_BOOLEAN, 64, NULL,
			0x0002000000000000,
			NULL, HFILL }
		},
		{ &hf_eth_retrans_limit,
			{ "If value 1 then the Retransmission Limit was reached", "ebhscr.eth.rtrlmt",
			FT_BOOLEAN, 64, NULL,
			0x0004000000000000,
			NULL, HFILL }
		},
		{ &hf_eth_late_collision,
			{ "If value 1 then a Late collision was detected.", "ebhscr.eth.ltcls",
			FT_BOOLEAN, 64, NULL,
			0x0008000000000000,
			NULL, HFILL }
		},
		{ &hf_ts_time_offset_valid,
			{ "Time offset in ns valid (byte 0-7)", "ebhscr.ts.tov",
			FT_BOOLEAN, 16,	NULL,
			0x0001,
			NULL, HFILL }
		},
		{ &hf_ts_last_offset_change_valid,
		{ "Last offset change in ns valid (byte 8-15)", "ebhscr.ts.locv",
			FT_BOOLEAN, 16,
			NULL, 0x0002,
			NULL, HFILL }
		},
		{ &hf_ts_nano_seconds_last_jump_valid,
			{ "Nano seconds last jump valid (byte 16-23)", "ebhscr.ts.nsljv",
			FT_BOOLEAN, 16,
			NULL, 0x0004,
			NULL, HFILL }
		},
		{ &hf_ts_UTC_leap_seconds_valid,
		{ "UTC leap seconds valid (byte 24-25)", "ebhscr.ts.utclsv",
			FT_BOOLEAN, 16,
			NULL, 0x0008,
			NULL, HFILL }
		},
		{ &hf_ts_sync_state_valid,
		{ "Sync state valid (byte 26-27)", "ebhscr.ts.ssv",
			FT_BOOLEAN, 16,
			NULL, 0x0010,
			NULL, HFILL }
		},
		{ &hf_ts_time_source,
		{ "Time source", "ebhscr.ts.tsrc",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(ts_time_source_strings), 0x0,
			NULL, HFILL }
		},
		{ &hf_ts_time_offset_ns,
		{ "Time offset in nanoseconds", "ebhscr.ts.off", FT_UINT64, BASE_HEX,
			NULL, 0, "The offset is the difference of the zero-based capture counter to TAI", HFILL }
		},
		{ &hf_ts_last_offset_ns,
			{ "Last offset change in nano seconds", "ebhscr.ts.lstoff", FT_UINT64, BASE_HEX,
			NULL, 0, "Point in time of last change of time offset.", HFILL }
		},
		{ &hf_ts_last_jump_ns,
			{ "Nano seconds last jump", "ebhscr.ts.lstjmp", FT_UINT64, BASE_HEX,
			NULL, 0, "Point in time of last hard change/jump of time count after the jump.", HFILL }
		},
		{ &hf_ts_utc_leap_sec,
			{ "UTC leap-seconds", "ebhscr.ts.leap", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_ts_sync_state,
			{ "Sync state", "ebhscr.ts.syn", FT_UINT16, BASE_HEX,
			VALS(ts_sync_state_strings), 0, NULL, HFILL }
		},
		{ &hf_lin_1_3_classic_chksum,
			{ "LIN 1.3 Classic Checksum received", "ebhscr.lin.clchksum",
			FT_BOOLEAN, 16,
			NULL, 0x0001,
			"During reception the checksum is validated to determine this bit."
			"If the received checksum is invalid this bit can not be evaluated."
			"Version 1.3 checksum is calculated over data bytes.", HFILL }
		},
		{ &hf_lin_1_2_enhanced_chksum,
			{ "LIN 2.0 Enhanced Checksum received", "ebhscr.lin.enchksum",
			FT_BOOLEAN, 16,
			NULL, 0x0002,
			"During reception the checksum is validated to determine this bit."
			"If the received checksum is invalid this bit can not be evaluated."
			"Version 2.0 checksum is calculated over ID and data byes.", HFILL }
		},
		{ &hf_lin_wakeup,
			{ "LIN Wake-Up Packet was received", "ebhscr.lin.wakeup",
			FT_BOOLEAN, 16,
			NULL, 0x0010,
			"A wakeup packet contains no payload (Payload length field is set to 0)."
			"The wakeup length field in the major number specific header is set.", HFILL }
		},
		{ &hf_lin_time_jump,
            { "Time jump occurred near the edge and thus the timestamp was estimated", "ebhscr.lin.timejmp",
			FT_BOOLEAN, 16,
			NULL, 0x0400,
			"Only relevant for capture, ignored for replay.", HFILL }
		},
		{ &hf_lin_reserved_bytes,
			{ "Reserved", "ebhscr.lin.rsv",
			FT_BOOLEAN, 64, NULL,
			0x00000000FFFFFFFF,
			NULL, HFILL }
		},
		{ &hf_lin_wakeup_length,
			{ "Wake-Up signal low phase length in us", "ebhscr.lin.wakeup.length",
			FT_UINT64, BASE_DEC, NULL,
			0xFFFF000000000000,
			"Only valid if wakeup bit in status header is set. Set to 0 otherwise.", HFILL }
		},
		{ &hf_lin_sts_reserved,
			{ "Reserved bit", "ebhscr.lin.bitrsv",
			FT_BOOLEAN, 64,
			NULL, 0x0000000100000000,
			NULL, HFILL }
		},
		{ &hf_lin_sts_syn,
			{ "SYN - Received synchronization field is not 0x55", "ebhscr.lin.syn",
			FT_BOOLEAN, 64,
			NULL, 0x0000000200000000,
			NULL, HFILL }
		},
		{ &hf_lin_sts_par,
			{ "PAR - Received parity does not match calculated parity", "ebhscr.lin.par",
			FT_BOOLEAN, 64,
			NULL, 0x0000000400000000,
			NULL, HFILL }
		},
		{ &hf_lin_sts_res,
			{ "RES - No response detected after LIN header", "ebhscr.lin.res",
			FT_BOOLEAN, 64,
			NULL, 0x0000000800000000,
			NULL, HFILL }
		},
		{ &hf_lin_sts_dat,
			{ "DAT - Too many data bytes received", "ebhscr.lin.dat",
			FT_BOOLEAN, 64,
			NULL, 0x0000001000000000,
			NULL, HFILL }
		},
		{ &hf_lin_sts_chk,
			{ "CHK - Checksum is invalid", "ebhscr.lin.chk",
			FT_BOOLEAN, 64,
			NULL, 0x0000002000000000,
			NULL, HFILL }
		},
		{ &hf_lin_sts_sta,
			{ "STA - Expected start bit, but detected recessive bus level", "ebhscr.lin.sta",
			FT_BOOLEAN, 64,
			NULL, 0x0000004000000000,
			NULL, HFILL }
		},
		{ &hf_lin_sts_sto,
			{ "STO - Expected stop bit, but detected recessive bus level", "ebhscr.lin.sto",
			FT_BOOLEAN, 64,
			NULL, 0x0000008000000000,
			NULL, HFILL }
		},
		{ &hf_lin_sts_emp,
			{ "EMP - Break and Sync received, but no further data", "ebhscr.lin.emp",
			FT_BOOLEAN, 64,
			NULL, 0x0000010000000000,
			NULL, HFILL }
		},
		{ &hf_lin_payload,
			{ "Payload", "ebhscr.lin.payload",
			FT_BYTES, SEP_SPACE,
			NULL, 0x0,
			NULL, HFILL }
			},
		{ &hf_lin_payload_pid,
			{ "LIN protected identifier", "ebhscr.lin.payload.pid",
			FT_UINT8, BASE_HEX,
			NULL, 0,
			NULL, HFILL }
			},
		{ &hf_lin_payload_id,
			{ "LIN identifier", "ebhscr.lin.payload.id",
			FT_UINT8, BASE_HEX,
			NULL, 0x3F,
			NULL, HFILL }
			},
		{ &hf_lin_payload_id_parity_0,
			{ "LIN identifier parity bit 0", "ebhscr.lin.payload.id_parity0",
			FT_UINT8, BASE_HEX,
			NULL, 0x40,
			NULL, HFILL }
			},
		{ &hf_lin_payload_id_parity_1,
			{ "LIN identifier parity bit 1", "ebhscr.lin.payload.id_parity1",
			FT_UINT8, BASE_HEX,
			NULL, 0x80,
			NULL, HFILL }
			},
		{ &hf_lin_payload_data,
			{ "Data", "ebhscr.lin.payload.data",
			FT_BYTES, SEP_SPACE,
			NULL, 0x0,
			NULL, HFILL }
			},
		{ &hf_lin_payload_checksum,
			{ "Checksum", "ebhscr.lin.payload.checksum",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
			},
		{ &hf_dio_overflow_mon_unit,
			{ "Overflow in the monitoring unit", "ebhscr.dio.ofw_mon",
			FT_BOOLEAN, 16,
			NULL, 0x0001,
			"Set to 1 in case of an overflow in the monitoring unit. In this case all remaining fields are invalid.", HFILL }
		},
		{ &hf_dio_jump_occurred,
			{ "Time jump occurred", "ebhscr.dio.jump_occ",
			FT_BOOLEAN, 16,
			NULL, 0x0400,
			"Set to 1 if a time jump occurred near the edge and thus the timestamp was estimated.", HFILL }
		},
		{ &hf_dio_value_type,
			{ "Digital IO value type", "ebhscr.dio.valtype",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			VALS64(dio_val_type_strings), 0x0300000000000000,
			NULL, HFILL }
		},
		{ &hf_dio_channel_ref,
			{ "Digital IO EBHSCR header 'Channel' referrence", "ebhscr.dio.ch_ref",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			VALS64(dio_channel_ref_strings), 0x0400000000000000,
			NULL, HFILL }
		},
		{ &hf_dio_gpio_id,
			{ "Digital IO GPIO ID", "ebhscr.dio.gpio_id",
			FT_UINT64, BASE_DEC | BASE_VAL64_STRING,
			NULL, 0x00FF000000000000,
			"Specifies the ID of a GPIO. Based on the Physical Module this may refer to a physical"
			"GPIO-PIN on the interface module or a virtual GPIO-ID", HFILL }
		},
		{ &hf_dio_reserved_bytes,
			{ "Reserved Flags", "ebhscr.dio.rsv",
			FT_BOOLEAN, 64, NULL,
			0x0000FFFFFFFFFFFF,
			NULL, HFILL }
		},
		{ &hf_flexray_ch_a,
			{ "Channel A", "ebhscr.flexray.cha",
			FT_BOOLEAN, 8, NULL,
			0x01,
			NULL, HFILL}
		},
		{ &hf_flexray_ch_b,
			{ "Channel B", "ebhscr.flexray.chb",
			FT_BOOLEAN, 8, NULL,
			FLEXRAY_CHANNEL_B_MASK,
			NULL, HFILL}
		},
		{ &hf_flexray_ctrl_id,
			{ "Controller id", "ebhscr.flexray.ctrl",
			FT_UINT8, BASE_HEX,
			NULL, 0x1C,
			NULL, HFILL}
		},
		{ &hf_flexray_monitoring_bit,
			{ "Synchronous monitoring packet", "ebhscr.flexray.syncmon",
			FT_UINT16, BASE_HEX,
			VALS(flexray_monitoring_bit_strings), 0x0001,
			NULL, HFILL }
		},
		{ &hf_flexray_sync_bit,
			{ "If value 1 then FlexRay cluster is sync (only valid if bit 0 = 1).", "ebhscr.flexray.sync",
			FT_BOOLEAN, 16,
			NULL, 0x0002,
			NULL, HFILL }
		},
		{ &hf_flexray_packet_type,
			{ "FlexRay packet type", "ebhscr.flexray.pkttype",
			FT_UINT16, BASE_HEX,
			VALS(flexray_packet_type_strings), 0x000C,
			NULL, HFILL }
		},
		{ &hf_flexray_CODERR,
			{ "Coding error", "ebhscr.flexray.coderr",
			FT_BOOLEAN, 16,
			NULL, FLEXRAY_CODERR_MASK,
			"Indicates if a Frame Start Sequence Error (FSSERR) or a Byte Start Sequence error (BSSERR)", HFILL }
		},
		{ &hf_flexray_TSSVIOL,
			{ "TSS violation", "ebhscr.flexray.tssviol",
			FT_BOOLEAN, 16,
			NULL, FLEXRAY_TSSVIOL_MASK,
			NULL, HFILL }
		},
		{ &hf_flexray_HCRCERR,
			{ "Header CRC error", "ebhscr.flexray.hcrcerr",
			FT_BOOLEAN, 16,
			NULL, FLEXRAY_HCRCERR_MASK,
			NULL, HFILL }
		},
		{ &hf_flexray_FCRCERR,
			{ "Frame CRC error", "ebhscr.flexray.fcrcerr",
			FT_BOOLEAN, 16,
			NULL, FLEXRAY_FCRCERR_MASK,
			NULL, HFILL }
		},
		{ &hf_flexray_FESERR,
			{ "Frame end sequence error", "ebhscr.flexray.feserr",
			FT_BOOLEAN, 16,
			NULL, FLEXRAY_FESERR_MASK,
			NULL, HFILL }
		},
		{ &hf_flexray_FSSERR,
			{ "Frame start sequence error", "ebhscr.flexray.fsserr",
			FT_BOOLEAN, 16,
			NULL, 0x0200,
			NULL, HFILL }
		},
		{ &hf_flexray_BSSERR,
			{ "Byte start sequence error", "ebhscr.flexray.bsserr",
			FT_BOOLEAN, 16,
			NULL, 0x0400,
			NULL, HFILL }
		},
		{ &hf_flexray_jump_occurred,
			{ "Time jump occurred", "ebhscr.flexray.jump_occ",
			FT_BOOLEAN, 16,
			NULL, 0x0800,
			"Set to 1 if a time jump occurred near the edge and thus the timestamp was estimated.", HFILL }
		},
		{ &hf_flexray_overflow_err,
			{ "Overflow error", "ebhscr.flexray.overflow_err",
			FT_BOOLEAN, 16,
			NULL, 0x0010,
			"FIFO overflow error. Captured FlexRay data were lost.", HFILL }
		},
		{ &hf_flexray_slot_information,
			{ "Slot information", "ebhscr.flexray.slotinfo",
			FT_UINT16, BASE_HEX,
			NULL, 0,
			NULL, HFILL }
		},
		{ &hf_flexray_SBV,
			{ "Slot boundary violation", "ebhscr.flexray.slotinfo.sbv",
			FT_BOOLEAN, 16,
			NULL, 0x8000,
			NULL, HFILL }
		},
		{ &hf_flexray_ACI,
			{ "Additional communication indicator", "ebhscr.flexray.slotinfo.aci",
			FT_BOOLEAN, 16,
			NULL, 0x4000,
			NULL, HFILL }
		},
		{ &hf_flexray_CED,
			{ "Content error detected", "ebhscr.flexray.slotinfo.ced",
			FT_BOOLEAN, 16,
			NULL, 0x2000,
			NULL, HFILL }
		},
		{ &hf_flexray_SED,
			{ "Syntax error detected", "ebhscr.flexray.slotinfo.sed",
			FT_BOOLEAN, 16,
			NULL, 0x1000,
			NULL, HFILL }
		},
		{ &hf_flexray_VFR,
			{ "Valid Frame Received", "ebhscr.flexray.slotinfo.vfr",
			FT_BOOLEAN, 16,
			NULL, 0x0800,
			NULL, HFILL }
		},
		{ &hf_flexray_SID,
			{ "Slot ID", "ebhscr.flexray.slotinfo.sid",
			FT_UINT16, BASE_HEX,
			NULL, 0x07FF,
			NULL, HFILL }
		},
		{ &hf_flexray_frame_status,
			{ "Frame status", "ebhscr.flexray.framests",
			FT_UINT16, BASE_HEX,
			NULL, 0,
			NULL, HFILL }
		},
		{ &hf_flexray_SPLERR,
			{ "Static payload length error", "ebhscr.flexray.framests.splerr",
			FT_BOOLEAN, 16,
			NULL, 0x8000,
			NULL, HFILL }
		},
		{ &hf_flexray_CCERR,
			{ "Cycle counter error", "ebhscr.flexray.framests.ccerr",
			FT_BOOLEAN, 16,
			NULL, 0x4000,
			NULL, HFILL }
		},
		{ &hf_flexray_FIDERR,
			{ "Frame ID error", "ebhscr.flexray.framests.fiderr",
			FT_BOOLEAN, 16,
			NULL, 0x2000,
			NULL, HFILL }
		},
		{ &hf_flexray_SSERR,
			{ "Sync or startup error", "ebhscr.flexray.framests.sserr",
			FT_BOOLEAN, 16,
			NULL, 0x1000,
			NULL, HFILL }
		},
		{ &hf_flexray_NERR,
			{ "Null frame error", "ebhscr.flexray.framests.nerr",
			FT_BOOLEAN, 16,
			NULL, 0x0800,
			NULL, HFILL }
		},
		{ &hf_flexray_SOVERR,
			{ "Slot overbooked error", "ebhscr.flexray.framests.soverr",
			FT_BOOLEAN, 16,
			NULL, 0x0400,
			NULL, HFILL }
		},
		{ &hf_flexray_SWVIOL,
			{ "Symbol Window violation", "ebhscr.flexray.framests.swviol",
			FT_BOOLEAN, 16,
			NULL, 0x0200,
			NULL, HFILL }
		},
		{ &hf_flexray_NITVIOL,
			{ "NIT violation", "ebhscr.flexray.framests.nitviol",
			FT_BOOLEAN, 16,
			NULL, 0x0100,
			NULL, HFILL }
		},
		{ &hf_flexray_BVIOL,
			{ "Boundary violation", "ebhscr.flexray.framests.bviol",
			FT_BOOLEAN, 16,
			NULL, 0x0080,
			NULL, HFILL }
		},
		{ &hf_flexray_PCD,
			{ "Prolonged channel idle detection", "ebhscr.flexray.framests.pcd",
			FT_BOOLEAN, 16,
			NULL, 0x0040,
			"FES to CHIRP took longer than 11 bit times. This is always true for dynamic frames because of the DTS.", HFILL }
		},
		{ &hf_flexray_SYNCERR,
			{ "Sync and/or startup bit wrongly set", "ebhscr.flexray.framests.syncerr",
			FT_BOOLEAN, 16,
			NULL, 0x0020,
			NULL, HFILL }
		},
		{ &hf_flexray_CP,
			{ "Communication cycle part", "ebhscr.flexray.framests.cp",
			FT_UINT16, BASE_HEX,
			VALS(flexray_CP_strings), 0x0018,
			NULL, HFILL }
		},
		{ &hf_flexray_BRC,
			{ "Byte Received Counter", "ebhscr.flexray.framests.brc",
			FT_UINT16, BASE_HEX,
			NULL, 0x0007,
			"Number of bytes received by the decoder without coding error. When more than 7 bytes are received, the counter is set to 7", HFILL }
		},
		{ &hf_flexray_symbol_length_and_status,
			{ "Symbol length and status", "ebhscr.flexray.slsts",
			FT_UINT8, BASE_HEX,
			NULL, 0,
			NULL, HFILL }
		},
		{ &hf_flexray_SYERR,
			{ "The low phase was too long", "ebhscr.flexray.slsts.syerr",
			FT_BOOLEAN, 8,
			NULL, 0x80,
			NULL, HFILL }
		},
		{ &hf_flexray_SL,
			{ "Symbol length in units of bit cells", "ebhscr.flexray.slsts.sl",
			FT_UINT8, BASE_DEC,
			NULL, 0x7F,
			NULL, HFILL }
		},
		{ &hf_flexray_POC_state,
			{ "Protocol operation control state", "ebhscr.flexray.pocstate",
			FT_UINT8, BASE_HEX,
			VALS(flexray_POC_state_strings), 0,
			NULL, HFILL }
		},
		{ &hf_flexray_following_cycle_counter,
			{ "Cycle counter of following cycle", "ebhscr.flexray.fcc",
			FT_UINT8, BASE_DEC,
			NULL, 0,
			NULL, HFILL }
		},
		{ &hf_flexray_supercycle_counter,
			{ "Supercycle counter", "ebhscr.flexray.scc",
			FT_UINT32, BASE_DEC,
			NULL, 0,
			NULL, HFILL }
		},
		{ &hf_dsi3_status_crc_error,
			{ "CRC Error", "ebhscr.dsi3.status_crc_err",
			FT_BOOLEAN, 16,
			TFS(&dsi3_status_err_CRC_strings), 0x01,
			NULL, HFILL }
		},
		{ &hf_dsi3_status_transition_error,
			{ "Transition Error", "ebhscr.dsi3.status_trans_err",
			FT_BOOLEAN, 16,
			TFS(&dsi3_status_err_trans_strings), 0x02,
			NULL, HFILL }
		},
		{ &hf_dsi3_status_packet_truncated_error,
			{ "Packet Truncated Error", "ebhscr.dsi3.status_trunc_err",
			FT_BOOLEAN, 16,
			TFS(&dsi3_status_err_trunc_strings), 0x04,
			NULL, HFILL }
		},
		{ &hf_dsi3_status_packet_dropped_error,
			{ "Packet Dropped Error", "ebhscr.dsi3.status_drop_err",
			FT_BOOLEAN, 16,
			TFS(&dsi3_status_err_drop_strings), 0x08,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_st0_command_type,
			{ "DSI3 Command Type", "ebhscr.dsi3.st0.cmd_type",
			FT_BOOLEAN, 32,
			TFS(&dsi3_mjr_hdr_st0_command_type_strings), 0x0100000,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_slave_st0_bit_count,
			{ "Bit Count", "ebhscr.dsi3.sl.st0.bit_cnt",
			FT_UINT32, BASE_HEX,
			NULL, 0x70000000,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_slave_st2_blnk_err,
			{ "Blanking Error", "ebhscr.dsi3.sl.st2.blnk_err",
			FT_BOOLEAN, 32,
			NULL, 0x00000100,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_slave_st2_no_trans_err,
			{ "No Transmission", "ebhscr.dsi3.sl.st2.no_trans",
			FT_BOOLEAN, 32,
			NULL, 0x00000200,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_slave_st3_crc_err,
			{ "CRC Error", "ebhscr.dsi3.sl.st3.crc_err",
			FT_BOOLEAN, 32,
			NULL, 0x00000001,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_slave_st3_cnt_overflow,
			{ "Counter Overflow", "ebhscr.dsi3.sl.st3.cnt_overflow",
			FT_BOOLEAN, 32,
			NULL, 0x00000002,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_slave_st3_disabled_err,
			{ "Disabled Error", "ebhscr.dsi3.sl.st3.disabled_err",
			FT_BOOLEAN, 32,
			NULL, 0x00000004,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_slave_st3_trunc_data,
			{ "Truncate Data", "ebhscr.dsi3.sl.st3.trunc_data",
			FT_BOOLEAN, 32,
			NULL, 0x00000008,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_slave_st3_drop_data,
			{ "Drop Data", "ebhscr.dsi3.sl.st3.drop_data",
			FT_BOOLEAN, 32,
			NULL, 0x00000010,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_master_st0_nibble_count,
			{ "Nibble Count", "ebhscr.dsi3.ms.st0.nbc",
			FT_UINT32, BASE_HEX,
			NULL, 0x10000000,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_master_st2_blnk_err,
			{ "Blanking error", "ebhscr.dsi3.ms.st2.blnk_err",
			FT_BOOLEAN, 32,
			NULL, 0x00000100,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_master_st2_bad_trans_err,
			{ "Bad Transition", "ebhscr.dsi3.ms.st2.bad_trans",
			FT_BOOLEAN, 32,
			NULL, 0x00000200,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_master_st2_bad_chip_err,
			{ "Bad Chip", "ebhscr.dsi3.ms.st2.bad_chip",
			FT_BOOLEAN, 32,
			NULL, 0x00000400,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_master_st2_no_trans_err,
			{ "No Transition", "ebhscr.dsi3.ms.st2.no_trans",
			FT_BOOLEAN, 32,
			NULL, 0x00000800,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_master_st3_crc_err,
			{ "CRC Error", "ebhscr.dsi3.ms.st3.crc_err",
			FT_BOOLEAN, 32,
			NULL, 0x00000001,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_master_st3_bad_decode_err,
			{ "Bad Decode", "ebhscr.dsi3.ms.st3.bad_dec_err",
			FT_BOOLEAN, 32,
			NULL, 0x00000002,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_master_st3_cnt_overflow,
			{ "Counter Overflow", "ebhscr.dsi3.ms.st3.cnt_overflow",
			FT_BOOLEAN, 32,
			NULL, 0x00000004,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_master_st3_disable_err,
			{ "Disable Error", "ebhscr.dsi3.ms.st3.dsbl_err",
			FT_BOOLEAN, 32,
			NULL, 0x00000008,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_master_st3_trunc_data,
			{ "Truncate Data", "ebhscr.dsi3.ms.st3.trunc_data",
			FT_BOOLEAN, 32,
			NULL, 0x00000010,
			NULL, HFILL }
		},
		{ &hf_dsi3_mjr_hdr_master_st3_drop_data,
			{ "Drop Data", "ebhscr.dsi3.ms.st3.drop_data",
			FT_BOOLEAN, 32,
			NULL, 0x00000020,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_status_packet_checksum_err,
			{ "MIPI CSI-2 long packet checksum error", "ebhscr.mipi_csi2.st.chceksum_err",
			FT_BOOLEAN, 12,
			NULL, 0x001,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_status_ecc_err,
			{ "MIPI CSI-2 packet header contains an uncorrectable ECC error", "ebhscr.mipi_csi2.st.ecc_err",
			FT_BOOLEAN, 12,
			NULL, 0x004,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_status_payload_fifo_overflow,
			{ "Payload FIFO Overflow error", "ebhscr.mipi_csi2.st.pld_fifo_of",
			FT_BOOLEAN, 12,
			NULL, 0x008,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_status_header_fifo_overflow,
			{ "Header FIFO Overflow error", "ebhscr.mipi_csi2.st.hdr_fifo_of",
			FT_BOOLEAN, 12,
			NULL, 0x010,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_status_rcv_decoder_err,
			{ "Receiver Decoder error", "ebhscr.mipi_csi2.st.rcv_dec_err",
			FT_BOOLEAN, 12,
			NULL, 0x020,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_status_payload_trunc_err,
			{ "Payload Truncated Error", "ebhscr.mipi_csi2.st.pld_trunc_err",
			FT_BOOLEAN, 12,
			NULL, 0x040,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_status_trans_rejected,
			{ "Transmission Rejected", "ebhscr.mipi_csi2.st.trns_rjct",
			FT_BOOLEAN, 12,
			NULL, 0x400,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_mjr_hdr_flags_packet_checksum_err,
			{ "MIPI CSI-2 long packet checksum error", "ebhscr.mipi_csi2.mjhdr.flg.pkt_chsm_err",
			FT_BOOLEAN, 16,
			NULL, 0x01,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_mjr_hdr_flags_correctable_ecc_err,
			{ "MIPI CSI-2 packet header contains an correctable ECC error", "ebhscr.mipi_csi2.mjhdr.flg.corr_ecc_err",
			FT_BOOLEAN, 16,
			NULL, 0x02,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_mjr_hdr_flags_uncorrectable_ecc_err,
			{ "MIPI CSI-2 packet header contains an uncorrectable ECC error", "ebhscr.mipi_csi2.mjhdr.flg.uncorr_ecc_err",
			FT_BOOLEAN, 16,
			NULL, 0x04,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_mjr_hdr_flags_mipi_phy_type,
			{ "MIPI PHY Type", "ebhscr.mipi_csi2.mjhdr.flg.phy_type",
			FT_BOOLEAN, 16,
			TFS(&hf_mipi_csi2_mjr_hdr_flags_mipi_phy_type_string), 0x4000,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_mjr_hdr_flags_first_line_of_frame,
			{ "Packet contains first line of a frame", "ebhscr.mipi_csi2.mjhdr.flg.flof",
			FT_BOOLEAN, 16,
			NULL, 0x8000,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_mjr_hdr_frame_counter,
			{ "Frame Counter", "ebhscr.mipi_csi2.mjhdr.frame_cnt",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_mjr_hdr_line_counter,
			{ "Line Counter", "ebhscr.mipi_csi2.mjhdr.line_cnt",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_payload_pkt_hdr,
			{ "MIPI CSI-2 Packet Header", "ebhscr.mipi_csi2.pkt_hdr",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_payload_pkt_hdr_dt,
			{ "Data Type", "ebhscr.mipi_csi2.pkt_hdr.data_type",
			FT_UINT8, BASE_HEX,
			NULL, 0x3F,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_payload_pkt_hdr_vc,
			{ "Virtual Channel", "ebhscr.mipi_csi2.pkt_hdr.vc",
			FT_UINT8, BASE_HEX,
			NULL, 0x03,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_payload_pkt_hdr_ecc,
			{ "ECC", "ebhscr.mipi_csi2.pkt_hdr.ecc",
			FT_UINT8, BASE_HEX,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_payload_pkt_hdr_crc,
			{ "Checksum", "ebhscr.mipi_csi2.pkt_hdr.crc",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_payload_pkt_hdr_wc_lsb,
			{ "Word Count / Short packet Data Field (LSB)", "ebhscr.mipi_csi2.pkt_hdr.wc.lsb",
			FT_UINT16, BASE_HEX,
			NULL, 0xFF00,
			NULL, HFILL }
		},
		{ &hf_mipi_csi2_payload_pkt_hdr_wc_msb,
			{ "Word Count / Short packet Data Field (MSB)", "ebhscr.mipi_csi2.pkt_hdr.wc.msb",
			FT_UINT16, BASE_HEX,
			NULL, 0x00FF,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_status_packet_checksum_err,
			{ "MIPI CSI-2 long packet checksum error", "ebhscr.csi2_frame.st.checksum_err",
			FT_BOOLEAN, 12,
			NULL, 0x001,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_status_ecc_err,
			{ "MIPI CSI-2 packet header contains an uncorrectable ECC error", "ebhscr.csi2_frame.st.ecc_err",
			FT_BOOLEAN, 12,
			NULL, 0x004,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_status_rcv_decoder_err,
			{ "Receiver Decoder error", "ebhscr.csi2_frame.st.decoder_err",
			FT_BOOLEAN, 12,
			NULL, 0x008,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_status_section_err,
			{ "Section Error", "ebhscr.csi2_frame.st.section_err",
			FT_BOOLEAN, 12,
			NULL, 0x010,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_status_fifo_overflow,
			{ "FIFO Overflow error", "ebhscr.csi2_frame.st.fifo_of",
			FT_BOOLEAN, 12,
			NULL, 0x020,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_status_payload_trunc_err,
			{ "Payload Truncated Error", "ebhscr.csi2_frame.st.trunc_err",
			FT_BOOLEAN, 12,
			NULL, 0x040,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_status_trans_rejected,
			{ "Transmission Rejected", "ebhscr.csi2_frame.st.trns_rjct",
			FT_BOOLEAN, 12,
			NULL, 0x400,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_mjr_hdr_flags_proc,
			{ "The image has been processed", "ebhscr.csi2_frame.mjr_hdr.flags.proc",
			FT_BOOLEAN, 32,
			NULL, 0x00010000,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_mjr_hdr_flags_pad_align,
			{ "Padding and alignment of 8 bytes", "ebhscr.csi2_frame.mjr_hdr.flags.pd_algn",
			FT_BOOLEAN, 32,
			NULL, 0x00040000,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_mjr_hdr_flags_mipi_phy_type,
			{ "MIPI PHY Type", "ebhscr.csi2_frame.mjr_hdr.flags.phy_type",
			FT_BOOLEAN, 32,
			TFS(&hf_mipi_csi2_mjr_hdr_flags_mipi_phy_type_string), 0x80000000,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_mjr_hdr_vc,
			{ "Virtual Channel", "ebhscr.csi2_frame.mjr_hdr.vc",
			FT_UINT32, BASE_HEX,
			NULL, 0x00000F00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_mjr_hdr_imhv,
			{ "Image Header Version", "ebhscr.csi2_frame.mjr_hdr.imhv",
			FT_UINT32, BASE_HEX,
			NULL, 0x000000FF,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_header,
			{ "CSI-2 Frame Packet Header", "ebhscr.csi2_frame_hdrs",
			FT_BYTES, BASE_NO_DISPLAY_VALUE,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_sections[0],
			{ "Section 0", "ebhscr.csi2_frame_hdr0",
			FT_BYTES, BASE_NO_DISPLAY_VALUE,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_sections[1],
			{ "Section 1", "ebhscr.csi2_frame_hdr1",
			FT_BYTES, BASE_NO_DISPLAY_VALUE,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_sections[2],
			{ "Section 2", "ebhscr.csi2_frame_hdr2",
			FT_BYTES, BASE_NO_DISPLAY_VALUE,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_sections[3],
			{ "Section 3", "ebhscr.csi2_frame_hdr3",
			FT_BYTES, BASE_NO_DISPLAY_VALUE,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_sections[4],
			{ "Section 4", "ebhscr.csi2_frame_hdr4",
			FT_BYTES, BASE_NO_DISPLAY_VALUE,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_sections[5],
			{ "Section 5", "ebhscr.csi2_frame_hdr5",
			FT_BYTES, BASE_NO_DISPLAY_VALUE,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_sections[6],
			{ "Section 6", "ebhscr.csi2_frame_hdr6",
			FT_BYTES, BASE_NO_DISPLAY_VALUE,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_sections[7],
			{ "Section 7", "ebhscr.csi2_frame_hdr7",
			FT_BYTES, BASE_NO_DISPLAY_VALUE,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_header_payload_byte_offset,
			{ "Payload Byte Offset", "ebhscr.csi2_frame_hdr.pbo",
			FT_UINT32, BASE_DEC,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_header_bytes_total,
			{ "Bytes Total", "ebhscr.csi2_frame_hdr.byte_total",
			FT_UINT32, BASE_DEC,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_header_bytes_per_line,
			{ "Bytes Per Line", "ebhscr.csi2_frame_hdr.bpl",
			FT_UINT16, BASE_DEC,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_header_number_lines,
			{ "Number Lines", "ebhscr.csi2_frame_hdr.num_lines",
			FT_UINT16, BASE_DEC,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_header_error_bits_field,
			{ "Error Bits", "ebhscr.csi2_frame_hdr.err_bits",
			FT_UINT8, BASE_HEX,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_header_mipi_data_type,
			{ "MIPI Data Type", "ebhscr.csi2_frame_hdr.mipi_dt",
			FT_UINT8, BASE_HEX,
			NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_header_error_bits_packet_checksum_err,
			{ "MIPI CSI-2 long packet checksum error", "ebhscr.csi2_frame_hdr.err_bits.crc_err",
			FT_BOOLEAN, 8,
			NULL, 0x01,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_header_error_bits_correctable_ecc_err,
			{ "MIPI CSI-2 packet header contains an correctable ECC error", "ebhscr.csi2_frame_hdr.err_bits.cor_ecc_err",
			FT_BOOLEAN, 8,
			NULL, 0x02,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_header_error_bits_uncorrectable_ecc_err,
			{ "MIPI CSI-2 packet header contains an uncorrectable ECC error", "ebhscr.csi2_frame_hdr.err_bits.uncor_ecc_err",
			FT_BOOLEAN, 8,
			NULL, 0x04,
			NULL, HFILL }
		},
		{ &hf_csi2_frame_header_error_bits_rcv_dec_err,
			{ "Receiver Decoder error", "ebhscr.csi2_frame_hdr.err_bits.rcv_decode_err",
			FT_BOOLEAN, 8,
			NULL, 0x08,
			NULL, HFILL }
		}
	};

	static int *ett[] = {
		&ett_ebhscr,
		&ett_ebhscr_channel,
		&ett_ebhscr_packet_header,
		&ett_ebhscr_status,
		&ett_ebhscr_mjr_hdr,
		&ett_lin_payload,
	};

	static ei_register_info ei[] = {
		{ &ei_ebhscr_frame_header,
			{ "ebhscr.frame_header", PI_MALFORMED, PI_ERROR,
			"Frame Header is malformed", EXPFILL }
		},
		{ &ei_ebhscr_err_status_flag,
			{ "ebhscr.sts.err.status", PI_PROTOCOL, PI_WARN,
			"Status Flag is set", EXPFILL }
		},
		{ &ei_ebhscr_info_status_flag,
			{ "ebhscr.sts.info.status", PI_PROTOCOL, PI_CHAT,
			"Status Flag is set", EXPFILL }
		},
		{ &ei_ebhscr_err_channel_flag,
			{ "ebhscr.channel.err", PI_PROTOCOL, PI_ERROR,
			"Channel number is invalid", EXPFILL }
		},
		{ &ei_ebhscr_warn_mjr_hdr_status_flag,
			{ "ebhscr.mjrhdr.warn", PI_PROTOCOL, PI_WARN,
			"Major number specific header status flag is set", EXPFILL }
		},
		{ &ei_ebhscr_warn_csi2_hdr_error_flag,
			{ "ebhscr.csi2_frame_hdr.warn", PI_PROTOCOL, PI_WARN,
			"CSI-2 Frame header error bit is set", EXPFILL }
		}
	};

	proto_ebhscr = proto_register_protocol("EBHSCR Protocol", "EBHSCR", "ebhscr");

	proto_register_field_array(proto_ebhscr, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_ebhscr = expert_register_protocol(proto_ebhscr);
	expert_register_field_array(expert_ebhscr, ei, array_length(ei));

	ebhscr_handle = register_dissector("ebhscr", dissect_ebhscr, proto_ebhscr);
	subdissector_table = register_decode_as_next_proto(proto_ebhscr, "ebhscr.subdissector",
														"ebhscr next level dissector", NULL);
}

void
proto_reg_handoff_ebhscr(void)
{
	can_handle = find_dissector_add_dependency("can-hostendian", proto_ebhscr);
	can_fd_handle = find_dissector_add_dependency("canfd", proto_ebhscr);

	eth_withfcs_handle = find_dissector_add_dependency("eth_withfcs", proto_ebhscr);
	eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_ebhscr);
	ebhscr_user_handle = find_dissector_add_dependency("ebhscr_user", proto_ebhscr);

	flexray_handle = find_dissector_add_dependency("flexray", proto_ebhscr);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_EBHSCR, ebhscr_handle);
}

/*
 * Editor modelines - https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
