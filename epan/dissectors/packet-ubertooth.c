/* packet-ubertooth.c
 * Routines for Ubertooth USB dissection
 *
 * Copyright 2013, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>

#include "packet-bluetooth.h"
#include "packet-ubertooth.h"

static int proto_ubertooth = -1;

static int hf_command = -1;
static int hf_response = -1;
static int hf_argument_0 = -1;
static int hf_argument_1 = -1;
static int hf_estimated_length = -1;
static int hf_board_id = -1;
static int hf_reserved = -1;
static int hf_length = -1;
static int hf_firmware_revision = -1;
static int hf_firmware_compile_info = -1;
static int hf_user_led = -1;
static int hf_rx_led = -1;
static int hf_tx_led = -1;
static int hf_1v8_led = -1;
static int hf_channel = -1;
static int hf_status = -1;
static int hf_serial_number = -1;
static int hf_part_number = -1;
static int hf_packet_type = -1;
static int hf_chip_status_dma_overflow = -1;
static int hf_chip_status_dma_error = -1;
static int hf_chip_status_cs_trigger = -1;
static int hf_chip_status_fifo_overflow = -1;
static int hf_chip_status_rssi_trigger = -1;
static int hf_chip_status_reserved = -1;
static int hf_clock_ns = -1;
static int hf_clock_100ns = -1;
static int hf_rssi_min = -1;
static int hf_rssi_max = -1;
static int hf_rssi_avg = -1;
static int hf_rssi_count = -1;
static int hf_data = -1;
static int hf_crc_verify = -1;
static int hf_paen = -1;
static int hf_hgm = -1;
static int hf_modulation = -1;
static int hf_power_amplifier_reserved = -1;
static int hf_power_amplifier_level = -1;
static int hf_range_test_valid = -1;
static int hf_range_test_request_power_amplifier = -1;
static int hf_range_test_request_number = -1;
static int hf_range_test_reply_power_amplifier = -1;
static int hf_range_test_reply_number = -1;
static int hf_squelch = -1;
static int hf_register = -1;
static int hf_register_value = -1;
static int hf_access_address = -1;
static int hf_high_frequency = -1;
static int hf_low_frequency = -1;
static int hf_rx_packets = -1;
static int hf_rssi_threshold = -1;
static int hf_clock_offset = -1;
static int hf_afh_map = -1;
static int hf_bdaddr = -1;
static int hf_usb_rx_packet = -1;
static int hf_state = -1;
static int hf_crc_init = -1;
static int hf_hop_interval = -1;
static int hf_hop_increment = -1;
static int hf_usb_rx_packet_channel = -1;
static int hf_spectrum_entry = -1;
static int hf_frequency = -1;
static int hf_rssi = -1;
static int hf_jam_mode = -1;
static int hf_ego_mode = -1;
static int hf_cc2400_value = -1;
static int hf_cc2400_main_resetn = -1;
static int hf_cc2400_main_reserved_14_10 = -1;
static int hf_cc2400_main_fs_force_en = -1;
static int hf_cc2400_main_rxn_tx = -1;
static int hf_cc2400_main_reserved_7_4 = -1;
static int hf_cc2400_main_reserved_3 = -1;
static int hf_cc2400_main_reserved_2 = -1;
static int hf_cc2400_main_xosc16m_bypass = -1;
static int hf_cc2400_main_xosc16m_en = -1;
static int hf_cc2400_fsctrl_reserved = -1;
static int hf_cc2400_fsctrl_lock_threshold = -1;
static int hf_cc2400_fsctrl_cal_done = -1;
static int hf_cc2400_fsctrl_cal_running = -1;
static int hf_cc2400_fsctrl_lock_length = -1;
static int hf_cc2400_fsctrl_lock_status = -1;
static int hf_cc2400_fsdiv_reserved = -1;
static int hf_cc2400_fsdiv_frequency = -1;
static int hf_cc2400_fsdiv_freq_high = -1;
static int hf_cc2400_fsdiv_freq = -1;
static int hf_cc2400_mdmctrl_reserved = -1;
static int hf_cc2400_mdmctrl_mod_offset = -1;
static int hf_cc2400_mdmctrl_mod_dev = -1;
static int hf_cc2400_agcctrl_vga_gain = -1;
static int hf_cc2400_agcctrl_reserved = -1;
static int hf_cc2400_agcctrl_agc_locked = -1;
static int hf_cc2400_agcctrl_agc_lock = -1;
static int hf_cc2400_agcctrl_agc_sync_lock = -1;
static int hf_cc2400_agcctrl_vga_gain_oe = -1;
static int hf_cc2400_frend_reserved_15_4 = -1;
static int hf_cc2400_frend_reserved_3 = -1;
static int hf_cc2400_frend_pa_level = -1;
static int hf_cc2400_rssi_rssi_val = -1;
static int hf_cc2400_rssi_rssi_cs_thres = -1;
static int hf_cc2400_rssi_rssi_filt = -1;
static int hf_cc2400_freqest_rx_freq_offset = -1;
static int hf_cc2400_freqest_reserved = -1;
static int hf_cc2400_iocfg_reserved = -1;
static int hf_cc2400_iocfg_gio6_cfg = -1;
static int hf_cc2400_iocfg_gio1_cfg = -1;
static int hf_cc2400_iocfg_hssd_src = -1;
static int hf_cc2400_fsmtc_tc_rxon2agcen = -1;
static int hf_cc2400_fsmtc_tc_paon2switch = -1;
static int hf_cc2400_fsmtc_res = -1;
static int hf_cc2400_fsmtc_tc_txend2switch = -1;
static int hf_cc2400_fsmtc_tc_txend2paoff = -1;
static int hf_cc2400_reserved_0x0C_res_15_5 = -1;
static int hf_cc2400_reserved_0x0C_res_4_0 = -1;
static int hf_cc2400_manand_vga_reset_n = -1;
static int hf_cc2400_manand_lock_status = -1;
static int hf_cc2400_manand_balun_ctrl = -1;
static int hf_cc2400_manand_rxtx = -1;
static int hf_cc2400_manand_pre_pd = -1;
static int hf_cc2400_manand_pa_n_pd = -1;
static int hf_cc2400_manand_pa_p_pd = -1;
static int hf_cc2400_manand_dac_lpf_pd = -1;
static int hf_cc2400_manand_bias_pd = -1;
static int hf_cc2400_manand_xosc16m_pd = -1;
static int hf_cc2400_manand_chp_pd = -1;
static int hf_cc2400_manand_fs_pd = -1;
static int hf_cc2400_manand_adc_pd = -1;
static int hf_cc2400_manand_vga_pd = -1;
static int hf_cc2400_manand_rxbpf_pd = -1;
static int hf_cc2400_manand_lnamix_pd = -1;
static int hf_cc2400_fsmstate_reserved_15_13 = -1;
static int hf_cc2400_fsmstate_fsm_state_bkpt = -1;
static int hf_cc2400_fsmstate_reserved_7_5 = -1;
static int hf_cc2400_fsmstate_fsm_cur_state = -1;
static int hf_cc2400_adctst_reserved_15 = -1;
static int hf_cc2400_adctst_adc_i = -1;
static int hf_cc2400_adctst_reserved_7 = -1;
static int hf_cc2400_adctst_adc_q = -1;
static int hf_cc2400_rxbpftst_reserved = -1;
static int hf_cc2400_rxbpftst_rxbpf_cap_oe = -1;
static int hf_cc2400_rxbpftst_rxbpf_cap_o = -1;
static int hf_cc2400_rxbpftst_rxbpf_cap_res = -1;
static int hf_cc2400_pamtst_reserved_15_13 = -1;
static int hf_cc2400_pamtst_vc_in_test_en = -1;
static int hf_cc2400_pamtst_atestmod_pd = -1;
static int hf_cc2400_pamtst_atestmod_mode = -1;
static int hf_cc2400_pamtst_reserved_7 = -1;
static int hf_cc2400_pamtst_txmix_cap_array = -1;
static int hf_cc2400_pamtst_txmix_current = -1;
static int hf_cc2400_pamtst_pa_current = -1;
static int hf_cc2400_lmtst_reserved = -1;
static int hf_cc2400_lmtst_rxmix_hgm = -1;
static int hf_cc2400_lmtst_rxmix_tail = -1;
static int hf_cc2400_lmtst_rxmix_vcm = -1;
static int hf_cc2400_lmtst_rxmix_current = -1;
static int hf_cc2400_lmtst_lna_cap_array = -1;
static int hf_cc2400_lmtst_lna_lowgain = -1;
static int hf_cc2400_lmtst_lna_gain = -1;
static int hf_cc2400_lmtst_lna_current = -1;
static int hf_cc2400_manor_vga_reset_n = -1;
static int hf_cc2400_manor_lock_status = -1;
static int hf_cc2400_manor_balun_ctrl = -1;
static int hf_cc2400_manor_rxtx = -1;
static int hf_cc2400_manor_pre_pd = -1;
static int hf_cc2400_manor_pa_n_pd = -1;
static int hf_cc2400_manor_pa_p_pd = -1;
static int hf_cc2400_manor_dac_lpf_pd = -1;
static int hf_cc2400_manor_bias_pd = -1;
static int hf_cc2400_manor_xosc16m_pd = -1;
static int hf_cc2400_manor_chp_pd = -1;
static int hf_cc2400_manor_fs_pd = -1;
static int hf_cc2400_manor_adc_pd = -1;
static int hf_cc2400_manor_vga_pd = -1;
static int hf_cc2400_manor_rxbpf_pd = -1;
static int hf_cc2400_manor_lnamix_pd = -1;
static int hf_cc2400_mdmtst0_reserved = -1;
static int hf_cc2400_mdmtst0_tx_prng = -1;
static int hf_cc2400_mdmtst0_tx_1mhz_offset_n = -1;
static int hf_cc2400_mdmtst0_invert_data = -1;
static int hf_cc2400_mdmtst0_afc_adjust_on_packet = -1;
static int hf_cc2400_mdmtst0_afc_settling = -1;
static int hf_cc2400_mdmtst0_afc_delta = -1;
static int hf_cc2400_mdmtst1_reserved = -1;
static int hf_cc2400_mdmtst1_bsync_threshold = -1;
static int hf_cc2400_dactst_reserved = -1;
static int hf_cc2400_dactst_dac_src = -1;
static int hf_cc2400_dactst_dac_i_o = -1;
static int hf_cc2400_dactst_dac_q_o = -1;
static int hf_cc2400_agctst0_agc_settle_blank_dn = -1;
static int hf_cc2400_agctst0_agc_win_size = -1;
static int hf_cc2400_agctst0_agc_settle_peak = -1;
static int hf_cc2400_agctst0_agc_settle_adc = -1;
static int hf_cc2400_agctst0_agc_attempts = -1;
static int hf_cc2400_agctst1_reserved = -1;
static int hf_cc2400_agctst1_agc_var_gain_sat = -1;
static int hf_cc2400_agctst1_agc_settle_blank_up = -1;
static int hf_cc2400_agctst1_peakdet_cur_boost = -1;
static int hf_cc2400_agctst1_agc_mult_slow = -1;
static int hf_cc2400_agctst1_agc_settle_fixed = -1;
static int hf_cc2400_agctst1_agc_settle_var = -1;
static int hf_cc2400_agctst2_reserved = -1;
static int hf_cc2400_agctst2_agc_backend_blanking = -1;
static int hf_cc2400_agctst2_agc_adjust_m3db = -1;
static int hf_cc2400_agctst2_agc_adjust_m1db = -1;
static int hf_cc2400_agctst2_agc_adjust_p3db = -1;
static int hf_cc2400_agctst2_agc_adjust_p1db = -1;
static int hf_cc2400_fstst0_rxmixbuf_cur = -1;
static int hf_cc2400_fstst0_txmixbuf_cur = -1;
static int hf_cc2400_fstst0_vco_array_settle_long = -1;
static int hf_cc2400_fstst0_vco_array_oe = -1;
static int hf_cc2400_fstst0_vco_array_o = -1;
static int hf_cc2400_fstst0_vco_array_res = -1;
static int hf_cc2400_fstst1_rxbpf_locur = -1;
static int hf_cc2400_fstst1_rxbpf_midcur = -1;
static int hf_cc2400_fstst1_vco_current_ref = -1;
static int hf_cc2400_fstst1_vco_current_k = -1;
static int hf_cc2400_fstst1_vc_dac_en = -1;
static int hf_cc2400_fstst1_vc_dac_val = -1;
static int hf_cc2400_fstst2_reserved = -1;
static int hf_cc2400_fstst2_vco_curcal_speed = -1;
static int hf_cc2400_fstst2_vco_current_oe = -1;
static int hf_cc2400_fstst2_vco_current_o = -1;
static int hf_cc2400_fstst2_vco_current_res = -1;
static int hf_cc2400_fstst3_reserved = -1;
static int hf_cc2400_fstst3_chp_test_up = -1;
static int hf_cc2400_fstst3_chp_test_dn = -1;
static int hf_cc2400_fstst3_chp_disable = -1;
static int hf_cc2400_fstst3_pd_delay = -1;
static int hf_cc2400_fstst3_chp_step_period = -1;
static int hf_cc2400_fstst3_stop_chp_current = -1;
static int hf_cc2400_fstst3_start_chp_current = -1;
static int hf_cc2400_manfidl_partnum = -1;
static int hf_cc2400_manfidl_manfid = -1;
static int hf_cc2400_manfidh_version = -1;
static int hf_cc2400_manfidh_partnum = -1;
static int hf_cc2400_grmdm_reserved = -1;
static int hf_cc2400_grmdm_sync_errbits_allowed = -1;
static int hf_cc2400_grmdm_pin_mode = -1;
static int hf_cc2400_grmdm_packet_mode = -1;
static int hf_cc2400_grmdm_pre_bytes = -1;
static int hf_cc2400_grmdm_sync_word_size = -1;
static int hf_cc2400_grmdm_crc_on = -1;
static int hf_cc2400_grmdm_data_format = -1;
static int hf_cc2400_grmdm_modulation_format = -1;
static int hf_cc2400_grmdm_tx_gaussian_filter = -1;
static int hf_cc2400_grdec_reserved = -1;
static int hf_cc2400_grdec_ind_saturation = -1;
static int hf_cc2400_grdec_dec_shift = -1;
static int hf_cc2400_grdec_channel_dec = -1;
static int hf_cc2400_grdec_dec_val = -1;
static int hf_cc2400_pktstatus_reserved_15_11 = -1;
static int hf_cc2400_pktstatus_sync_word_received = -1;
static int hf_cc2400_pktstatus_crc_ok = -1;
static int hf_cc2400_pktstatus_reserved_8 = -1;
static int hf_cc2400_pktstatus_reserved_7_0 = -1;
static int hf_cc2400_int_reserved_15_8 = -1;
static int hf_cc2400_int_reserved_7 = -1;
static int hf_cc2400_int_pkt_polarity = -1;
static int hf_cc2400_int_fifo_polarity = -1;
static int hf_cc2400_int_fifo_threshold = -1;
static int hf_cc2400_reserved_0x24_res_15_14 = -1;
static int hf_cc2400_reserved_0x24_res_13_10 = -1;
static int hf_cc2400_reserved_0x24_res_9_7 = -1;
static int hf_cc2400_reserved_0x24_res_6_0 = -1;
static int hf_cc2400_reserved_0x25_res_15_12 = -1;
static int hf_cc2400_reserved_0x25_res_11_0 = -1;
static int hf_cc2400_reserved_0x26_res_15_10 = -1;
static int hf_cc2400_reserved_0x26_res_9_0 = -1;
static int hf_cc2400_reserved_0x27_res_15_8 = -1;
static int hf_cc2400_reserved_0x27_res_7_3 = -1;
static int hf_cc2400_reserved_0x27_res_2_0 = -1;
static int hf_cc2400_reserved_0x28_res_15 = -1;
static int hf_cc2400_reserved_0x28_res_14_13 = -1;
static int hf_cc2400_reserved_0x28_res_12_7 = -1;
static int hf_cc2400_reserved_0x28_res_6_0 = -1;
static int hf_cc2400_reserved_0x29_res_15_8 = -1;
static int hf_cc2400_reserved_0x29_res_7_3 = -1;
static int hf_cc2400_reserved_0x29_res_2_0 = -1;
static int hf_cc2400_reserved_0x2A_res_15_11 = -1;
static int hf_cc2400_reserved_0x2A_res_10 = -1;
static int hf_cc2400_reserved_0x2A_res_9_0 = -1;
static int hf_cc2400_reserved_0x2B_res_15_14 = -1;
static int hf_cc2400_reserved_0x2B_res_13 = -1;
static int hf_cc2400_reserved_0x2B_res_12 = -1;
static int hf_cc2400_reserved_0x2B_res_11_0 = -1;
static int hf_cc2400_syncl = -1;
static int hf_cc2400_synch = -1;

static gint ett_ubertooth = -1;
static gint ett_command = -1;
static gint ett_usb_rx_packet = -1;
static gint ett_usb_rx_packet_data = -1;
static gint ett_entry = -1;
static gint ett_register_value = -1;
static gint ett_fsdiv_frequency = -1;

static expert_field ei_unexpected_response = EI_INIT;
static expert_field ei_unknown_data = EI_INIT;
static expert_field ei_unexpected_data = EI_INIT;

static dissector_handle_t ubertooth_handle;
static dissector_handle_t bluetooth_ubertooth_handle;

static wmem_tree_t *command_info = NULL;

typedef struct _command_data {
    guint32  bus_id;
    guint32  device_address;

    guint8   command;
    guint32  command_frame_number;
    gint32   register_id;
} command_data_t;


static const value_string command_vals[] = {
    { 0,  "Ping" },
    { 1,  "Rx Symbols" },
    { 2,  "Tx Symbols" },
    { 3,  "Get User LED" },
    { 4,  "Set User LED" },
    { 5,  "Get Rx LED" },
    { 6,  "Set Rx LED" },
    { 7,  "Get Tx LED" },
    { 8,  "Set Tx LED" },
    { 9,  "Get 1V8" },
    { 10,  "Set 1V8" },
    { 11,  "Get Channel" },
    { 12,  "Set Channel" },
    { 13,  "Reset" },
    { 14,  "Get Microcontroller Serial Number" },
    { 15,  "Get Microcontroller Part Number" },
    { 16,  "Get PAEN" },
    { 17,  "Set PAEN" },
    { 18,  "Get HGM" },
    { 19,  "Set HGM" },
    { 20,  "Tx Test" },
    { 21,  "Stop" },
    { 22,  "Get Modulation" },
    { 23,  "Set Modulation" },
    { 24,  "Set ISP" },
    { 25,  "Flash" },
    { 26,  "Bootloader Flash" },
    { 27,  "Spectrum Analyzer" },
    { 28,  "Get Power Amplifier Level" },
    { 29,  "Set Power Amplifier Level" },
    { 30,  "Repeater" },
    { 31,  "Range Test" },
    { 32,  "Range Check" },
    { 33,  "Get Firmware Revision Number" },
    { 34,  "LED Spectrum Analyzer" },
    { 35,  "Get Hardware Board ID" },
    { 36,  "Set Squelch" },
    { 37,  "Get Squelch" },
    { 38,  "Set BDADDR" },
    { 39,  "Start Hopping" },
    { 40,  "Set Clock" },
    { 41,  "Get Clock" },
    { 42,  "BTLE Sniffing" },
    { 43,  "Get Access Address" },
    { 44,  "Set Access Address" },
    { 45,  "Do Something" },
    { 46,  "Do Something Reply" },
    { 47,  "Get CRC Verify" },
    { 48,  "Set CRC Verify" },
    { 49,  "Poll" },
    { 50,  "BTLE Promiscuous Mode" },
    { 51,  "Set AFH Map" },
    { 52,  "Clear AFH Map" },
    { 53,  "Read Register" },
    { 54,  "BTLE Slave" },
    { 55,  "Get Compile Info" },
    { 56,  "BTLE Set Target" },
    { 57,  "BTLE Phy" },
    { 58,  "Write Register" },
    { 59,  "Jam Mode" },
    { 60,  "Ego" },
    { 0x00, NULL }
};
static value_string_ext(command_vals_ext) = VALUE_STRING_EXT_INIT(command_vals);

static const value_string board_id_vals[] = {
    { 0x00,  "Ubertooth Zero" },
    { 0x01,  "Ubertooth One" },
    { 0x02,  "ToorCon 13 Badge" },
    { 0x00, NULL }
};
static value_string_ext(board_id_vals_ext) = VALUE_STRING_EXT_INIT(board_id_vals);

static const value_string led_state_vals[] = {
    { 0x00,  "Off" },
    { 0x01,  "On" },
    { 0x00, NULL }
};
static value_string_ext(led_state_vals_ext) = VALUE_STRING_EXT_INIT(led_state_vals);

static const value_string state_vals[] = {
    { 0x00,  "False" },
    { 0x01,  "True" },
    { 0x00, NULL }
};
static value_string_ext(state_vals_ext) = VALUE_STRING_EXT_INIT(state_vals);

static const value_string packet_type_vals[] = {
    { 0x00,  "BR/EDR" },
    { 0x01,  "LE" },
    { 0x02,  "Message" },
    { 0x03,  "Keep Alive" },
    { 0x04,  "Spectrum Analyze"},
    { 0x05,  "LE Promiscuous" },
    { 0x06,  "Ego Packet" },
    { 0x00, NULL }
};
static value_string_ext(packet_type_vals_ext) = VALUE_STRING_EXT_INIT(packet_type_vals);

static const value_string usb_rx_packet_state_vals[] = {
    { 0x00,  "Access Address" },
    { 0x01,  "CRC Init" },
    { 0x02,  "Hop Interval" },
    { 0x03,  "Hop Increment" },
    { 0x00, NULL }
};

static const value_string modulation_vals[] = {
    { 0x00,  "Basic Rate" },
    { 0x01,  "Low Energy" },
    { 0x02,  "802.11 FHSS" },
    { 0x00, NULL }
};
static value_string_ext(modulation_vals_ext) = VALUE_STRING_EXT_INIT(modulation_vals);


static const value_string jam_mode_vals[] = {
    { 0x00,  "None" },
    { 0x01,  "Once" },
    { 0x02,  "Continuous" },
    { 0x00, NULL }
};


static const value_string ego_mode_vals[] = {
    { 0x00,  "Follow" },
    { 0x01,  "Continuous Rx" },
    { 0x02,  "Jam" },
    { 0x00, NULL }
};

static const value_string register_vals[] = {
    { 0x00,  "MAIN" },
    { 0x01,  "FSCTRL" },
    { 0x02,  "FSDIV" },
    { 0x03,  "MDMCTRL" },
    { 0x04,  "AGCCTRL" },
    { 0x05,  "FREND" },
    { 0x06,  "RSSI" },
    { 0x07,  "FREQEST" },
    { 0x08,  "IOCFG" },
    { 0x0B,  "FSMTC" },
    { 0x0C,  "RESERVED 0x0C" },
    { 0x0D,  "MANAND" },
    { 0x0E,  "FSMSTATE" },
    { 0x0F,  "ADCTST" },
    { 0x10,  "RXBPFTST" },
    { 0x11,  "PAMTST" },
    { 0x12,  "LMTST" },
    { 0x13,  "MANOR" },
    { 0x14,  "MDMTST0" },
    { 0x15,  "MDMTST1" },
    { 0x16,  "DACTST" },
    { 0x17,  "AGCTST0" },
    { 0x18,  "AGCTST1" },
    { 0x19,  "AGCTST2" },
    { 0x1A,  "FSTST0" },
    { 0x1B,  "FSTST1" },
    { 0x1C,  "FSTST2" },
    { 0x1D,  "FSTST3" },
    { 0x1E,  "MANFIDL" },
    { 0x1F,  "MANFIDH" },
    { 0x20,  "GRMDM" },
    { 0x21,  "GRDEC" },
    { 0x22,  "PKTSTATUS" },
    { 0x23,  "INT" },
    { 0x24,  "RESERVED 0x24" },
    { 0x25,  "RESERVED 0x25" },
    { 0x26,  "RESERVED 0x26" },
    { 0x27,  "RESERVED 0x27" },
    { 0x28,  "RESERVED 0x28" },
    { 0x29,  "RESERVED 0x29" },
    { 0x2A,  "RESERVED 0x2A" },
    { 0x2B,  "RESERVED 0x2B" },
    { 0x2C,  "SYNCL" },
    { 0x2D,  "SYNCH" },
    { 0x60,  "SXOSCON" },
    { 0x61,  "SFSON" },
    { 0x62,  "SRX" },
    { 0x63,  "STX" },
    { 0x64,  "SRFOFF" },
    { 0x65,  "SXOSCOFF" },
    { 0x70,  "FIFOREG" },
    { 0x00, NULL }
};
static value_string_ext(register_vals_ext) = VALUE_STRING_EXT_INIT(register_vals);

static const value_string register_description_vals[] = {
    { 0x00,  "Main Control Register" },
    { 0x01,  "Frequency Synthesiser Control and Status" },
    { 0x02,  "Frequency Synthesiser Frequency Division Control" },
    { 0x03,  "Modem Control and Status" },
    { 0x04,  "Automatic Gain Control and Status" },
    { 0x05,  "Front-end Control Register" },
    { 0x06,  "Received Signal Strength Indicator Status and Control Register" },
    { 0x07,  "Received Frequency Offset Estimation" },
    { 0x08,  "IO Configuration Register" },
    { 0x0B,  "Finite State Machine Time Constants" },
    { 0x0C,  "Reserved Register Containing Spare Control and Status Bits" },
    { 0x0D,  "Manual Signal and Override Register" },
    { 0x0E,  "Finite State Machine Information and Breakpoint" },
    { 0x0F,  "Analog-to-Digital Converter Test Register" },
    { 0x10,  "Receiver Band-pass Filters Test Register" },
    { 0x11,  "Power Amplifier and Transmit Mixers Test Register" },
    { 0x12,  "Low Noise Amplifier and Receive Mixers Test Register" },
    { 0x13,  "Manual Signal or Override Register" },
    { 0x14,  "Modem Test Register 0" },
    { 0x15,  "Modem Test Register 1" },
    { 0x16,  "Digital-to-Analog Converter Test Register" },
    { 0x17,  "Automatic Gain Control Test Register 0" },
    { 0x18,  "Automatic Gain Control Test Register 1" },
    { 0x19,  "Automatic Gain Control Test Register 2" },
    { 0x1A,  "Frequency Synthesiser Test Register 0" },
    { 0x1B,  "Frequency Synthesiser Test Register 1" },
    { 0x1C,  "Frequency Synthesiser Test Register 2" },
    { 0x1D,  "Frequency Synthesiser Test Register 3" },
    { 0x1E,  "Manufacturer ID, Lower 16 Bit" },
    { 0x1F,  "Manufacturer ID, Upper 16 Bit" },
    { 0x20,  "Generic Radio Modem Control and Status" },
    { 0x21,  "Generic Radio Decimation Control and Status" },
    { 0x22,  "Packet Mode Status" },
    { 0x23,  "Interrupt Register" },
    { 0x24,  "Reserved 0x24" },
    { 0x25,  "Reserved 0x25" },
    { 0x26,  "Reserved 0x26" },
    { 0x27,  "Reserved 0x27" },
    { 0x28,  "Reserved 0x28" },
    { 0x29,  "Reserved 0x29" },
    { 0x2A,  "Reserved 0x2A" },
    { 0x2B,  "Reserved 0x2B" },
    { 0x2C,  "Sync Word, Lower 16 Bit" },
    { 0x2D,  "Sync Word, Upper 16 Bit" },
    { 0x60,  "Command Strobe Register: Turn on XOSC" },
    { 0x61,  "Command Strobe register: Start and calibrate Frequency Synthesizer and go from RX/TX to a wait mode where the Frequency Synthesizer is running" },
    { 0x62,  "Command Strobe register: Start RX" },
    { 0x63,  "Command Strobe register: Start TX (turn on Power Amplifier)" },
    { 0x64,  "Command Strobe register: Turn off RX/TX and Frequency Synthesizer" },
    { 0x65,  "Command Strobe register: Turn off XOSC" },
    { 0x70,  "Used to write data to and read data from the 8-bit wide 32 bytes FIFO used to buffer outgoing TX data and incoming RX data in buffered RF mode" },
    { 0x00, NULL }
};
static value_string_ext(register_description_vals_ext) = VALUE_STRING_EXT_INIT(register_description_vals);

static const value_string cc2400_grdec_dec_shift_vals[] = {
    { 0x00,  "0" },
    { 0x01,  "1" },
    { 0x02,  "-2" },
    { 0x03,  "-1" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_grdec_dec_shift_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_grdec_dec_shift_vals);

static const value_string cc2400_grdec_channel_dec_vals[] = {
    { 0x00,  "1 MHz (used for 1Mbps and 250 kbps datarates)" },
    { 0x01,  "500 kHz (used for 10 kbps data rate)" },
    { 0x02,  "250 kHz" },
    { 0x03,  "125 kHz" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_grdec_channel_dec_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_grdec_channel_dec_vals);

static const value_string cc2400_grmdm_pin_mode_vals[] = {
    { 0x00,  "Unbuffered Mode" },
    { 0x01,  "Buffered Mode" },
    { 0x02,  "HSSD Test Mode" },
    { 0x03,  "Unused" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_grmdm_pin_mode_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_grmdm_pin_mode_vals);

static const value_string cc2400_grmdm_pre_bytes_vals[] = {
    { 0x00,  "0" },
    { 0x01,  "1" },
    { 0x02,  "2" },
    { 0x03,  "4" },
    { 0x04,  "8" },
    { 0x05,  "16" },
    { 0x06,  "32" },
    { 0x07,  "Infinitely On" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_grmdm_pre_bytes_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_grmdm_pre_bytes_vals);

static const value_string cc2400_grmdm_sync_word_size_vals[] = {
    { 0x00,  "The 8 MSB bits of SYNC_WORD" },
    { 0x01,  "The 16 MSB bits of SYNC_WORD" },
    { 0x02,  "The 24 MSB bits of SYNC_WORD" },
    { 0x03,  "The 32 MSB bits of SYNC_WORD" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_grmdm_sync_word_size_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_grmdm_sync_word_size_vals);

static const value_string cc2400_grmdm_data_format_vals[] = {
    { 0x00,  "NRZ" },
    { 0x01,  "Manchester" },
    { 0x02,  "8/10 line-coding (Not applied to preambles or sync words)" },
    { 0x03,  "Reserved" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_grmdm_data_format_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_grmdm_data_format_vals);

static const value_string cc2400_grmdm_modulation_format_vals[] = {
    { 0x00,  "FSK/GFSK" },
    { 0x01,  "Reserved" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_grmdm_modulation_format_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_grmdm_modulation_format_vals);

static const value_string cc2400_fstst3_pd_delay_vals[] = {
    { 0x00,  "Short Reset Delay" },
    { 0x01,  "Long Reset Delay" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_fstst3_pd_delay_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_fstst3_pd_delay_vals);

static const value_string cc2400_fstst3_chp_step_period_vals[] = {
    { 0x00,  "0.25 us" },
    { 0x01,  "0.5 us" },
    { 0x02,  "1 us" },
    { 0x03,  "4 us" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_fstst3_chp_step_period_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_fstst3_chp_step_period_vals);

static const value_string cc2400_fstst2_vco_curcal_speed_vals[] = {
    { 0x00,  "Normal" },
    { 0x01,  "Undefined" },
    { 0x02,  "Half Speed" },
    { 0x03,  "Undefined" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_fstst2_vco_curcal_speed_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_fstst2_vco_curcal_speed_vals);

static const value_string cc2400_fstst1_rxbpf_locur_vals[] = {
    { 0x00,  "4 uA (nominal)" },
    { 0x01,  "3 uA" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_fstst1_rxbpf_locur_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_fstst1_rxbpf_locur_vals);

static const value_string cc2400_fstst1_rxbpf_midcur_vals[] = {
    { 0x00,  "4 uA (nominal)" },
    { 0x01,  "3.5 uA" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_fstst1_rxbpf_midcur_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_fstst1_rxbpf_midcur_vals);

static const value_string cc2400_fstst1_vc_dac_en_vals[] = {
    { 0x00,  "Loop filter (closed loop PLL)" },
    { 0x01,  "VC DAC(open loop PLL)" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_fstst1_vc_dac_en_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_fstst1_vc_dac_en_vals);

static const value_string cc2400_fstst0_rxtxmixbuf_cur_vals[] = {
    { 0x00,  "690 uA" },
    { 0x01,  "980 uA" },
    { 0x02,  "1.16 mA (nominal)" },
    { 0x03,  "1.44 mA" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_fstst0_rxtxmixbuf_cur_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_fstst0_rxtxmixbuf_cur_vals);


static const value_string cc2400_agctst1_agc_var_gain_sat_vals[] = {
    { 0x00,  "-1/-3 gain steps" },
    { 0x01,  "-3/-5 gain steps" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_agctst1_agc_var_gain_sat_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_agctst1_agc_var_gain_sat_vals);

static const value_string cc2400_dactst_dac_src_vals[] = {
    { 0x00,  "Normal Operation (from Mudulator)" },
    { 0x01,  "The DAC_I_O and DAC_Q_O override values below" },
    { 0x02,  "From ADC" },
    { 0x03,  "I/Q after digital down-mixing and channel filtering" },
    { 0x04,  "Full-spectrum White Noise (from PRNG)" },
    { 0x05,  "RX signal magnitude / frequency filtered (from demodulator)" },
    { 0x06,  "RSSI/RX frequency offset estimation" },
    { 0x07,  "HSSD module" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_dactst_dac_src_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_dactst_dac_src_vals);

static const value_string cc2400_mdmtst0_afc_settling_vals[] = {
    { 0x00,  "1 pair" },
    { 0x01,  "2 pairs" },
    { 0x02,  "4 pairs" },
    { 0x03,  "8 pairs" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_mdmtst0_afc_settling_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_mdmtst0_afc_settling_vals);

static const value_string cc2400_lmtst_rxmix_tail_vals[] = {
    { 0x00,  "12 uA" },
    { 0x01,  "16 uA (Nominal)" },
    { 0x02,  "20 uA" },
    { 0x03,  "24 uA" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_lmtst_rxmix_tail_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_lmtst_rxmix_tail_vals);

static const value_string cc2400_lmtst_rxmix_vcm_vals[] = {
    { 0x00,  "8 uA mixer current" },
    { 0x01,  "12 uA mixer current (Nominal)" },
    { 0x02,  "16 uA mixer current" },
    { 0x03,  "20 uA mixer current" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_lmtst_rxmix_vcm_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_lmtst_rxmix_vcm_vals);

static const value_string cc2400_lmtst_rxmix_current_vals[] = {
    { 0x00,  "360 uA mixer current (x2)" },
    { 0x01,  "720 uA mixer current (x2)" },
    { 0x02,  "900 uA mixer current (x2) (Nominal)" },
    { 0x03,  "1260 uA mixer current (x2)" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_lmtst_rxmix_current_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_lmtst_rxmix_current_vals);

static const value_string cc2400_lmtst_lna_cap_array_vals[] = {
    { 0x00,  "Off" },
    { 0x01,  "0.1pF (x2) (Nominal)" },
    { 0x02,  "0.2pF (x2)" },
    { 0x03,  "0.3pF (x2)" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_lmtst_lna_cap_array_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_lmtst_lna_cap_array_vals);

static const value_string cc2400_lmtst_lna_lowgain_vals[] = {
    { 0x00,  "19 dB (Nominal)" },
    { 0x01,  "7 dB" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_lmtst_lna_lowgain_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_lmtst_lna_lowgain_vals);

static const value_string cc2400_lmtst_lna_gain_vals[] = {
    { 0x00,  "Off (Nominal)" },
    { 0x01,  "100 uA LNA current" },
    { 0x02,  "300 uA LNA current" },
    { 0x03,  "1000 uA LNA current" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_lmtst_lna_gain_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_lmtst_lna_gain_vals);

static const value_string cc2400_lmtst_lna_current_vals[] = {
    { 0x00,  "240 uA LNA current (x2)" },
    { 0x01,  "480 uA LNA current (x2)" },
    { 0x02,  "640 uA LNA current (x2) (Nominal)" },
    { 0x03,  "1280 uA LNA current (x2)" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_lmtst_lna_current_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_lmtst_lna_current_vals);

static const value_string cc2400_pamtst_atestmod_mode_vals[] = {
    { 0x00,  "Outputs I (ATEST2) and Q (ATEST1) from RxMIX" },
    { 0x01,  "Inputs I (ATEST2) and Q (ATEST1) to BPF" },
    { 0x02,  "Outputs I (ATEST2) and Q (ATEST1) from VGA" },
    { 0x03,  "Inputs I (ATEST2) and Q (ATEST1) to ADC" },
    { 0x04,  "Outputs I (ATEST2) and Q (ATEST1) from LPF" },
    { 0x05,  "Inputs I (ATEST2) and Q (ATEST1) to TxMIX" },
    { 0x06,  "Outputs P (ATEST2) and N (ATEST1) from Prescaler" },
    { 0x07,  "Connects TX IF to RX IF and simultaneously the ATEST1 pin to the internal VC node" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_pamtst_atestmod_mode_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_pamtst_atestmod_mode_vals);

static const value_string cc2400_pamtst_txmix_current_vals[] = {
    { 0x00,  "1.72 mA" },
    { 0x01,  "1.88 mA" },
    { 0x02,  "2.05 mA" },
    { 0x03,  "2.21 mA" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_pamtst_txmix_current_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_pamtst_txmix_current_vals);

static const value_string cc2400_pamtst_pa_current_vals[] = {
    { 0x00,  "-3 current adjustment" },
    { 0x01,  "-2 current adjustment" },
    { 0x02,  "-1 current adjustment" },
    { 0x03,  "Nominal Setting" },
    { 0x04,  "+1 current adjustment" },
    { 0x05,  "+2 current adjustment" },
    { 0x06,  "+3 current adjustment" },
    { 0x07,  "+4 current adjustment" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_pamtst_pa_current_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_pamtst_pa_current_vals);

static const value_string cc2400_iocfg_hssd_src_vals[] = {
    { 0x00,  "Off" },
    { 0x01,  "Output AGC status (gain setting / peak detector status / accumulator value)" },
    { 0x02,  "Output ADC I and Q values" },
    { 0x03,  "Output I/Q after digital down-mixing and channel filtering" },
    { 0x04,  "Output RX signal magnitude / frequency unfiltered (from demodulator)" },
    { 0x05,  "Output RX signal magnitude / frequency filtered (from demodulator)" },
    { 0x06,  "Output RSSI / RX frequency offset estimation" },
    { 0x07,  "Input DAC values" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_iocfg_hssd_src_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_iocfg_hssd_src_vals);

static const value_string cc2400_rssi_rssi_filt_vals[] = {
    { 0x00,  "0 bits (no filtering)" },
    { 0x01,  "1 bit" },
    { 0x02,  "4 bits" },
    { 0x03,  "8 bits" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_rssi_rssi_filt_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_rssi_rssi_filt_vals);

static const value_string cc2400_fsctlr_lock_threshold_vals[] = {
    { 0x00,  "64" },
    { 0x01,  "128" },
    { 0x02,  "256" },
    { 0x03,  "512" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_fsctlr_lock_threshold_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_fsctlr_lock_threshold_vals);

static const value_string cc2400_fsctlr_lock_length_vals[] = {
    { 0x00,  "2 CLK_PRE Periods" },
    { 0x01,  "4 CLK_PRE Periods" },
    { 0x00, NULL }
};
static value_string_ext(cc2400_fsctlr_lock_length_vals_ext) = VALUE_STRING_EXT_INIT(cc2400_fsctlr_lock_length_vals);

void proto_register_ubertooth(void);
void proto_reg_handoff_ubertooth(void);


static void
dissect_cc2400_register(proto_tree *tree, tvbuff_t *tvb, gint offset, guint8 register_id)
{
    proto_item  *sub_item;
    proto_item  *sub_tree;

    switch (register_id) {
    case 0x00: /* MAIN */
        proto_tree_add_item(tree, hf_cc2400_main_resetn, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_main_reserved_14_10, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_main_fs_force_en, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_main_rxn_tx, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_main_reserved_7_4, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_main_reserved_3, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_main_reserved_2, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_main_xosc16m_bypass, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_main_xosc16m_en, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x01: /* FSCTRL */
        proto_tree_add_item(tree, hf_cc2400_fsctrl_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fsctrl_lock_threshold, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fsctrl_cal_done, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fsctrl_cal_running, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fsctrl_lock_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fsctrl_lock_status, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x02: /* FSDIV */
        proto_tree_add_item(tree, hf_cc2400_fsdiv_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        sub_item = proto_tree_add_item(tree, hf_cc2400_fsdiv_frequency, tvb, offset, 2, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_fsdiv_frequency);

        proto_tree_add_item(sub_tree, hf_cc2400_fsdiv_freq_high, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_cc2400_fsdiv_freq, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x03: /* MDMCTRL */
        proto_tree_add_item(tree, hf_cc2400_mdmctrl_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_mdmctrl_mod_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_mdmctrl_mod_dev, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x04: /* AGCCTRL */
        proto_tree_add_item(tree, hf_cc2400_agcctrl_vga_gain, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agcctrl_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agcctrl_agc_locked, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agcctrl_agc_lock, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agcctrl_agc_sync_lock, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agcctrl_vga_gain_oe, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x05: /* FREND  */
        proto_tree_add_item(tree, hf_cc2400_frend_reserved_15_4, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_frend_reserved_3, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_frend_pa_level, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x06: /* RSSI */
        proto_tree_add_item(tree, hf_cc2400_rssi_rssi_val, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_rssi_rssi_cs_thres, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_rssi_rssi_filt, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x07: /* FREQEST */
        proto_tree_add_item(tree, hf_cc2400_freqest_rx_freq_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_freqest_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x08: /* IOCFG */
        proto_tree_add_item(tree, hf_cc2400_iocfg_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_iocfg_gio6_cfg, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_iocfg_gio1_cfg, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_iocfg_hssd_src, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x0B: /* FSMTC */
        proto_tree_add_item(tree, hf_cc2400_fsmtc_tc_rxon2agcen, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fsmtc_tc_paon2switch, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fsmtc_res, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fsmtc_tc_txend2switch, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fsmtc_tc_txend2paoff, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x0C: /* Reserved */
        proto_tree_add_item(tree, hf_cc2400_reserved_0x0C_res_15_5, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x0C_res_4_0, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x0D: /* MANAND */
        proto_tree_add_item(tree, hf_cc2400_manand_vga_reset_n, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_lock_status, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_balun_ctrl, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_rxtx, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_pre_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_pa_n_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_pa_p_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_dac_lpf_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_bias_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_xosc16m_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_chp_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_fs_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_adc_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_vga_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_rxbpf_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manand_lnamix_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x0E: /* FSMSTATE */
        proto_tree_add_item(tree, hf_cc2400_fsmstate_reserved_15_13, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fsmstate_fsm_state_bkpt, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fsmstate_reserved_7_5, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fsmstate_fsm_cur_state, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x0F: /* ADCTST */
        proto_tree_add_item(tree, hf_cc2400_adctst_reserved_15, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_adctst_adc_i, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_adctst_reserved_7, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_adctst_adc_q, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x10: /* RXBPFTST */
        proto_tree_add_item(tree, hf_cc2400_rxbpftst_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_rxbpftst_rxbpf_cap_oe, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_rxbpftst_rxbpf_cap_o, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_rxbpftst_rxbpf_cap_res, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x11: /* PAMTST */
        proto_tree_add_item(tree, hf_cc2400_pamtst_reserved_15_13, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_pamtst_vc_in_test_en, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_pamtst_atestmod_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_pamtst_atestmod_mode, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_pamtst_reserved_7, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_pamtst_txmix_cap_array, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_pamtst_txmix_current, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_pamtst_pa_current, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x12: /* LMTST */
        proto_tree_add_item(tree, hf_cc2400_lmtst_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_lmtst_rxmix_hgm, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_lmtst_rxmix_tail, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_lmtst_rxmix_vcm, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_lmtst_rxmix_current, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_lmtst_lna_cap_array, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_lmtst_lna_lowgain, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_lmtst_lna_gain, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_lmtst_lna_current, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x13: /* MANOR */
        proto_tree_add_item(tree, hf_cc2400_manor_vga_reset_n, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_lock_status, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_balun_ctrl, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_rxtx, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_pre_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_pa_n_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_pa_p_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_dac_lpf_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_bias_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_xosc16m_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_chp_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_fs_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_adc_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_vga_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_rxbpf_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manor_lnamix_pd, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x14: /* MDMTST0 */
        proto_tree_add_item(tree, hf_cc2400_mdmtst0_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_mdmtst0_tx_prng, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_mdmtst0_tx_1mhz_offset_n, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_mdmtst0_invert_data, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_mdmtst0_afc_adjust_on_packet, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_mdmtst0_afc_settling, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_mdmtst0_afc_delta, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x15: /* MDMTST1 */
        proto_tree_add_item(tree, hf_cc2400_mdmtst1_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_mdmtst1_bsync_threshold, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x16: /* DACTST */
        proto_tree_add_item(tree, hf_cc2400_dactst_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_dactst_dac_src, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_dactst_dac_i_o, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_dactst_dac_q_o, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x17: /* AGCTST0 */
        proto_tree_add_item(tree, hf_cc2400_agctst0_agc_settle_blank_dn, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst0_agc_win_size, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst0_agc_settle_peak, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst0_agc_settle_adc, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst0_agc_attempts, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x18: /* AGCTST1 */
        proto_tree_add_item(tree, hf_cc2400_agctst1_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst1_agc_var_gain_sat, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst1_agc_settle_blank_up, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst1_peakdet_cur_boost, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst1_agc_mult_slow, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst1_agc_settle_fixed, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst1_agc_settle_var, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x19: /* AGCTST2 */
        proto_tree_add_item(tree, hf_cc2400_agctst2_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst2_agc_backend_blanking, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst2_agc_adjust_m3db, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst2_agc_adjust_m1db, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst2_agc_adjust_p3db, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_agctst2_agc_adjust_p1db, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x1A: /* FSTST0 */
        proto_tree_add_item(tree, hf_cc2400_fstst0_rxmixbuf_cur, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst0_txmixbuf_cur, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst0_vco_array_settle_long, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst0_vco_array_oe, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst0_vco_array_o, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst0_vco_array_res, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x1B: /* FSTST1 */
        proto_tree_add_item(tree, hf_cc2400_fstst1_rxbpf_locur, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst1_rxbpf_midcur, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst1_vco_current_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst1_vco_current_k, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst1_vc_dac_en, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst1_vc_dac_val, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x1C: /* FSTST2 */
        proto_tree_add_item(tree, hf_cc2400_fstst2_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst2_vco_curcal_speed, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst2_vco_current_oe, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst2_vco_current_o, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst2_vco_current_res, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x1D: /* FSTST3 */
        proto_tree_add_item(tree, hf_cc2400_fstst3_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst3_chp_test_up, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst3_chp_test_dn, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst3_chp_disable, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst3_pd_delay, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst3_chp_step_period, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst3_stop_chp_current, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_fstst3_start_chp_current, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x1E: /* MANFIDL */
        proto_tree_add_item(tree, hf_cc2400_manfidl_partnum, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manfidl_manfid, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x1F: /* MANFIDH */
        proto_tree_add_item(tree, hf_cc2400_manfidh_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_manfidh_partnum, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x20: /* GRMDM */
        proto_tree_add_item(tree, hf_cc2400_grmdm_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_grmdm_sync_errbits_allowed, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_grmdm_pin_mode, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_grmdm_packet_mode, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_grmdm_pre_bytes, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_grmdm_sync_word_size, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_grmdm_crc_on, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_grmdm_data_format, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_grmdm_modulation_format, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_grmdm_tx_gaussian_filter, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x21: /* GRDEC */
        proto_tree_add_item(tree, hf_cc2400_grdec_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_grdec_ind_saturation, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_grdec_dec_shift, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_grdec_channel_dec, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_grdec_dec_val, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x22: /* PKTSTATUS */
        proto_tree_add_item(tree, hf_cc2400_pktstatus_reserved_15_11, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_pktstatus_sync_word_received, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_pktstatus_crc_ok, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_pktstatus_reserved_8, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_pktstatus_reserved_7_0, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x23: /* INT */
        proto_tree_add_item(tree, hf_cc2400_int_reserved_15_8, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_int_reserved_7, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_int_pkt_polarity, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_int_fifo_polarity, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_int_fifo_threshold, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x24: /* Reserved */
        proto_tree_add_item(tree, hf_cc2400_reserved_0x24_res_15_14, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x24_res_13_10, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x24_res_9_7, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x24_res_6_0, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x25: /* Reserved */
        proto_tree_add_item(tree, hf_cc2400_reserved_0x25_res_15_12, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x25_res_11_0, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x26: /* Reserved */
        proto_tree_add_item(tree, hf_cc2400_reserved_0x26_res_15_10, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x26_res_9_0, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x27: /* Reserved */
        proto_tree_add_item(tree, hf_cc2400_reserved_0x27_res_15_8, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x27_res_7_3, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x27_res_2_0, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x28: /* Reserved */
        proto_tree_add_item(tree, hf_cc2400_reserved_0x28_res_15, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x28_res_14_13, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x28_res_12_7, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x28_res_6_0, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x29: /* Reserved */
        proto_tree_add_item(tree, hf_cc2400_reserved_0x29_res_15_8, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x29_res_7_3, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x29_res_2_0, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x2A: /* Reserved */
        proto_tree_add_item(tree, hf_cc2400_reserved_0x2A_res_15_11, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x2A_res_10, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x2A_res_9_0, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x2B: /* Reserved */
        proto_tree_add_item(tree, hf_cc2400_reserved_0x2B_res_15_14, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x2B_res_13, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x2B_res_12, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_cc2400_reserved_0x2B_res_11_0, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x2C: /* SYNCL */
        proto_tree_add_item(tree, hf_cc2400_syncl, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 0x2D: /* SYNCH */
        proto_tree_add_item(tree, hf_cc2400_synch, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    default:
        proto_tree_add_item(tree, hf_cc2400_value, tvb, offset, 2, ENC_BIG_ENDIAN);
    }
}

static gint
dissect_usb_rx_packet(proto_tree *main_tree, proto_tree *tree, packet_info *pinfo,
        tvbuff_t *tvb, gint offset, gint16 command, usb_conv_info_t *usb_conv_info)
{
    proto_item  *sub_item;
    proto_tree  *sub_tree;
    proto_item  *p_item;
    proto_item  *data_item;
    proto_tree  *data_tree;
    proto_item  *entry_item;
    proto_tree  *entry_tree;
    gint         i_spec;
    gint         length;
    tvbuff_t    *next_tvb;
    guint8       packet_type;
    guint32      start_offset;
    guint32      clock_100ns;
    guint8       channel;
    ubertooth_data_t  *ubertooth_data;

    sub_item = proto_tree_add_item(tree, hf_usb_rx_packet, tvb, offset, 64, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_usb_rx_packet);

    start_offset = offset;

    proto_tree_add_item(sub_tree, hf_packet_type, tvb, offset, 1, ENC_NA);
    packet_type = tvb_get_guint8(tvb, offset);
    offset += 1;

    if (packet_type == 0x05) { /* LE_PROMISC */
        guint8  state;

        proto_tree_add_item(sub_tree, hf_state, tvb, offset, 1, ENC_NA);
        state = tvb_get_guint8(tvb, offset);
        col_append_fstr(pinfo->cinfo, COL_INFO, " LE Promiscuous - %s", val_to_str_const(state, usb_rx_packet_state_vals, "Unknown"));
        offset += 1;

        switch (state) {
        case 0: /* Access Address */
            proto_tree_add_item(sub_tree, hf_access_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%04x", tvb_get_letohl(tvb, offset));
            offset += 4;
            break;
        case 1: /* CRC Init */
            proto_tree_add_item(sub_tree, hf_crc_init, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%06x", tvb_get_letoh24(tvb, offset));
            offset += 3;
            break;
        case 2: /* Hop Interval */
            p_item = proto_tree_add_item(sub_tree, hf_hop_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_append_text(p_item, " (%f ms), ", tvb_get_letohs(tvb, offset) * 1.25);
            col_append_fstr(pinfo->cinfo, COL_INFO, " %f ms", tvb_get_letohs(tvb, offset) * 1.25);
            offset += 2;
            break;
        case 3: /* Hop Increment */
            proto_tree_add_item(sub_tree, hf_hop_increment, tvb, offset, 1, ENC_NA);
            col_append_fstr(pinfo->cinfo, COL_INFO, " %u", tvb_get_guint8(tvb, offset));
            offset += 1;
            break;
        }

        proto_tree_add_item(sub_tree, hf_reserved, tvb, offset, 64 - (offset - start_offset), ENC_NA);
        offset += 64 - (offset - start_offset);

        return offset;
    }

    proto_tree_add_item(sub_tree, hf_chip_status_reserved, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_chip_status_rssi_trigger, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_chip_status_cs_trigger, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_chip_status_fifo_overflow, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_chip_status_dma_error, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_chip_status_dma_overflow, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_usb_rx_packet_channel, tvb, offset, 1, ENC_NA);
    channel = tvb_get_guint8(tvb, offset);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_clock_ns, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_clock_100ns, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    clock_100ns = tvb_get_letohl(tvb, offset);
    offset += 4;

    proto_tree_add_item(sub_tree, hf_rssi_max, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_rssi_min, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_rssi_avg, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_rssi_count, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(sub_tree, hf_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;

    data_item = proto_tree_add_item(sub_tree, hf_data, tvb, offset, 50, ENC_NA);
    data_tree = proto_item_add_subtree(data_item, ett_usb_rx_packet_data);

    switch (command) {
    case 27: /* Spectrum Analyzer */
        for (i_spec = 0; i_spec < 48; i_spec += 3) {
            entry_item = proto_tree_add_item(data_tree, hf_spectrum_entry, tvb, offset, 3, ENC_NA);
            entry_tree = proto_item_add_subtree(entry_item, ett_entry);

            proto_tree_add_item(entry_tree, hf_frequency, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(entry_tree, hf_rssi, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_item_append_text(entry_item, " Frequency = %u MHz, RSSI = %i", tvb_get_ntohs(tvb, offset - 3), (gint8) tvb_get_guint8(tvb, offset - 1));
        }

        proto_tree_add_item(data_tree, hf_reserved, tvb, offset, 2, ENC_NA);
        offset += 2;
        break;
    case 49: /* Poll */
        if (packet_type == 0x00) {/* BD/EDR */
            /* TODO: btbb dissector */
            offset += 50;
        } else if (packet_type == 0x01 || packet_type == 0x05) { /* LE || LE Promiscuous */
            length = 9; /* From BTLE: AccessAddress (4) + Header (2) + Length from Header (below) + CRC (3) */

            if (tvb_get_letohl(tvb, offset) == ACCESS_ADDRESS_ADVERTISING)
                length += tvb_get_guint8(tvb, offset + 5) & 0x3f;
            else
                length += tvb_get_guint8(tvb, offset + 5) & 0x1f;

            ubertooth_data = wmem_new(wmem_packet_scope(), ubertooth_data_t);
            ubertooth_data->bus_id = usb_conv_info->bus_id;
            ubertooth_data->device_address = usb_conv_info->device_address;
            ubertooth_data->clock_100ns = clock_100ns;
            ubertooth_data->channel = channel;

            next_tvb = tvb_new_subset_length(tvb, offset, length);
            call_dissector_with_data(bluetooth_ubertooth_handle, next_tvb, pinfo, main_tree, ubertooth_data);
            offset += length;
        } else if (packet_type == 0x06) {/* Ego */
            /* NOTE: Yuneec E-GO skateboard - unknown protocol */
            offset += 50;
        } else if (packet_type == 0x02 || packet_type == 0x03 || packet_type == 0x04) { /* Message || Keep Alive || Spectrum Analyze */
            /* NOTE: ? */
            offset += 50;
        }

        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(data_tree, hf_reserved, tvb, offset, -1, ENC_NA);
            offset += tvb_captured_length_remaining(tvb, offset);
        }

        break;
    default:
        offset += 50;
    }

    return offset;
}

static gint
dissect_ubertooth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item       *main_tree = NULL;
    proto_tree       *main_item = NULL;
    proto_item       *command_item;
    proto_item       *command_tree;
    proto_item       *sub_item;
    proto_item       *sub_tree;
    gint              offset = 0;
    usb_conv_info_t  *usb_conv_info = (usb_conv_info_t *)data;
    gint              p2p_dir_save;
    guint8            command;
    gint16            command_response = -1;
    command_data_t   *command_data = NULL;
    wmem_tree_t      *wmem_tree;
    wmem_tree_key_t   key[5];
    guint32           bus_id;
    guint32           device_address;
    guint32           k_bus_id;
    guint32           k_device_address;
    guint32           k_frame_number;
    guint8            length;
    guint32          *serial;
    guint8            status;
    gint32            register_id = -1;

    main_item = proto_tree_add_item(tree, proto_ubertooth, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_ubertooth);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UBERTOOTH");

    if (!usb_conv_info) return offset;

    p2p_dir_save = pinfo->p2p_dir;
    pinfo->p2p_dir = (usb_conv_info->is_request) ? P2P_DIR_SENT : P2P_DIR_RECV;

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_add_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_add_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
            pinfo->p2p_dir);
        break;
    }

    bus_id         = usb_conv_info->bus_id;
    device_address = usb_conv_info->device_address;

    k_bus_id          = bus_id;
    k_device_address  = device_address;
    k_frame_number    = pinfo->num;

    key[0].length = 1;
    key[0].key = &k_bus_id;
    key[1].length = 1;
    key[1].key = &k_device_address;


    if (usb_conv_info->is_setup) {
        proto_tree_add_item(main_tree, hf_command, tvb, offset, 1, ENC_NA);
        command = tvb_get_guint8(tvb, offset);
        offset += 1;

        col_append_fstr(pinfo->cinfo, COL_INFO, "Command: %s",
                val_to_str_ext_const(command, &command_vals_ext, "Unknown"));

        switch (command) {
/* Group of commands with parameters by "setup" */
        case 1: /* Rx Symbols */
        case 4: /* Set User LED */
        case 6: /* Set Rx LED */
        case 8: /* Set Tx LED */
        case 10: /* Set 1V8 */
        case 12: /* Set Channel */
        case 17: /* Set PAEN */
        case 19: /* Set HGM */
        case 23: /* Set Modulation */
        case 29: /* Set Power Amplifier Level */
        case 34: /* LED Spectrum Analyzer */
        case 36: /* Set Squelch */
        case 42: /* BTLE Sniffing */
        case 48: /* Set CRC Verify */
        case 53: /* Read Register */
        case 58: /* Write Register */
        case 59: /* Jam Mode */
        case 60: /* Ego */

            switch (command) {
            case 1: /* Rx Symbols */
            case 42: /* BTLE Sniffing */
                proto_tree_add_item(main_tree, hf_rx_packets, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - Rx Packets: %u", tvb_get_letohs(tvb, offset));
                offset += 2;

                break;
            case 4: /* Set User LED */
                proto_tree_add_item(main_tree, hf_user_led, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &led_state_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 6: /* Set Rx LED */
                proto_tree_add_item(main_tree, hf_rx_led, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &led_state_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 8: /* Set Tx LED */
                proto_tree_add_item(main_tree, hf_tx_led, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &led_state_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 10: /* Set 1V8 */
                proto_tree_add_item(main_tree, hf_1v8_led, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &led_state_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 12: /* Set Channel */
                proto_tree_add_item(main_tree, hf_channel, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %u MHz", tvb_get_letohs(tvb, offset));
                offset += 2;

                break;
            case 17: /* Set PAEN */
                proto_tree_add_item(main_tree, hf_paen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &state_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 19: /* Set HGM */
                proto_tree_add_item(main_tree, hf_hgm, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &state_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 23: /* Set Modulation */
                proto_tree_add_item(main_tree, hf_modulation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &modulation_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 29: /* Set Power Amplifier Level */
                proto_tree_add_item(main_tree, hf_power_amplifier_reserved, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(main_tree, hf_power_amplifier_level, tvb, offset, 1, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, " = %u", tvb_get_letohs(tvb, offset) & 0x7);
                offset += 1;

                proto_tree_add_item(main_tree, hf_reserved, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            case 34: /* LED Spectrum Analyzer */
                proto_tree_add_int(main_tree, hf_rssi_threshold, tvb, offset, 2, (gint8) tvb_get_letohs(tvb, offset));
                col_append_fstr(pinfo->cinfo, COL_INFO, " = %i", (gint8) tvb_get_letohs(tvb, offset));
                offset += 2;

                break;
            case 36: /* Set Squelch */
                proto_tree_add_item(main_tree, hf_squelch, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " = %i", (gint16) tvb_get_letohs(tvb, offset));
                offset += 2;

                break;
            case 48: /* Set CRC Verify */
                proto_tree_add_item(main_tree, hf_crc_verify, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_ext_const(tvb_get_letohs(tvb, offset), &state_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 53: /* Read Register */
                sub_item = proto_tree_add_item(main_tree, hf_register, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                register_id = tvb_get_letohs(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",
                        val_to_str_ext_const(register_id, &register_vals_ext, "Unknown"));
                if (try_val_to_str_ext(register_id, &register_vals_ext))
                    proto_item_append_text(sub_item, " [%s]", val_to_str_ext_const(register_id, &register_description_vals_ext, "Unknown"));
                offset += 2;

                break;
            case 58: /* Write Register */
                sub_item = proto_tree_add_item(main_tree, hf_register, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                register_id = tvb_get_letohs(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",
                        val_to_str_ext_const(register_id, &register_vals_ext, "Unknown"));
                if (try_val_to_str_ext(register_id, &register_vals_ext))
                    proto_item_append_text(sub_item, " [%s]", val_to_str_ext_const(register_id, &register_description_vals_ext, "Unknown"));
                offset += 2;

                sub_item = proto_tree_add_item(main_tree, hf_register_value, tvb, offset, 2, ENC_BIG_ENDIAN);
                sub_tree = proto_item_add_subtree(sub_item, ett_register_value);
                col_append_fstr(pinfo->cinfo, COL_INFO, " = %s:  0x%04x",
                        val_to_str_ext_const(register_id, &register_vals_ext, "Unknown"),
                        tvb_get_ntohs(tvb, offset));

                dissect_cc2400_register(sub_tree, tvb, offset, register_id);
                offset += 2;

                break;
            case 59: /* Jam Mode */
                proto_tree_add_item(main_tree, hf_jam_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_const(tvb_get_letohs(tvb, offset), jam_mode_vals, "Unknown"));
                offset += 2;

                break;
            case 60: /* Ego */
                proto_tree_add_item(main_tree, hf_ego_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_const(tvb_get_letohs(tvb, offset), ego_mode_vals, "Unknown"));
                offset += 2;

                break;
            default:
                proto_tree_add_item(main_tree, hf_argument_0, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }

            proto_tree_add_item(main_tree, hf_argument_1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 27: /* Spectrum Analyzer */
            proto_tree_add_item(main_tree, hf_low_frequency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_high_frequency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            col_append_fstr(pinfo->cinfo, COL_INFO, " - %u-%u MHz", tvb_get_letohs(tvb, offset - 4), tvb_get_letohs(tvb, offset - 2));

            break;
/* Group of commands with parameters by "data" but no "setup"*/
        case 38: /* Set BDADDR */
        case 39: /* Start Hopping */
        case 40: /* Set Clock */
        case 44: /* Set Access Address */
        case 51: /* Set AFH Map */
        case 54: /* BTLE Slave */
/* Group of commands without any parameters */
        case 0: /* Ping */
        case 2: /* Tx Symbols */ /* NOTE: This one seems to be not implemented in firmware at all*/
        case 3: /* Get User LED */
        case 5: /* Get Rx LED */
        case 7: /* Get Tx LED */
        case 9: /* Get 1V8 */
        case 11: /* Get Channel */
        case 13: /* Reset */
        case 14: /* Get Microcontroller Serial Number */
        case 15: /* Get Microcontroller Part Number */
        case 16: /* Get PAEN */
        case 18: /* Get HGM */
        case 20: /* Tx Test */
        case 21: /* Stop */
        case 22: /* Get Modulation */
        case 24: /* Set ISP */
        case 25: /* Flash */
        case 26: /* Bootloader Flash */ /* NOTE: This one seems to be not implemented in firmware at all*/
        case 28: /* Get Power Amplifier Level */
        case 30: /* Repeater */
        case 31: /* Range Test */
        case 32: /* Range Check */
        case 33: /* Get Firmware Revision Number */
        case 35: /* Get Hardware Board ID */
        case 37: /* Get Squelch */
        case 41: /* Get Clock */
        case 43: /* Get Access Address */
        case 45: /* Do Something */
        case 46: /* Do Something Reply */
        case 47: /* Get CRC Verify */
        case 49: /* Poll */
        case 50: /* BTLE Promiscuous Mode */
        case 52: /* Clear AFH Map */
        case 55: /* Get Compile Info */
        default:
            proto_tree_add_item(main_tree, hf_argument_0, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(main_tree, hf_argument_1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        proto_tree_add_item(main_tree, hf_estimated_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;


        switch (command) {
            case 38: /* Set BDADDR */
            case 54: /* BTLE Slave */
            case 56: /* BTLE Set Target */
                proto_tree_add_item(main_tree, hf_bdaddr, tvb, offset, 6, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",
                        tvb_get_ether_name(tvb, offset));

                offset += 6;
                break;
            case 39: /* Start Hopping */
                proto_tree_add_item(main_tree, hf_clock_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %u", tvb_get_letohl(tvb, offset));

                offset += 4;
                break;
            case 40: /* Set Clock */
                proto_tree_add_item(main_tree, hf_clock_100ns, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %u", tvb_get_letohl(tvb, offset));

                offset += 4;
                break;
            case 44: /* Set Access Address */
                proto_tree_add_item(main_tree, hf_access_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %08x", tvb_get_letohl(tvb, offset));

                offset += 4;
                break;
            case 51: /* Set AFH Map */
                proto_tree_add_item(main_tree, hf_afh_map, tvb, offset, 10, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, 10));

                offset += 10;
                break;
        }

        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_expert(main_tree, pinfo, &ei_unexpected_data, tvb, offset, tvb_captured_length_remaining(tvb, offset));
            offset = tvb_captured_length(tvb);
        }

        /* Save request info (command_data) */
        if (!pinfo->fd->flags.visited && command != 21) {
            key[2].length = 1;
            key[2].key = &k_frame_number;
            key[3].length = 0;
            key[3].key = NULL;

            command_data = wmem_new(wmem_file_scope(), command_data_t);
            command_data->bus_id = bus_id;
            command_data->device_address = device_address;

            command_data->command = command;
            command_data->command_frame_number = pinfo->num;
            command_data->register_id = register_id;

            wmem_tree_insert32_array(command_info, key, command_data);
        }

        pinfo->p2p_dir = p2p_dir_save;

        return offset;
    }

    /* Get request info (command_data) */
    key[2].length = 0;
    key[2].key = NULL;

    wmem_tree = (wmem_tree_t *) wmem_tree_lookup32_array(command_info, key);
   if (wmem_tree) {
        command_data = (command_data_t *) wmem_tree_lookup32_le(wmem_tree, pinfo->num);
        if (command_data) {
            command_response = command_data->command;
            register_id = command_data->register_id;
        }
   }

    if (!command_data) {
        col_append_str(pinfo->cinfo, COL_INFO, "Response: Unknown");

        proto_tree_add_expert(main_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_captured_length_remaining(tvb, offset));

        pinfo->p2p_dir = p2p_dir_save;

        return tvb_captured_length(tvb);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, "Response: %s",
            val_to_str_ext_const(command_response, &command_vals_ext, "Unknown"));

    command_item = proto_tree_add_uint(main_tree, hf_response, tvb, offset, 0, command_response);
    command_tree = proto_item_add_subtree(command_item, ett_command);
    PROTO_ITEM_SET_GENERATED(command_item);
    switch (command_response) {

    case 1: /* Rx Symbols */
    case 27: /* Spectrum Analyzer */
        if (usb_conv_info->transfer_type == URB_BULK) {

            while (tvb_reported_length_remaining(tvb, offset) > 0) {
                offset = dissect_usb_rx_packet(tree, main_tree, pinfo, tvb, offset, command_response, usb_conv_info);
            }
            break;
        }
    case 0: /* Ping */
    case 2: /* Tx Symbols */        /* NOTE: This one seems to be not implemented in firmware at all*/
    case 26: /* Bootloader Flash */ /* NOTE: This one seems to be not implemented in firmware at all*/
    case 4: /* Set User LED */
    case 6: /* Set Rx LED */
    case 8: /* Set Tx LED */
    case 10: /* Set 1V8 */
    case 12: /* Set Channel */
    case 13: /* Reset */
    case 17: /* Set PAEN */
    case 19: /* Set HGM */
    case 20: /* Tx Test */
    case 21: /* Stop */
    case 29: /* Set Power Amplifier Level */
    case 30: /* Repeater */
    case 31: /* Range Test */
    case 23: /* Set Modulation */
    case 24: /* Set ISP */
    case 25: /* Flash */
    case 34: /* LED Spectrum Analyzer */
    case 36: /* Set Squelch */
    case 38: /* Set BDADDR */
    case 39: /* Start Hopping */
    case 40: /* Set Clock */
    case 42: /* BTLE Sniffing */
    case 44: /* Set Access Address */
    case 45: /* Do Something */
    case 48: /* Set CRC Verify */
    case 50: /* BTLE Promiscuous Mode */
    case 51: /* Set AFH Map */
    case 52: /* Clear AFH Map */
    case 54: /* BTLE Slave */
    case 56: /* BTLE Set Target */
    case 58: /* Write Register */
        proto_tree_add_expert(command_tree, pinfo, &ei_unexpected_response, tvb, offset, 0);
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_expert(main_tree, pinfo, &ei_unknown_data, tvb, offset, -1);
            offset = tvb_captured_length(tvb);
        }
        break;
    case 3: /* Get User LED */
        proto_tree_add_item(main_tree, hf_user_led, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &led_state_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 5: /* Get Rx LED */
        proto_tree_add_item(main_tree, hf_rx_led, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &led_state_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 7: /* Get Tx LED */
        proto_tree_add_item(main_tree, hf_tx_led, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &led_state_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 9: /* Get 1V8 */
        proto_tree_add_item(main_tree, hf_1v8_led, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &led_state_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 11: /* Get Channel */
        proto_tree_add_item(main_tree, hf_channel, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %u MHz", tvb_get_letohs(tvb, offset));
        offset += 2;

        break;
    case 14: /* Get Microcontroller Serial Number */
        proto_tree_add_item(main_tree, hf_status, tvb, offset, 1, ENC_NA);
        status = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (status) break;

        serial = (guint32 *) wmem_alloc(wmem_packet_scope(), 16);
        serial[0] = tvb_get_ntohl(tvb, offset);
        serial[1] = tvb_get_ntohl(tvb, offset + 4);
        serial[2] = tvb_get_ntohl(tvb, offset + 8);
        serial[3] = tvb_get_ntohl(tvb, offset + 12);

        proto_tree_add_bytes(main_tree, hf_serial_number, tvb,
                offset, 16, (guint8 *) serial);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s",
                bytes_to_str(wmem_packet_scope(), (guint8 *) serial, 16));
        offset += 16;

        break;
    case 15: /* Get Microcontroller Part Number */
        proto_tree_add_item(main_tree, hf_status, tvb, offset, 1, ENC_NA);
        status = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (status) break;

        proto_tree_add_item(main_tree, hf_part_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %08X", tvb_get_letohl(tvb, offset));
        offset += 4;

        break;
    case 16: /* Get PAEN */
        proto_tree_add_item(main_tree, hf_paen, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &state_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 18: /* Get HGM */
        proto_tree_add_item(main_tree, hf_hgm, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &state_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 22: /* Get Modulation */
        proto_tree_add_item(main_tree, hf_modulation, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &modulation_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 28: /* Get Power Amplifier Level */
        proto_tree_add_item(main_tree, hf_power_amplifier_reserved, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(main_tree, hf_power_amplifier_level, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %u", tvb_get_guint8(tvb, offset) & 0x7);
        offset += 1;

        break;
    case 32: /* Range Check */
        proto_tree_add_item(main_tree, hf_range_test_valid, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(main_tree, hf_range_test_request_power_amplifier, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(main_tree, hf_range_test_request_number, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(main_tree, hf_range_test_reply_power_amplifier, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(main_tree, hf_range_test_reply_number, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 33: /* Get Firmware Revision Number */
        {
        const guint8* firmware;
        proto_tree_add_item(main_tree, hf_reserved, tvb, offset, 2, ENC_NA);
        offset += 2;

        proto_tree_add_item(main_tree, hf_length, tvb, offset, 1, ENC_NA);
        length = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item_ret_string(main_tree, hf_firmware_revision, tvb, offset, length, ENC_NA | ENC_ASCII, wmem_packet_scope(), &firmware);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", firmware);
        offset += length;
        }
        break;
    case 35: /* Get Hardware Board ID */
        proto_tree_add_item(main_tree, hf_board_id, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &board_id_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 37: /* Get Squelch */
        proto_tree_add_item(main_tree, hf_squelch, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %i", (gint8) tvb_get_guint8(tvb, offset));
        offset += 1;

        break;
    case 41: /* Get Clock */
        proto_tree_add_item(main_tree, hf_clock_ns, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %u", tvb_get_guint8(tvb, offset));
        offset += 1;

        break;
    case 43: /* Get Access Address */
        proto_tree_add_item(main_tree, hf_access_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %08x", tvb_get_letohl(tvb, offset));
        offset += 4;

        break;
    case 46: /* Do Something Reply */
            proto_tree_add_item(main_tree, hf_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;

        break;
    case 47: /* Get CRC Verify */
        proto_tree_add_item(main_tree, hf_crc_verify, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", val_to_str_ext_const(tvb_get_guint8(tvb, offset), &state_vals_ext, "Unknown"));
        offset += 1;

        break;
    case 49: /* Poll */
    case 59: /* Jam Mode */
    case 60: /* Ego */
        if (tvb_reported_length_remaining(tvb, offset) == 1) {
            proto_tree_add_item(main_tree, hf_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        }

        offset = dissect_usb_rx_packet(tree, main_tree, pinfo, tvb, offset, command_response, usb_conv_info);

        break;
    case 53: /* Read Register */
        sub_item = proto_tree_add_uint(main_tree, hf_register, tvb, offset, 0, register_id);
        PROTO_ITEM_SET_GENERATED(sub_item);
        if (try_val_to_str_ext(register_id, &register_vals_ext))
            proto_item_append_text(sub_item, " [%s]", val_to_str_ext_const(register_id, &register_description_vals_ext, "Unknown"));


        sub_item = proto_tree_add_item(main_tree, hf_register_value, tvb, offset, 2, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_register_value);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s:  0x%04x",
                val_to_str_ext_const(register_id, &register_vals_ext, "Unknown"),
                tvb_get_ntohs(tvb, offset));

        dissect_cc2400_register(sub_tree, tvb, offset, register_id);
        offset += 2;

        break;
    case 55: /* Get Compile Info */
        {
        const guint8* compile;
        proto_tree_add_item(main_tree, hf_length, tvb, offset, 1, ENC_NA);
        length = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item_ret_string(main_tree, hf_firmware_compile_info, tvb, offset, length, ENC_NA | ENC_ASCII, wmem_packet_scope(), &compile);
        col_append_fstr(pinfo->cinfo, COL_INFO, " = %s", compile);
        offset += length;
        }
        break;
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert(main_tree, pinfo, &ei_unknown_data, tvb, offset, -1);
        offset = tvb_captured_length(tvb);
    }

    pinfo->p2p_dir = p2p_dir_save;

    return offset;
}

void
proto_register_ubertooth(void)
{
    module_t         *module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_command,
            { "Command",                         "ubertooth.command",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &command_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_response,
            { "Response",                        "ubertooth.response",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &command_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_argument_0,
            { "Unused Argument 0",               "ubertooth.argument.0",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_argument_1,
            { "Unused Argument 1",               "ubertooth.argument.1",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_estimated_length,
            { "Estimated Length",                "ubertooth.estimated_length",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_board_id,
            { "Board ID",                        "ubertooth.board_id",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &board_id_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_reserved,
            { "Reserved",                        "ubertooth.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_length,
            { "Length",                          "ubertooth.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_firmware_revision,
            { "Firmware Revision",               "ubertooth.firmware.reversion",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_firmware_compile_info,
            { "Firmware Compile Info",           "ubertooth.firmware.compile_info",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_user_led,
            { "User LED State",                  "ubertooth.user_led",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &led_state_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_rx_led,
            { "Rx LED State",                    "ubertooth.rx_led",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &led_state_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_tx_led,
            { "Tx LED State",                    "ubertooth.tx_led",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &led_state_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_1v8_led,
            { "1V8 LED State",                   "ubertooth.1v8_led",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &led_state_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_channel,
            { "Channel",                         "ubertooth.channel",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_usb_rx_packet_channel,
            { "Channel",                         "ubertooth.usb_rx_packet.channel",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_serial_number,
            { "Serial Number",                   "ubertooth.serial_number",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_status,
            { "Status",                          "ubertooth.status",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_part_number,
            { "Part Number",                     "ubertooth.part_number",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_packet_type,
            { "Packet Type",                     "ubertooth.packet_type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &packet_type_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_state,
            { "State",                           "ubertooth.state",
            FT_UINT8, BASE_HEX, VALS(usb_rx_packet_state_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_crc_init,
            { "CRC Init",                        "ubertooth.crc_init",
            FT_UINT24, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_hop_interval,
            { "Hop Interval",                    "ubertooth.hop_interval",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            "Hop Interval in unit 1.25ms", HFILL }
        },
        { &hf_hop_increment,
            { "Hop Increment",                    "ubertooth.hop_increment",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_chip_status_reserved,
            { "Reserved",                        "ubertooth.status.resered",
            FT_BOOLEAN, 8, NULL, 0xE0,
            NULL, HFILL }
        },
        { &hf_chip_status_rssi_trigger,
            { "RSSI Trigger",                    "ubertooth.status.rssi_trigger",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_chip_status_cs_trigger,
            { "CS Trigger",                      "ubertooth.status.cs_trigger",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_chip_status_fifo_overflow,
            { "FIFO Overflow",                   "ubertooth.status.fifo_overflow",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_chip_status_dma_error,
            { "DMA Error",                       "ubertooth.status.dma_error",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_chip_status_dma_overflow,
            { "DMA Overflow",                    "ubertooth.status.dma_overflow",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_clock_ns,
            { "Clock 1ns",                      "ubertooth.clock_ns",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_clock_100ns,
            { "Clock 100ns",                    "ubertooth.clock_100ns",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rssi_min,
            { "RSSI Min",                        "ubertooth.rssi_min",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rssi_max,
            { "RSSI Max",                        "ubertooth.rssi_max",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rssi_avg,
            { "RSSI Avg",                        "ubertooth.rssi_avg",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rssi_count,
            { "RSSI Count",                      "ubertooth.rssi_count",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_paen,
            { "PAEN",                            "ubertooth.paen",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &state_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_hgm,
            { "HGM",                             "ubertooth.hgm",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &state_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_crc_verify,
            { "CRC Verify",                      "ubertooth.crc_verify",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &state_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_modulation,
            { "Modulation",                      "ubertooth.modulation",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &modulation_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_power_amplifier_reserved,
            { "Reserved",                        "ubertooth.power_amplifier.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF8,
            NULL, HFILL }
        },
        { &hf_power_amplifier_level,
            { "Level",                           "ubertooth.power_amplifier.level",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_range_test_valid,
            { "Valid",                           "ubertooth.range_test.valid",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_range_test_request_power_amplifier,
            { "Request Power Amplifier",         "ubertooth.range_test.request_power_amplifier",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_range_test_request_number,
            { "Request Power Amplifier",         "ubertooth.range_test.request_number",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_range_test_reply_power_amplifier,
            { "Request Power Amplifier",         "ubertooth.range_test.reply_power_amplifier",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_range_test_reply_number,
            { "Reply Power Amplifier",           "ubertooth.range_test.reply_number",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_squelch,
            { "Squelch",                         "ubertooth.squelch",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_access_address,
            { "Access Address",                  "ubertooth.access_address",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_jam_mode,
            { "Jam Mode",                        "ubertooth.jam_mode",
            FT_UINT16, BASE_HEX, VALS(jam_mode_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ego_mode,
            { "Ego Mode",                        "ubertooth.ego_mode",
            FT_UINT16, BASE_HEX, VALS(ego_mode_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_register,
            { "Register",                        "ubertooth.register",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &register_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_register_value,
            { "Register Value",                  "ubertooth.register.value",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_low_frequency,
            { "Low Frequency",                   "ubertooth.low_frequency",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_high_frequency,
            { "High Frequency",                  "ubertooth.high_frequency",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rx_packets,
            { "Rx Packets",                      "ubertooth.rx_packets",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rssi_threshold,
            { "RSSI Threshold",                  "ubertooth.rssi_threshold",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_clock_offset,
            { "Clock Offset",                    "ubertooth.clock_offset",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_afh_map,
            { "AFH Map",                         "ubertooth.afh_map",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bdaddr,
          { "BD_ADDR",                           "ubertooth.bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "Bluetooth Device Address", HFILL}
        },
        { &hf_usb_rx_packet,
            { "USB Rx Packet",                   "ubertooth.usb_rx_packet",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_spectrum_entry,
            { "Spectrum Entry",                  "ubertooth.spectrum_entry",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_frequency,
            { "Frequency",                       "ubertooth.spectrum_entry.frequency",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_rssi,
            { "RSSI",                            "ubertooth.spectrum_entry.rssi",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_data,
            { "Data",                            "ubertooth.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_cc2400_value,
            { "Value",                           "ubertooth.register.value",
            FT_UINT16, BASE_HEX_DEC, NULL, 0xFFFF,
            NULL, HFILL }
        },
        { &hf_cc2400_syncl,
            { "Synchronisation Word, lower 16 bit",        "ubertooth.register.value.syncl",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_cc2400_synch,
            { "Synchronisation Word, upper 16 bit",        "ubertooth.register.value.synch",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x2B_res_15_14,
            { "Reserved [15:14]",                          "ubertooth.register.value.reserved.0x2B.15_14",
            FT_UINT16, BASE_DEC, NULL, 0xC000,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x2B_res_13,
            { "Reserved [13]",                             "ubertooth.register.value.reserved.0x2B.13",
            FT_BOOLEAN, 16, NULL, 0x2000,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x2B_res_12,
            { "Reserved [12]",                             "ubertooth.register.value.reserved.0x2B.12",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x2B_res_11_0,
            { "Reserved [11:0]",                           "ubertooth.register.value.reserved.0x2B.11_0",
            FT_UINT16, BASE_DEC, NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x2A_res_15_11,
            { "Reserved [15:11]",                          "ubertooth.register.value.reserved.0x2A.15_11",
            FT_UINT16, BASE_DEC, NULL, 0xF800,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x2A_res_10,
            { "Reserved [10]",                             "ubertooth.register.value.reserved.0x2A.10",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x2A_res_9_0,
            { "Reserved [9:0]",                            "ubertooth.register.value.reserved.0x2A.9_0",
            FT_UINT16, BASE_DEC, NULL, 0x03FF,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x29_res_15_8,
            { "Reserved [15:8]",                           "ubertooth.register.value.reserved.0x29.15_8",
            FT_UINT16, BASE_DEC, NULL, 0xFF00,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x29_res_7_3,
            { "Reserved [7:3]",                            "ubertooth.register.value.reserved.0x29.7_3",
            FT_UINT16, BASE_DEC, NULL, 0x00F8,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x29_res_2_0,
            { "Reserved [2:0]",                            "ubertooth.register.value.reserved.0x29.2_0",
            FT_UINT16, BASE_DEC, NULL, 0x0007,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x28_res_15,
            { "Reserved [15]",                             "ubertooth.register.value.reserved.0x28.15",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x28_res_14_13,
            { "Reserved [14:13]",                          "ubertooth.register.value.reserved.0x28.14_13",
            FT_UINT16, BASE_DEC, NULL, 0x6000,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x28_res_12_7,
            { "Reserved [12:7]",                           "ubertooth.register.value.reserved.0x28.12_7",
            FT_UINT16, BASE_DEC, NULL, 0x1F80,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x28_res_6_0,
            { "Reserved [6:0]",                            "ubertooth.register.value.reserved.0x28.6_0",
            FT_UINT16, BASE_DEC, NULL, 0x007F,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x27_res_15_8,
            { "Reserved [15:8]",                           "ubertooth.register.value.reserved.0x27.15_8",
            FT_UINT16, BASE_DEC, NULL, 0xFF00,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x27_res_7_3,
            { "Reserved [7:3]",                            "ubertooth.register.value.reserved.0x27.7_3",
            FT_UINT16, BASE_DEC, NULL, 0x00F8,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x27_res_2_0,
            { "Reserved [2:0]",                            "ubertooth.register.value.reserved.0x27.2_0",
            FT_UINT16, BASE_DEC, NULL, 0x0007,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x26_res_15_10,
            { "Reserved [15:10]",                          "ubertooth.register.value.reserved.0x26.15_10",
            FT_UINT16, BASE_DEC, NULL, 0xFC00,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x26_res_9_0,
            { "Reserved [9:0]",                            "ubertooth.register.value.reserved.0x26.9_0",
            FT_UINT16, BASE_DEC, NULL, 0x03FF,
            NULL, HFILL }
        },

        { &hf_cc2400_reserved_0x25_res_15_12,
            { "Reserved [15:12]",                          "ubertooth.register.value.reserved.0x25.15_12",
            FT_UINT16, BASE_DEC, NULL, 0xF000,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x25_res_11_0,
            { "Reserved [11:0]",                            "ubertooth.register.value.reserved.0x25.11_0",
            FT_UINT16, BASE_DEC, NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x24_res_15_14,
            { "Reserved [15:14]",                          "ubertooth.register.value.reserved.0x24.15_14",
            FT_UINT16, BASE_DEC, NULL, 0xC000,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x24_res_13_10,
            { "Reserved [13:10]",                          "ubertooth.register.value.reserved.0x24.13_10",
            FT_UINT16, BASE_DEC, NULL, 0x3C00,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x24_res_9_7,
            { "Reserved [9:7]",                            "ubertooth.register.value.reserved.0x24.9_7",
            FT_UINT16, BASE_DEC, NULL, 0x0380,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x24_res_6_0,
            { "Reserved [6:0]",                            "ubertooth.register.value.reserved.0x24.6_0",
            FT_UINT16, BASE_DEC, NULL, 0x007F,
            NULL, HFILL }
        },
        { &hf_cc2400_int_reserved_15_8,
            { "Reserved [15:8]",                           "ubertooth.register.value.int.reserved.15_8",
            FT_UINT16, BASE_DEC, NULL, 0xFF00,
            NULL, HFILL }
        },
        { &hf_cc2400_int_reserved_7,
            { "Reserved [7]",                              "ubertooth.register.value.int.reserved.7",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_cc2400_int_pkt_polarity,
            { "PKT Polarity",                              "ubertooth.register.value.int.pkt_polarity",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_cc2400_int_fifo_polarity,
            { "FIFO Polarity",                             "ubertooth.register.value.int.fifo_polarity",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_cc2400_int_fifo_threshold,
            { "FIFO Threshold",                            "ubertooth.register.value.int.fifo_threshold",
            FT_UINT16, BASE_DEC, NULL, 0x001F,
            NULL, HFILL }
        },
        { &hf_cc2400_main_resetn,
            { "Reset N",                                   "ubertooth.register.value.main.resetn",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_cc2400_main_reserved_14_10,
            { "Reserved [14:10]",                          "ubertooth.register.value.main.reserved.14_10",
            FT_UINT16, BASE_DEC, NULL, 0x7C00,
            NULL, HFILL }
        },
        { &hf_cc2400_main_fs_force_en,
            { "Forces Frequency Synthesiser",              "ubertooth.register.value.main.fs_force_en",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_cc2400_main_rxn_tx,
            { "RxN Tx",                                    "ubertooth.register.value.main.rxn_tx",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_cc2400_main_reserved_7_4,
            { "Reserved [7:4]",                            "ubertooth.register.value.main.reserved.7_4",
            FT_UINT16, BASE_DEC, NULL, 0x00F0,
            NULL, HFILL }
        },
        { &hf_cc2400_main_reserved_3,
            { "Reserved [3]",                              "ubertooth.register.value.main.reserved.3",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_cc2400_main_reserved_2,
            { "Reserved [2]",                              "ubertooth.register.value.main.reserved.2",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_cc2400_main_xosc16m_bypass,
            { "Bypass 16 MHz Crystal Oscillator",          "ubertooth.register.value.main.xosc16m_bypass",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_cc2400_main_xosc16m_en,
            { "Force 16 MHz Crystal Oscillator",           "ubertooth.register.value.main.xosc16m_en",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_cc2400_fsctrl_reserved,
            { "Reserved [15:6]",                           "ubertooth.register.value.fsctrl.reserved.15_6",
            FT_UINT16, BASE_DEC, NULL, 0xFFC0,
            NULL, HFILL }
        },
        { &hf_cc2400_fsctrl_lock_threshold,
            { "Lock Threshold",                            "ubertooth.register.value.fsctrl.lock_threshold",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_fsctlr_lock_threshold_vals_ext, 0x0030,
            NULL, HFILL }
        },
        { &hf_cc2400_fsctrl_cal_done,
            { "Calibration Done",                          "ubertooth.register.value.fsctrl.cal_done",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_cc2400_fsctrl_cal_running,
            { "Calibration Running",                       "ubertooth.register.value.fsctrl.cal_running",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_cc2400_fsctrl_lock_length,
            { "Lock Length",                               "ubertooth.register.value.fsctrl.lock_length",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_fsctlr_lock_length_vals_ext, 0x0002,
            NULL, HFILL }
        },
        { &hf_cc2400_fsctrl_lock_status,
            { "PLL Lock Status",                           "ubertooth.register.value.fsctrl.lock_status",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_cc2400_fsdiv_reserved,
            { "Reserved [15:12]",                          "ubertooth.register.value.fsdiv.reserved.15_12",
            FT_UINT16, BASE_DEC, NULL, 0xF000,
            NULL, HFILL }
        },
        { &hf_cc2400_fsdiv_frequency,
            { "Frequency",                                 "ubertooth.register.value.fsdiv.frequency",
            FT_UINT16, BASE_DEC, NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_cc2400_fsdiv_freq_high,
            { "Frequency High Part",                       "ubertooth.register.value.fsdiv.frequency.high",
            FT_UINT16, BASE_DEC, NULL, 0x0C00,
            NULL, HFILL }
        },
        { &hf_cc2400_fsdiv_freq,
            { "Frequency Lower Part",                      "ubertooth.register.value.fsdiv.frequency.low",
            FT_UINT16, BASE_DEC, NULL, 0x03FF,
            NULL, HFILL }
        },
        { &hf_cc2400_mdmctrl_reserved,
            { "Reserved [15:13]",                          "ubertooth.register.value.mdmctrl.reserved.15_13",
            FT_UINT16, BASE_DEC, NULL, 0xE000,
            NULL, HFILL }
        },
        { &hf_cc2400_mdmctrl_mod_offset,
            { "Modulator Offset",                          "ubertooth.register.value.mdmctrl.mod_offset",
            FT_UINT16, BASE_DEC, NULL, 0x1F80,
            NULL, HFILL }
        },
        { &hf_cc2400_mdmctrl_mod_dev,
            { "Modulator Deviation",                       "ubertooth.register.value.mdmctrl.mod_dev",
            FT_UINT16, BASE_DEC, NULL, 0x007F,
            NULL, HFILL }
        },
        { &hf_cc2400_agcctrl_vga_gain,
            { "VGA Gain",                                  "ubertooth.register.value.agcctrl.vga_gain",
            FT_UINT16, BASE_HEX, NULL, 0xFF00,
            NULL, HFILL }
        },
        { &hf_cc2400_agcctrl_reserved,
            { "Reserved [7:4]",                            "ubertooth.register.value.agcctrl.reserved.7_4",
            FT_UINT16, BASE_DEC, NULL, 0x00F0,
            NULL, HFILL }
        },
        { &hf_cc2400_agcctrl_agc_locked,
            { "AGC Locked",                                "ubertooth.register.value.agcctrl.agc_locked",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_cc2400_agcctrl_agc_lock,
            { "AGC Lock",                                  "ubertooth.register.value.agcctrl.agc_lock",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_cc2400_agcctrl_agc_sync_lock,
            { "AGC Sync Lock",                             "ubertooth.register.value.agcctrl.agc_sync_lock",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_cc2400_agcctrl_vga_gain_oe,
            { "VGA Gain Override Enable",                  "ubertooth.register.value.agcctrl.vga_gain_oe",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_cc2400_frend_reserved_15_4,
            { "Reserved [15:4]",                           "ubertooth.register.value.frend.reserved.15_4",
            FT_UINT16, BASE_DEC, NULL, 0xFFF0,
            NULL, HFILL }
        },
        { &hf_cc2400_frend_reserved_3,
            { "Reserved [3]",                              "ubertooth.register.value.frend.reserved.3",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_cc2400_frend_pa_level,
            { "Power Amplifier Level",                     "ubertooth.register.value.frend.pa_level",
            FT_UINT16, BASE_DEC, NULL, 0x0007,
            NULL, HFILL }
        },
        { &hf_cc2400_rssi_rssi_val,
            { "Avarage RSSI Value",                        "ubertooth.register.value.rssi.rssi_val",
            FT_INT8, BASE_DEC, NULL, 0xFF00,
            NULL, HFILL }
        },
        { &hf_cc2400_rssi_rssi_cs_thres,
            { "RSSI Carrier Sense Threshold",              "ubertooth.register.value.rssi.rssi_cs_thres",
            FT_INT16, BASE_DEC, NULL, 0x00FC,
            NULL, HFILL }
        },
        { &hf_cc2400_rssi_rssi_filt,
            { "RSSI Averaging Filter Length",              "ubertooth.register.value.rssi.rssi_filt",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_rssi_rssi_filt_vals_ext, 0x0003,
            NULL, HFILL }
        },
        { &hf_cc2400_freqest_rx_freq_offset,
            { "Rx Frequence Offset",                       "ubertooth.register.value.freqest.rx_freq_offset",
            FT_INT16, BASE_DEC, NULL, 0xFF00,
            NULL, HFILL }
        },
        { &hf_cc2400_freqest_reserved,
            { "Reserved [7:0]",                            "ubertooth.register.value.freqest.reserved.7_0",
            FT_UINT16, BASE_DEC, NULL, 0x00FF,
            NULL, HFILL }
        },
        { &hf_cc2400_iocfg_reserved,
            { "Reserved [15]",                             "ubertooth.register.value.iocfg.reserved.15",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_cc2400_iocfg_gio6_cfg,
            { "GIO6 Configuration",                        "ubertooth.register.value.iocfg.gio6_cfg",
            FT_UINT16, BASE_DEC, NULL, 0x7E00,
            NULL, HFILL }
        },
        { &hf_cc2400_iocfg_gio1_cfg,
            { "GIO1 Configuration",                        "ubertooth.register.value.iocfg.gio1_cfg",
            FT_UINT16, BASE_DEC, NULL, 0x01F8,
            NULL, HFILL }
        },
        { &hf_cc2400_iocfg_hssd_src,
            { "High Speed Serial Data Source",             "ubertooth.register.value.iocfg.hssd_src",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_iocfg_hssd_src_vals_ext, 0x0007,
            NULL, HFILL }
        },
        { &hf_cc2400_fsmtc_tc_rxon2agcen,
            { "Rx On to AGC Enabled",                      "ubertooth.register.value.fsmtc.tc_rxon2agcen",
            FT_UINT16, BASE_DEC, NULL, 0xE000,
            NULL, HFILL }
        },
        { &hf_cc2400_fsmtc_tc_paon2switch,
            { "Power Amplifier On to Switch",              "ubertooth.register.value.fsmtc.tc_paon2switch",
            FT_UINT16, BASE_DEC, NULL, 0x1C00,
            NULL, HFILL }
        },
        { &hf_cc2400_fsmtc_res,
            { "Reserved [9:6]",                            "ubertooth.register.value.fsmtc.reserved.9_6",
            FT_UINT16, BASE_DEC, NULL, 0x03C0,
            NULL, HFILL }
        },
        { &hf_cc2400_fsmtc_tc_txend2switch,
            { "Tx End to Switch",                          "ubertooth.register.value.fsmtc.tc_txend2switch",
            FT_UINT16, BASE_DEC, NULL, 0x0038,
            NULL, HFILL }
        },
        { &hf_cc2400_fsmtc_tc_txend2paoff,
            { "Tx End to Power Amplifier Off",             "ubertooth.register.value.fsmtc.tc_txend2paoff",
            FT_UINT16, BASE_DEC, NULL, 0x0007,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x0C_res_15_5,
            { "Reserved [15:5]",                           "ubertooth.register.value.reserved.0x0C.15_5",
            FT_UINT16, BASE_DEC, NULL, 0xFFE0,
            NULL, HFILL }
        },
        { &hf_cc2400_reserved_0x0C_res_4_0,
            { "Reserved [4:0]",                            "ubertooth.register.value.reserved.0x0C.4_0",
            FT_UINT16, BASE_DEC, NULL, 0x001F,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_vga_reset_n,
            { "No VGA Reset",                              "ubertooth.register.value.manand.vga_reset_n",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_lock_status,
            { "Lock Status",                               "ubertooth.register.value.manand.lock_status",
            FT_BOOLEAN, 16, NULL, 0x4000,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_balun_ctrl,
            { "Balun Control",                             "ubertooth.register.value.manand.balun_ctrl",
            FT_BOOLEAN, 16, NULL, 0x2000,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_rxtx,
            { "RxTx",                                      "ubertooth.register.value.manand.rxtx",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_pre_pd,
            { "Power Down of Prescaler",                   "ubertooth.register.value.manand.pre_pd",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_pa_n_pd,
            { "Power Down of Power Amplifier (negative path)",  "ubertooth.register.value.manand.pa_n_pd",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_pa_p_pd,
            { "Power Down of Power Amplifier (positive path)",  "ubertooth.register.value.manand.pa_p_pd",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_dac_lpf_pd,
            { "Power Down of Tx DAC",                      "ubertooth.register.value.manand.dac_lpf_pd",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_bias_pd,
            { "Power Down control of global bias generator + XOSC clock buffer",         "ubertooth.register.value.manand.bias_pd",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_xosc16m_pd,
            { "Power Down control of 16 MHz XOSC core",    "ubertooth.register.value.manand.xosc16m_pd",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_chp_pd,
            { "Power Down control of Charge Pump",         "ubertooth.register.value.manand.chp_pd",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_fs_pd,
            { "Power Down control of VCO, I/Q generator, LO buffers",     "ubertooth.register.value.manand.fs_pd",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_adc_pd,
            { "Power Down control of the ADC",                            "ubertooth.register.value.manand.adc_pd",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_vga_pd,
            { "Power Down control of the VGA",                            "ubertooth.register.value.manand.vga_pd",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_rxbpf_pd,
            { "Power Down control of complex band-pass receive filter",   "ubertooth.register.value.manand.rxbpf_pd",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_cc2400_manand_lnamix_pd,
            { "Power Down control of LNA, down-conversion mixers and front-end bias",    "ubertooth.register.value.manand.lnamix_pd",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_cc2400_fsmstate_reserved_15_13,
            { "Reserved [15:13]",                          "ubertooth.register.value.fsmstate.reserved.15_13",
            FT_UINT16, BASE_DEC, NULL, 0xE000,
            NULL, HFILL }
        },
        { &hf_cc2400_fsmstate_fsm_state_bkpt,
            { "FSM breakpoint state",                      "ubertooth.register.value.fsmstate.fsm_state_bkpt",
            FT_UINT16, BASE_DEC, NULL, 0x1F00,
            NULL, HFILL }
        },
        { &hf_cc2400_fsmstate_reserved_7_5,
            { "Reserved [7:5]",                            "ubertooth.register.value.fsmstate.reserved.7_5",
            FT_UINT16, BASE_DEC, NULL, 0x00E0,
            NULL, HFILL }
        },
        { &hf_cc2400_fsmstate_fsm_cur_state,
            { "Current state of the finite state machine", "ubertooth.register.value.fsmstate.fsm_cur_state",
            FT_UINT16, BASE_DEC, NULL, 0x001F,
            NULL, HFILL }
        },
        { &hf_cc2400_adctst_reserved_15,
            { "Reserved [15]",                             "ubertooth.register.value.adctst.reserved.15",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_cc2400_adctst_adc_i,
            { "Current ADC I-branch value",                "ubertooth.register.value.adctst.adc_i",
            FT_UINT16, BASE_DEC, NULL, 0x7F00,
            NULL, HFILL }
        },
        { &hf_cc2400_adctst_reserved_7,
            { "Reserved [7]",                              "ubertooth.register.value.adctst.reserved.7",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_cc2400_adctst_adc_q,
            { "Current ADC Q-branch value",                "ubertooth.register.value.adctst.adc_q",
            FT_UINT16, BASE_DEC, NULL, 0x007F,
            NULL, HFILL }
        },
        { &hf_cc2400_rxbpftst_reserved,
            { "Reserved [15]",                             "ubertooth.register.value.rxbpftst.reserved.15",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_cc2400_rxbpftst_rxbpf_cap_oe,
            { "RX band-pass filter capacitance calibration override enable",   "ubertooth.register.value.rxbpftst.rxbpf_cap_oe",
            FT_BOOLEAN, 16, NULL, 0x4000,
            NULL, HFILL }
        },
        { &hf_cc2400_rxbpftst_rxbpf_cap_o,
            { "RX band-pass filter capacitance calibration override value",    "ubertooth.register.value.rxbpftst.rxbpf_cap_o",
            FT_UINT16, BASE_DEC, NULL, 0x3F80,
            NULL, HFILL }
        },
        { &hf_cc2400_rxbpftst_rxbpf_cap_res,
            { "RX band-pass filter capacitance calibration result",    "ubertooth.register.value.rxbpftst.rxbpf_cap_res",
            FT_UINT16, BASE_DEC, NULL, 0x007F,
            NULL, HFILL }
        },
        { &hf_cc2400_pamtst_reserved_15_13,
            { "Reserved [15:13]",                          "ubertooth.register.value.pamtst.reserved.15_13",
            FT_UINT16, BASE_DEC, NULL, 0xE000,
            NULL, HFILL }
        },
        { &hf_cc2400_pamtst_vc_in_test_en,
            { "VC in Test En",                             "ubertooth.register.value.pamtst.vc_in_test_en",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_cc2400_pamtst_atestmod_pd,
            { "Power down of the analog test module",      "ubertooth.register.value.pamtst.atestmod_pd",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_cc2400_pamtst_atestmod_mode,
            { "Function of the Analog Test Module",        "ubertooth.register.value.pamtst.atestmod_mode",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_pamtst_atestmod_mode_vals_ext, 0x0700,
            NULL, HFILL }
        },
        { &hf_cc2400_pamtst_reserved_7,
            { "Reserved [7]",                              "ubertooth.register.value.pamtst.reserved.7",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_cc2400_pamtst_txmix_cap_array,
            { "Varactor array settings in the transmit mixers", "ubertooth.register.value.pamtst.txmix_cap_array",
            FT_UINT16, BASE_DEC, NULL, 0x0060,
            NULL, HFILL }
        },
        { &hf_cc2400_pamtst_txmix_current,
            { "Transmit Mixers Current",                   "ubertooth.register.value.pamtst.txmix_current",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_pamtst_txmix_current_vals_ext, 0x0018,
            NULL, HFILL }
        },
        { &hf_cc2400_pamtst_pa_current,
            { "Power Amplifier Current",                   "ubertooth.register.value.pamtst.pa_current",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_pamtst_pa_current_vals_ext, 0x0007,
            NULL, HFILL }
        },
        { &hf_cc2400_lmtst_reserved,
            { "Reserved [15:14]",                          "ubertooth.register.value.lmtst.reserved.15_14",
            FT_UINT16, BASE_DEC, NULL, 0xC000,
            NULL, HFILL }
        },
        { &hf_cc2400_lmtst_rxmix_hgm,
            { "Receiver Mixers High Gain Mode Enable",     "ubertooth.register.value.lmtst.rxmix_hgm",
            FT_BOOLEAN, 16, NULL, 0x2000,
            NULL, HFILL }
        },
        { &hf_cc2400_lmtst_rxmix_tail,
            { "Receiver Mixers Output Current",            "ubertooth.register.value.lmtst.rxmix_tail",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_lmtst_rxmix_tail_vals_ext, 0x1800,
            NULL, HFILL }
        },
        { &hf_cc2400_lmtst_rxmix_vcm,
            { "Controls VCM level in the mixer feedback loop",  "ubertooth.register.value.lmtst.rxmix_vcm",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_lmtst_rxmix_vcm_vals_ext, 0x0600,
            NULL, HFILL }
        },
        { &hf_cc2400_lmtst_rxmix_current,
            { "Controls current in the mixer",             "ubertooth.register.value.lmtst.rxmix_current",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_lmtst_rxmix_current_vals_ext, 0x0180,
            NULL, HFILL }
        },
        { &hf_cc2400_lmtst_lna_cap_array,
            { "Varactor array setting in the LNA",         "ubertooth.register.value.lmtst.lna_cap_array",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_lmtst_lna_cap_array_vals_ext, 0x0060,
            NULL, HFILL }
        },
        { &hf_cc2400_lmtst_lna_lowgain,
            { "Low gain mode of the LNA",                  "ubertooth.register.value.lmtst.lna_lowgain",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_lmtst_lna_lowgain_vals_ext, 0x0010,
            NULL, HFILL }
        },
        { &hf_cc2400_lmtst_lna_gain,
            { "Controls current in the LNA gain compensation branch",  "ubertooth.register.value.lmtst.lna_gain",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_lmtst_lna_gain_vals_ext, 0x000C,
            NULL, HFILL }
        },
        { &hf_cc2400_lmtst_lna_current,
            { "Main current in the LNA",                   "ubertooth.register.value.lmtst.lna_current",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_lmtst_lna_current_vals_ext, 0x003,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_vga_reset_n,
            { "No VGA Reset",                              "ubertooth.register.value.manor.vga_reset_n",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_lock_status,
            { "Lock Status",                               "ubertooth.register.value.manor.lock_status",
            FT_BOOLEAN, 16, NULL, 0x4000,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_balun_ctrl,
            { "Balun Control",                             "ubertooth.register.value.manor.balun_ctrl",
            FT_BOOLEAN, 16, NULL, 0x2000,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_rxtx,
            { "RxTx",                                      "ubertooth.register.value.manor.rxtx",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_pre_pd,
            { "Power Down of Prescaler",                   "ubertooth.register.value.manor.pre_pd",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_pa_n_pd,
            { "Power Down of Power Amplifier (negative path)",  "ubertooth.register.value.manor.pa_n_pd",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_pa_p_pd,
            { "Power Down of Power Amplifier (positive path)",  "ubertooth.register.value.manor.pa_p_pd",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_dac_lpf_pd,
            { "Power Down of Tx DAC",                      "ubertooth.register.value.manor.dac_lpf_pd",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_bias_pd,
            { "Power Down control of global bias generator + XOSC clock buffer",         "ubertooth.register.value.manor.bias_pd",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_xosc16m_pd,
            { "Power Down control of 16 MHz XOSC core",    "ubertooth.register.value.manor.xosc16m_pd",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_chp_pd,
            { "Power Down control of Charge Pump",         "ubertooth.register.value.manor.chp_pd",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_fs_pd,
            { "Power Down control of VCO, I/Q generator, LO buffers",     "ubertooth.register.value.manor.fs_pd",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_adc_pd,
            { "Power Down control of the ADC",                            "ubertooth.register.value.manor.adc_pd",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_vga_pd,
            { "Power Down control of the VGA",                            "ubertooth.register.value.manor.vga_pd",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_rxbpf_pd,
            { "Power Down control of complex band-pass receive filter",   "ubertooth.register.value.manor.rxbpf_pd",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL }
        },
        { &hf_cc2400_manor_lnamix_pd,
            { "Power Down control of LNA, down-conversion mixers and front-end bias",    "ubertooth.register.value.manor.lnamix_pd",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_cc2400_mdmtst0_reserved,
            { "Reserved [15:14]",                          "ubertooth.register.value.mdmtst0.reserved.15_14",
            FT_UINT16, BASE_DEC, NULL, 0xC000,
            NULL, HFILL }
        },
        { &hf_cc2400_mdmtst0_tx_prng,
            { "Tx PRNG",                                   "ubertooth.register.value.mdmtst0.tx_prng",
            FT_BOOLEAN, 16, NULL, 0x2000,
            NULL, HFILL }
        },
        { &hf_cc2400_mdmtst0_tx_1mhz_offset_n,
            { "Tx No 1MHz Offset",                         "ubertooth.register.value.mdmtst0.tx_1mhz_offset_n",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_cc2400_mdmtst0_invert_data,
            { "Invert Data",                               "ubertooth.register.value.mdmtst0.invert_data",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_cc2400_mdmtst0_afc_adjust_on_packet,
            { "AFC Adjust on Packet",                      "ubertooth.register.value.mdmtst0.afc_adjust_on_packet",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_cc2400_mdmtst0_afc_settling,
            { "AFC Settling",                              "ubertooth.register.value.mdmtst0.afc_settling",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_mdmtst0_afc_settling_vals_ext, 0x0300,
            NULL, HFILL }
        },
        { &hf_cc2400_mdmtst0_afc_delta,
            { "AFC Delta",                                 "ubertooth.register.value.mdmtst0.afc_delta",
            FT_UINT16, BASE_DEC, NULL, 0x00FF,
            NULL, HFILL }
        },
        { &hf_cc2400_mdmtst1_reserved,
            { "Reserved [15:7]",                           "ubertooth.register.value.mdmtst1.reserved.15_7",
            FT_UINT16, BASE_DEC, NULL, 0xFF80,
            NULL, HFILL }
        },
        { &hf_cc2400_mdmtst1_bsync_threshold,
            { "B-Sync Threshold",                          "ubertooth.register.value.mdmtst1.bsync_threshold",
            FT_UINT16, BASE_DEC, NULL, 0x07F,
            NULL, HFILL }
        },
        { &hf_cc2400_dactst_reserved,
            { "Reserved [15]",                             "ubertooth.register.value.dactst.reserved.15",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_cc2400_dactst_dac_src,
            { "DAC Source",                                "ubertooth.register.value.dactst.dac_src",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_dactst_dac_src_vals_ext, 0x7000,
            NULL, HFILL }
        },
        { &hf_cc2400_dactst_dac_i_o,
            { "I-branch DAC Override Value",               "ubertooth.register.value.dactst.dac_i_o",
            FT_UINT16, BASE_DEC, NULL, 0x0FC0,
            NULL, HFILL }
        },
        { &hf_cc2400_dactst_dac_q_o,
            { "Q-branch DAC Override Value",               "ubertooth.register.value.dactst.dac_q_o",
            FT_UINT16, BASE_DEC, NULL, 0x003F,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst0_agc_settle_blank_dn,
            { "AGC Settle Blank Down",                     "ubertooth.register.value.agctst0.agc_settle_blank_down",
            FT_UINT16, BASE_DEC, NULL, 0xE000,
            "Duration of blanking signal in 8 MHz clock cycles", HFILL }
        },
        { &hf_cc2400_agctst0_agc_win_size,
            { "AGC Window Size",                           "ubertooth.register.value.agctst0.agc_win_size",
            FT_UINT16, BASE_DEC, NULL, 0x1800,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst0_agc_settle_peak,
            { "AGC Settle Peak Period",                    "ubertooth.register.value.agctst0.agc_settle_peak",
            FT_UINT16, BASE_DEC, NULL, 0x0780,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst0_agc_settle_adc,
            { "AGC Settle ADC Period",                    "ubertooth.register.value.agctst0.agc_settle_adc",
            FT_UINT16, BASE_DEC, NULL, 0x0078,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst0_agc_attempts,
            { "AGC Attempts",                              "ubertooth.register.value.agctst0.agc_attempts",
            FT_UINT16, BASE_DEC, NULL, 0x0007,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst1_reserved,
            { "Reserved [15]",                             "ubertooth.register.value.agctst1.reserved.15",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst1_agc_var_gain_sat,
            { "AGC Variable Gain Stage",                   "ubertooth.register.value.agctst1.agc_var_gain_sat",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_agctst1_agc_var_gain_sat_vals_ext, 0x4000,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst1_agc_settle_blank_up,
            { "AGC Settle Bank Up",                        "ubertooth.register.value.agctst1.agc_settle_blank_up",
            FT_UINT16, BASE_DEC, NULL, 0x3800,
            "Duration of blanking signal in 8 MHz clock cycles", HFILL }
        },
        { &hf_cc2400_agctst1_peakdet_cur_boost,
            { "Current Peak Detectors Boost",              "ubertooth.register.value.agctst1.peakdet_cur_boost",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst1_agc_mult_slow,
            { "AGC Timing Multiplier Slow Mode",           "ubertooth.register.value.agctst1.agc_mult_slow",
            FT_UINT16, BASE_DEC, NULL, 0x03C0,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst1_agc_settle_fixed,
            { "AGC Settling Period Fixed Gain Step",       "ubertooth.register.value.agctst1.agc_settle_fixed",
            FT_UINT16, BASE_DEC, NULL, 0x003C,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst1_agc_settle_var,
            { "AGC Settling Period Variable Gain Step",    "ubertooth.register.value.agctst1.agc_settle_var",
            FT_UINT16, BASE_DEC, NULL, 0x0003,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst2_reserved,
            { "Reserved [15:14]",                          "ubertooth.register.value.agctst2.reserved.15_14",
            FT_UINT16, BASE_DEC, NULL, 0xC000,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst2_agc_backend_blanking,
            { "AGC Backend Blanking",                      "ubertooth.register.value.agctst2.agc_backend_blanking",
            FT_UINT16, BASE_DEC, NULL, 0x3000,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst2_agc_adjust_m3db,
            { "AGC Adjust -3db",                           "ubertooth.register.value.agctst2.agc_adjust_m3db",
            FT_UINT16, BASE_DEC, NULL, 0x0E00,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst2_agc_adjust_m1db,
            { "AGC Adjust -1db",                           "ubertooth.register.value.agctst2.agc_adjust_m1db",
            FT_UINT16, BASE_DEC, NULL, 0x01C0,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst2_agc_adjust_p3db,
            { "AGC Adjust +3db",                           "ubertooth.register.value.agctst2.agc_adjust_p3db",
            FT_UINT16, BASE_DEC, NULL, 0x0038,
            NULL, HFILL }
        },
        { &hf_cc2400_agctst2_agc_adjust_p1db,
            { "AGC Adjust +1db",                           "ubertooth.register.value.agctst2.agc_adjust_p1db",
            FT_UINT16, BASE_DEC, NULL, 0x0007,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst0_rxmixbuf_cur,
            { "Rx Mixer Buffer Bias Current",      "ubertooth.register.value.fstst0.rxmixbuf_cur",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_fstst0_rxtxmixbuf_cur_vals_ext, 0xC000,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst0_txmixbuf_cur,
            { "TX Mixer Buffer Bias Current",     "ubertooth.register.value.fstst0.txmixbuf_cur",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_fstst0_rxtxmixbuf_cur_vals_ext, 0x3000,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst0_vco_array_settle_long,
            { "Voltage Controlled Oscillator Array Settle Long",              "ubertooth.register.value.fstst0.vco_array_settle_lon",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst0_vco_array_oe,
            { "Voltage Controlled Oscillator Array Manual Override Enable",   "ubertooth.register.value.fstst0.vco_array_oe",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst0_vco_array_o,
            { "Voltage Controlled Oscillator Array Override Value",           "ubertooth.register.value.fstst0.vco_array_o",
            FT_UINT16, BASE_DEC, NULL, 0x03E0,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst0_vco_array_res,
            { "Resulting VCO Array Setting from Last Calibration",            "ubertooth.register.value.fstst0.vco_array_res",
            FT_UINT16, BASE_DEC, NULL, 0x001F,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst1_rxbpf_locur,
            { "Rx Band-pass Filters LO Bias Current",      "ubertooth.register.value.fstst1.rxbpf_locur",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_fstst1_rxbpf_locur_vals_ext, 0x8000,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst1_rxbpf_midcur,
            { "Rx Band-pass Filters MID Bias Current",     "ubertooth.register.value.fstst1.rxbpf_midcur",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_fstst1_rxbpf_midcur_vals_ext, 0x4000,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst1_vco_current_ref,
            { "VCO Current Reference",                     "ubertooth.register.value.fstst1.vco_current_ref",
            FT_UINT16, BASE_DEC, NULL, 0x3C00,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst1_vco_current_k,
            { "VCO Current Calibration Constant",          "ubertooth.register.value.fstst1.vco_current_k",
            FT_UINT16, BASE_DEC, NULL, 0x03F0,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst1_vc_dac_en,
            { "VCO Source",                                "ubertooth.register.value.fstst1.vc_dac_en",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_fstst1_vc_dac_en_vals_ext, 0x0008,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst1_vc_dac_val,
            { "VCO DAC Output Value",                      "ubertooth.register.value.fstst1.vc_dac_val",
            FT_UINT16, BASE_DEC, NULL, 0x0007,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst2_reserved,
            { "Reserved [15]",                                                "ubertooth.register.value.fstst2.reserved.15",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst2_vco_curcal_speed,
            { "Voltage Controlled Oscillator Current Calibration",            "ubertooth.register.value.fstst2.vco_curcal_speed",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_fstst2_vco_curcal_speed_vals_ext, 0x6000,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst2_vco_current_oe,
            { "Voltage Controlled Oscillator Current Manual Override Enable", "ubertooth.register.value.fstst2.vco_current_oe",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst2_vco_current_o,
            { "Voltage Controlled Oscillator Current Override Value",         "ubertooth.register.value.fstst2.vco_current_o",
            FT_UINT16, BASE_DEC, NULL, 0x0FC0,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst2_vco_current_res,
            { "Resulting VCO Current Setting from Last Calibration",          "ubertooth.register.value.fstst2.vco_current_res",
            FT_UINT16, BASE_DEC, NULL, 0x003F,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst3_reserved,
            { "Reserved [15:14]",                          "ubertooth.register.value.fstst3.reserved.15_14",
            FT_UINT16, BASE_DEC, NULL, 0xC000,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst3_chp_test_up,
            { "Charge Pump Test Up",                       "ubertooth.register.value.fstst3.chp_test_up",
            FT_BOOLEAN, 16, NULL, 0x2000,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst3_chp_test_dn,
            { "Charge Pump Test Down",                     "ubertooth.register.value.fstst3.chp_test_down",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst3_chp_disable,
            { "Charge Pump Disable",                       "ubertooth.register.value.fstst3.chp_disable",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst3_pd_delay,
            { "Phase Detector Delay",                      "ubertooth.register.value.fstst3.pd_delay",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_fstst3_pd_delay_vals_ext, 0x0400,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst3_chp_step_period,
            { "Charge Pump Step Period",                   "ubertooth.register.value.fstst3.chp_step_period",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_fstst3_chp_step_period_vals_ext, 0x0300,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst3_stop_chp_current,
            { "Stop Charge Pump Current",                  "ubertooth.register.value.fstst3.stop_chp_current",
            FT_UINT16, BASE_DEC, NULL, 0x00F0,
            NULL, HFILL }
        },
        { &hf_cc2400_fstst3_start_chp_current,
            { "Start Charge Pump Current",                 "ubertooth.register.value.fstst3.start_chp_current",
            FT_UINT16, BASE_DEC, NULL, 0x000F,
            NULL, HFILL }
        },

        { &hf_cc2400_manfidl_partnum,
            { "Part Number [3:0]",                         "ubertooth.register.value.manfidl.partnum",
            FT_UINT16, BASE_DEC, NULL, 0xF000,
            NULL, HFILL }
        },
        { &hf_cc2400_manfidl_manfid,
            { "Manufacturer ID",                           "ubertooth.register.value.manfidl.manfid",
            FT_UINT16, BASE_HEX, NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_cc2400_manfidh_version,
            { "Version",                                   "ubertooth.register.value.manfidh.version",
            FT_UINT16, BASE_DEC, NULL, 0xF000,
            NULL, HFILL }
        },
        { &hf_cc2400_manfidh_partnum,
            { "Part Number [15:4]",                        "ubertooth.register.value.manfidh.partnum",
            FT_UINT16, BASE_DEC, NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_cc2400_grmdm_reserved,
            { "Reserved [15]",                             "ubertooth.register.value.grmdm.reserved.15",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_cc2400_grmdm_sync_errbits_allowed,
            { "Sync Error Bits Allowed",                   "ubertooth.register.value.grmdm.sync_errbits_allowed",
            FT_UINT16, BASE_DEC, NULL, 0x6000,
            NULL, HFILL }
        },
        { &hf_cc2400_grmdm_pin_mode,
            { "PIN Mode",                                  "ubertooth.register.value.grmdm.pin_mode",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_grmdm_pin_mode_vals_ext, 0x1800,
            NULL, HFILL }
        },
        { &hf_cc2400_grmdm_packet_mode,
            { "Packet Mode",                               "ubertooth.register.value.grmdm.packet_mode",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_cc2400_grmdm_pre_bytes,
            { "Preamble Bytes",                            "ubertooth.register.value.grmdm.pre_bytes",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_grmdm_pre_bytes_vals_ext, 0x0380,
            NULL, HFILL }
        },
        { &hf_cc2400_grmdm_sync_word_size,
            { "Sync Word Size",                            "ubertooth.register.value.grmdm.sync_word_size",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_grmdm_sync_word_size_vals_ext, 0x0060,
            NULL, HFILL }
        },
        { &hf_cc2400_grmdm_crc_on,
            { "CRC On",                                    "ubertooth.register.value.grmdm.crc_on",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL }
        },
        { &hf_cc2400_grmdm_data_format,
            { "Data Format",                               "ubertooth.register.value.grmdm.data_format",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_grmdm_data_format_vals_ext, 0x000C,
            NULL, HFILL }
        },
        { &hf_cc2400_grmdm_modulation_format,
            { "Modulation Format",                         "ubertooth.register.value.grmdm.modulation_format",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_grmdm_modulation_format_vals_ext, 0x0002,
            NULL, HFILL }
        },
        { &hf_cc2400_grmdm_tx_gaussian_filter,
            { "Tx Gaussian Filter",                        "ubertooth.register.value.grmdm.tx_gaussian_filter",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_cc2400_grdec_reserved,
            { "Reserved [15:13]",                          "ubertooth.register.value.grdec.reserved.15_13",
            FT_UINT16, BASE_DEC, NULL, 0xE000,
            NULL, HFILL }
        },
        { &hf_cc2400_grdec_ind_saturation,
            { "Ind Saturation",                            "ubertooth.register.value.grdec.ind_saturation",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL }
        },
        { &hf_cc2400_grdec_dec_shift,
            { "Decimation Shift",                          "ubertooth.register.value.grdec.dec_shift",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_grdec_dec_shift_vals_ext, 0x0C00,
            NULL, HFILL }
        },
        { &hf_cc2400_grdec_channel_dec,
            { "Channel Decimation",                        "ubertooth.register.value.grdec.channel_dec",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cc2400_grdec_channel_dec_vals_ext, 0x0300,
            NULL, HFILL }
        },
        { &hf_cc2400_grdec_dec_val,
            { "Decimation Value",                          "ubertooth.register.value.grdec.dec_val",
            FT_UINT16, BASE_DEC, NULL, 0x00FF,
            NULL, HFILL }
        },
        { &hf_cc2400_pktstatus_reserved_15_11,
            { "Reserved [15:11]",                          "ubertooth.register.value.pktstatus.reserved.15_11",
            FT_UINT16, BASE_DEC, NULL, 0xF800,
            NULL, HFILL }
        },
        { &hf_cc2400_pktstatus_sync_word_received,
            { "Sync Word Received",                        "ubertooth.register.value.pktstatus.sync_word_received",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL }
        },
        { &hf_cc2400_pktstatus_crc_ok,
            { "CRC OK",                                    "ubertooth.register.value.pktstatus.crc_ok",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL }
        },
        { &hf_cc2400_pktstatus_reserved_8,
            { "Reserved [8]",                              "ubertooth.register.value.pktstatus.reserved.8",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL }
        },
        { &hf_cc2400_pktstatus_reserved_7_0,
            { "Reserved [7:0]",                            "ubertooth.register.value.pktstatus.reserved.7_0",
            FT_UINT16, BASE_DEC, NULL, 0x00FF,
            NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_unexpected_response, { "ubertooth.unexpected_response", PI_PROTOCOL, PI_ERROR, "Unexpected response for this command", EXPFILL }},
        { &ei_unknown_data, { "ubertooth.unknown_data", PI_PROTOCOL, PI_NOTE, "Unknown data", EXPFILL }},
        { &ei_unexpected_data, { "ubertooth.unexpected_data", PI_PROTOCOL, PI_WARN, "Unexpected data", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_ubertooth,
        &ett_command,
        &ett_usb_rx_packet,
        &ett_usb_rx_packet_data,
        &ett_entry,
        &ett_register_value,
        &ett_fsdiv_frequency
    };

    command_info = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_ubertooth = proto_register_protocol("Ubertooth", "UBERTOOTH", "ubertooth");
    proto_register_field_array(proto_ubertooth, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    ubertooth_handle = register_dissector("ubertooth", dissect_ubertooth, proto_ubertooth);

    expert_module = expert_register_protocol(proto_ubertooth);
    expert_register_field_array(expert_module, ei, array_length(ei));

    module = prefs_register_protocol(proto_ubertooth, NULL);
    prefs_register_static_text_preference(module, "version",
            "Ubertooth Firmware: 2012-10-R1 (also latest version prior to: git-4470774)",
            "Version of protocol supported by this dissector.");
}

void
proto_reg_handoff_ubertooth(void)
{
    bluetooth_ubertooth_handle = find_dissector_add_dependency("bluetooth_ubertooth", proto_ubertooth);

    dissector_add_uint("usb.product", (0x1d50 << 16) | 0x6000, ubertooth_handle); /* Ubertooth Zero */
    dissector_add_uint("usb.product", (0x1d50 << 16) | 0x6002, ubertooth_handle); /* Ubertooth One */

    dissector_add_for_decode_as("usb.device",   ubertooth_handle);
    dissector_add_for_decode_as("usb.protocol", ubertooth_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
