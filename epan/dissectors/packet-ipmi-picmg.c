/* packet-ipmi-picmg.c
 * Sub-dissectors for IPMI messages (netFn=Group, defining body = PICMG)
 * Copyright 2007-2008, Alexey Neyman, Pigeon Point Systems <avn@pigeonpoint.com>
 *
 * $Id$
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <epan/packet.h>

#include "packet-ipmi.h"

static gint ett_ipmi_picmg_led_color = -1;
static gint ett_ipmi_picmg_link_info = -1;
static gint ett_ipmi_picmg_05_byte1 = -1;
static gint ett_ipmi_picmg_06_byte1 = -1;
static gint ett_ipmi_picmg_06_byte2 = -1;
static gint ett_ipmi_picmg_06_byte3 = -1;
static gint ett_ipmi_picmg_08_byte1 = -1;
static gint ett_ipmi_picmg_09_ipmba = -1;
static gint ett_ipmi_picmg_09_ipmbb = -1;
static gint ett_ipmi_picmg_0a_byte2 = -1;
static gint ett_ipmi_picmg_0a_byte3 = -1;
static gint ett_ipmi_picmg_0b_byte1 = -1;
static gint ett_ipmi_picmg_0f_chan = -1;
static gint ett_ipmi_picmg_12_byte1 = -1;
static gint ett_ipmi_picmg_14_prop = -1;
static gint ett_ipmi_picmg_1e_byte1 = -1;
static gint ett_ipmi_picmg_21_byte9 = -1;
static gint ett_ipmi_picmg_XX_compbits = -1;
static gint ett_ipmi_picmg_2e_byte2 = -1;
static gint ett_ipmi_picmg_prop00_byte1 = -1;
static gint ett_ipmi_picmg_prop01_byte1 = -1;
static gint ett_ipmi_picmg_34_byte3 = -1;
static gint ett_ipmi_picmg_36_byte2 = -1;
static gint ett_ipmi_picmg_37_byte2 = -1;

static gint hf_ipmi_picmg_led_function = -1;
static gint hf_ipmi_picmg_led_on_duration = -1;
static gint hf_ipmi_picmg_led_color = -1;

static gint hf_ipmi_picmg_linkinfo_grpid = -1;
static gint hf_ipmi_picmg_linkinfo_type_ext = -1;
static gint hf_ipmi_picmg_linkinfo_type = -1;
static gint hf_ipmi_picmg_linkinfo_ports = -1;
static gint hf_ipmi_picmg_linkinfo_iface = -1;
static gint hf_ipmi_picmg_linkinfo_chan = -1;
static gint hf_ipmi_picmg_linkinfo_state = -1;

static gint hf_ipmi_picmg_00_version = -1;
static gint hf_ipmi_picmg_00_max_fruid = -1;
static gint hf_ipmi_picmg_00_ipmc_fruid = -1;

static gint hf_ipmi_picmg_01_rq_fruid = -1;
static gint hf_ipmi_picmg_01_rq_addr_key_type = -1;
static gint hf_ipmi_picmg_01_rq_addr_key = -1;
static gint hf_ipmi_picmg_01_rq_site_type = -1;
static gint hf_ipmi_picmg_01_rs_hwaddr = -1;
static gint hf_ipmi_picmg_01_rs_ipmbaddr = -1;
static gint hf_ipmi_picmg_01_rs_rsrv = -1;
static gint hf_ipmi_picmg_01_rs_fruid = -1;
static gint hf_ipmi_picmg_01_rs_site_num = -1;
static gint hf_ipmi_picmg_01_rs_site_type = -1;

static gint hf_ipmi_picmg_04_fruid = -1;
static gint hf_ipmi_picmg_04_cmd = -1;

static gint hf_ipmi_picmg_05_fruid = -1;
static gint hf_ipmi_picmg_05_led3 = -1;
static gint hf_ipmi_picmg_05_led2 = -1;
static gint hf_ipmi_picmg_05_led1 = -1;
static gint hf_ipmi_picmg_05_blue_led = -1;
static gint hf_ipmi_picmg_05_app_leds = -1;

static gint hf_ipmi_picmg_06_fruid = -1;
static gint hf_ipmi_picmg_06_ledid = -1;
static gint hf_ipmi_picmg_06_cap_white = -1;
static gint hf_ipmi_picmg_06_cap_orange = -1;
static gint hf_ipmi_picmg_06_cap_amber = -1;
static gint hf_ipmi_picmg_06_cap_green = -1;
static gint hf_ipmi_picmg_06_cap_red = -1;
static gint hf_ipmi_picmg_06_cap_blue = -1;
static gint hf_ipmi_picmg_06_default_local_color = -1;
static gint hf_ipmi_picmg_06_default_override_color = -1;

static gint hf_ipmi_picmg_07_fruid = -1;
static gint hf_ipmi_picmg_07_ledid = -1;

static gint hf_ipmi_picmg_08_fruid = -1;
static gint hf_ipmi_picmg_08_ledid = -1;
static gint hf_ipmi_picmg_08_state_lamptest = -1;
static gint hf_ipmi_picmg_08_state_override = -1;
static gint hf_ipmi_picmg_08_state_local = -1;
static gint hf_ipmi_picmg_08_lamptest_duration = -1;

static gint hf_ipmi_picmg_09_ipmba = -1;
static gint hf_ipmi_picmg_09_ipmbb = -1;

static gint hf_ipmi_picmg_0a_fruid = -1;
static gint hf_ipmi_picmg_0a_msk_d_locked = -1;
static gint hf_ipmi_picmg_0a_msk_locked = -1;
static gint hf_ipmi_picmg_0a_d_locked = -1;
static gint hf_ipmi_picmg_0a_locked = -1;

static gint hf_ipmi_picmg_0b_fruid = -1;
static gint hf_ipmi_picmg_0b_d_locked = -1;
static gint hf_ipmi_picmg_0b_locked = -1;

static gint hf_ipmi_picmg_0c_fruid = -1;
static gint hf_ipmi_picmg_0c_cmd = -1;

static gint hf_ipmi_picmg_0d_fruid = -1;
static gint hf_ipmi_picmg_0d_start = -1;
static gint hf_ipmi_picmg_0d_recordid = -1;

static gint hf_ipmi_picmg_0f_iface = -1;
static gint hf_ipmi_picmg_0f_chan = -1;

static gint hf_ipmi_picmg_10_fruid = -1;
static gint hf_ipmi_picmg_10_nslots = -1;
static gint hf_ipmi_picmg_10_ipmc_loc = -1;

static gint hf_ipmi_picmg_11_fruid = -1;
static gint hf_ipmi_picmg_11_power_level = -1;
static gint hf_ipmi_picmg_11_set_to_desired = -1;

static gint hf_ipmi_picmg_12_fruid = -1;
static gint hf_ipmi_picmg_12_pwr_type = -1;
static gint hf_ipmi_picmg_12_dynamic = -1;
static gint hf_ipmi_picmg_12_pwr_lvl = -1;
static gint hf_ipmi_picmg_12_delay = -1;
static gint hf_ipmi_picmg_12_pwr_mult = -1;
static gint hf_ipmi_picmg_12_pwr_draw = -1;

static gint hf_ipmi_picmg_13_fruid = -1;

static gint hf_ipmi_picmg_14_fruid = -1;
static gint hf_ipmi_picmg_14_speed_min = -1;
static gint hf_ipmi_picmg_14_speed_max = -1;
static gint hf_ipmi_picmg_14_speed_norm = -1;
static gint hf_ipmi_picmg_14_local_control = -1;

static gint hf_ipmi_picmg_15_fruid = -1;
static gint hf_ipmi_picmg_15_fan_level = -1;
static gint hf_ipmi_picmg_15_local_enable = -1;

static gint hf_ipmi_picmg_16_fruid = -1;
static gint hf_ipmi_picmg_16_override_level = -1;
static gint hf_ipmi_picmg_16_local_level = -1;
static gint hf_ipmi_picmg_16_local_enable = -1;

static gint hf_ipmi_picmg_17_cmd = -1;
static gint hf_ipmi_picmg_17_resid = -1;
static gint hf_ipmi_picmg_17_status = -1;

static gint hf_ipmi_picmg_18_li_key_type = -1;
static gint hf_ipmi_picmg_18_li_key = -1;
static gint hf_ipmi_picmg_18_link_num = -1;
static gint hf_ipmi_picmg_18_sensor_num = -1;

static gint hf_ipmi_picmg_1b_addr_active = -1;
static gint hf_ipmi_picmg_1b_addr_backup = -1;

static gint hf_ipmi_picmg_1c_fan_site_number = -1;
static gint hf_ipmi_picmg_1c_fan_enable_state = -1;
static gint hf_ipmi_picmg_1c_fan_policy_timeout = -1;
static gint hf_ipmi_picmg_1c_site_number = -1;
static gint hf_ipmi_picmg_1c_site_type = -1;

static gint hf_ipmi_picmg_1d_fan_site_number = -1;
static gint hf_ipmi_picmg_1d_site_number = -1;
static gint hf_ipmi_picmg_1d_site_type = -1;
static gint hf_ipmi_picmg_1d_policy = -1;
static gint hf_ipmi_picmg_1d_coverage = -1;

static gint hf_ipmi_picmg_1e_fruid = -1;
static gint hf_ipmi_picmg_1e_cap_diagintr = -1;
static gint hf_ipmi_picmg_1e_cap_graceful_reboot = -1;
static gint hf_ipmi_picmg_1e_cap_warm_reset = -1;

static gint hf_ipmi_picmg_1f_rq_fruid = -1;
static gint hf_ipmi_picmg_1f_rq_op = -1;
static gint hf_ipmi_picmg_1f_rq_lockid = -1;
static gint hf_ipmi_picmg_1f_rs_lockid = -1;
static gint hf_ipmi_picmg_1f_rs_tstamp = -1;

static gint hf_ipmi_picmg_20_fruid = -1;
static gint hf_ipmi_picmg_20_lockid = -1;
static gint hf_ipmi_picmg_20_offset = -1;
static gint hf_ipmi_picmg_20_data = -1;
static gint hf_ipmi_picmg_20_count = -1;

static gint hf_ipmi_picmg_21_addr_num = -1;
static gint hf_ipmi_picmg_21_tstamp = -1;
static gint hf_ipmi_picmg_21_addr_count = -1;
static gint hf_ipmi_picmg_21_site_type = -1;
static gint hf_ipmi_picmg_21_site_num = -1;
static gint hf_ipmi_picmg_21_max_unavail = -1;
static gint hf_ipmi_picmg_21_is_shm = -1;
static gint hf_ipmi_picmg_21_addr_type = -1;
static gint hf_ipmi_picmg_21_ipaddr = -1;
static gint hf_ipmi_picmg_21_rmcpport = -1;

static gint hf_ipmi_picmg_22_feed_idx = -1;
static gint hf_ipmi_picmg_22_update_cnt = -1;
static gint hf_ipmi_picmg_22_pwr_alloc = -1;

static gint hf_ipmi_picmg_XX_comp7 = -1;
static gint hf_ipmi_picmg_XX_comp6 = -1;
static gint hf_ipmi_picmg_XX_comp5 = -1;
static gint hf_ipmi_picmg_XX_comp4 = -1;
static gint hf_ipmi_picmg_XX_comp3 = -1;
static gint hf_ipmi_picmg_XX_comp2 = -1;
static gint hf_ipmi_picmg_XX_comp1 = -1;
static gint hf_ipmi_picmg_XX_comp0 = -1;

static gint hf_ipmi_picmg_2e_version = -1;
static gint hf_ipmi_picmg_2e_upgrade_undesirable = -1;
static gint hf_ipmi_picmg_2e_auto_rollback_override = -1;
static gint hf_ipmi_picmg_2e_ipmc_degraded = -1;
static gint hf_ipmi_picmg_2e_deferred_activate = -1;
static gint hf_ipmi_picmg_2e_services_affected = -1;
static gint hf_ipmi_picmg_2e_manual_rollback = -1;
static gint hf_ipmi_picmg_2e_auto_rollback = -1;
static gint hf_ipmi_picmg_2e_self_test = -1;
static gint hf_ipmi_picmg_2e_upgrade_tout = -1;
static gint hf_ipmi_picmg_2e_selftest_tout = -1;
static gint hf_ipmi_picmg_2e_rollback_tout = -1;
static gint hf_ipmi_picmg_2e_inaccessibility_tout = -1;

static gint hf_ipmi_picmg_prop00_cold_reset = -1;
static gint hf_ipmi_picmg_prop00_deferred_activation = -1;
static gint hf_ipmi_picmg_prop00_comparison = -1;
static gint hf_ipmi_picmg_prop00_preparation = -1;
static gint hf_ipmi_picmg_prop00_rollback = -1;
static gint hf_ipmi_picmg_prop01_fw_major = -1;
static gint hf_ipmi_picmg_prop01_fw_minor = -1;
static gint hf_ipmi_picmg_prop01_fw_aux = -1;
static gint hf_ipmi_picmg_prop02_desc = -1;

static gint hf_ipmi_picmg_2f_comp_id = -1;
static gint hf_ipmi_picmg_2f_comp_prop = -1;
static gint hf_ipmi_picmg_2f_prop_data = -1;

static gint hf_ipmi_picmg_31_action = -1;

static gint hf_ipmi_picmg_32_block = -1;
static gint hf_ipmi_picmg_32_data = -1;
static gint hf_ipmi_picmg_32_sec_offs = -1;
static gint hf_ipmi_picmg_32_sec_len = -1;

static gint hf_ipmi_picmg_33_comp_id = -1;
static gint hf_ipmi_picmg_33_img_len = -1;

static gint hf_ipmi_picmg_34_cmd = -1;
static gint hf_ipmi_picmg_34_ccode = -1;
static gint hf_ipmi_picmg_34_percentage = -1;

static gint hf_ipmi_picmg_35_rollback_override = -1;

static gint hf_ipmi_picmg_36_result = -1;
static gint hf_ipmi_picmg_36_fail = -1;
static gint hf_ipmi_picmg_36_fail_sel = -1;
static gint hf_ipmi_picmg_36_fail_sdr = -1;
static gint hf_ipmi_picmg_36_fail_bmc_fru = -1;
static gint hf_ipmi_picmg_36_fail_ipmb_sig = -1;
static gint hf_ipmi_picmg_36_fail_sdr_empty = -1;
static gint hf_ipmi_picmg_36_fail_iua = -1;
static gint hf_ipmi_picmg_36_fail_bb_fw = -1;
static gint hf_ipmi_picmg_36_fail_oper_fw = -1;

static gint hf_ipmi_picmg_37_percent = -1;

static const value_string site_type_vals[] = {
	{ 0x00, "PICMG board" },
	{ 0x01, "Power Entry" },
	{ 0x02, "Shelf FRU Information" },
	{ 0x03, "Dedicated ShMC" },
	{ 0x04, "Fan Tray / Cooling Unit" },
	{ 0x05, "Fan Filter Tray" },
	{ 0x06, "Alarm" },
	{ 0x07, "AdvancedMC module" },
	{ 0x08, "PMC" },
	{ 0x09, "Rear Transition Module" },
	{ 0x0A, "MicroTCA Carrier Hub" },
	{ 0x0B, "Power Module" },
	{ 0xC0, "OEM" },
	{ 0xC1, "OEM" },
	{ 0xC2, "OEM" },
	{ 0xC3, "OEM" },
	{ 0xC4, "OEM" },
	{ 0xC5, "OEM" },
	{ 0xC6, "OEM" },
	{ 0xC7, "OEM" },
	{ 0xC8, "OEM" },
	{ 0xC9, "OEM" },
	{ 0xCA, "OEM" },
	{ 0xCB, "OEM" },
	{ 0xCC, "OEM" },
	{ 0xCD, "OEM" },
	{ 0xCE, "OEM" },
	{ 0xCF, "OEM" },
	{ 0, NULL }
};

static const value_string addr_key_type_vals[] = {
	{ 0x00, "Hardware Address" },
	{ 0x01, "IPMB-0 Address" },
	{ 0x03, "Physical Address" },
	{ 0, NULL }
};

static const struct true_false_string set_clear_tfs = {
	"Set", "Clear"
};

static const value_string led_color_vals[] = {
	{ 0x00, "Reserved (Control not supported)" },
	{ 0x01, "Blue" },
	{ 0x02, "Red" },
	{ 0x03, "Green" },
	{ 0x04, "Amber" },
	{ 0x05, "Orange" },
	{ 0x06, "White" },
	{ 0x0E, "Do not change" },
	{ 0x0F, "Use default" },
	{ 0, NULL }
};

static const value_string linkinfo_type_vals[] = {
	{ 0x01, "PICMG3.0 Base Interface 10/100/1000 BASE-T" },
	{ 0x02, "PICMG3.1 Ethernet Fabric Interface" },
	{ 0x03, "PICMG3.2 Infiniband Fabric Interface" },
	{ 0x04, "PICMG3.3 StarFabric Fabric Interface" },
	{ 0x05, "PICMG3.4 PCI Express Fabric Interface" },
	{ 0xf0, "OEM" }, { 0xf1, "OEM" }, { 0xf2, "OEM" }, { 0xf3, "OEM" },
	{ 0xf4, "OEM" }, { 0xf5, "OEM" }, { 0xf6, "OEM" }, { 0xf7, "OEM" },
	{ 0xf8, "OEM" }, { 0xf9, "OEM" }, { 0xfa, "OEM" }, { 0xfb, "OEM" },
	{ 0xfc, "OEM" }, { 0xfd, "OEM" }, { 0xfe, "OEM" },

	{ 0, NULL }
};

static const value_string linkinfo_ports_vals[] = {
	{ 0x00, "None" },
	{ 0x01, "0" },
	{ 0x02, "1" },
	{ 0x03, "0,1" },
	{ 0x04, "2" },
	{ 0x05, "0,2" },
	{ 0x06, "1,2" },
	{ 0x07, "0,1,2" },
	{ 0x08, "3" },
	{ 0x09, "0,3" },
	{ 0x0a, "1,3" },
	{ 0x0b, "0,1,3" },
	{ 0x0c, "2,3" },
	{ 0x0d, "0,2,3" },
	{ 0x0e, "1,2,3" },
	{ 0x0f, "0,1,2,3" },

	{ 0, NULL }
};

static const value_string linkinfo_iface_vals[] = {
	{ 0x00, "Base Interface" },
	{ 0x01, "Fabric Interface" },
	{ 0x02, "Update Channel Interface" },

	{ 0, NULL }
};

static const value_string busresid_vals[] = {
	{ 0x00, "Metallic Test Bus #1" },
	{ 0x01, "Metallic Test Bus #2" },
	{ 0x02, "Synch clock group #1" },
	{ 0x03, "Synch clock group #2" },
	{ 0x04, "Synch clock group #3" },
	{ 0, NULL }
};

static const value_string fan_level_vals[] = {
	{ 0xFE, "Shut down" },
	{ 0xFF, "Local control" },
	{ 0, NULL }
};

static const value_string enable_vals[] = {
	{ 0x00, "Disable" },
	{ 0x01, "Enable" },
	{ 0, NULL }
};

static const value_string enabled_vals[] = {
	{ 0x00, "Disabled" },
	{ 0x01, "Enabled" },
	{ 0, NULL }
};

static const value_string vals_04_cmd[] = {
	{ 0x00, "Cold Reset" },
	{ 0x01, "Warm Reset" },
	{ 0x02, "Graceful Reboot" },
	{ 0x03, "Issue Diagnostic Interrupt" },
	{ 0x04, "Quiesce" },
	{ 0, NULL }
};

static const value_string vals_0c_cmd[] = {
	{ 0x00, "Deactivate FRU" },
	{ 0x01, "Activate FRU" },
	{ 0, NULL }
};

static const value_string vals_11_set[] = {
	{ 0x00, "Do not change present levels" },
	{ 0x01, "Copy desired levels to present levels" },
	{ 0, NULL }
};

static const value_string vals_12_pwr_type[] = {
	{ 0x00, "Steady state power draw levels" },
	{ 0x01, "Desired steady state draw levels" },
	{ 0x02, "Early power draw levels" },
	{ 0x03, "Desired early levels" },
	{ 0, NULL }
};

static const value_string vals_18_keytype[] = {
	{ 0x00, "Link Info Key contains Link Number" },
	{ 0x01, "Link Info Key contains Sensor Number" },
	{ 0, NULL }
};

static const value_string vals_1d_policy[] = {
	{ 0x00, "Disabled" },
	{ 0x01, "Enabled" },
	{ 0xFF, "Indeterminate" },
	{ 0, NULL }
};

static const value_string vals_1d_coverage[] = {
	{ 0x00, "Not Covered" },
	{ 0x01, "Covered" },
	{ 0, NULL }
};

static const value_string vals_1f_op[] = {
	{ 0x00, "Get Last Commit Timestamp" },
	{ 0x01, "Lock" },
	{ 0x02, "Unlock and Discard" },
	{ 0x03, "Unlock and Commit" },
	{ 0, NULL }
};

static const value_string vals_21_addr_type[] = {
	{ 0x01, "IPv4" },
	{ 0x60, "OEM" }, { 0x61, "OEM" }, { 0x62, "OEM" }, { 0x63, "OEM" },
	{ 0x64, "OEM" }, { 0x65, "OEM" }, { 0x66, "OEM" }, { 0x67, "OEM" },
	{ 0x68, "OEM" }, { 0x69, "OEM" }, { 0x6a, "OEM" }, { 0x6b, "OEM" },
	{ 0x6c, "OEM" }, { 0x6d, "OEM" }, { 0x6e, "OEM" }, { 0x6f, "OEM" },
	{ 0x70, "OEM" }, { 0x71, "OEM" }, { 0x72, "OEM" }, { 0x73, "OEM" },
	{ 0x74, "OEM" }, { 0x75, "OEM" }, { 0x76, "OEM" }, { 0x77, "OEM" },
	{ 0x78, "OEM" }, { 0x79, "OEM" }, { 0x7a, "OEM" }, { 0x7b, "OEM" },
	{ 0x7c, "OEM" }, { 0x7d, "OEM" }, { 0x7e, "OEM" }, { 0x7f, "OEM" },
	{ 0, NULL }
};

static const value_string vals_prop00_rollback[] = {
	{ 0x00, "Not supported" },
	{ 0x01, "Rollback supported, Backup required" },
	{ 0x02, "Rollback supported, Backup not required" },
	{ 0, NULL }
};

static const value_string vals_31_action[] = {
	{ 0x00, "Backup components" },
	{ 0x01, "Prepare components" },
	{ 0x02, "Upload for upgrade" },
	{ 0x03, "Upload for compare" },
	{ 0, NULL }
};

static const value_string vals_35_override[] = {
	{ 0x00, "Automatic Rollback allowed" },
	{ 0x01, "Automatic Rollback override" },
	{ 0, NULL }
};

static const value_string vals_36_result[] = {
	{ 0x55, "No error. All Self Tests Passed" },
	{ 0x56, "Reserved, cannot be used" },
	{ 0x57, "Corrupted or inaccessible data or devices" },
	{ 0x58, "Fatal hardware error" },
	{ 0x60, "Component failure" },
	{ 0xff, "Reserved" },
	{ 0, NULL }
};

static const struct true_false_string tfs_36_fail_unknown = {
	"Test failed",
	"Unknown"
};

/* Get PICMG Properties.
 */
static void
rs00(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_00_version, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_00_max_fruid, tvb, 1, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_00_ipmc_fruid, tvb, 2, 1, TRUE);
}

/* Get Address Info Command.
 */
static void
rq01(tvbuff_t *tvb, proto_tree *tree)
{
	if (tvb_length(tvb) > 0) {
		proto_tree_add_item(tree, hf_ipmi_picmg_01_rq_fruid, tvb, 0, 1, TRUE);
	}
	if (tvb_length(tvb) > 1) {
		proto_tree_add_item(tree, hf_ipmi_picmg_01_rq_addr_key_type, tvb, 1, 1, TRUE);
	}
	if (tvb_length(tvb) > 2) {
		proto_tree_add_item(tree, hf_ipmi_picmg_01_rq_addr_key, tvb, 2, 1, TRUE);
	}
	if (tvb_length(tvb) > 3) {
		proto_tree_add_item(tree, hf_ipmi_picmg_01_rq_site_type, tvb, 3, 1, TRUE);
	}
}

static void
rs01(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_01_rs_hwaddr, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_01_rs_ipmbaddr, tvb, 1, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_01_rs_rsrv, tvb, 2, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_01_rs_fruid, tvb, 3, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_01_rs_site_num, tvb, 4, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_01_rs_site_type, tvb, 5, 1, TRUE);
	/* TBD Next byte is carrier number in MTCA */
}

/* Get Shelf Address Info
 */
static void
rs02(tvbuff_t *tvb, proto_tree *tree)
{
	ipmi_add_typelen(tree, "Shelf Address", tvb, 0, TRUE);
}

/* Set Shelf Address Info
 */
static void
rq03(tvbuff_t *tvb, proto_tree *tree)
{
	ipmi_add_typelen(tree, "Shelf Address", tvb, 0, TRUE);
}

/* FRU Control.
 */
static void
rq04(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_04_fruid, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_04_cmd, tvb, 1, 1, TRUE);
}

/* Get FRU LED Properties
 */
static void
rq05(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_05_fruid, tvb, 0, 1, TRUE);
}

static void
rs05(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_picmg_05_led3, &hf_ipmi_picmg_05_led2,
		&hf_ipmi_picmg_05_led1, &hf_ipmi_picmg_05_blue_led, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "General Status LEDs: ", "None",
			ett_ipmi_picmg_05_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_picmg_05_app_leds, tvb, 1, 1, TRUE);
}

/* Get LED Color Capabilities
 */
static void
rq06(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_06_fruid, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_06_ledid, tvb, 1, 1, TRUE);
}

static void
rs06(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_picmg_06_cap_white, &hf_ipmi_picmg_06_cap_orange,
		&hf_ipmi_picmg_06_cap_amber, &hf_ipmi_picmg_06_cap_green, &hf_ipmi_picmg_06_cap_red,
		&hf_ipmi_picmg_06_cap_blue, NULL };
	static const int *byte2[] = { &hf_ipmi_picmg_06_default_local_color, NULL };
	static const int *byte3[] = { &hf_ipmi_picmg_06_default_override_color, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "Color capabilities: ", "None",
			ett_ipmi_picmg_06_byte1, byte1, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
			ett_ipmi_picmg_06_byte2, byte2, TRUE, 0);
	proto_tree_add_bitmask_text(tree, tvb, 2, 1, NULL, NULL,
			ett_ipmi_picmg_06_byte3, byte3, TRUE, 0);
}

static void
parse_led_state(proto_tree *tree, tvbuff_t *tvb, guint offs, const char *desc)
{
	static const int *color[] = { &hf_ipmi_picmg_led_color, NULL };
	static const value_string funcs[] = {
		{ 0x00, "LED Off override" },
		{ 0xfb, "Lamp Test state" },
		{ 0xfc, "Restore Local Control" },
		{ 0xfd, "Reserved" },
		{ 0xfe, "Reserved" },
		{ 0xff, "LED On override" },
		{ 0, NULL }
	};
	proto_item *ti;
	guint8 v;

	v = tvb_get_guint8(tvb, offs);
	proto_tree_add_uint_format(tree, hf_ipmi_picmg_led_function, tvb, offs, 1,
			v, "%sFunction: %s (0x%02x)", desc,
			val_to_str(v, funcs, "LED Blinking override, off-duration %d0ms"),
			v);
	v = tvb_get_guint8(tvb, offs + 1);
	proto_tree_add_uint_format(tree, hf_ipmi_picmg_led_on_duration, tvb, offs + 1, 1,
			v, "%sOn-duration: %d0ms", desc, v);
	v = tvb_get_guint8(tvb, offs + 2) & 0x0f;
	ti = proto_tree_add_bitmask_text(tree, tvb, offs + 2, 1,
			NULL, NULL, ett_ipmi_picmg_led_color, color, TRUE, 0);
	proto_item_set_text(ti, "%sColor: %s", desc, val_to_str(v, led_color_vals, "Reserved"));
}

/* Set FRU LED State
 */
static void
rq07(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_07_fruid, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_07_ledid, tvb, 1, 1, TRUE);
	parse_led_state(tree, tvb, 2, "");
}

/* Get FRU LED State
 */
static void
rq08(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_08_fruid, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_08_ledid, tvb, 1, 1, TRUE);
}

static void
rs08(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_picmg_08_state_lamptest, &hf_ipmi_picmg_08_state_override,
		&hf_ipmi_picmg_08_state_local, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "LED States: ", "None",
			ett_ipmi_picmg_08_byte1, byte1, TRUE, 0);
	parse_led_state(tree, tvb, 1, "Local Control ");
	if (tvb_length(tvb) > 4) {
		parse_led_state(tree, tvb, 4, "Override ");
	}
	if (tvb_length(tvb) > 7) {
		proto_tree_add_item(tree, hf_ipmi_picmg_08_lamptest_duration, tvb, 7, 1, TRUE);
	}
}

/* Set IPMB State
 */
static void
parse_ipmb_state(proto_tree *tree, tvbuff_t *tvb, guint offs, int hf, int ett)
{
	char buf[32];
	const char *desc;
	proto_tree *s_tree;
	proto_item *ti;
	guint8 v, num;

	v = tvb_get_guint8(tvb, offs);
	if (v == 0xff) {
		proto_tree_add_uint_format_value(tree, hf, tvb, 0, 1,
				v, "Don't change (0xff)");
	} else {
		num = v >> 1;
		if (!num) {
			desc = "All Links";
		} else if (num < 0x60) {
			g_snprintf(buf, sizeof(buf), "Link #%d", num);
			desc = buf;
		} else {
			desc = "Reserved";
		}
		ti = proto_tree_add_uint_format_value(tree, hf, tvb, 0, 1,
				v, "%s, %s", desc, (v & 1) ? "Local Control" : "Override");
		s_tree = proto_item_add_subtree(ti, ett);
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sLink: %s (0x%02x)",
				ipmi_dcd8(v, 0xfe), desc, num);
		proto_tree_add_text(s_tree, tvb, 0, 1, "%sState: %s",
				ipmi_dcd8(v, 0x01), (v & 1) ? "Local Control State" : "Override State (Isolate)");
	}
}

static void
rq09(tvbuff_t *tvb, proto_tree *tree)
{
	parse_ipmb_state(tree, tvb, 0, hf_ipmi_picmg_09_ipmba, ett_ipmi_picmg_09_ipmba);
	parse_ipmb_state(tree, tvb, 1, hf_ipmi_picmg_09_ipmbb, ett_ipmi_picmg_09_ipmbb);
}

/* Set FRU Activation Policy
 */
static void
rq0a(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte2[] = { &hf_ipmi_picmg_0a_msk_d_locked, &hf_ipmi_picmg_0a_msk_locked, NULL };
	static const int *byte3[] = { &hf_ipmi_picmg_0a_d_locked, &hf_ipmi_picmg_0a_locked, NULL };

	proto_tree_add_item(tree, hf_ipmi_picmg_0a_fruid, tvb, 0, 1, TRUE);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, "Will affect bits: ", "None",
			ett_ipmi_picmg_0a_byte2, byte2, TRUE, BMT_NO_TFS);
	proto_tree_add_bitmask_text(tree, tvb, 2, 1, "Activation Policy Set Bits: ", NULL,
			ett_ipmi_picmg_0a_byte3, byte3, TRUE, 0);
}

/* Get FRU Activation Policy
 */
static void
rq0b(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_0b_fruid, tvb, 0, 1, TRUE);
}

static void
rs0b(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_picmg_0b_d_locked, &hf_ipmi_picmg_0b_locked, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "Activation Policy Bits: ", NULL,
			ett_ipmi_picmg_0b_byte1, byte1, TRUE, 0);
}


/* Set FRU Activation
 */
static void
rq0c(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_0c_fruid, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_0c_cmd, tvb, 1, 1, TRUE);
}

/* Get Device Locator Record ID
 */
static void
rq0d(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_0d_fruid, tvb, 0, 1, TRUE);
	if (tvb_length(tvb) > 1) {
		proto_tree_add_item(tree, hf_ipmi_picmg_0d_start, tvb, 1, 2, TRUE);
	}
}

static void
rs0d(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_0d_recordid, tvb, 0, 2, TRUE);
}

static void
parse_link_info_state(proto_tree *tree, tvbuff_t *tvb, guint offs, const char *num, const value_string *vs)
{
	static const int *link_info[] = { &hf_ipmi_picmg_linkinfo_grpid, &hf_ipmi_picmg_linkinfo_type_ext,
		&hf_ipmi_picmg_linkinfo_type, &hf_ipmi_picmg_linkinfo_ports, &hf_ipmi_picmg_linkinfo_iface,
		&hf_ipmi_picmg_linkinfo_chan, NULL };
	guint8 v = tvb_get_guint8(tvb, offs + 4);
	char buf[32];

	g_snprintf(buf, sizeof(buf), "Link info%s: ", num);
	proto_tree_add_bitmask_text(tree, tvb, offs, 4, buf, NULL,
			ett_ipmi_picmg_link_info, link_info, TRUE, 0);
	proto_tree_add_uint_format(tree, hf_ipmi_picmg_linkinfo_state, tvb, offs + 4, 1,
			v, "State%s: %s (0x%02x)", num, val_to_str(v, vs, "Reserved"), v);
}

/* Set Port State
 */
static void
rq0e(tvbuff_t *tvb, proto_tree *tree)
{
	static const value_string state_vals[] = {
		{ 0x00, "Disable" },
		{ 0x01, "Enable" },
		{ 0, NULL }
	};

	parse_link_info_state(tree, tvb, 0, "", state_vals);
}

/* Get Port State
 */
static void
rq0f(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *chan[] = { &hf_ipmi_picmg_0f_iface, &hf_ipmi_picmg_0f_chan, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_picmg_0f_chan, chan, TRUE, 0);
}

static void
rs0f(tvbuff_t *tvb, proto_tree *tree)
{
	static const value_string state_vals[] = {
		{ 0x00, "Disabled" },
		{ 0x01, "Enabled" },
		{ 0, NULL }
	};

	if (tvb_length(tvb) > 0) {
		parse_link_info_state(tree, tvb, 0, " 1", state_vals);
	}
	if (tvb_length(tvb) > 5) {
		parse_link_info_state(tree, tvb, 5, " 2", state_vals);
	}
	if (tvb_length(tvb) > 10) {
		parse_link_info_state(tree, tvb, 10, " 3", state_vals);
	}
	if (tvb_length(tvb) > 15) {
		parse_link_info_state(tree, tvb, 15, " 4", state_vals);
	}
}

/* Compute Power Properties
 */
static void
rq10(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_10_fruid, tvb, 0, 1, TRUE);
}

static void
rs10(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_10_nslots, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_10_ipmc_loc, tvb, 1, 1, TRUE);
}

/* Set Power Level
 */
static void
rq11(tvbuff_t *tvb, proto_tree *tree)
{
	static const value_string plvl_vals[] = {
		{ 0x00, "Power Off" },
		{ 0xff, "Do not change" },
		{ 0, NULL }
	};
	guint8 v = tvb_get_guint8(tvb, 1);

	proto_tree_add_item(tree, hf_ipmi_picmg_11_fruid, tvb, 0, 1, TRUE);
	proto_tree_add_uint_format_value(tree, hf_ipmi_picmg_11_power_level, tvb, 1, 1,
			v, "%s", val_to_str(v, plvl_vals, "Power Level %d"));
	proto_tree_add_item(tree, hf_ipmi_picmg_11_set_to_desired, tvb, 2, 1, TRUE);
}

/* Get Power Level
 */
static void
rq12(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_12_fruid, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_12_pwr_type, tvb, 1, 1, TRUE);
}

static void
rs12(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_picmg_12_dynamic, &hf_ipmi_picmg_12_pwr_lvl, NULL };
	guint8 v, v2, i, max;
	guint32 tmp;

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL, ett_ipmi_picmg_12_byte1, byte1, TRUE, BMT_NO_FALSE);
	proto_tree_add_item(tree, hf_ipmi_picmg_12_delay, tvb, 1, 1, TRUE);
	v = tvb_get_guint8(tvb, 2);
	proto_tree_add_uint_format_value(tree, hf_ipmi_picmg_12_pwr_mult, tvb, 2, 1,
			v, "%d.%dW", v / 10, v % 10);
	max = tvb_length(tvb) - 3;
	if (max == 0) {
		max = 1; /* One byte is mandatory */
	} else if (max > 20) {
		max = 20; /* 20 levels at most */
	}
	for (i = 1; i <= max; i++) {
		v2 = tvb_get_guint8(tvb, 2 + i);
		tmp = (guint)v2 * v;
		proto_tree_add_uint_format(tree, hf_ipmi_picmg_12_pwr_draw, tvb, 2 + i, 1,
				v2, "Power Draw [%d]: %d.%dW (0x%02x)", i,
				tmp / 10, tmp % 10, v2);

	}
}

/* Renegotiate Power
 */
static void
rq13(tvbuff_t *tvb, proto_tree *tree)
{
	if (tvb_length(tvb) > 0) {
		proto_tree_add_item(tree, hf_ipmi_picmg_13_fruid, tvb, 0, 1, TRUE);
	}
}

/* Get Fan Speed Properties
 */
static void
rq14(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_14_fruid, tvb, 0, 1, TRUE);
}

static void
rs14(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *prop[] = { &hf_ipmi_picmg_14_local_control, NULL };

	proto_tree_add_item(tree, hf_ipmi_picmg_14_speed_min, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_14_speed_max, tvb, 1, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_14_speed_norm, tvb, 2, 1, TRUE);
	proto_tree_add_bitmask_text(tree, tvb, 3, 1, "Fan Tray Properties: ", "None",
			ett_ipmi_picmg_14_prop, prop, TRUE, 0);
}

/* Set Fan Level
 */
static void
rq15(tvbuff_t *tvb, proto_tree *tree)
{
	guint8 v = tvb_get_guint8(tvb, 1);

	proto_tree_add_item(tree, hf_ipmi_picmg_15_fruid, tvb, 0, 1, TRUE);
	proto_tree_add_uint_format_value(tree, hf_ipmi_picmg_15_fan_level, tvb, 1, 1,
			v, "%s", val_to_str(v, fan_level_vals, "%d"));
	if (tvb_length(tvb) > 2) {
		proto_tree_add_item(tree, hf_ipmi_picmg_15_local_enable, tvb, 2, 1, TRUE);
	}
}

/* Get Fan Level
 */
static void
rq16(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_16_fruid, tvb, 0, 1, TRUE);
}

static void
rs16(tvbuff_t *tvb, proto_tree *tree)
{
	guint8 v;

	v = tvb_get_guint8(tvb, 0);
	proto_tree_add_uint_format_value(tree, hf_ipmi_picmg_16_override_level, tvb, 0, 1,
			v, "%s", val_to_str(v, fan_level_vals, "%d"));
	if (tvb_length(tvb) > 1) {
		proto_tree_add_item(tree, hf_ipmi_picmg_16_local_level, tvb, 1, 1, TRUE);
	}
	if (tvb_length(tvb) > 2) {
		proto_tree_add_item(tree, hf_ipmi_picmg_16_local_enable, tvb, 2, 1, TRUE);
	}
}

/* Bused Resource Control
 */
static void
rq17(tvbuff_t *tvb, proto_tree *tree)
{
	static const value_string vals_17_cmd_fromshmm[] = {
		{ 0x00, "Query" },
		{ 0x01, "Release" },
		{ 0x02, "Force" },
		{ 0x03, "Bus Free" },
		{ 0, NULL }
	};
	static const value_string vals_17_cmd_toshmm[] = {
		{ 0x00, "Request" },
		{ 0x01, "Relinquish" },
		{ 0x02, "Notify" },
		{ 0, NULL }
	};
	guint to_shmm = ipmi_current_hdr->trg_sa == 0x20;
	guint cmd = tvb_get_guint8(tvb, 0);

	if (!tree) {
		ipmi_setsaveddata(0, (to_shmm << 8) | cmd);
		return;
	}

	proto_tree_add_uint_format_value(tree, hf_ipmi_picmg_17_cmd, tvb, 0, 1,
			cmd, "%s (0x%02x)", val_to_str(cmd,
				to_shmm ? vals_17_cmd_toshmm : vals_17_cmd_fromshmm,
				"Reserved"), cmd);
	proto_tree_add_item(tree, hf_ipmi_picmg_17_resid, tvb, 1, 1, TRUE);
}

static void
rs17(tvbuff_t *tvb, proto_tree *tree)
{
	/* Key is 3 bytes: direction, command, status */
	static const value_string response_vals[] = {
		{ 0x000000, "In Control" },
		{ 0x000001, "No Control" },
		{ 0x000100, "Ack" },
		{ 0x000101, "Refused" },
		{ 0x000102, "No Control" },
		{ 0x000200, "Ack" },
		{ 0x000201, "No Control" },
		{ 0x000300, "Accept" },
		{ 0x000301, "Not Needed" },
		{ 0x010000, "Grant" },
		{ 0x010001, "Busy" },
		{ 0x010002, "Defer" },
		{ 0x010003, "Deny" },
		{ 0x010100, "Ack" },
		{ 0x010101, "Error" },
		{ 0x010200, "Ack" },
		{ 0x010201, "Error" },
		{ 0x010202, "Deny" },
		{ 0, NULL }
	};
	guint32 val;
	guint8 status;

	if (!ipmi_getsaveddata(0, &val)) {
		/* Without knowing the command, we cannot decipher the response */
		proto_tree_add_item(tree, hf_ipmi_picmg_17_status, tvb, 0, 1, TRUE);
		return;
	}

	status = tvb_get_guint8(tvb, 0);
	val = (val << 8) | status;
	proto_tree_add_uint_format_value(tree, hf_ipmi_picmg_17_status, tvb, 0, 1,
			status, "%s (0x%02x)", val_to_str(val, response_vals, "Reserved"), status);
}

/* Get IPMB Link Info
 */
static void
rq18(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_18_li_key_type, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_18_li_key, tvb, 1, 1, TRUE);
}

static void
rs18(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_18_link_num, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_18_sensor_num, tvb, 1, 1, TRUE);
}

/* Get Shelf Manager IPMB Address
 */
static void
rs1b(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_1b_addr_active, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_1b_addr_backup, tvb, 0, 1, TRUE);
}

/* Set Fan Policy
 */
static void
rq1c(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_1c_fan_site_number, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_1c_fan_enable_state, tvb, 1, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_1c_fan_policy_timeout, tvb, 2, 1, TRUE);
	if (tvb_length(tvb) > 3) {
		proto_tree_add_item(tree, hf_ipmi_picmg_1c_site_number, tvb, 3, 1, TRUE);
		proto_tree_add_item(tree, hf_ipmi_picmg_1c_site_type, tvb, 4, 1, TRUE);
	}
}

/* Get Fan Policy
 */
static void
rq1d(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_1d_fan_site_number, tvb, 0, 1, TRUE);
	if (tvb_length(tvb) > 1) {
		proto_tree_add_item(tree, hf_ipmi_picmg_1d_site_number, tvb, 1, 1, TRUE);
		proto_tree_add_item(tree, hf_ipmi_picmg_1d_site_type, tvb, 2, 1, TRUE);
	}
}

static void
rs1d(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_1d_policy, tvb, 0, 1, TRUE);
	if (tvb_length(tvb) > 1) {
		proto_tree_add_item(tree, hf_ipmi_picmg_1d_coverage, tvb, 1, 1, TRUE);
	}
}

/* FRU Control Capabilities
 */
static void
rq1e(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_1e_fruid, tvb, 0, 1, TRUE);
}

static void
rs1e(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte1[] = { &hf_ipmi_picmg_1e_cap_diagintr,
		&hf_ipmi_picmg_1e_cap_graceful_reboot, &hf_ipmi_picmg_1e_cap_warm_reset, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "FRU Control Capabilities: ", "None",
			ett_ipmi_picmg_1e_byte1, byte1, TRUE, 0);
}

/* FRU Inventory Device Lock Control
 */
static void
rq1f(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_1f_rq_fruid, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_1f_rq_op, tvb, 1, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_1f_rq_lockid, tvb, 2, 2, TRUE);
}

static void
rs1f(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_1f_rs_lockid, tvb, 0, 2, TRUE);
	ipmi_add_timestamp(tree, hf_ipmi_picmg_1f_rs_tstamp, tvb, 2);
}

static const value_string cc1f[] = {
	{ 0x80, "Invalid FRU Information" },
	{ 0x81, "Lock Failed" },
	{ 0, NULL }
};

/* FRU Inventory Device Write
 */
static void
rq20(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_20_fruid, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_20_lockid, tvb, 1, 2, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_20_offset, tvb, 3, 2, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_20_data, tvb, 5, tvb_length(tvb) - 5, ENC_NA);
}

static void
rs20(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_20_count, tvb, 0, 1, ENC_NA);
}

static const value_string cc20[] = {
	{ 0x80, "Invalid Lock ID" },
	{ 0, NULL }
};

/* Get Shelf Manager IP Address
 */
static void
rq21(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_21_addr_num, tvb, 0, 1, TRUE);
}

static void
rs21(tvbuff_t *tvb, proto_tree *tree)
{
	static const int *byte9[] = { &hf_ipmi_picmg_21_is_shm, &hf_ipmi_picmg_21_addr_type, NULL };
	guint8 addrtype;

	ipmi_add_timestamp(tree, hf_ipmi_picmg_21_tstamp, tvb, 0);
	proto_tree_add_item(tree, hf_ipmi_picmg_21_addr_count, tvb, 4, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_21_site_type, tvb, 5, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_21_site_num, tvb, 6, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_21_max_unavail, tvb, 7, 1, TRUE);
	proto_tree_add_bitmask_text(tree, tvb, 8, 1, NULL, NULL, ett_ipmi_picmg_21_byte9, byte9, TRUE, 0);

	addrtype = tvb_get_guint8(tvb, 8) & 0x7f;
	if (addrtype == 0x01) {
		/* IP address and RMCP port are in network byte order! */
		proto_tree_add_item(tree, hf_ipmi_picmg_21_ipaddr, tvb, 9, 4, FALSE);
		proto_tree_add_item(tree, hf_ipmi_picmg_21_rmcpport, tvb, 13, 2, FALSE);
	};
}

/* Get Shelf Power Allocation
 */
static void
rq22(tvbuff_t *tvb, proto_tree *tree)
{
	if (!tree) {
		ipmi_setsaveddata(0, tvb_get_guint8(tvb, 0));
		return;
	}
	proto_tree_add_item(tree, hf_ipmi_picmg_22_feed_idx, tvb, 0, 1, TRUE);
}

static void
rs22(tvbuff_t *tvb, proto_tree *tree)
{
	guint32 offs = 0;
	guint16 v;
	guint i, max;

	proto_tree_add_item(tree, hf_ipmi_picmg_22_update_cnt, tvb, 0, 2, TRUE);

	max = tvb_length(tvb) / 2 - 1;
	if (!max) {
		/* At least one shall be present */
		max = 1;
	}
	ipmi_getsaveddata(0, &offs);
	for (i = 0; i < max; i++) {
		v = tvb_get_letohs(tvb, 2 + 2 * i);
		proto_tree_add_uint_format(tree, hf_ipmi_picmg_22_pwr_alloc, tvb, 2 + 2 * i, 2,
				v, "Power Feed [%d] Allocation: %d Watts", offs + i, v);
	}
}

static void
add_component_bits(proto_tree *tree, tvbuff_t *tvb, guint offs, const char *desc)
{
	static const gint *compbits[] = { &hf_ipmi_picmg_XX_comp7, &hf_ipmi_picmg_XX_comp6, &hf_ipmi_picmg_XX_comp5,
		&hf_ipmi_picmg_XX_comp4, &hf_ipmi_picmg_XX_comp3, &hf_ipmi_picmg_XX_comp2, &hf_ipmi_picmg_XX_comp1, &hf_ipmi_picmg_XX_comp0, NULL };

	proto_tree_add_bitmask_text(tree, tvb, offs, 1, desc, "None",
			ett_ipmi_picmg_XX_compbits, compbits, TRUE, 0);
}

/* Get Target Upgrade Capabilities
 */
static void
rs2e(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte2[] = { &hf_ipmi_picmg_2e_upgrade_undesirable, &hf_ipmi_picmg_2e_auto_rollback_override,
		&hf_ipmi_picmg_2e_ipmc_degraded, &hf_ipmi_picmg_2e_deferred_activate, &hf_ipmi_picmg_2e_services_affected,
		&hf_ipmi_picmg_2e_manual_rollback, &hf_ipmi_picmg_2e_auto_rollback, &hf_ipmi_picmg_2e_self_test, NULL };

	proto_tree_add_item(tree, hf_ipmi_picmg_2e_version, tvb, 0, 1, TRUE);
	proto_tree_add_bitmask_text(tree, tvb, 1, 1, "Capabilities: ", "None",
			ett_ipmi_picmg_2e_byte2, byte2, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_picmg_2e_upgrade_tout, tvb, 2, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_2e_selftest_tout, tvb, 3, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_2e_rollback_tout, tvb, 4, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_2e_inaccessibility_tout, tvb, 5, 1, TRUE);
	add_component_bits(tree, tvb, 6, "Components present: ");
}

static const value_string cc2e[] = {
	{ 0x81, "Firmware Upgrade is not supported over this interface" },
	{ 0, NULL }
};

/* Get Component Properties
 */
static void
prop_00(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_picmg_prop00_cold_reset, &hf_ipmi_picmg_prop00_deferred_activation,
		&hf_ipmi_picmg_prop00_comparison, &hf_ipmi_picmg_prop00_preparation, &hf_ipmi_picmg_prop00_rollback, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, "General Component Properties: ", "None",
			ett_ipmi_picmg_prop00_byte1, byte1, TRUE, 0);
}

static void
parse_version(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte1[] = { &hf_ipmi_picmg_prop01_fw_major, NULL };

	proto_tree_add_bitmask_text(tree, tvb, 0, 1, NULL, NULL,
			ett_ipmi_picmg_prop01_byte1, byte1, TRUE, 0);
	proto_tree_add_item(tree, hf_ipmi_picmg_prop01_fw_minor, tvb, 1, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_prop01_fw_aux, tvb, 2, 4, ENC_NA);
}

static void
prop_02(tvbuff_t *tvb, proto_tree *tree)
{
	guint len = tvb_length(tvb);

	if (len > 12) {
		len = 12;
	}
	proto_tree_add_item(tree, hf_ipmi_picmg_prop02_desc, tvb, 0, len, TRUE);
}

static const struct {
	void (*intrp)(tvbuff_t *tvb, proto_tree *tree);
	const char *name;
} compprops[] = {
	{ prop_00, "General Component Properties" },
	{ parse_version, "Current Version" },
	{ prop_02, "Description String" },
	{ parse_version, "Rollback firmware version" },
	{ parse_version, "Deferred upgrade firmware version" }
};

static void
rq2f(tvbuff_t *tvb, proto_tree *tree)
{
	guint8 pno = tvb_get_guint8(tvb, 1);
	const char *desc;

	if (!tree) {
		ipmi_setsaveddata(0, pno);
		return;
	}

	if (pno < array_length(compprops)) {
		desc = compprops[pno].name;
	} else if (pno >= 0xC0) {
		desc = "OEM";
	} else {
		desc = "Reserved";
	}

	proto_tree_add_item(tree, hf_ipmi_picmg_2f_comp_id, tvb, 0, 1, TRUE);
	proto_tree_add_uint_format_value(tree, hf_ipmi_picmg_2f_comp_prop, tvb, 1, 1, pno,
			"%s (0x%02x)", desc, pno);
}

static void
rs2f(tvbuff_t *tvb, proto_tree *tree)
{
	guint32 pno;
	const char *desc;
	proto_item *ti;

	if (!ipmi_getsaveddata(0, &pno)) {
		/* Can't parse further if property selector is not known */
		proto_tree_add_item(tree, hf_ipmi_picmg_2f_prop_data, tvb, 0, tvb_length(tvb), ENC_NA);
		return;
	}

	if (pno < array_length(compprops)) {
		desc = compprops[pno].name;
	} else if (pno >= 0xC0) {
		desc = "OEM";
	} else {
		desc = "Reserved";
	}

	ti = proto_tree_add_text(tree, tvb, 0, 0, "Property selector: %s (0x%02x)", desc, pno);
	PROTO_ITEM_SET_GENERATED(ti);
	if (pno < array_length(compprops)) {
		compprops[pno].intrp(tvb, tree);
	} else {
		proto_tree_add_item(tree, hf_ipmi_picmg_2f_prop_data, tvb, 0, tvb_length(tvb), ENC_NA);
	}
}

static const value_string cc2f[] = {
	{ 0x81, "Firmware Upgrade is not supported over this interface" },
	{ 0x82, "Invalid Component ID" },
	{ 0x83, "Invalid Component property selector" },
	{ 0, NULL }
};

/* Abort Firmware Upgrade
 */
static const value_string cc30[] = {
	{ 0x80, "Firmware Upgrade cannot be aborted at this moment" },
	{ 0x81, "Firmware Upgrade aborted, IPMC cannot resume normal operation" },
	{ 0, NULL }
};

/* Initiate upgrade action
 */
static void
rq31(tvbuff_t *tvb, proto_tree *tree)
{
	add_component_bits(tree, tvb, 0, "Components: ");
	proto_tree_add_item(tree, hf_ipmi_picmg_31_action, tvb, 1, 1, TRUE);
}

static const value_string cc31[] = {
	{ 0x80, "Command in progress" },
	{ 0x81, "Invalid component" },
	{ 0, NULL }
};

/* Upload Firmware Block
 */
static void
rq32(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_32_block, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_32_data, tvb, 1, tvb_length(tvb) - 1, ENC_NA);
}

static void
rs32(tvbuff_t *tvb, proto_tree *tree)
{
	if (tvb_length(tvb) > 0) {
		proto_tree_add_item(tree, hf_ipmi_picmg_32_sec_offs, tvb, 0, 4, TRUE);
		proto_tree_add_item(tree, hf_ipmi_picmg_32_sec_len, tvb, 4, 4, TRUE);
	}
}

static const value_string cc32[] = {
	{ 0x80, "Command in progress" },
	{ 0x81, "Invalid component" },
	{ 0x82, "Internal checksum error detected in the received blocks" },
	{ 0, NULL }
};

/* Finish Firmware Upgrade
 */
static void
rq33(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ipmi_picmg_33_comp_id, tvb, 0, 1, TRUE);
	proto_tree_add_item(tree, hf_ipmi_picmg_33_img_len, tvb, 1, 4, TRUE);
}

static const value_string cc33[] = {
	{ 0x80, "Command in progress" },
	{ 0x81, "Number of bytes received does not match size in the request" },
	{ 0x82, "Internal checksum error detected in the received image" },
	{ 0x83, "Uploaded firmware does not match current" },
	{ 0, NULL }
};

/* Get Upgrade Status
 */
static void
rs34(tvbuff_t *tvb, proto_tree *tree)
{
	static const guint8 sig = 0;
	static const gint *byte3[] = { &hf_ipmi_picmg_34_percentage, NULL };
	guint8 v;
	ipmi_cmd_t *c;

	v = tvb_get_guint8(tvb, 0);
	c = ipmi_getcmd(ipmi_getnetfn(IPMI_GROUP_REQ, &sig), v);
	proto_tree_add_uint_format_value(tree, hf_ipmi_picmg_34_cmd, tvb, 0, 1, v,
			"%s (0x%02x)", c->desc, v);
	v = tvb_get_guint8(tvb, 1);
	proto_tree_add_uint_format_value(tree, hf_ipmi_picmg_34_ccode, tvb, 1, 1, v,
			"%s (0x%02x)", ipmi_get_completion_code(v, c), v);
	if (tvb_length(tvb) > 2) {
		proto_tree_add_bitmask_text(tree, tvb, 2, 1, NULL, NULL,
				ett_ipmi_picmg_34_byte3, byte3, TRUE, 0);
	}
}

static const value_string cc34[] = {
	{ 0x80, "Command in progress" },
	{ 0, NULL }
};

/* Activate Firmware
 */
static void
rq35(tvbuff_t *tvb, proto_tree *tree)
{
	if (tvb_length(tvb) > 0) {
		proto_tree_add_item(tree, hf_ipmi_picmg_35_rollback_override, tvb, 0, 1, TRUE);
	}
}

static const value_string cc35[] = {
	{ 0x80, "Command in progress" },
	{ 0, NULL }
};

/* Query Self-test Results
 */
static void
rs36(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte2[] = { &hf_ipmi_picmg_36_fail_sel, &hf_ipmi_picmg_36_fail_sdr,
		&hf_ipmi_picmg_36_fail_bmc_fru, &hf_ipmi_picmg_36_fail_ipmb_sig, &hf_ipmi_picmg_36_fail_sdr_empty,
		&hf_ipmi_picmg_36_fail_iua, &hf_ipmi_picmg_36_fail_bb_fw, &hf_ipmi_picmg_36_fail_oper_fw, NULL };
	int res, fail;

	res = tvb_get_guint8(tvb, 0);
	fail = tvb_get_guint8(tvb, 1);

	proto_tree_add_uint_format(tree, hf_ipmi_picmg_36_result, tvb, 0, 1,
			res, "Self test result: %s (0x%02x)",
			val_to_str(res, vals_36_result, "Device-specific internal failure"),
			res);

	if (res == 0x55 || res == 0xff) {
		proto_tree_add_uint_format_value(tree, hf_ipmi_picmg_36_fail, tvb, 1, 1,
				fail, "0x%02x (must be 0x00)",
				fail);
	} else if (res == 0x57) {
		proto_tree_add_bitmask(tree, tvb, 1, hf_ipmi_picmg_36_fail, ett_ipmi_picmg_36_byte2, byte2, TRUE);
	} else if (res == 0x60) {
		add_component_bits(tree, tvb, 1, "Failed components: ");
	} else {
		proto_tree_add_uint_format_value(tree, hf_ipmi_picmg_36_fail, tvb, 1, 1,
				fail, "0x%02x (device-specific)", fail);
	}
}

static const value_string cc36[] = {
	{ 0x80, "Self-test in progress" },
	{ 0x81, "Firmware upgrade not supported over this interface" },
	{ 0, NULL }
};

/* Query Rollback Results
 */
static void
rs37(tvbuff_t *tvb, proto_tree *tree)
{
	static const gint *byte2[] = { &hf_ipmi_picmg_37_percent, NULL };
	const char *desc;

	switch (ipmi_current_hdr->ccode) {
	case 0x00: desc = "Components completed rollback: "; break;
	case 0x80: desc = "Components (should be None): "; break;
	case 0x81: desc = "Components failed to rollback: "; break;
	default: desc = "Components (ignored): "; break;
	}

	add_component_bits(tree, tvb, 0, desc);
	if (tvb_length(tvb) > 1) {
		proto_tree_add_bitmask_text(tree, tvb, 1, 1, NULL, NULL,
				ett_ipmi_picmg_37_byte2, byte2, TRUE, 0);
	}
}

static const value_string cc37[] = {
	{ 0x80, "Rollback in progress" },
	{ 0x81, "Rollback failure" },
	{ 0x82, "Rollback overridden" },
	{ 0x83, "Rollback denied for integrity reasons" },
	{ 0, NULL }
};

/* Initiate Manual Rollback
 */
static const value_string cc38[] = {
	{ 0x80, "Rollback in progress" },
	{ 0, NULL }
};

static ipmi_cmd_t cmd_picmg[] = {
  /* AdvancedTCA Commands */
  { 0x00, NULL, rs00, NULL, NULL, "[ATCA] Get PICMG Properties", 0 },
  { 0x01, rq01, rs01, NULL, NULL, "[ATCA] Get Address Info", 0 },
  { 0x02, NULL, rs02, NULL, NULL, "[ATCA] Get Shelf Address Info", 0 },
  { 0x03, rq03, NULL, NULL, NULL, "[ATCA] Set Shelf Address Info", 0 },
  { 0x04, rq04, NULL, NULL, NULL, "[ATCA] FRU Control", 0 },
  { 0x05, rq05, rs05, NULL, NULL, "[ATCA] Get FRU LED Properties", 0 },
  { 0x06, rq06, rs06, NULL, NULL, "[ATCA] Get LED Color Capabilities", 0 },
  { 0x07, rq07, NULL, NULL, NULL, "[ATCA] Set FRU LED State", 0 },
  { 0x08, rq08, rs08, NULL, NULL, "[ATCA] Get FRU LED State", 0 },
  { 0x09, rq09, NULL, NULL, NULL, "[ATCA] Set IPMB State", 0 },
  { 0x0a, rq0a, NULL, NULL, NULL, "[ATCA] Set FRU Activation Policy", 0 },
  { 0x0b, rq0b, rs0b, NULL, NULL, "[ATCA] Get FRU Activation Policy", 0 },
  { 0x0c, rq0c, NULL, NULL, NULL, "[ATCA] Set FRU Activation", 0 },
  { 0x0d, rq0d, rs0d, NULL, NULL, "[ATCA] Get Device Locator Record ID", 0 },
  { 0x0e, rq0e, NULL, NULL, NULL, "[ATCA] Set Port State", 0 },
  { 0x0f, rq0f, rs0f, NULL, NULL, "[ATCA] Get Port State", 0 },
  { 0x10, rq10, rs10, NULL, NULL, "[ATCA] Compute Power Properties", 0 },
  { 0x11, rq11, NULL, NULL, NULL, "[ATCA] Set Power Level", 0 },
  { 0x12, rq12, rs12, NULL, NULL, "[ATCA] Get Power Level", 0 },
  { 0x13, rq13, NULL, NULL, NULL, "[ATCA] Renegotiate Power", 0 },
  { 0x14, rq14, rs14, NULL, NULL, "[ATCA] Get Fan Speed Properties", 0 },
  { 0x15, rq15, NULL, NULL, NULL, "[ATCA] Set Fan Level", 0 },
  { 0x16, rq16, rs16, NULL, NULL, "[ATCA] Get Fan Level", 0 },
  { 0x17, rq17, rs17, NULL, NULL, "[ATCA] Bused Resource Control", CMD_CALLRQ },
  { 0x18, rq18, rs18, NULL, NULL, "[ATCA] Get IPMB Link Info", 0 },
  { 0x19, IPMI_TBD,   NULL, NULL, "[AMC.0] Set AMC Port State", 0 },
  { 0x1a, IPMI_TBD,   NULL, NULL, "[AMC.0] Get AMC Port State", 0 },
  { 0x1b, NULL, rs1b, NULL, NULL, "[ATCA] Get Shelf Manager IPMB Address", 0 },
  { 0x1c, rq1c, NULL, NULL, NULL, "[ATCA] Set Fan Policy", 0 },
  { 0x1d, rq1d, rs1d, NULL, NULL, "[ATCA] Get Fan Policy", 0 },
  { 0x1e, rq1e, rs1e, NULL, NULL, "[ATCA] FRU Control Capabilities", 0 },
  { 0x1f, rq1f, rs1f, cc1f, NULL, "[ATCA] FRU Inventory Device Lock Control", 0 },
  { 0x20, rq20, rs20, cc20, NULL, "[ATCA] FRU Inventory Device Write", 0 },
  { 0x21, rq21, rs21, NULL, NULL, "[ATCA] Get Shelf Manager IP Addresses", 0 },
  { 0x22, rq22, rs22, NULL, NULL, "[ATCA] Get Shelf Power Allocation", CMD_CALLRQ },
  { 0x23, IPMI_TBD,   NULL, NULL, "[uTCA] Get Location Information", 0 },
  { 0x24, IPMI_TBD,   NULL, NULL, "[uTCA] Power Channel Control", 0 },
  { 0x25, IPMI_TBD,   NULL, NULL, "[uTCA] Get Power Channel Status", 0 },
  { 0x26, IPMI_TBD,   NULL, NULL, "[uTCA] PM Reset", 0 },
  { 0x27, IPMI_TBD,   NULL, NULL, "[uTCA] Get PM Status", 0 },
  { 0x28, IPMI_TBD,   NULL, NULL, "[uTCA] PM Heartbeat", 0 },
  { 0x29, IPMI_TBD,   NULL, NULL, "[uTCA] Get Telco Alarm Capability", 0 },
  { 0x2a, IPMI_TBD,   NULL, NULL, "[uTCA] Set Telco Alarm State", 0 },
  { 0x2b, IPMI_TBD,   NULL, NULL, "[uTCA] Get Telco Alarm State", 0 },
  { 0x2c, IPMI_TBD,   NULL, NULL, "[AMC.0] Set Clock State", 0 },
  { 0x2d, IPMI_TBD,   NULL, NULL, "[AMC.0] Get Clock State", 0 },
  { 0x2e, NULL, rs2e, cc2e, NULL, "[HPM.1] Get Target Upgrade Capabilities", 0 },
  { 0x2f, rq2f, rs2f, cc2f, NULL, "[HPM.1] Get Component Properties", CMD_CALLRQ },
  { 0x30, NULL, NULL, cc30, NULL, "[HPM.1] Abort Firmware Upgrade", 0 },
  { 0x31, rq31, NULL, cc31, NULL, "[HPM.1] Initiate Upgrade Action", 0 },
  { 0x32, rq32, rs32, cc32, NULL, "[HPM.1] Upload Firmware Block", 0 },
  { 0x33, rq33, NULL, cc33, NULL, "[HPM.1] Finish Firmware Upload", 0 },
  { 0x34, NULL, rs34, cc34, NULL, "[HPM.1] Get Upgrade Status", 0 },
  { 0x35, rq35, NULL, cc35, NULL, "[HPM.1] Activate Firmware", 0 },
  { 0x36, NULL, rs36, cc36, NULL, "[HPM.1] Query Self-test Results", 0 },
  { 0x37, NULL, rs37, cc37, NULL, "[HPM.1] Query Rollback Status", 0 },
  { 0x38, NULL, NULL, cc38, NULL, "[HPM.1] Initiate Manual Rollback", 0 },
};

void
ipmi_register_picmg(gint proto_ipmi)
{
	static hf_register_info hf[] = {
		{ &hf_ipmi_picmg_led_function,
			{ "LED Function",
				"ipmi.led.function", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_led_on_duration,
			{ "On-duration",
				"ipmi.led.on_duration", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_led_color,
			{ "Color",
				"ipmi.led.color", FT_UINT8, BASE_HEX, led_color_vals, 0x0f, NULL, HFILL }},

		{ &hf_ipmi_picmg_linkinfo_grpid,
			{ "Grouping ID",
				"ipmi.linkinfo.grpid", FT_UINT32, BASE_DEC, NULL, 0xff000000, NULL, HFILL }},
		{ &hf_ipmi_picmg_linkinfo_type_ext,
			{ "Type extension",
				"ipmi.linkinfo.type_ext", FT_UINT32, BASE_HEX, NULL, 0x00f00000, NULL, HFILL }},
		{ &hf_ipmi_picmg_linkinfo_type,
			{ "Type",
				"ipmi.linkinfo.type", FT_UINT32, BASE_HEX, linkinfo_type_vals, 0x000ff000, NULL, HFILL }},
		{ &hf_ipmi_picmg_linkinfo_ports,
			{ "Ports",
				"ipmi.linkinfo.ports", FT_UINT32, BASE_HEX, linkinfo_ports_vals, 0x00000f00, NULL, HFILL }},
		{ &hf_ipmi_picmg_linkinfo_iface,
			{ "Interface",
				"ipmi.linkinfo.iface", FT_UINT32, BASE_HEX, linkinfo_iface_vals, 0x000000c0, NULL, HFILL }},
		{ &hf_ipmi_picmg_linkinfo_chan,
			{ "Channel",
				"ipmi.linkinfo.chan", FT_UINT32, BASE_DEC, NULL, 0x0000003f, NULL, HFILL }},
		{ &hf_ipmi_picmg_linkinfo_state,
			{ "State",
				"ipmi.picmg0e.state", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_00_version,
			{ "PICMG Extension Version",
				"ipmi.picmg00.version", FT_UINT8, BASE_CUSTOM, ipmi_fmt_version, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_00_max_fruid,
			{ "Max FRU Device ID",
				"ipmi.picmg00.max_fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_00_ipmc_fruid,
			{ "FRU Device ID for IPMC",
				"ipmi.picmg00.ipmc_fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_01_rq_fruid,
			{ "FRU ID",
				"ipmi.picmg01.rq_fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_01_rq_addr_key_type,
			{ "Address Key Type",
				"ipmi.picmg01.rq_addr_key_type", FT_UINT8, BASE_HEX, addr_key_type_vals, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_01_rq_addr_key,
			{ "Address Key",
				"ipmi.picmg01.rq_addr_key", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_01_rq_site_type,
			{ "Site Type",
				"ipmi.picmg01.rq_site_type", FT_UINT8, BASE_HEX, site_type_vals, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_01_rs_hwaddr,
			{ "Hardware Address",
				"ipmi.picmg01.rs_hwaddr", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_01_rs_ipmbaddr,
			{ "IPMB-0 Address",
				"ipmi.picmg01.rs_ipmbaddr", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_01_rs_rsrv,
			{ "Reserved (shall be 0xFF)",
				"ipmi.picmg01.rs_rsrv", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_01_rs_fruid,
			{ "FRU ID",
				"ipmi.picmg01.rs_fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_01_rs_site_num,
			{ "Site Number",
				"ipmi.picmg01.rs_site_num", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_01_rs_site_type,
			{ "Site Type",
				"ipmi.picmg01.rs_site_type", FT_UINT8, BASE_HEX, site_type_vals, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_04_fruid,
			{ "FRU ID",
				"ipmi.picmg04.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_04_cmd,
			{ "Command",
				"ipmi.picmg04.cmd", FT_UINT8, BASE_HEX, vals_04_cmd, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_05_fruid,
			{ "FRU ID",
				"ipmi.picmg05.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_05_led3,
			{ "LED 3",
				"ipmi.picmg05.led3", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_picmg_05_led2,
			{ "LED 2",
				"ipmi.picmg05.led2", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_picmg_05_led1,
			{ "LED 1",
				"ipmi.picmg05.led1", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_picmg_05_blue_led,
			{ "BLUE LED",
				"ipmi.picmg05.blue_led", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_picmg_05_app_leds,
			{ "Application-specific LED Count",
				"ipmi.picmg05.app_leds", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_06_fruid,
			{ "FRU ID",
				"ipmi.picmg06.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_06_ledid,
			{ "LED ID",
				"ipmi.picmg06.ledid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_06_cap_white,
			{ "White",
				"ipmi.picmg06.cap_white", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
		{ &hf_ipmi_picmg_06_cap_orange,
			{ "Orange",
				"ipmi.picmg06.cap_orange", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_picmg_06_cap_amber,
			{ "Amber",
				"ipmi.picmg06.cap_amber", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_picmg_06_cap_green,
			{ "Green",
				"ipmi.picmg06.cap_green", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_picmg_06_cap_red,
			{ "Red",
				"ipmi.picmg06.cap_red", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_picmg_06_cap_blue,
			{ "Blue",
				"ipmi.picmg06.cap_blue", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_picmg_06_default_local_color,
			{ "Default LED Color in Local Control state",
				"ipmi.picmg06.def_local", FT_UINT8, BASE_HEX, led_color_vals, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_picmg_06_default_override_color,
			{ "Default LED Color in Override state",
				"ipmi.picmg06.def_override", FT_UINT8, BASE_HEX, led_color_vals, 0x0f, NULL, HFILL }},

		{ &hf_ipmi_picmg_07_fruid,
			{ "FRU ID",
				"ipmi.picmg07.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_07_ledid,
			{ "LED ID",
				"ipmi.picmg07.ledid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_08_fruid,
			{ "FRU ID",
				"ipmi.picmg08.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_08_ledid,
			{ "LED ID",
				"ipmi.picmg08.ledid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_08_state_lamptest,
			{ "Lamp Test",
				"ipmi.picmg08.state_lamptest", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_picmg_08_state_override,
			{ "Override",
				"ipmi.picmg08.state_override", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_picmg_08_state_local,
			{ "Local Control",
				"ipmi.picmg08.state_local", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_picmg_08_lamptest_duration,
			{ "Lamp test duration",
				"ipmi.picmg08.lamptest_duration", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_09_ipmba,
			{ "IPMB-A State",
				"ipmi.picmg09.ipmba", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_09_ipmbb,
			{ "IPMB-B State",
				"ipmi.picmg09.ipmbb", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_0a_fruid,
			{ "FRU ID",
				"ipmi.picmg0a.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_0a_msk_d_locked,
			{ "Deactivation-Locked bit",
				"ipmi.picmg0a.msk_deactivation", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_picmg_0a_msk_locked,
			{ "Locked bit",
				"ipmi.picmg0a.msk_locked", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_picmg_0a_d_locked,
			{ "Deactivation-Locked bit",
				"ipmi.picmg0a.deactivation", FT_BOOLEAN, 8, TFS(&set_clear_tfs), 0x02, NULL, HFILL }},
		{ &hf_ipmi_picmg_0a_locked,
			{ "Locked bit",
				"ipmi.picmg0a.locked", FT_BOOLEAN, 8, TFS(&set_clear_tfs), 0x01, NULL, HFILL }},

		{ &hf_ipmi_picmg_0b_fruid,
			{ "FRU ID",
				"ipmi.picmg0b.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_0b_d_locked,
			{ "Deactivation-Locked bit",
				"ipmi.picmg0b.deactivation", FT_BOOLEAN, 8, TFS(&set_clear_tfs), 0x02, NULL, HFILL }},
		{ &hf_ipmi_picmg_0b_locked,
			{ "Locked bit",
				"ipmi.picmg0b.locked", FT_BOOLEAN, 8, TFS(&set_clear_tfs), 0x01, NULL, HFILL }},

		{ &hf_ipmi_picmg_0c_fruid,
			{ "FRU ID",
				"ipmi.picmg0c.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_0c_cmd,
			{ "Command",
				"ipmi.picmg0c.cmd", FT_UINT8, BASE_HEX, vals_0c_cmd, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_0d_fruid,
			{ "FRU ID",
				"ipmi.picmg0d.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_0d_start,
			{ "Search after record ID",
				"ipmi.picmg0d.start", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_0d_recordid,
			{ "Record ID",
				"ipmi.picmg0d.recordid", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_0f_iface,
			{ "Interface",
				"ipmi.linkinfo.iface", FT_UINT8, BASE_HEX, linkinfo_iface_vals, 0x000000c0, NULL, HFILL }},
		{ &hf_ipmi_picmg_0f_chan,
			{ "Channel",
				"ipmi.linkinfo.chan", FT_UINT8, BASE_DEC, NULL, 0x0000003f, NULL, HFILL }},

		{ &hf_ipmi_picmg_10_fruid,
			{ "FRU ID",
				"ipmi.picmg10.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_10_nslots,
			{ "Number of spanned slots",
				"ipmi.picmg10.nslots", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_10_ipmc_loc,
			{ "IPMC Location",
				"ipmi.picmg10.ipmc_loc", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_11_fruid,
			{ "FRU ID",
				"ipmi.picmg11.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_11_power_level,
			{ "Power Level",
				"ipmi.picmg11.power_level", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_11_set_to_desired,
			{ "Set Present Levels to Desired",
				"ipmi.picmg11.set_to_desired", FT_UINT8, BASE_HEX, vals_11_set, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_12_fruid,
			{ "FRU ID",
				"ipmi.picmg12.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_12_pwr_type,
			{ "Power Type",
				"ipmi.picmg12.pwr_type", FT_UINT8, BASE_HEX, vals_12_pwr_type, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_12_dynamic,
			{ "Dynamic Power Configuration",
				"ipmi.picmg12.dynamic", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_picmg_12_pwr_lvl,
			{ "Power Level",
				"ipmi.picmg12.pwd_lvl", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_ipmi_picmg_12_delay,
			{ "Delay to stable power",
				"ipmi.picmg12.delay", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_12_pwr_mult,
			{ "Power multiplier",
				"ipmi.picmg12.pwr_mult", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_12_pwr_draw,
			{ "Power draw",
				"ipmi.picmg12.pwr_draw", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_13_fruid,
			{ "FRU ID",
				"ipmi.picmg13.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_14_fruid,
			{ "FRU ID",
				"ipmi.picmg14.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_14_speed_min,
			{ "Minimum Speed Level",
				"ipmi.picmg14.speed_min", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_14_speed_max,
			{ "Maximum Speed Level",
				"ipmi.picmg14.speed_max", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_14_speed_norm,
			{ "Normal Operating Level",
				"ipmi.picmg14.speed_norm", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_14_local_control,
			{ "Local Control Mode Supported",
				"ipmi.picmg14.local_control", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},

		{ &hf_ipmi_picmg_15_fruid,
			{ "FRU ID",
				"ipmi.picmg15.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_15_fan_level,
			{ "Fan Level",
				"ipmi.picmg15.fan_level", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_15_local_enable,
			{ "Local Control Enable State",
				"ipmi.picmg15.local_enable", FT_UINT8, BASE_HEX, enable_vals, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_16_fruid,
			{ "FRU ID",
				"ipmi.picmg16.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_16_override_level,
			{ "Override Fan Level",
				"ipmi.picmg16.override_level", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_16_local_level,
			{ "Local Control Fan Level",
				"ipmi.picmg16.local_level", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_16_local_enable,
			{ "Local Control Enable State",
				"ipmi.picmg16.local_enable", FT_UINT8, BASE_HEX, enabled_vals, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_17_cmd,
			{ "Command",
				"ipmi.picmg17.cmd", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_17_resid,
			{ "Bused Resource ID",
				"ipmi.picmg17.resid", FT_UINT8, BASE_HEX, busresid_vals, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_17_status,
			{ "Status",
				"ipmi.picmg17.status", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_18_li_key_type,
			{ "Link Info Key Type",
				"ipmi.picmg18.li_key_type", FT_UINT8, BASE_HEX, vals_18_keytype, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_18_li_key,
			{ "Link Info Key",
				"ipmi.picmg18.li_key", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_18_link_num,
			{ "Link Number",
				"ipmi.picmg18.link_num", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_18_sensor_num,
			{ "Sensor Number",
				"ipmi.picmg18.sensor_num", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_1b_addr_active,
			{ "Active Shelf Manager IPMB Address",
				"ipmi.picmg1b.addr_active", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_1b_addr_backup,
			{ "Backup Shelf Manager IPMB Address",
				"ipmi.picmg1b.addr_backup", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_1c_fan_site_number,
			{ "Fan Tray Site Number",
				"ipmi.picmg1c.fan_site_number", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_1c_fan_enable_state,
			{ "Fan Enable state",
				"ipmi.picmg1c.fan_enable_state", FT_UINT8, BASE_HEX, enable_vals, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_1c_fan_policy_timeout,
			{ "Fan Policy Timeout",
				"ipmi.picmg1c.fan_policy_timeout", FT_UINT8, BASE_CUSTOM, ipmi_fmt_5s_1based, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_1c_site_number,
			{ "Site Number",
				"ipmi.picmg1c.site_number", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_1c_site_type,
			{ "Site Type",
				"ipmi.picmg1c.site_type", FT_UINT8, BASE_HEX, site_type_vals, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_1d_fan_site_number,
			{ "Fan Tray Site Number",
				"ipmi.picmg1d.fan_site_number", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_1d_site_number,
			{ "Site Number",
				"ipmi.picmg1d.site_number", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_1d_site_type,
			{ "Site Type",
				"ipmi.picmg1d.site_type", FT_UINT8, BASE_HEX, site_type_vals, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_1d_policy,
			{ "Policy",
				"ipmi.picmg1d.fan_enable_state", FT_UINT8, BASE_HEX, vals_1d_policy, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_1d_coverage,
			{ "Coverage",
				"ipmi.picmg1d.coverage", FT_UINT8, BASE_HEX, vals_1d_coverage, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_1e_fruid,
			{ "FRU ID",
				"ipmi.picmg1e.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_1e_cap_diagintr,
			{ "Diagnostic interrupt",
				"ipmi.picmg1e.cap_diagintr", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_picmg_1e_cap_graceful_reboot,
			{ "Graceful reboot",
				"ipmi.picmg1e.cap_reboot", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_picmg_1e_cap_warm_reset,
			{ "Warm Reset",
				"ipmi.picmg1e.cap_warmreset", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},

		{ &hf_ipmi_picmg_1f_rq_fruid,
			{ "FRU ID",
				"ipmi.picmg1f.rq_fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_1f_rq_op,
			{ "Operation",
				"ipmi.picmg1f.rq_op", FT_UINT8, BASE_HEX, vals_1f_op, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_1f_rq_lockid,
			{ "Lock ID",
				"ipmi.picmg1f.rq_lockid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_1f_rs_lockid,
			{ "Lock ID",
				"ipmi.picmg1f.rs_lockid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_1f_rs_tstamp,
			{ "Last Commit Timestamp",
				"ipmi.picmg1f.rs_tstamp", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_20_fruid,
			{ "FRU ID",
				"ipmi.picmg20.fruid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_20_lockid,
			{ "Lock ID",
				"ipmi.picmg20.lockid", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_20_offset,
			{ "Offset to write",
				"ipmi.picmg20.offset", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_20_data,
			{ "Data to write",
				"ipmi.picmg20.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_20_count,
			{ "Count written",
				"ipmi.picmg20.count", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_21_addr_num,
			{ "Address Number",
				"ipmi.picmg21.addr_num", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_21_tstamp,
			{ "Shelf IP Address Last Change Timestamp",
				"ipmi.picmg21.tstamp", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_21_addr_count,
			{ "Address Count",
				"ipmi.picmg21.addr_count", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_21_site_type,
			{ "Site Type",
				"ipmi.picmg21.site_type", FT_UINT8, BASE_HEX, site_type_vals, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_21_site_num,
			{ "Site Number",
				"ipmi.picmg21.site_num", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_21_max_unavail,
			{ "Maximum Unavailable Time",
				"ipmi.picmg21.max_unavail", FT_UINT8, BASE_CUSTOM, ipmi_fmt_1s_1based, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_21_is_shm,
			{ "Shelf Manager IP Address",
				"ipmi.picmg21.is_shm", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_picmg_21_addr_type,
			{ "Address Type",
				"ipmi.picmg21.addr_type", FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_picmg_21_ipaddr,
			{ "IP Address",
				"ipmi.picmg21.ip_addr", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_21_rmcpport,
			{ "RMCP Port",
				"ipmi.picmg21.rmcp_port", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_22_feed_idx,
			{ "Power Feed Index",
				"ipmi.picmg22.feed_idx", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_22_update_cnt,
			{ "Update Counter",
				"ipmi.picmg22.update_cnt", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_22_pwr_alloc,
			{ "Power Feed Allocation",
				"ipmi.picmg22.pwr_alloc", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_XX_comp7,
			{ "Component 7",
				"ipmi.hpm1.comp7", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_picmg_XX_comp6,
			{ "Component 6",
				"ipmi.hpm1.comp6", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
		{ &hf_ipmi_picmg_XX_comp5,
			{ "Component 5",
				"ipmi.hpm1.comp5", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_picmg_XX_comp4,
			{ "Component 4",
				"ipmi.hpm1.comp4", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_picmg_XX_comp3,
			{ "Component 3",
				"ipmi.hpm1.comp3", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_picmg_XX_comp2,
			{ "Component 2",
				"ipmi.hpm1.comp2", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_picmg_XX_comp1,
			{ "Component 1",
				"ipmi.hpm1.comp1", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_picmg_XX_comp0,
			{ "Component 0",
				"ipmi.hpm1.comp0", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},

		{ &hf_ipmi_picmg_2e_version,
			{ "HPM.1 version",
				"ipmi.picmg2e.hpm1_version", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_2e_upgrade_undesirable,
			{ "Firmware Upgrade Undesirable",
				"ipmi.picmg2e.upgrade_undesirable", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
		{ &hf_ipmi_picmg_2e_auto_rollback_override,
			{ "Automatic Rollback Overridden",
				"ipmi.picmg2e.auto_rollback_override", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
		{ &hf_ipmi_picmg_2e_ipmc_degraded,
			{ "IPMC degraded during upgrade",
				"ipmi.picmg2e.ipmc_degraded", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_picmg_2e_deferred_activate,
			{ "Deferred Activation supported",
				"ipmi.picmg2e.deferred_activate", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_picmg_2e_services_affected,
			{ "Services affected by upgrade",
				"ipmi.picmg2e.services_affected", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_picmg_2e_manual_rollback,
			{ "Manual Rollback supported",
				"ipmi.picmg2e.manual_rollback", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_picmg_2e_auto_rollback,
			{ "Automatic Rollback supported",
				"ipmi.picmg2e.auto_rollback", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_ipmi_picmg_2e_self_test,
			{ "Self-Test supported",
				"ipmi.picmg2e.self_test", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_ipmi_picmg_2e_upgrade_tout,
			{ "Upgrade timeout",
				"ipmi.picmg2e.upgrade_tout", FT_UINT8, BASE_CUSTOM, ipmi_fmt_5s_1based, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_2e_selftest_tout,
			{ "Self-test timeout",
				"ipmi.picmg2e.selftest_tout", FT_UINT8, BASE_CUSTOM, ipmi_fmt_5s_1based, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_2e_rollback_tout,
			{ "Rollback timeout",
				"ipmi.picmg2e.rollback_tout", FT_UINT8, BASE_CUSTOM, ipmi_fmt_5s_1based, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_2e_inaccessibility_tout,
			{ "Inaccessibility timeout",
				"ipmi.picmg2e.inaccessibility_tout", FT_UINT8, BASE_CUSTOM, ipmi_fmt_5s_1based, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_prop00_cold_reset,
			{ "Payload cold reset required",
				"ipmi.prop00.cold_reset", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
		{ &hf_ipmi_picmg_prop00_deferred_activation,
			{ "Deferred firmware activation supported",
				"ipmi.prop00.deferred_activation", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
		{ &hf_ipmi_picmg_prop00_comparison,
			{ "Firmware comparison supported",
				"ipmi.prop00.firmware_comparison", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_ipmi_picmg_prop00_preparation,
			{ "Prepare Components action required",
				"ipmi.prop00.preparation", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_ipmi_picmg_prop00_rollback,
			{ "Rollback/Backup support",
				"ipmi.prop00.rollback", FT_UINT8, BASE_HEX, vals_prop00_rollback, 0x03, NULL, HFILL }},
		{ &hf_ipmi_picmg_prop01_fw_major,
			{ "Major Firmware Revision (binary encoded)",
				"ipmi.prop01.fw_major", FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL }},
		{ &hf_ipmi_picmg_prop01_fw_minor,
			{ "Minor Firmware Revision (BCD encoded)",
				"ipmi.prop01.fw_minor", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_prop01_fw_aux,
			{ "Auxiliary Firmware Revision Information",
				"ipmi.prop01.fw_aux", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_prop02_desc,
			{ "Description string",
				"ipmi.prop02.desc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_2f_comp_id,
			{ "Component ID",
				"ipmi.picmg2f.comp_id", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_2f_comp_prop,
			{ "Component property selector",
				"ipmi.picmg2f.comp_prop", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_2f_prop_data,
			{ "Unknown property data",
				"ipmi.picmg2f.prop_data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_31_action,
			{ "Upgrade action",
				"ipmi.picmg31.action", FT_UINT8, BASE_HEX, vals_31_action, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_32_block,
			{ "Block Number",
				"ipmi.picmg32.block", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_32_data,
			{ "Data",
				"ipmi.picmg32.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_32_sec_offs,
			{ "Section Offset",
				"ipmi.picmg32.sec_offs", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_32_sec_len,
			{ "Section Length",
				"ipmi.picmg32.sec_len", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_33_comp_id,
			{ "Component ID",
				"ipmi.picmg33.comp_id", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_33_img_len,
			{ "Image Length",
				"ipmi.picmg33.img_len", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_34_cmd,
			{ "Command in progress",
				"ipmi.picmg34.cmd", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_34_ccode,
			{ "Last command completion code",
				"ipmi.picmg34.ccode", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_34_percentage,
			{ "Completion estimate",
				"ipmi.picmg34.percent", FT_UINT8, BASE_CUSTOM, ipmi_fmt_percent, 0x7f, NULL, HFILL }},

		{ &hf_ipmi_picmg_35_rollback_override,
			{ "Rollback Override Policy",
				"ipmi.picmg35.rollback_override", FT_UINT8, BASE_HEX, vals_35_override, 0, NULL, HFILL }},

		{ &hf_ipmi_picmg_36_result,
			{ "Self test result",
				"ipmi.picmg36.self_test_result", FT_UINT8, BASE_HEX, vals_36_result, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_36_fail,
			{ "Self-test error bitfield",
				"ipmi.picmg36.fail", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_picmg_36_fail_sel,
			{ "Cannot access SEL device",
				"ipmi.picmg36.fail.sel", FT_BOOLEAN, 8, TFS(&tfs_36_fail_unknown), 0x80, NULL, HFILL }},
		{ &hf_ipmi_picmg_36_fail_sdr,
			{ "Cannot access SDR Repository",
				"ipmi.picmg36.fail.sdr", FT_BOOLEAN, 8, TFS(&tfs_36_fail_unknown), 0x40, NULL, HFILL }},
		{ &hf_ipmi_picmg_36_fail_bmc_fru,
			{ "Cannot access BMC FRU device",
				"ipmi.picmg36.fail.bmc_fru", FT_BOOLEAN, 8, TFS(&tfs_36_fail_unknown), 0x20, NULL, HFILL }},
		{ &hf_ipmi_picmg_36_fail_ipmb_sig,
			{ "IPMB signal lines do not respond",
				"ipmi.picmg36.fail.ipmb_sig", FT_BOOLEAN, 8, TFS(&tfs_36_fail_unknown), 0x10, NULL, HFILL }},
		{ &hf_ipmi_picmg_36_fail_sdr_empty,
			{ "SDR Repository is empty",
				"ipmi.picmg36.fail.sdr_empty", FT_BOOLEAN, 8, TFS(&tfs_36_fail_unknown), 0x08, NULL, HFILL }},
		{ &hf_ipmi_picmg_36_fail_iua,
			{ "Internal Use Area of BMC FRU corrupted",
				"ipmi.picmg36.fail.iua", FT_BOOLEAN, 8, TFS(&tfs_36_fail_unknown), 0x04, NULL, HFILL }},
		{ &hf_ipmi_picmg_36_fail_bb_fw,
			{ "Controller update boot block firmware corrupted",
				"ipmi.picmg36.fail.bb_fw", FT_BOOLEAN, 8, TFS(&tfs_36_fail_unknown), 0x02, NULL, HFILL }},
		{ &hf_ipmi_picmg_36_fail_oper_fw,
			{ "Controller operational firmware corrupted",
				"ipmi.picmg36.fail.oper_fw", FT_BOOLEAN, 8, TFS(&tfs_36_fail_unknown), 0x01, NULL, HFILL }},

		{ &hf_ipmi_picmg_37_percent,
			{ "Estimated percentage complete",
				"ipmi.picmg37.percent", FT_UINT8, BASE_CUSTOM, ipmi_fmt_percent, 0x7f, NULL, HFILL }},

	};
	static gint *ett[] = {
		&ett_ipmi_picmg_led_color,
		&ett_ipmi_picmg_link_info,
		&ett_ipmi_picmg_05_byte1,
		&ett_ipmi_picmg_06_byte1,
		&ett_ipmi_picmg_06_byte2,
		&ett_ipmi_picmg_06_byte3,
		&ett_ipmi_picmg_08_byte1,
		&ett_ipmi_picmg_09_ipmba,
		&ett_ipmi_picmg_09_ipmbb,
		&ett_ipmi_picmg_0a_byte2,
		&ett_ipmi_picmg_0a_byte3,
		&ett_ipmi_picmg_0b_byte1,
		&ett_ipmi_picmg_0f_chan,
		&ett_ipmi_picmg_12_byte1,
		&ett_ipmi_picmg_14_prop,
		&ett_ipmi_picmg_1e_byte1,
		&ett_ipmi_picmg_21_byte9,
		&ett_ipmi_picmg_XX_compbits,
		&ett_ipmi_picmg_2e_byte2,
		&ett_ipmi_picmg_prop00_byte1,
		&ett_ipmi_picmg_prop01_byte1,
		&ett_ipmi_picmg_34_byte3,
		&ett_ipmi_picmg_36_byte2,
		&ett_ipmi_picmg_37_byte2,
	};
	static guint8 sig_picmg[1] = { 0 };

	proto_register_field_array(proto_ipmi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	ipmi_register_netfn_cmdtab(IPMI_GROUP_REQ, IPMI_OEM_NONE, sig_picmg, 1,
			"PICMG", cmd_picmg, array_length(cmd_picmg));
}
