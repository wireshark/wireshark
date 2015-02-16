/* packet-ipmi-vita.c
 * Sub-dissectors for IPMI messages (netFn=Group, defining body = VSO)
 * Copyright 2014, Dmitry Bazhenov, Pigeon Point Systems <dima_b@pigeonpoint.com>
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

#include "config.h"

#include <epan/packet.h>

#include "packet-ipmi.h"

void proto_register_ipmi_vita(void);

/* Tree type identifiers.
*/
static gint ett_vita_ipmc = -1;
static gint ett_vita_ipmb = -1;
static gint ett_vita_vso = -1;
static gint ett_vita_led_caps = -1;
static gint ett_vita_led_color = -1;
static gint ett_vita_led_flags = -1;
static gint ett_vita_led_states = -1;
static gint ett_vita_ipmb_state = -1;
static gint ett_vita_fru_policy_bits = -1;
static gint ett_vita_fan_properties = -1;
static gint ett_vita_fru_control_caps = -1;
static gint ett_vita_chassis_addr_type = -1;
static gint ett_vita_chassis_addr = -1;
static gint ett_vita_persistent_control_state = -1;
static gint ett_vita_persistent_control_caps = -1;

/* Field identifiers.
*/
static gint hf_vita_reserved = -1;
static gint hf_vita_fruid = -1;
static gint hf_vita_addr_key_type = -1;
static gint hf_vita_addr_key = -1;
static gint hf_vita_hw_addr = -1;
static gint hf_vita_ipmb_addr = -1;
static gint hf_vita_site_type = -1;
static gint hf_vita_site_num = -1;
static gint hf_vita_ipmbl_addr = -1;

static gint hf_vita_chassis_identifier = -1;
static gint hf_vita_chassis_identifier_type = -1;
static gint hf_vita_chassis_identifier_length = -1;
static gint hf_vita_ipmc = -1;
static gint hf_vita_tier = -1;
static gint hf_vita_layer = -1;
static gint hf_vita_ipmb = -1;
static gint hf_vita_ipmb_itfs = -1;
static gint hf_vita_ipmb_freq = -1;
static gint hf_vita_vso = -1;
static gint hf_vita_vso_std = -1;
static gint hf_vita_rev = -1;
static gint hf_vita_max_fruid = -1;
static gint hf_vita_ipmc_fruid = -1;
static gint hf_vita_fru_control = -1;

static gint hf_vita_led_count = -1;
static gint hf_vita_led_id = -1;
static gint hf_vita_led_caps = -1;
static gint hf_vita_led_cap_blue = -1;
static gint hf_vita_led_cap_red = -1;
static gint hf_vita_led_cap_green = -1;
static gint hf_vita_led_cap_amber = -1;
static gint hf_vita_led_cap_orange = -1;
static gint hf_vita_led_cap_white = -1;
static gint hf_vita_led_def_loc_color = -1;
static gint hf_vita_led_def_ovr_color = -1;
static gint hf_vita_led_color = -1;
static gint hf_vita_led_flags = -1;
static gint hf_vita_led_flag_pwr = -1;
static gint hf_vita_led_flag_hw_restrict = -1;
static gint hf_vita_led_states = -1;
static gint hf_vita_led_loc_func = -1;
static gint hf_vita_led_loc_duration = -1;
static gint hf_vita_led_loc_color = -1;
static gint hf_vita_led_ovr_func = -1;
static gint hf_vita_led_ovr_duration = -1;
static gint hf_vita_led_ovr_color = -1;
static gint hf_vita_led_lamp_test_duration = -1;
static gint hf_vita_led_state_local = -1;
static gint hf_vita_led_state_override = -1;
static gint hf_vita_led_state_lamp_test = -1;
static gint hf_vita_led_state_hw_restrict = -1;

static gint hf_vita_ipmba_state = -1;
static gint hf_vita_ipmbb_state = -1;
static gint hf_vita_ipmb_state = -1;
static gint hf_vita_ipmb_link_id = -1;

static gint hf_vita_fru_policy_mask_bits = -1;
static gint hf_vita_fru_policy_set_bits = -1;
static gint hf_vita_fru_policy_bits = -1;
static gint hf_vita_fru_activation_locked = -1;
static gint hf_vita_fru_deactivation_locked = -1;
static gint hf_vita_fru_commanded_deactivation_ignored = -1;
static gint hf_vita_fru_default_activation_locked = -1;

static gint hf_vita_fru_activation = -1;

static gint hf_vita_record_id = -1;

static gint hf_vita_fan_min_level = -1;
static gint hf_vita_fan_max_level = -1;
static gint hf_vita_fan_norm_level = -1;
static gint hf_vita_fan_properties = -1;
static gint hf_vita_fan_prop_local_control = -1;
static gint hf_vita_fan_override_level = -1;
static gint hf_vita_fan_local_level = -1;
static gint hf_vita_fan_local_control = -1;

static gint hf_vita_ipmb_link_key_type = -1;
static gint hf_vita_ipmb_link_key_value = -1;
static gint hf_vita_ipmb_link_number = -1;
static gint hf_vita_ipmb_sensor_number = -1;

static gint hf_vita_active_chmc_ipmb_addr = -1;
static gint hf_vita_backup_chmc_ipmb_addr = -1;

static gint hf_vita_fan_number = -1;
static gint hf_vita_fan_policy = -1;
static gint hf_vita_fan_policy_timeout = -1;
static gint hf_vita_fan_coverage = -1;

static gint hf_vita_fru_control_caps = -1;
static gint hf_vita_fru_control_cap_cold = -1;
static gint hf_vita_fru_control_cap_warm = -1;
static gint hf_vita_fru_control_cap_grace = -1;
static gint hf_vita_fru_control_cap_diag = -1;
static gint hf_vita_fru_control_cap_pwr = -1;

static gint hf_vita_fru_lock_operation = -1;
static gint hf_vita_fru_lock_id = -1;
static gint hf_vita_fru_lock_timestamp = -1;

static gint hf_vita_fru_write_offset = -1;
static gint hf_vita_fru_write_data = -1;
static gint hf_vita_fru_write_count = -1;

static gint hf_vita_chassis_addr_number = -1;
static gint hf_vita_chassis_addr_timestamp = -1;
static gint hf_vita_chassis_addr_count = -1;
static gint hf_vita_chassis_max_unavail = -1;
static gint hf_vita_chassis_addr_type = -1;
static gint hf_vita_chassis_addr = -1;
static gint hf_vita_chassis_addr_chmc = -1;
static gint hf_vita_chassis_addr_format = -1;
static gint hf_vita_ipv4_addr = -1;
static gint hf_vita_rmcp_port = -1;

static gint hf_vita_persistent_control_state = -1;
static gint hf_vita_persistent_control_cold = -1;
static gint hf_vita_persistent_control_warm = -1;
static gint hf_vita_persistent_control_mask = -1;
static gint hf_vita_persistent_control_set = -1;
static gint hf_vita_persistent_control_caps = -1;
static gint hf_vita_persistent_control_cap_cold = -1;
static gint hf_vita_persistent_control_cap_warm = -1;

static gint hf_vita_fru_state_sensor_num = -1;
static gint hf_vita_fru_health_sensor_num = -1;
static gint hf_vita_fru_voltage_sensor_num = -1;
static gint hf_vita_fru_temp_sensor_num = -1;
static gint hf_vita_payload_test_results_sensor_num = -1;
static gint hf_vita_payload_test_status_sensor_num = -1;

/* String values.
*/
static const value_string str_vita_ipmc_tiers[] = {
	{ 0x00, "Tier-1" },
	{ 0x01, "Tier-2" },
	{ 0x02, "Reserved" },
	{ 0x03, "Reserved" },
	{ 0, NULL }
};

static const value_string str_vita_ipmc_layers[] = {
	{ 0x00, "IPMC" },
	{ 0x01, "Chassis Manager" },
	{ 0x02, "System Manager" },
	{ 0x03, "Reserved" },
	{ 0, NULL }
};

static const value_string str_vita_ipmb_itfs[] = {
	{ 0x00, "1 IPMB interface" },
	{ 0x01, "2 IPMB interfaces" },
	{ 0x02, "Reserved" },
	{ 0x03, "Reserved" },
	{ 0, NULL }
};

static const value_string str_vita_ipmb_freq[] = {
	{ 0x00, "100KHz" },
	{ 0x01, "400KHz" },
	{ 0x02, "Reserved" },
	{ 0x03, "Reserved" },
	{ 0, NULL }
};

static const value_string str_vita_vso_std[] = {
	{ 0x00, "VITA 46.11" },
	{ 0, NULL }
};

static const value_string str_vita_addr_key_types[] = {
	{ 0x00, "Hardware Address" },
	{ 0x01, "IPMB Address" },
	{ 0x02, "Reserved" },
	{ 0x03, "Physical Address" },
	{ 0, NULL }
};

static const value_string str_vita_site_types[] = {
	{ 0x00, "Front Loading VPX Plug-In Module" },
	{ 0x01, "Power Entry Module" },
	{ 0x02, "Chassis FRU Information Module" },
	{ 0x03, "Dedicated ChMC" },
	{ 0x04, "Fan Tray" },
	{ 0x05, "Fan Tray Filter" },
	{ 0x06, "Alarm Panel" },
	{ 0x07, "XMC" },
	{ 0x08, "Reserved" },
	{ 0x09, "VPX Rear Transition Module" },
	{ 0x0A, "Reserved" },
	{ 0x0B, "Reserved" },
	{ 0x0C, "Power Supply" },
	{ 0x0D, "Reserved" },
	{ 0x0E, "Reserved" },
	{ 0x0F, "FMC" },
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

static value_string_ext str_vita_site_types_ext = VALUE_STRING_EXT_INIT(str_vita_site_types);

static const value_string str_vita_fru_controls[] = {
	{ 0x00, "Cold Reset" },
	{ 0x01, "Warm Reset" },
	{ 0x02, "Graceful Reboot" },
	{ 0x03, "Diagnostic Interrupt" },
	{ 0, NULL }
};

static const value_string str_vita_led_colors[] = {
	{ 0x00, "Reserved (Control not supported)" },
	{ 0x01, "BLUE" },
	{ 0x02, "RED" },
	{ 0x03, "GREEN" },
	{ 0x04, "AMBER" },
	{ 0x05, "ORANGE" },
	{ 0x06, "WHITE" },
	{ 0x0E, "Do not change" },
	{ 0x0F, "Use default" },
	{ 0, NULL }
};

static const range_string str_vita_led_func[] = {
	{ 0x00, 0x00, "LED off" },
	{ 0x01, 0xFA, "LED BLINKING (off duration)" },
	{ 0xFB, 0xFB, "LAMP TEST" },
	{ 0xFC, 0xFC, "LED restored to Local Control state" },
	{ 0xFF, 0xFF, "LED on" },
	{ 0, 0, NULL }
};

static const range_string str_vita_ipmb_state[] = {
	{ 0x0, 0xFE, "System IPMB state" },
	{ 0xFF, 0xFF, "Do not change current state" },
	{ 0, 0, NULL }
};

static const true_false_string str_vita_ipmb_override = {
	"Local Control State",
	"Override state - Isolate(disable)"
};

static const range_string str_vita_ipmb_link_id[] = {
	{ 0x00, 0x00, "Select all System IPMB Links" },
	{ 0x01, 0x5F, "System IPMB Link Number" },
	{ 0x60, 0x7F, "Reserved" },
	{ 0, 0, NULL }
};

static const value_string str_vita_fru_activation[] = {
	{ 0x00, "Deactivate FRU" },
	{ 0x01, "Activate FRU" },
	{ 0, NULL }
};

static const value_string str_vita_fan_levels[] = {
	{ 0xFE, "Shut Down" },
	{ 0xFF, "Local Control" },
	{ 0, NULL }
};

static const value_string str_vita_fan_local_control[] = {
	{ 0x00, "Disabled" },
	{ 0x01, "Enabled" },
	{ 0, NULL }
};

static const value_string str_vita_ipmb_link_key_types[] = {
	{ 0x00, "Key is IPMB Link Number" },
	{ 0x01, "Key is IPMB Sensor Number" },
	{ 0, NULL }
};

static const value_string str_vita_fan_policies[] = {
	{ 0x00, "Disable" },
	{ 0x01, "Enable" },
	{ 0xFF, "Indeterminate" },
	{ 0, NULL }
};

static const value_string str_vita_fan_policy_timeouts[] = {
	{ 0xFF, "Infinite" },
	{ 0, NULL }
};

static const value_string str_vita_fan_coverages[] = {
	{ 0x00, "Not Covered" },
	{ 0x01, "Covered" },
	{ 0, NULL }
};

static const value_string str_vita_fru_lock_operations[] = {
	{ 0x00, "Get Last Commit Timestamp" },
	{ 0x01, "Lock" },
	{ 0x02, "Unlock and Discard" },
	{ 0x03, "Unlock and Commit	" },
	{ 0, NULL }
};

static const range_string str_vita_chassis_addr_formats[] = {
	{ 0x00, 0x00, "IPv4 Address" },
	{ 0x01, 0x5F, "Reserved" },
	{ 0x60, 0x7F, "OEM" },
	{ 0, 0, NULL }
};


static const value_string cc1F[] = {
	{ 0x80, "Invalid FRU Information" },
	{ 0x81, "Lock Failed" },
	{ 0, NULL }
};

static const value_string cc20[] = {
	{ 0x80, "Invalid Lock ID" },
	{ 0, NULL }
};


/* Array of sub-tree identifiers (needed for registration).
*/
static gint * const ett_ipmi_vita[] = {
	&ett_vita_ipmc,
	&ett_vita_ipmb,
	&ett_vita_vso,
	&ett_vita_led_caps,
	&ett_vita_led_color,
	&ett_vita_led_flags,
	&ett_vita_led_states,
	&ett_vita_ipmb_state,
	&ett_vita_fru_policy_bits,
	&ett_vita_fan_properties,
	&ett_vita_fru_control_caps,
	&ett_vita_chassis_addr_type,
	&ett_vita_chassis_addr,
	&ett_vita_persistent_control_state,
	&ett_vita_persistent_control_caps
};

static const int * bits_vita_led_color[] = {
	&hf_vita_led_color,
	NULL
};

static const int * bits_vita_fru_policy_bits[] = {
	&hf_vita_fru_activation_locked,
	&hf_vita_fru_deactivation_locked,
	&hf_vita_fru_commanded_deactivation_ignored,
	&hf_vita_fru_default_activation_locked,
	NULL
};

static const int * bits_vita_persistent_control_state[] = {
	&hf_vita_persistent_control_cold,
	&hf_vita_persistent_control_warm,
	NULL
};

/* Array of field descriptors.
*/
static hf_register_info hf_ipmi_vita[] = {
	{ &hf_vita_ipmc,
		{ "IPMC Identifier", "ipmi.vita.ipmc",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_tier,
		{ "Tier Functionality", "ipmi.vita.ipmc.tier",
			FT_UINT8, BASE_HEX, VALS(str_vita_ipmc_tiers), 0x3, NULL, HFILL }},
	{ &hf_vita_layer,
		{ "Layer Functionality", "ipmi.vita.ipmc.tier",
			FT_UINT8, BASE_HEX, VALS(str_vita_ipmc_layers), 0x30, NULL, HFILL }},
	{ &hf_vita_ipmb,
		{ "IPMB Capabilities", "ipmi.vita.ipmb",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_ipmb_itfs,
		{ "Number of supported interfaces", "ipmi.vita.ipmc.itfs",
			FT_UINT8, BASE_HEX, VALS(str_vita_ipmb_itfs), 0x3, NULL, HFILL }},
	{ &hf_vita_ipmb_freq,
		{ "Maximum operating frequency", "ipmi.vita.ipmc.freq",
			FT_UINT8, BASE_HEX, VALS(str_vita_ipmb_freq), 0x30, NULL, HFILL }},
	{ &hf_vita_vso,
		{ "VSO Standard", "ipmi.vita.vso",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_vso_std,
		{ "VSO Standard", "ipmi.vita.vso.std",
			FT_UINT8, BASE_HEX, VALS(str_vita_vso_std), 0x3, NULL, HFILL }},
	{ &hf_vita_rev,
		{ "VSO Specification Revision", "ipmi.vita.vso.rev",
			FT_UINT8, BASE_CUSTOM, CF_FUNC(ipmi_fmt_version), 0, NULL, HFILL }},
	{ &hf_vita_max_fruid,
		{ "Max FRU Device ID", "ipmi.vita.max.fruid",
			FT_UINT8, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_ipmc_fruid,
		{ "FRU Device ID for IPMC", "ipmi.vita.ipmc.fruid",
			FT_UINT8, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fruid,
		{ "FRU Device ID", "ipmi.vita.fruid",
			FT_UINT8, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_addr_key_type,
		{ "Address Key Type", "ipmi.vita.key.type",
			FT_UINT8, BASE_HEX, VALS(str_vita_addr_key_types), 0, NULL, HFILL }},
	{ &hf_vita_addr_key,
		{ "Address Key", "ipmi.vita.key",
			FT_UINT8, BASE_HEX_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_vita_site_type,
		{ "Site Type", "ipmi.vita.site.type",
			FT_UINT8, BASE_HEX|BASE_EXT_STRING, &str_vita_site_types_ext, 0, NULL, HFILL }},
	{ &hf_vita_hw_addr,
		{ "Hardware Address", "ipmi.vita.hwaddr",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_ipmb_addr,
		{ "IPMB Address", "ipmi.vita.ipmb.addr",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_site_num,
		{ "Site Number", "ipmi.vita.site.num",
			FT_UINT8, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_ipmbl_addr,
		{ "Address on IPMI Channel 7", "ipmi.vita.ipmbl.addr",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_chassis_identifier,
		{ "Chassis Identifier",
			"ipmi.vita.chassis_identifier", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_vita_chassis_identifier_type,
		{ "Type",
			"ipmi.vita.chassis_identifier_type", FT_UINT8, BASE_DEC, NULL, 0xc0, NULL, HFILL }},
	{ &hf_vita_chassis_identifier_length,
		{ "Length",
			"ipmi.vita.chassis_identifier_length", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL }},
	{ &hf_vita_reserved,
		{ "Reserved", "ipmi.vita.reserved",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fru_control,
		{ "FRU Control", "ipmi.vita.fru.control",
			FT_UINT8, BASE_DEC, VALS(str_vita_fru_controls), 0, NULL, HFILL }},
	{ &hf_vita_led_count,
		{ "LED Count", "ipmi.vita.led.count",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_vita_led_id,
		{ "LED ID", "ipmi.vita.led.id",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_vita_led_caps,
		{ "LED Color Capabilities", "ipmi.vita.led.caps",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_led_cap_blue,
		{ "LED supports BLUE", "ipmi.vita.led.cap.blue",
			FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	{ &hf_vita_led_cap_red,
		{ "LED supports RED", "ipmi.vita.led.cap.red",
			FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
	{ &hf_vita_led_cap_green,
		{ "LED supports GREEN", "ipmi.vita.led.cap.green",
			FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
	{ &hf_vita_led_cap_amber,
		{ "LED supports AMBER", "ipmi.vita.led.cap.amber",
			FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
	{ &hf_vita_led_cap_orange,
		{ "LED supports ORANGE", "ipmi.vita.led.cap.orange",
			FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
	{ &hf_vita_led_cap_white,
		{ "LED supports WHITE", "ipmi.vita.led.cap.white",
			FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
	{ &hf_vita_led_def_loc_color,
		{ "Default LED Color in Local Control State", "ipmi.vita.led.def.loc.color",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_led_def_ovr_color,
		{ "Default LED Color in Override State", "ipmi.vita.led.def.ovr.color",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_led_flags,
		{ "LED Flags", "ipmi.vita.led.flags",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_led_flag_pwr,
		{ "LED is powered from Payload power", "ipmi.vita.led.flag.pwr",
			FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	{ &hf_vita_led_flag_hw_restrict,
		{ "LED has other hardware restrictions", "ipmi.vita.led.flag.hw.restrict",
			FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	{ &hf_vita_led_color,
		{ "LED Color Value", "ipmi.vita.led.color",
			FT_UINT8, BASE_HEX, VALS(str_vita_led_colors), 0x0F, NULL, HFILL }},
	{ &hf_vita_led_ovr_func,
		{ "Override State LED Function", "ipmi.vita.led.ovr.func",
			FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(str_vita_led_func), 0, NULL, HFILL }},
	{ &hf_vita_led_ovr_duration,
		{ "Override State On-Duration", "ipmi.vita.led.ovr.diration",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_vita_led_ovr_color,
		{ "Override State Color", "ipmi.vita.led.ovr.color",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_led_lamp_test_duration,
		{ "Lamp Test Duration", "ipmi.vita.led.lamp.duration",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_vita_led_loc_func,
		{ "Local Control LED Function", "ipmi.vita.led.loc.func",
			FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(str_vita_led_func), 0, NULL, HFILL }},
	{ &hf_vita_led_loc_duration,
		{ "Local Control On-Duration", "ipmi.vita.led.loc.diration",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_vita_led_loc_color,
		{ "Local Control Color", "ipmi.vita.led.loc.color",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_led_states,
		{ "LED States", "ipmi.vita.led.states",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_led_state_local,
		{ "Local Control State", "ipmi.vita.led.state.loc",
			FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	{ &hf_vita_led_state_override,
		{ "Override State", "ipmi.vita.led.state.ovr",
			FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	{ &hf_vita_led_state_lamp_test,
		{ "Lamp Test", "ipmi.vita.led.state.lamp",
			FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
	{ &hf_vita_led_state_hw_restrict,
		{ "Hardware Restriction", "ipmi.vita.led.state.hw",
			FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
	{ &hf_vita_ipmba_state,
		{ "IPMB-A State", "ipmi.vita.ipmba.state",
			FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(str_vita_ipmb_state), 0, NULL, HFILL }},
	{ &hf_vita_ipmbb_state,
		{ "IPMB-B State", "ipmi.vita.ipmbb.state",
			FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(str_vita_ipmb_state), 0, NULL, HFILL }},
	{ &hf_vita_ipmb_state,
		{ "IPMB State", "ipmi.vita.ipmb.ovr",
			FT_BOOLEAN, 8, TFS(&str_vita_ipmb_override), 0x01, NULL, HFILL }},
	{ &hf_vita_ipmb_link_id,
		{ "IPMB Link ID", "ipmi.vita.ipmb.link.id",
			FT_UINT8, BASE_DEC_HEX|BASE_RANGE_STRING, RVALS(str_vita_ipmb_link_id), 0xFE, NULL, HFILL }},
	{ &hf_vita_fru_policy_mask_bits,
		{ "FRU Activation Policy Mask Bits", "ipmi.vita.fru.policy.mask",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fru_policy_set_bits,
		{ "FRU Activation Policy Set Bits", "ipmi.vita.fru.policy.set",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fru_policy_bits,
		{ "FRU Activation Policies", "ipmi.vita.fru.policy.bits",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fru_activation_locked,
		{ "Activation Locked", "ipmi.vita.fru.policy.al",
			FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	{ &hf_vita_fru_deactivation_locked,
		{ "Deactivation Locked", "ipmi.vita.fru.policy.dl",
			FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	{ &hf_vita_fru_commanded_deactivation_ignored,
		{ "Commanded Deactivation Ignored", "ipmi.vita.fru.policy.cdi",
			FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
	{ &hf_vita_fru_default_activation_locked,
		{ "Default Activation Locked", "ipmi.vita.fru.policy.dal",
			FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
	{ &hf_vita_fru_activation,
		{ "FRU Activation/Deactivation", "ipmi.vita.fru.activation",
			FT_UINT8, BASE_DEC, VALS(str_vita_fru_activation), 0, NULL, HFILL }},
	{ &hf_vita_record_id,
		{ "Record ID", "ipmi.vita.record.id",
			FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fan_min_level,
		{ "Minimum Speed Level", "ipmi.vita.fan.min",
			FT_UINT8, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fan_max_level,
		{ "Maximum Speed Level", "ipmi.vita.fan.max",
			FT_UINT8, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fan_norm_level,
		{ "Normal Operating Level", "ipmi.vita.fan.norm",
			FT_UINT8, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fan_properties,
		{ "Fan Tray Properties", "ipmi.vita.fan.props",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fan_prop_local_control,
		{ "Local Control Supported", "ipmi.vita.fan.prop.lc",
			FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
	{ &hf_vita_fan_override_level,
		{ "Override Fan Level", "ipmi.vita.fan.ovr",
			FT_UINT8, BASE_HEX, VALS(str_vita_fan_levels), 0, NULL, HFILL }},
	{ &hf_vita_fan_local_level,
		{ "Local Control Fan Level", "ipmi.vita.fan.loc",
			FT_UINT8, BASE_HEX, VALS(str_vita_fan_levels), 0, NULL, HFILL }},
	{ &hf_vita_fan_local_control,
		{ "Local Control Enable State", "ipmi.vita.fan.lc",
			FT_UINT8, BASE_DEC, VALS(str_vita_fan_local_control), 0, NULL, HFILL }},
	{ &hf_vita_ipmb_link_key_type,
		{ "IPMB Link Info Key Type", "ipmi.vita.ipmb.link.key.type",
			FT_UINT8, BASE_DEC, VALS(str_vita_ipmb_link_key_types), 0, NULL, HFILL }},
	{ &hf_vita_ipmb_link_key_value,
		{ "IPMB Link Info Key", "ipmi.vita.ipmb.link.key.value",
				FT_UINT8, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_ipmb_link_number,
		{ "IPMB Link Number", "ipmi.vita.ipmb.link.number",
			FT_UINT8, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_ipmb_sensor_number,
		{ "IPMB Sensor Number", "ipmi.vita.ipmb.sensor.number",
			FT_UINT8, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_active_chmc_ipmb_addr,
		{ "Active Chassis Manager IPMB Address", "ipmi.vita.active.chmc.ipmb.addr",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_backup_chmc_ipmb_addr,
		{ "Backup Chassis Manager IPMB Address", "ipmi.vita.backup.chmc.ipmb.addr",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fan_number,
		{ "Fan Tray Site Number", "ipmi.vita.fan.num",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fan_policy,
		{ "Fan Enable State", "ipmi.vita.fan.policy",
			FT_UINT8, BASE_DEC, VALS(str_vita_fan_policies), 0, NULL, HFILL }},
	{ &hf_vita_fan_policy_timeout,
		{ "Fan Policy Timeout", "ipmi.vita.fan.policy.timeout",
			FT_UINT8, BASE_DEC, VALS(str_vita_fan_policy_timeouts), 0, NULL, HFILL }},
	{ &hf_vita_fan_coverage,
		{ "Coverage", "ipmi.vita.fan.coverage",
			FT_UINT8, BASE_DEC, VALS(str_vita_fan_coverages), 0, NULL, HFILL }},
	{ &hf_vita_fru_control_caps,
		{ "FRU Control Capabilities Mask", "ipmi.vita.fru.control.caps",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fru_control_cap_cold,
		{ "Capable of issuing a cold reset", "ipmi.vita.fru.control.cap.cold",
			FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	{ &hf_vita_fru_control_cap_warm,
		{ "Capable of issuing a warm reset", "ipmi.vita.fru.control.cap.warm",
			FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	{ &hf_vita_fru_control_cap_grace,
		{ "Capable of issuing a graceful reboot", "ipmi.vita.fru.control.cap.grace",
			FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
	{ &hf_vita_fru_control_cap_diag,
		{ "Capable of issuing a diagnostic interrupt", "ipmi.vita.fru.control.cap.diag",
			FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
	{ &hf_vita_fru_control_cap_pwr,
		{ "Capable of controlling payload power", "ipmi.vita.fru.control.cap.pwr",
			FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
	{ &hf_vita_fru_lock_operation,
		{ "FRU Inventory Device Lock Operation", "ipmi.vita.fru.lock.op",
			FT_UINT8, BASE_DEC, VALS(str_vita_fru_lock_operations), 0, NULL, HFILL }},
	{ &hf_vita_fru_lock_id,
		{ "FRU Inventory Device Lock ID", "ipmi.vita.fru.lock.id",
			FT_UINT16, BASE_HEX_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fru_lock_timestamp,
		{ "FRU Inventory Device Last Commit Timestamp", "ipmi.vita.fru.lock.stamp",
			FT_UINT32, BASE_HEX_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fru_write_offset,
		{ "FRU Inventory offset to write", "ipmi.vita.fru.write.offset",
			FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fru_write_data,
		{ "Data to write", "ipmi.vita.fru.write.data",
			FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fru_write_count,
		{ "Written byte count", "ipmi.vita.fru.write.count",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_chassis_addr_number,
		{ "Address Number", "ipmi.vita.chassis.addr.num",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_chassis_addr_timestamp,
		{ "Chassis IP Address Last Change Timestamp", "ipmi.vita.chassis.stamp",
			FT_UINT32, BASE_HEX_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_vita_chassis_addr_count,
		{ "Address Count", "ipmi.vita.chassis.addr.count",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_chassis_max_unavail,
		{ "Maximum Unavailable Time", "ipmi.vita.chassis.max.unavail",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_chassis_addr_type,
		{ "Address Type", "ipmi.vita.chassis.addr.type",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_chassis_addr,
		{ "Address", "ipmi.vita.chassis.addr",
			FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_vita_chassis_addr_chmc,
		{ "Chassis Manager IP Address", "ipmi.vita.chassis.addr.chmc",
			FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
	{ &hf_vita_chassis_addr_format,
		{ "Address Type", "ipmi.vita.chassis.addr.format",
			FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(str_vita_chassis_addr_formats), 0x7F, NULL, HFILL }},
	{ &hf_vita_ipv4_addr,
		{ "IPv4 Address", "ipmi.vita.ipv4.addr",
			FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_vita_rmcp_port,
		{ "RMCP Port", "ipmi.vita.rmcp.port",
			FT_UINT16, BASE_HEX_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_vita_persistent_control_state,
		{ "FRU Persistent Control Current State", "ipmi.vita.pers.state",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_persistent_control_cold,
		{ "Persistent Cold Reset State", "ipmi.vita.pers.state.cold",
			FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	{ &hf_vita_persistent_control_warm,
		{ "Persistent Warm Reset State", "ipmi.vita.pers.state.warm",
			FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	{ &hf_vita_persistent_control_mask,
		{ "FRU Persistent Control Selection Mask", "ipmi.vita.pers.mask",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_persistent_control_set,
		{ "FRU Persistent Control Selection", "ipmi.vita.pers.set",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_persistent_control_caps,
		{ "FRU Persistent Control Capabilities Mask", "ipmi.vita.pers.caps",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_persistent_control_cap_cold,
		{ "Capable of asserting a persistent cold reset", "ipmi.vita.pers.cap.cold",
			FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
	{ &hf_vita_persistent_control_cap_warm,
		{ "Capable of asserting a persistent warm reset", "ipmi.vita.pers.cap.warm",
			FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
	{ &hf_vita_fru_state_sensor_num,
		{ "FRU State Sensor Number", "ipmi.vita.sensor.fru.state",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fru_health_sensor_num,
		{ "FRU Health Sensor Number", "ipmi.vita.sensor.fru.health",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fru_voltage_sensor_num,
		{ "FRU Voltage Sensor Number", "ipmi.vita.sensor.fru.voltage",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_fru_temp_sensor_num,
		{ "FRU Temperature Sensor Number", "ipmi.vita.sensor.fru.temp",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_payload_test_results_sensor_num,
		{ "Payload Test Results Sensor Number", "ipmi.vita.sensor.payload.test.res",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_vita_payload_test_status_sensor_num,
		{ "Payload Test Status Sensor Number", "ipmi.vita.sensor.payload.test.status",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }}
};

/* Get VSO Capabilities (response).
 */
static void
cmd00_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	static const gint * bits_vita_ipmc[] = {
		&hf_vita_tier, &hf_vita_layer, NULL
	};
	static const gint * bits_vita_ipmb[] = {
		&hf_vita_ipmb_itfs, &hf_vita_ipmb_freq, NULL
	};
	static const gint * bits_vita_vso[] = {
		&hf_vita_vso_std, NULL
	};

	proto_tree_add_bitmask(tree, tvb, 0, hf_vita_ipmc,
			ett_vita_ipmc, bits_vita_ipmc, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, 1, hf_vita_ipmb,
			ett_vita_ipmb, bits_vita_ipmb, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, 2, hf_vita_vso,
			ett_vita_vso, bits_vita_vso, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_rev, tvb, 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_max_fruid, tvb, 4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_ipmc_fruid, tvb, 5, 1, ENC_LITTLE_ENDIAN);
}

/* Get Chassis Address Table Info (request).
*/
static void
cmd01_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint len = tvb_captured_length(tvb);

	if (len > 0) {
		proto_tree_add_item(tree, hf_vita_fruid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	}
	if (len > 1) {
		proto_tree_add_item(tree, hf_vita_addr_key_type, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	}
	if (len > 2) {
		proto_tree_add_item(tree, hf_vita_addr_key, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	}
	if (len > 3) {
		proto_tree_add_item(tree, hf_vita_site_type, tvb, 3, 1, ENC_LITTLE_ENDIAN);
	}
}

/* Get Chassis Address Table Info (response).
 */
static void
cmd01_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_hw_addr, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_ipmb_addr, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_reserved, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fruid, tvb, 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_site_num, tvb, 4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_site_type, tvb, 5, 1, ENC_LITTLE_ENDIAN);
	if (tvb_captured_length(tvb) > 7) {
		proto_tree_add_item(tree, hf_vita_reserved, tvb, 6, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_vita_ipmbl_addr, tvb, 7, 1, ENC_LITTLE_ENDIAN);
	}
}

/* Get Chassis Identifier (response), Set Chassis Identifier (request)
*/
static void
cmd02_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	ipmi_add_typelen(tree, hf_vita_chassis_identifier, hf_vita_chassis_identifier_type, hf_vita_chassis_identifier_length, tvb, 0, TRUE);
}

/* FRU Control (request)
*/
static void
cmd04_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fruid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fru_control, tvb, 1, 1, ENC_LITTLE_ENDIAN);
}

/* Get FRU LED Properties (request)
*/
static void
cmd05_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fruid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

/* Get FRU LED Properties (response)
*/
static void
cmd05_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_reserved, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_led_count, tvb, 1, 1, ENC_LITTLE_ENDIAN);
}

/* Get LED Color Capabilities (request)
*/
static void
cmd06_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fruid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_led_id, tvb, 1, 1, ENC_LITTLE_ENDIAN);
}

/* Get LED Color Capabilities (response)
*/
static void
cmd06_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	static const gint * bits_vita_led_caps[] = {
		&hf_vita_led_cap_white, &hf_vita_led_cap_orange,
		&hf_vita_led_cap_amber, &hf_vita_led_cap_green,
		&hf_vita_led_cap_red, &hf_vita_led_cap_blue,
		NULL
	};
	static const int * bits_vita_led_flags[] = {
		&hf_vita_led_flag_pwr,
		&hf_vita_led_flag_hw_restrict,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, 0, hf_vita_led_caps,
			ett_vita_led_caps, bits_vita_led_caps, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, 1, hf_vita_led_def_loc_color,
			ett_vita_led_color, bits_vita_led_color, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, 2, hf_vita_led_def_ovr_color,
			ett_vita_led_color, bits_vita_led_color, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, 3, hf_vita_led_flags,
			ett_vita_led_flags, bits_vita_led_flags, ENC_LITTLE_ENDIAN);
}

/* Set FRU LED State (request)
*/
static void
cmd07_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fruid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_led_id, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_led_ovr_func, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_led_ovr_duration, tvb, 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, 4, hf_vita_led_ovr_color,
			ett_vita_led_color, bits_vita_led_color, ENC_LITTLE_ENDIAN);
}

/* Get FRU LED State (response)
*/
static void
cmd08_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	static const int * bits_vita_led_states[] = {
		&hf_vita_led_state_local,
		&hf_vita_led_state_override,
		&hf_vita_led_state_lamp_test,
		&hf_vita_led_state_hw_restrict,
		NULL
	};
	proto_tree_add_bitmask(tree, tvb, 0, hf_vita_led_states,
			ett_vita_led_states, bits_vita_led_states, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_led_loc_func, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_led_loc_duration, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, 3, hf_vita_led_loc_color,
			ett_vita_led_color, bits_vita_led_color, ENC_LITTLE_ENDIAN);
	if (tvb_captured_length(tvb) > 4) {
		proto_tree_add_item(tree, hf_vita_led_ovr_func, tvb, 4, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_vita_led_ovr_duration, tvb, 5, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_bitmask(tree, tvb, 6, hf_vita_led_ovr_color,
			ett_vita_led_color, bits_vita_led_color, ENC_LITTLE_ENDIAN);
	}
	if (tvb_captured_length(tvb) > 7) {
		proto_tree_add_item(tree, hf_vita_led_lamp_test_duration, tvb, 7, 1, ENC_LITTLE_ENDIAN);
	}
}

/* Set IPMB State (request)
*/
static void
cmd09_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	static const int * bits_vita_ipmb_state[] = {
		&hf_vita_ipmb_state,
		&hf_vita_ipmb_link_id,
		NULL
	};
	proto_tree_add_bitmask(tree, tvb, 0, hf_vita_ipmba_state,
			ett_vita_ipmb_state, bits_vita_ipmb_state, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, 1, hf_vita_ipmbb_state,
			ett_vita_ipmb_state, bits_vita_ipmb_state, ENC_LITTLE_ENDIAN);
}

/* Set FRU State Policy Bits (request)
*/
static void
cmd0A_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fruid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, 1, hf_vita_fru_policy_mask_bits,
			ett_vita_fru_policy_bits, bits_vita_fru_policy_bits,
			ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, 2, hf_vita_fru_policy_set_bits,
			ett_vita_fru_policy_bits, bits_vita_fru_policy_bits,
			ENC_LITTLE_ENDIAN);
}

/* Get FRU State Policy Bits (response)
*/
static void
cmd0B_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_bitmask(tree, tvb, 0, hf_vita_fru_policy_bits,
			ett_vita_fru_policy_bits, bits_vita_fru_policy_bits,
			ENC_LITTLE_ENDIAN);
}

/* Set FRU Activation (request)
*/
static void
cmd0C_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fruid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fru_activation, tvb, 1, 1, ENC_LITTLE_ENDIAN);
}

/* Get FRU Device Locator Record ID (response)
*/
static void
cmd0D_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_record_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

/* Get FAN Speed Properties (response)
*/
static void
cmd14_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	static const int * bits_vita_fan_properties[] = {
		&hf_vita_fan_prop_local_control,
		NULL
	};
	proto_tree_add_item(tree, hf_vita_fan_min_level, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fan_max_level, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fan_norm_level, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, 3, hf_vita_fan_properties,
			ett_vita_fan_properties, bits_vita_fan_properties, ENC_LITTLE_ENDIAN);
}

/* Set FAN Level (request)
*/
static void
cmd15_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fruid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fan_override_level, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	if (tvb_captured_length(tvb) > 2) {
		proto_tree_add_item(tree, hf_vita_fan_local_control, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	}
}

/* Get FAN Level (response)
*/
static void
cmd16_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fan_override_level, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	if (tvb_captured_length(tvb) > 1) {
		proto_tree_add_item(tree, hf_vita_fan_local_level, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	}
	if (tvb_captured_length(tvb) > 2) {
		proto_tree_add_item(tree, hf_vita_fan_local_control, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	}
}

/* Get IPMB Link Info (request)
*/
static void
cmd18_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_ipmb_link_key_type, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_ipmb_link_key_value, tvb, 1, 1, ENC_LITTLE_ENDIAN);
}

/* Get IPMB Link Info (response)
*/
static void
cmd18_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_ipmb_link_number, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_ipmb_sensor_number, tvb, 1, 1, ENC_LITTLE_ENDIAN);
}

/* Get Chassis Manager IPMB Address (response)
*/
static void
cmd1B_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_active_chmc_ipmb_addr, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_backup_chmc_ipmb_addr, tvb, 1, 1, ENC_LITTLE_ENDIAN);
}

/* Set FAN Policy (request)
*/
static void
cmd1C_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fan_number, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fan_policy, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	if (tvb_captured_length(tvb) > 2) {
		proto_tree_add_item(tree, hf_vita_fan_policy_timeout, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	}
	if (tvb_captured_length(tvb) > 3) {
		proto_tree_add_item(tree, hf_vita_site_num, tvb, 3, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_vita_site_type, tvb, 4, 1, ENC_LITTLE_ENDIAN);
	}
}

/* Get FAN Policy (request)
*/
static void
cmd1D_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fan_number, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	if (tvb_captured_length(tvb) > 1) {
		proto_tree_add_item(tree, hf_vita_site_num, tvb, 1, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_vita_site_type, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	}
}

/* Get FAN Policy (response)
*/
static void
cmd1D_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fan_policy, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	if (tvb_captured_length(tvb) > 1) {
		proto_tree_add_item(tree, hf_vita_fan_coverage, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	}
}

/* FRU Control Capabilities (response)
*/
static void
cmd1E_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	static const int * bits_vita_fru_control_caps[] = {
		&hf_vita_fru_control_cap_cold,
		&hf_vita_fru_control_cap_warm,
		&hf_vita_fru_control_cap_grace,
		&hf_vita_fru_control_cap_diag,
		&hf_vita_fru_control_cap_pwr,
		NULL
	};
	proto_tree_add_bitmask(tree, tvb, 0, hf_vita_fru_control_caps,
			ett_vita_fru_control_caps, bits_vita_fru_control_caps, ENC_LITTLE_ENDIAN);
}

/* FRU Inventory Device Lock Control (request)
*/
static void
cmd1F_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fruid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fru_lock_operation, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fru_lock_id, tvb, 2, 2, ENC_LITTLE_ENDIAN);
}

/* FRU Inventory Device Lock Control (response)
*/
static void
cmd1F_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fru_lock_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fru_lock_timestamp, tvb, 2, 4, ENC_LITTLE_ENDIAN);
}

/* FRU Inventory Device Write (request)
*/
static void
cmd20_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fruid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fru_lock_id, tvb, 1, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fru_write_offset, tvb, 3, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fru_write_data, tvb, 5,
			tvb_captured_length(tvb) - 5, ENC_NA);
}

/* FRU Inventory Device Write (response)
*/
static void
cmd20_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fru_write_count, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

/* Get Chassis Manager IP Address (request)
*/
static void
cmd21_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_chassis_addr_number, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

/* Get Chassis Manager IP Address (response)
*/
static void
cmd21_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item * item;
	static const int * bits_vita_chassis_addr_type[] = {
		&hf_vita_chassis_addr_chmc,
		&hf_vita_chassis_addr_format,
		NULL
	};
	proto_tree_add_item(tree, hf_vita_chassis_addr_timestamp, tvb, 0, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_chassis_addr_count, tvb, 4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_site_type, tvb, 5, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_site_num, tvb, 6, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_chassis_max_unavail, tvb, 7, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, 8, hf_vita_chassis_addr_type,
			ett_vita_chassis_addr_type, bits_vita_chassis_addr_type,
			ENC_LITTLE_ENDIAN);
	item = proto_tree_add_item(tree, hf_vita_chassis_addr, tvb, 8, -1, ENC_NA);

	if (!(tvb_get_guint8(tvb, 8) & 0x7f)) {
		proto_tree * sub = proto_item_add_subtree(item, ett_vita_chassis_addr);
		proto_tree_add_item(sub, hf_vita_ipv4_addr, tvb, 9, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(sub, hf_vita_rmcp_port, tvb, 13, 2, ENC_BIG_ENDIAN);
	}
}

/* Get FRU Persistent Control (response)
*/
static void
cmd41_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_bitmask(tree, tvb, 0, hf_vita_persistent_control_state,
			ett_vita_persistent_control_state,
			bits_vita_persistent_control_state,
			ENC_LITTLE_ENDIAN);
}

/* Set FRU Persistent Control (request)
*/
static void
cmd42_rq(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fruid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, 1, hf_vita_persistent_control_mask,
			ett_vita_persistent_control_state,
			bits_vita_persistent_control_state,
			ENC_LITTLE_ENDIAN);
	proto_tree_add_bitmask(tree, tvb, 2, hf_vita_persistent_control_set,
			ett_vita_persistent_control_state,
			bits_vita_persistent_control_state,
			ENC_LITTLE_ENDIAN);
}

/* FRU Persistent Control capabilities (response)
*/
static void
cmd43_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	static const int * bits_vita_persistent_control_caps[] = {
		&hf_vita_persistent_control_cap_cold,
		&hf_vita_persistent_control_cap_warm,
		NULL
	};
	proto_tree_add_bitmask(tree, tvb, 0, hf_vita_persistent_control_caps,
			ett_vita_persistent_control_caps,
			bits_vita_persistent_control_caps,
			ENC_LITTLE_ENDIAN);
}

/* Get Mandatory Sensor Numbers (response)
*/
static void
cmd44_rs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_vita_fru_state_sensor_num, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fru_health_sensor_num, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fru_voltage_sensor_num, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_fru_temp_sensor_num, tvb, 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_payload_test_results_sensor_num, tvb, 4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_vita_payload_test_status_sensor_num, tvb, 5, 1, ENC_LITTLE_ENDIAN);
}

/* Array of VITA 46.11 command descriptors.
*/
static ipmi_cmd_t cmd_vita[] = {
	{ 0x00, NULL,		cmd00_rs,	NULL, NULL, "[VITA] Get VSO Capabilities", 0 },
	{ 0x01, cmd01_rq,	cmd01_rs,	NULL, NULL, "[VITA] Get Chassis Address Table Info", 0 },
	{ 0x02, NULL,		cmd02_rs,	NULL, NULL, "[VITA] Get Chassis Identifier", 0 },
	{ 0x03, cmd02_rs,	NULL,		NULL, NULL, "[VITA] Set Chassis Identifier", 0 },
	{ 0x04, cmd04_rq,	NULL,		NULL, NULL, "[VITA] FRU Control", 0 },
	{ 0x05, cmd05_rq,	cmd05_rs,	NULL, NULL, "[VITA] Get FRU LED Properties", 0 },
	{ 0x06, cmd06_rq,	cmd06_rs,	NULL, NULL, "[VITA] Get LED Color Capabilities", 0 },
	{ 0x07, cmd07_rq,	NULL,		NULL, NULL, "[VITA] Set FRU LED State", 0 },
	{ 0x08, cmd06_rq,	cmd08_rs,	NULL, NULL, "[VITA] Get FRU LED State", 0 },
	{ 0x09, cmd09_rq,	NULL,		NULL, NULL, "[VITA] Set IPMB State", 0 },
	{ 0x0A, cmd0A_rq,	NULL,		NULL, NULL, "[VITA] Set FRU State Policy Bits", 0 },
	{ 0x0B, cmd05_rq,	cmd0B_rs,	NULL, NULL, "[VITA] Get FRU State Policy Bits", 0 },
	{ 0x0C, cmd0C_rq,	NULL,		NULL, NULL, "[VITA] Set FRU Activation", 0 },
	{ 0x0D, cmd05_rq,	cmd0D_rs,	NULL, NULL, "[VITA] Get Device Locator Record ID", 0 },
	{ 0x14, cmd05_rq,	cmd14_rs,	NULL, NULL, "[VITA] Get Fan Speed Properties", 0 },
	{ 0x15, cmd15_rq,	NULL,		NULL, NULL, "[VITA] Set Fan Level", 0 },
	{ 0x16, cmd05_rq,	cmd16_rs,	NULL, NULL, "[VITA] Get Fan Level", 0 },
	{ 0x18, cmd18_rq,	cmd18_rs,	NULL, NULL, "[VITA] Get IPMB Link Info", 0 },
	{ 0x1B, NULL,		cmd1B_rs,	NULL, NULL, "[VITA] Get Chassis Manager IPMB Address", 0 },
	{ 0x1C, cmd1C_rq,	NULL,		NULL, NULL, "[VITA] Set Fan Policy", 0 },
	{ 0x1D, cmd1D_rq,	cmd1D_rs,	NULL, NULL, "[VITA] Get Fan Policy", 0 },
	{ 0x1E, cmd05_rq,	cmd1E_rs,	NULL, NULL, "[VITA] FRU Control Capabilities", 0 },
	{ 0x1F, cmd1F_rq,	cmd1F_rs,	cc1F, NULL, "[VITA] FRU Inventory Device Lock Control", 0 },
	{ 0x20, cmd20_rq,	cmd20_rs,	cc20, NULL, "[VITA] FRU Inventory Device Write", 0 },
	{ 0x21, cmd21_rq,	cmd21_rs,	NULL, NULL, "[VITA] Get Chassis Manager IP Address", 0 },
	{ 0x40, cmd01_rq,	cmd01_rs,	NULL, NULL, "[VITA] Get FRU Address Info", 0 },
	{ 0x41, cmd05_rq,	cmd41_rs,	NULL, NULL, "[VITA] Get FRU Persistent Control", 0 },
	{ 0x42, cmd42_rq,	NULL,		NULL, NULL, "[VITA] Set FRU Persistent Control", 0 },
	{ 0x43, cmd05_rq,	cmd43_rs,	NULL, NULL, "[VITA] FRU Persistent Control Capabilities", 0 },
	{ 0x44, cmd05_rq,	cmd44_rs,	NULL, NULL, "[VITA] Get Mandatory Sensor Numbers", 0 }
};

/* VITA 46.11 command set registrator
*/
void
proto_register_ipmi_vita(void)
{
	static const guint8 sig_vita[1] = { 3 };

	proto_register_field_array(proto_ipmi, hf_ipmi_vita,
			array_length(hf_ipmi_vita));
	proto_register_subtree_array(ett_ipmi_vita,
			array_length(ett_ipmi_vita));
	ipmi_register_netfn_cmdtab(IPMI_GROUP_REQ, IPMI_OEM_NONE,
			sig_vita, 1, "VITA", cmd_vita, array_length(cmd_vita));
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
