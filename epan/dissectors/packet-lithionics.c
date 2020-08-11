/* packet-lithionics.c
 * Routines for Lithionics NeverDie Battery Management System (BMS)
 * By Michael Mann <Michael.Mann@jbtc.com>
 * Copyright 2018 Michael Mann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * From https://lithionicsbattery.com/wp-content/uploads/2018/06/NeverDie-BMS-Advanced-RS232-UART-serial-protocol-Rev7.15.pdf
 */

#include "config.h"

#include <epan/packet.h>
#include <wsutil/strtoi.h>

void proto_register_lithionics(void);
void proto_reg_handoff_lithionics(void);

static int proto_lithionics = -1;

static int hf_lithionics_battery_address = -1;
static int hf_lithionics_amp_hours_remain = -1;
static int hf_lithionics_volts = -1;
static int hf_lithionics_bat_gauge = -1;
static int hf_lithionics_soc = -1;
static int hf_lithionics_direction = -1;
static int hf_lithionics_amps = -1;
static int hf_lithionics_watts = -1;
static int hf_lithionics_temperature = -1;
static int hf_lithionics_system_status = -1;
static int hf_lithionics_system_status_high_voltage_state = -1;
static int hf_lithionics_system_status_charge_source_detected = -1;
static int hf_lithionics_system_status_neverdie_reserve_state = -1;
static int hf_lithionics_system_status_optoloop_cell_open = -1;
static int hf_lithionics_system_status_reserve_voltage_range = -1;
static int hf_lithionics_system_status_low_voltage_state = -1;
static int hf_lithionics_system_status_battery_protection_state = -1;
static int hf_lithionics_system_status_power_off_state = -1;
static int hf_lithionics_system_status_aux_contacts_state = -1;
static int hf_lithionics_system_status_aux_contacts_error = -1;
static int hf_lithionics_system_status_precharge_error = -1;
static int hf_lithionics_system_status_contactor_flutter = -1;
static int hf_lithionics_system_status_ac_power_present = -1;
static int hf_lithionics_system_status_tsm_charger_present = -1;
static int hf_lithionics_system_status_tsm_charger_error = -1;
static int hf_lithionics_system_status_external_temp_sensor_error = -1;
static int hf_lithionics_system_status_agsr_state = -1;
static int hf_lithionics_system_status_high_temperature_state = -1;
static int hf_lithionics_system_status_low_temperature_state = -1;
static int hf_lithionics_system_status_aux_input1_state = -1;
static int hf_lithionics_system_status_charge_disable_state = -1;
static int hf_lithionics_system_status_overcurrent_state = -1;
static int hf_lithionics_system_status_reserved = -1;
static int hf_lithionics_temination = -1;

static gint ett_lithionics = -1;
static gint ett_lithionics_system_status = -1;

static int* const system_status_flags[] = {
	&hf_lithionics_system_status_high_voltage_state,
	&hf_lithionics_system_status_charge_source_detected,
	&hf_lithionics_system_status_neverdie_reserve_state,
	&hf_lithionics_system_status_optoloop_cell_open,
	&hf_lithionics_system_status_reserve_voltage_range,
	&hf_lithionics_system_status_low_voltage_state,
	&hf_lithionics_system_status_battery_protection_state,
	&hf_lithionics_system_status_power_off_state,
	&hf_lithionics_system_status_aux_contacts_state,
	&hf_lithionics_system_status_aux_contacts_error,
	&hf_lithionics_system_status_precharge_error,
	&hf_lithionics_system_status_contactor_flutter,
	&hf_lithionics_system_status_ac_power_present,
	&hf_lithionics_system_status_tsm_charger_present,
	&hf_lithionics_system_status_tsm_charger_error,
	&hf_lithionics_system_status_external_temp_sensor_error,
	&hf_lithionics_system_status_agsr_state,
	&hf_lithionics_system_status_high_temperature_state,
	&hf_lithionics_system_status_low_temperature_state,
	&hf_lithionics_system_status_aux_input1_state,
	&hf_lithionics_system_status_charge_disable_state,
	&hf_lithionics_system_status_overcurrent_state,
	&hf_lithionics_system_status_reserved,
	NULL
};

static const value_string lithionics_direction_vals[] = {
	{ 0,   "Discharging" },
	{ 1,   "Charging" },
	{ 0, NULL }
};

static const true_false_string tfs_lithionics_high_voltage_state = { "Above HVC", "Below HVC" };
static const true_false_string tfs_lithionics_reserve_voltage_range = { "Below RVC", "Above RVC" };
static const true_false_string tfs_lithionics_low_voltage_state = { "Below LVC", "Above LVC" };
static const true_false_string tfs_lithionics_battery_protection_state = { "Recovering from abnormal event", "Normal" };
static const true_false_string tfs_lithionics_power_off_state = { "Command", "Button" };
static const true_false_string tfs_lithionics_high_temperature_state = { "Exceeds allowed threshold", "Normal" };
static const true_false_string tfs_lithionics_low_temperature_state = { "Below allowed threshold", "Normal" };

static int
dissect_lithionics(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree      *lithionics_tree, *status_tree;
	proto_item      *ti;
	int				offset = 0;
	char*			str;
	float			f;
	guint32			value;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Lithionics");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_lithionics, tvb, 0, -1, ENC_NA);
	lithionics_tree = proto_item_add_subtree(ti, ett_lithionics);

	//just put the whole packet string (minus newlines) in the Info column
	col_set_str(pinfo->cinfo, COL_INFO, (const gchar*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, tvb_reported_length_remaining(tvb, offset)-2, ENC_ASCII));

	str = (char*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, 1, ENC_ASCII);
	if (!ws_strtou32(str, NULL, &value))
		proto_tree_add_uint_format_value(lithionics_tree, hf_lithionics_battery_address, tvb, offset, 2, 0, "<Invalid value \"%s\">", str);
	else
		proto_tree_add_uint(lithionics_tree, hf_lithionics_battery_address, tvb, offset, 2, value);
	offset += 2;

	str = (char*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, 5, ENC_ASCII);
	if (!ws_strtou32(str, NULL, &value))
		proto_tree_add_float_format_value(lithionics_tree, hf_lithionics_amp_hours_remain, tvb, offset, 6, 0.0, "<Invalid value \"%s\">", str);
	else {
		f = (float)(value*.1);
		proto_tree_add_float_format_value(lithionics_tree, hf_lithionics_amp_hours_remain, tvb, offset, 6, f, "%0.1fAh", f);
	}
	offset += 6;

	str = (char*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, 4, ENC_ASCII);
	if (!ws_strtou32(str, NULL, &value))
		proto_tree_add_float_format_value(lithionics_tree, hf_lithionics_volts, tvb, offset, 5, 0.0, "<Invalid value \"%s\">", str);
	else {
		f = (float)(value*.1);
		proto_tree_add_float_format_value(lithionics_tree, hf_lithionics_volts, tvb, offset, 5, f, "%0.1fV", f);
	}
	offset += 5;

	str = (char*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, 3, ENC_ASCII);
	if (!ws_strtou32(str, NULL, &value))
		proto_tree_add_uint_format_value(lithionics_tree, hf_lithionics_bat_gauge, tvb, offset, 4, 0, "<Invalid value \"%s\">", str);
	else
		proto_tree_add_uint(lithionics_tree, hf_lithionics_bat_gauge, tvb, offset, 4, value);
	offset += 4;

	str = (char*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, 3, ENC_ASCII);
	if (!ws_strtou32(str, NULL, &value))
		proto_tree_add_uint_format_value(lithionics_tree, hf_lithionics_soc, tvb, offset, 4, 0, "<Invalid value \"%s\">", str);
	else
		proto_tree_add_uint(lithionics_tree, hf_lithionics_soc, tvb, offset, 4, value);
	offset += 4;

	str = (char*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, 1, ENC_ASCII);
	if (!ws_strtou32(str, NULL, &value))
		proto_tree_add_uint_format_value(lithionics_tree, hf_lithionics_direction, tvb, offset, 2, 0, "<Invalid value \"%s\">", str);
	else
		proto_tree_add_uint(lithionics_tree, hf_lithionics_direction, tvb, offset, 2, value);
	offset += 2;

	str = (char*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, 5, ENC_ASCII);
	if (!ws_strtou32(str, NULL, &value))
		proto_tree_add_float_format_value(lithionics_tree, hf_lithionics_amps, tvb, offset, 6, 0.0, "<Invalid value \"%s\">", str);
	else {
		f = (float)(value*.1);
		proto_tree_add_float_format_value(lithionics_tree, hf_lithionics_amps, tvb, offset, 6, f, "%0.1fAmp", f);
	}
	offset += 6;

	str = (char*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, 6, ENC_ASCII);
	if (!ws_strtou32(str, NULL, &value))
		proto_tree_add_uint_format_value(lithionics_tree, hf_lithionics_watts, tvb, offset, 7, 0, "<Invalid value \"%s\">", str);
	else
		proto_tree_add_uint(lithionics_tree, hf_lithionics_watts, tvb, offset, 7, value);
	offset += 7;

	str = (char*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, 3, ENC_ASCII);
	if (!ws_strtou32(str, NULL, &value))
		proto_tree_add_uint_format_value(lithionics_tree, hf_lithionics_temperature, tvb, offset, 4, 0, "<Invalid value \"%s\">", str);
	else
		proto_tree_add_uint(lithionics_tree, hf_lithionics_temperature, tvb, offset, 4, value);
	offset += 4;

	str = (char*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, 6, ENC_ASCII);
	//do this over proto_tree_add_bitmask_value to get better field highlighting
	if (!ws_hexstrtou32(str, NULL, &value))
		proto_tree_add_uint_format_value(lithionics_tree, hf_lithionics_system_status, tvb, offset, 7, 0, "<Invalid value \"%s\">", str);
	else {
		ti = proto_tree_add_uint(lithionics_tree, hf_lithionics_system_status, tvb, offset, 7, value);
		status_tree = proto_item_add_subtree(ti, ett_lithionics_system_status);
		proto_tree_add_bitmask_list_value(status_tree, tvb, offset, 7, system_status_flags, value);
	}
	offset += 7;

	proto_tree_add_item(lithionics_tree, hf_lithionics_temination, tvb, offset, 2, ENC_NA);
	offset += 2;

	return tvb_captured_length(tvb);
}

void
proto_register_lithionics(void)
{

	static hf_register_info hf[] = {
		{ &hf_lithionics_battery_address,
			{ "Battery address", "lithionics_bms.battery_address", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_lithionics_amp_hours_remain,
			{ "Amp Hours Remaining", "lithionics_bms.amp_hours_remain", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_lithionics_volts,
			{ "Volts", "lithionics_bms.volts", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_lithionics_bat_gauge,
			{ "Bat gauge", "lithionics_bms.bat_gauge", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_percent, 0x0, NULL, HFILL } },
		{ &hf_lithionics_soc,
			{ "SoC", "lithionics_bms.soc", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_percent, 0x0, NULL, HFILL } },
		{ &hf_lithionics_direction,
			{ "Direction", "lithionics_bms.direction", FT_UINT8, BASE_DEC, VALS(lithionics_direction_vals), 0x0, NULL, HFILL } },
		{ &hf_lithionics_amps,
			{ "Amps", "lithionics_bms.amps", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_lithionics_watts,
			{ "Watts", "lithionics_bms.watts", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_watt, 0x0, NULL, HFILL } },
		{ &hf_lithionics_temperature,
			{ "Temperature", "lithionics_bms.temperature", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_degree_degrees, 0x0, NULL, HFILL } },
		{ &hf_lithionics_temination,
			{ "Newline Termination", "lithionics_bms.termination", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_lithionics_system_status,
			{ "System Status", "lithionics_bms.system_status", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_lithionics_system_status_high_voltage_state,
			{ "High Voltage State", "lithionics_bms.system_status.high_voltage_state", FT_BOOLEAN, 24, TFS(&tfs_lithionics_high_voltage_state), 0x000001, NULL, HFILL } },
		{ &hf_lithionics_system_status_charge_source_detected,
			{ "Charge Source Detected", "lithionics_bms.system_status.charge_source_detected", FT_BOOLEAN, 24, NULL, 0x000002, NULL, HFILL } },
		{ &hf_lithionics_system_status_neverdie_reserve_state,
			{ "NeverDie Reserve State", "lithionics_bms.system_status.neverdie_reserve_state", FT_BOOLEAN, 24, NULL, 0x000004, NULL, HFILL } },
		{ &hf_lithionics_system_status_optoloop_cell_open,
			{ "OptoLoop Cell Loop is open", "lithionics_bms.system_status.optoloop_cell_open", FT_BOOLEAN, 24, NULL, 0x000008, NULL, HFILL } },
		{ &hf_lithionics_system_status_reserve_voltage_range,
			{ "Reserve Voltage Range", "lithionics_bms.system_status.reserve_voltage_range", FT_BOOLEAN, 24, TFS(&tfs_lithionics_reserve_voltage_range), 0x000010, NULL, HFILL } },
		{ &hf_lithionics_system_status_low_voltage_state,
			{ "Low Voltage State", "lithionics_bms.system_status.low_voltage_state", FT_BOOLEAN, 24, TFS(&tfs_lithionics_low_voltage_state), 0x000020, NULL, HFILL } },
		{ &hf_lithionics_system_status_battery_protection_state,
			{ "Battery Protection State", "lithionics_bms.system_status.battery_protection_state", FT_BOOLEAN, 24, TFS(&tfs_lithionics_battery_protection_state), 0x000040, NULL, HFILL } },
		{ &hf_lithionics_system_status_power_off_state,
			{ "Power Off State", "lithionics_bms.system_status.power_off_state", FT_BOOLEAN, 24, TFS(&tfs_lithionics_power_off_state), 0x000080, NULL, HFILL } },
		{ &hf_lithionics_system_status_aux_contacts_state,
			{ "AUX Contacts State", "lithionics_bms.system_status.aux_contacts_state", FT_BOOLEAN, 24, NULL, 0x000100, NULL, HFILL } },
		{ &hf_lithionics_system_status_aux_contacts_error,
			{ "AUX Contacts Error", "lithionics_bms.system_status.aux_contacts_error", FT_BOOLEAN, 24, NULL, 0x000200, NULL, HFILL } },
		{ &hf_lithionics_system_status_precharge_error,
			{ "Pre-charge Error", "lithionics_bms.system_status.precharge_error", FT_BOOLEAN, 24, NULL, 0x000400, NULL, HFILL } },
		{ &hf_lithionics_system_status_contactor_flutter,
			{ "Contactor Flutter", "lithionics_bms.system_status.contactor_flutter", FT_BOOLEAN, 24, NULL, 0x000800, NULL, HFILL } },
		{ &hf_lithionics_system_status_ac_power_present,
			{ "AC Power Present", "lithionics_bms.system_status.ac_power_present", FT_BOOLEAN, 24, NULL, 0x001000, NULL, HFILL } },
		{ &hf_lithionics_system_status_tsm_charger_present,
			{ "TSM Charger Present", "lithionics_bms.system_status.tsm_charger_present", FT_BOOLEAN, 24, NULL, 0x002000, NULL, HFILL } },
		{ &hf_lithionics_system_status_tsm_charger_error,
			{ "TSM Charger Error", "lithionics_bms.system_status.tsm_charger_error", FT_BOOLEAN, 24, NULL, 0x004000, NULL, HFILL } },
		{ &hf_lithionics_system_status_external_temp_sensor_error,
			{ "External Temp Sensor Error", "lithionics_bms.system_status.external_temp_sensor_error", FT_BOOLEAN, 24, NULL, 0x008000, NULL, HFILL } },
		{ &hf_lithionics_system_status_agsr_state,
			{ "AGSR State", "lithionics_bms.system_status.agsr_state", FT_BOOLEAN, 24, NULL, 0x010000, NULL, HFILL } },
		{ &hf_lithionics_system_status_high_temperature_state,
			{ "High Temperature State", "lithionics_bms.system_status.high_temperature_state", FT_BOOLEAN, 24, TFS(&tfs_lithionics_high_temperature_state), 0x020000, NULL, HFILL } },
		{ &hf_lithionics_system_status_low_temperature_state,
			{ "Low Temperature State", "lithionics_bms.system_status.low_temperature_state", FT_BOOLEAN, 24, TFS(&tfs_lithionics_low_temperature_state), 0x040000, NULL, HFILL } },
		{ &hf_lithionics_system_status_aux_input1_state,
			{ "Auxiliary Input 1 State", "lithionics_bms.system_status.aux_input1_state", FT_BOOLEAN, 24, NULL, 0x080000, NULL, HFILL } },
		{ &hf_lithionics_system_status_charge_disable_state,
			{ "Charge Disable State", "lithionics_bms.system_status.charge_disable_state", FT_BOOLEAN, 24, NULL, 0x100000, NULL, HFILL } },
		{ &hf_lithionics_system_status_overcurrent_state,
			{ "Overcurrent State", "lithionics_bms.system_status.overcurrent_state", FT_BOOLEAN, 24, NULL, 0x200000, NULL, HFILL } },
		{ &hf_lithionics_system_status_reserved,
			{ "Reserved", "lithionics_bms.system_status.reserved", FT_UINT24, BASE_HEX, NULL, 0xC00000, NULL, HFILL } },

	};

	static gint *ett[] = {
		&ett_lithionics,
		&ett_lithionics_system_status,
	};

	proto_lithionics = proto_register_protocol("Lithionics Battery Management System", "Lithionics BMS", "lithionics_bms");
	proto_register_field_array(proto_lithionics, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_lithionics(void)
{
	dissector_handle_t lithionics_handle;

	lithionics_handle = create_dissector_handle(dissect_lithionics, proto_lithionics);
	dissector_add_for_decode_as("udp.port", lithionics_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
