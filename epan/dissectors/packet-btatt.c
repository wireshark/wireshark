/* packet-btatt.c
 * Routines for Bluetooth Attribute Protocol dissection
 *
 * Copyright 2012, Allan M. Madsen <allan.m@madsen.dk>
 * Copyright 2015, Michal Labedzki for Tieto Corporation
 *  - dissect GATT level attributes
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

#include <glib.h>
#include <glib/gprintf.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/oui.h>
#include <epan/decode_as.h>
#include <epan/tap.h>
#include <epan/proto_data.h>

#include "packet-bluetooth.h"
#include "packet-btatt.h"
#include "packet-btl2cap.h"
#include "packet-btsdp.h"
#include "packet-http.h"
#include "packet-usb-hid.h"

#define HANDLE_TVB -1

/* Initialize the protocol and registered fields */
static int proto_btatt = -1;
static int proto_btgatt = -1;

static int hf_btatt_opcode = -1;
static int hf_btatt_handle = -1;
static int hf_btatt_starting_handle = -1;
static int hf_btatt_ending_handle = -1;
static int hf_btatt_group_end_handle = -1;
static int hf_btatt_value = -1;
static int hf_btatt_req_opcode_in_error = -1;
static int hf_btatt_handle_in_error = -1;
static int hf_btatt_error_code = -1;
static int hf_btatt_error_code_aios = -1;
static int hf_btatt_error_code_ans = -1;
static int hf_btatt_error_code_bms = -1;
static int hf_btatt_error_code_cgms = -1;
static int hf_btatt_error_code_cps = -1;
static int hf_btatt_error_code_cscs = -1;
static int hf_btatt_error_code_cts = -1;
static int hf_btatt_error_code_ess = -1;
static int hf_btatt_error_code_gls = -1;
static int hf_btatt_error_code_hps = -1;
static int hf_btatt_error_code_hrs = -1;
static int hf_btatt_error_code_hts = -1;
static int hf_btatt_error_code_ips = -1;
static int hf_btatt_error_code_ots = -1;
static int hf_btatt_error_code_rscs = -1;
static int hf_btatt_error_code_uds = -1;
static int hf_btatt_service_uuid16 = -1;
static int hf_btatt_service_uuid128 = -1;
static int hf_btatt_characteristic_uuid16 = -1;
static int hf_btatt_characteristic_uuid128 = -1;
static int hf_btatt_uuid16 = -1;
static int hf_btatt_uuid128 = -1;
static int hf_btatt_client_rx_mtu = -1;
static int hf_btatt_server_rx_mtu = -1;
static int hf_btatt_uuid_format = -1;
static int hf_btatt_length = -1;
static int hf_btatt_offset = -1;
static int hf_btatt_flags = -1;
static int hf_btatt_sign_counter = -1;
static int hf_btatt_signature = -1;
static int hf_btatt_attribute_data = -1;
static int hf_btatt_handles_info = -1;
static int hf_btatt_opcode_authentication_signature = -1;
static int hf_btatt_opcode_command = -1;
static int hf_btatt_opcode_method = -1;
static int hf_btatt_characteristic_properties = -1;
static int hf_btatt_characteristic_value_handle = -1;
static int hf_btatt_characteristic_properties_extended_properties = -1;
static int hf_btatt_characteristic_properties_authenticated_signed_writes = -1;
static int hf_btatt_characteristic_properties_indicate = -1;
static int hf_btatt_characteristic_properties_notify = -1;
static int hf_btatt_characteristic_properties_write = -1;
static int hf_btatt_characteristic_properties_write_without_response = -1;
static int hf_btatt_characteristic_properties_read = -1;
static int hf_btatt_characteristic_properties_broadcast = -1;
static int hf_btatt_information_data = -1;
static int hf_btatt_included_service_handle = -1;
static int hf_btatt_characteristic_configuration_client = -1;
static int hf_btatt_characteristic_configuration_client_reserved = -1;
static int hf_btatt_characteristic_configuration_client_indication = -1;
static int hf_btatt_characteristic_configuration_client_notification = -1;
static int hf_btatt_characteristic_configuration_server = -1;
static int hf_btatt_characteristic_configuration_server_reserved = -1;
static int hf_btatt_characteristic_configuration_server_broadcast = -1;
static int hf_btatt_hogp_protocol_mode = -1;
static int hf_btatt_hogp_bcd_hid = -1;
static int hf_btatt_hogp_b_country_code = -1;
static int hf_btatt_hogp_flags = -1;
static int hf_btatt_hogp_flags_reserved = -1;
static int hf_btatt_hogp_flags_normally_connectable = -1;
static int hf_btatt_hogp_flags_remote_wake = -1;
static int hf_btatt_hogp_hid_control_point_command = -1;
static int hf_btatt_report_reference_report_id = -1;
static int hf_btatt_report_reference_report_type = -1;
static int hf_btatt_characteristic_user_description = -1;
static int hf_btatt_characteristic_extended_properties = -1;
static int hf_btatt_characteristic_extended_properties_reserved = -1;
static int hf_btatt_characteristic_extended_properties_writable_auxiliaries = -1;
static int hf_btatt_characteristic_extended_properties_reliable_write = -1;
static int hf_btatt_characteristic_presentation_format = -1;
static int hf_btatt_characteristic_presentation_exponent = -1;
static int hf_btatt_characteristic_presentation_unit = -1;
static int hf_btatt_characteristic_presentation_namespace = -1;
static int hf_btatt_characteristic_presentation_namespace_description_btsig = -1;
static int hf_btatt_characteristic_presentation_namespace_description = -1;
static int hf_btatt_esp_trigger_logic = -1;
static int hf_btatt_esp_condition = -1;
static int hf_btatt_esp_operand = -1;
static int hf_btatt_esp_flags = -1;
static int hf_btatt_esp_sampling_function = -1;
static int hf_btatt_esp_measurement_period = -1;
static int hf_btatt_esp_update_interval = -1;
static int hf_btatt_esp_application = -1;
static int hf_btatt_esp_measurement_uncertainty = -1;
static int hf_btatt_device_name = -1;
static int hf_btatt_appearance = -1;
static int hf_btatt_appearance_category = -1;
static int hf_btatt_appearance_subcategory = -1;
static int hf_btatt_appearance_subcategory_watch = -1;
static int hf_btatt_appearance_subcategory_thermometer = -1;
static int hf_btatt_appearance_subcategory_heart_rate = -1;
static int hf_btatt_appearance_subcategory_blood_pressure = -1;
static int hf_btatt_appearance_subcategory_hid = -1;
static int hf_btatt_appearance_subcategory_running_walking_sensor = -1;
static int hf_btatt_appearance_subcategory_cycling = -1;
static int hf_btatt_appearance_subcategory_pulse_oximeter = -1;
static int hf_btatt_appearance_subcategory_outdoor_sports_activity = -1;
static int hf_btatt_peripheral_privacy_flag = -1;
static int hf_btatt_minimum_connection_interval = -1;
static int hf_btatt_maximum_connection_interval = -1;
static int hf_btatt_slave_latency = -1;
static int hf_btatt_connection_supervision_timeout_multiplier = -1;
static int hf_btatt_reconnection_address = -1;
static int hf_btatt_alert_level = -1;
static int hf_btatt_tx_power_level = -1;
static int hf_btatt_year = -1;
static int hf_btatt_month = -1;
static int hf_btatt_day = -1;
static int hf_btatt_hours = -1;
static int hf_btatt_minutes = -1;
static int hf_btatt_seconds = -1;
static int hf_btatt_day_of_week = -1;
static int hf_btatt_fractions256 = -1;
static int hf_btatt_dst_offset = -1;
static int hf_btatt_model_number_string = -1;
static int hf_btatt_serial_number_string = -1;
static int hf_btatt_firmware_revision_string = -1;
static int hf_btatt_hardware_revision_string = -1;
static int hf_btatt_software_revision_string = -1;
static int hf_btatt_manufacturer_string = -1;
static int hf_btatt_system_id_manufacturer_identifier = -1;
static int hf_btatt_system_id_organizationally_unique_identifier = -1;
static int hf_btatt_timezone = -1;
static int hf_btatt_time_accuracy = -1;
static int hf_btatt_time_source = -1;
static int hf_btatt_time_days_since_update = -1;
static int hf_btatt_time_hours_since_update = -1;
static int hf_btatt_time_update_control_point = -1;
static int hf_btatt_time_current_state = -1;
static int hf_btatt_time_result = -1;
static int hf_btatt_battery_level = -1;
static int hf_btatt_temperature_type = -1;
static int hf_btatt_measurement_interval = -1;
static int hf_btatt_time_adjust_reason = -1;
static int hf_btatt_time_adjust_reason_reserved = -1;
static int hf_btatt_time_adjust_reason_change_of_dst = -1;
static int hf_btatt_time_adjust_reason_change_of_timezone = -1;
static int hf_btatt_time_adjust_reason_external_reference_time_update = -1;
static int hf_btatt_time_adjust_reason_manual_time_update = -1;
static int hf_btatt_magnetic_declination = -1;
static int hf_btatt_scan_refresh = -1;
static int hf_btatt_body_sensor_location = -1;
static int hf_btatt_heart_rate_control_point = -1;
static int hf_btatt_alert_status = -1;
static int hf_btatt_alert_status_reserved = -1;
static int hf_btatt_alert_status_display_alert_status = -1;
static int hf_btatt_alert_status_vibrate_state = -1;
static int hf_btatt_alert_status_ringer_state = -1;
static int hf_btatt_ringer_control_point = -1;
static int hf_btatt_ringer_setting = -1;
static int hf_btatt_alert_category_id_bitmask_1 = -1;
static int hf_btatt_alert_category_id_bitmask_1_schedule = -1;
static int hf_btatt_alert_category_id_bitmask_1_voice_mail = -1;
static int hf_btatt_alert_category_id_bitmask_1_sms_mms = -1;
static int hf_btatt_alert_category_id_bitmask_1_missed_call = -1;
static int hf_btatt_alert_category_id_bitmask_1_call = -1;
static int hf_btatt_alert_category_id_bitmask_1_news = -1;
static int hf_btatt_alert_category_id_bitmask_1_email = -1;
static int hf_btatt_alert_category_id_bitmask_1_simple_alert = -1;
static int hf_btatt_alert_category_id_bitmask_2 = -1;
static int hf_btatt_alert_category_id_bitmask_2_reserved = -1;
static int hf_btatt_alert_category_id_bitmask_2_instant_message = -1;
static int hf_btatt_alert_category_id_bitmask_2_high_prioritized_alert = -1;
static int hf_btatt_alert_category_id = -1;
static int hf_btatt_alert_command_id = -1;
static int hf_btatt_alert_unread_count = -1;
static int hf_btatt_alert_number_of_new_alert = -1;
static int hf_btatt_alert_text_string_information = -1;
static int hf_btatt_blood_pressure_feature = -1;
static int hf_btatt_blood_pressure_feature_reserved = -1;
static int hf_btatt_blood_pressure_feature_multiple_bond = -1;
static int hf_btatt_blood_pressure_feature_measurement_position_detection = -1;
static int hf_btatt_blood_pressure_feature_puls_rate_range = -1;
static int hf_btatt_blood_pressure_feature_irregular_pulse_detection = -1;
static int hf_btatt_blood_pressure_feature_cuff_fit_detection = -1;
static int hf_btatt_blood_pressure_feature_body_movement_detection = -1;
static int hf_btatt_le_scan_interval = -1;
static int hf_btatt_le_scan_window = -1;
static int hf_btatt_pnp_id_vendor_id_source = -1;
static int hf_btatt_pnp_id_vendor_id = -1;
static int hf_btatt_pnp_id_vendor_id_bluetooth_sig = -1;
static int hf_btatt_pnp_id_vendor_id_usb_forum = -1;
static int hf_btatt_pnp_id_product_id = -1;
static int hf_btatt_pnp_id_product_version = -1;
static int hf_btatt_glucose_feature = -1;
static int hf_btatt_glucose_feature_reserved = -1;
static int hf_btatt_glucose_feature_multiple_bond = -1;
static int hf_btatt_glucose_feature_time_fault = -1;
static int hf_btatt_glucose_feature_general_device_fault = -1;
static int hf_btatt_glucose_feature_sensor_read_interrupt_detection = -1;
static int hf_btatt_glucose_feature_sensor_temperature_high_low_detection = -1;
static int hf_btatt_glucose_feature_sensor_result_high_low_detection = -1;
static int hf_btatt_glucose_feature_sensor_strip_type_error_detection = -1;
static int hf_btatt_glucose_feature_sensor_strip_insertion_error_detection = -1;
static int hf_btatt_glucose_feature_sensor_sample_size = -1;
static int hf_btatt_glucose_feature_sensor_malfunction_detection = -1;
static int hf_btatt_glucose_feature_low_battery_detection_during_measurement = -1;
static int hf_btatt_rsc_feature = -1;
static int hf_btatt_rsc_feature_reserved = -1;
static int hf_btatt_rsc_feature_multiple_sensor_locations = -1;
static int hf_btatt_rsc_feature_calibration_procedure = -1;
static int hf_btatt_rsc_feature_walking_or_running_status = -1;
static int hf_btatt_rsc_feature_total_distance_measurement = -1;
static int hf_btatt_rsc_feature_instantaneous_stride_length_measurement = -1;
static int hf_btatt_csc_feature = -1;
static int hf_btatt_csc_feature_reserved = -1;
static int hf_btatt_csc_feature_multiple_sensor_locations = -1;
static int hf_btatt_csc_feature_crank_revolution_data = -1;
static int hf_btatt_csc_feature_wheel_revolution_data = -1;
static int hf_btatt_sensor_location = -1;
static int hf_btatt_elevation = -1;
static int hf_btatt_pressure = -1;
static int hf_btatt_temperature = -1;
static int hf_btatt_humidity = -1;
static int hf_btatt_true_wind_speed = -1;
static int hf_btatt_true_wind_direction = -1;
static int hf_btatt_apparent_wind_speed = -1;
static int hf_btatt_apparent_wind_direction = -1;
static int hf_btatt_gust_factor = -1;
static int hf_btatt_pollen_concentration = -1;
static int hf_btatt_uv_index = -1;
static int hf_btatt_irradiance = -1;
static int hf_btatt_rainfall = -1;
static int hf_btatt_wind_chill = -1;
static int hf_btatt_heart_index = -1;
static int hf_btatt_dew_point = -1;
static int hf_btatt_descriptor_value_changed_flags = -1;
static int hf_btatt_descriptor_value_changed_flags_reserved = -1;
static int hf_btatt_descriptor_value_changed_flags_change_to_characteristic_user_description_descriptor = -1;
static int hf_btatt_descriptor_value_changed_flags_change_to_es_measurement_descriptor = -1;
static int hf_btatt_descriptor_value_changed_flags_change_to_es_configuration_descriptor = -1;
static int hf_btatt_descriptor_value_changed_flags_change_to_one_or_more_es_trigger_setting_descriptors = -1;
static int hf_btatt_descriptor_value_changed_flags_source_of_change = -1;
static int hf_btatt_aerobic_heart_rate_lower_limit = -1;
static int hf_btatt_aerobic_threshold = -1;
static int hf_btatt_age = -1;
static int hf_btatt_anaerobic_heart_rate_lower_limit = -1;
static int hf_btatt_anaerobic_heart_rate_upper_limit = -1;
static int hf_btatt_anaerobic_threshold = -1;
static int hf_btatt_aerobic_heart_rate_upper_limit = -1;
static int hf_btatt_email_address = -1;
static int hf_btatt_fat_burn_heart_rate_lower_limit = -1;
static int hf_btatt_fat_burn_heart_rate_upper_limit = -1;
static int hf_btatt_first_name = -1;
static int hf_btatt_five_zone_heart_rate_limits_very_light_light_limit = -1;
static int hf_btatt_five_zone_heart_rate_limits_light_moderate_limit = -1;
static int hf_btatt_five_zone_heart_rate_limits_moderate_hard_limit = -1;
static int hf_btatt_five_zone_heart_rate_limits_hard_maximum_limit = -1;
static int hf_btatt_gender = -1;
static int hf_btatt_heart_rate_max = -1;
static int hf_btatt_height = -1;
static int hf_btatt_hip_circumference = -1;
static int hf_btatt_last_name = -1;
static int hf_btatt_maximum_recommended_heart_rate = -1;
static int hf_btatt_resting_heart_rate = -1;
static int hf_btatt_sport_type_for_aerobic_and_anaerobic_thresholds = -1;
static int hf_btatt_three_zone_heart_rate_limits_light_moderate = -1;
static int hf_btatt_three_zone_heart_rate_limits_moderate_hard = -1;
static int hf_btatt_two_zone_heart_rate_limit_fat_burn_fitness = -1;
static int hf_btatt_vo2_max =-1;
static int hf_btatt_waist_circumference =-1;
static int hf_btatt_weight =-1;
static int hf_btatt_database_change_increment =-1;
static int hf_btatt_user_index = -1;
static int hf_btatt_magnetic_flux_density_x = -1;
static int hf_btatt_magnetic_flux_density_y = -1;
static int hf_btatt_magnetic_flux_density_z = -1;
static int hf_btatt_language = -1;
static int hf_btatt_barometric_pressure_trend = -1;
static int hf_btatt_central_address_resolution = -1;
static int hf_btatt_cycling_power_feature = -1;
static int hf_btatt_cycling_power_feature_reserved = -1;
static int hf_btatt_cycling_power_feature_factory_calibration_date = -1;
static int hf_btatt_cycling_power_feature_instantaneous_measurement_direction = -1;
static int hf_btatt_cycling_power_feature_sensor_measurement_context = -1;
static int hf_btatt_cycling_power_feature_span_length_adjustment = -1;
static int hf_btatt_cycling_power_feature_chain_weight_adjustment = -1;
static int hf_btatt_cycling_power_feature_chain_length_adjustment = -1;
static int hf_btatt_cycling_power_feature_crank_length_adjustment = -1;
static int hf_btatt_cycling_power_feature_multiple_sensor_locations = -1;
static int hf_btatt_cycling_power_feature_cycling_power_measurement_characteristic_content_masking = -1;
static int hf_btatt_cycling_power_feature_offset_compensation = -1;
static int hf_btatt_cycling_power_feature_offset_compensation_indicator = -1;
static int hf_btatt_cycling_power_feature_accumulated_energy = -1;
static int hf_btatt_cycling_power_feature_top_and_bottom_dead_spot_angles = -1;
static int hf_btatt_cycling_power_feature_extreme_angles = -1;
static int hf_btatt_cycling_power_feature_extreme_magnitudes = -1;
static int hf_btatt_cycling_power_feature_crank_revolution_data = -1;
static int hf_btatt_cycling_power_feature_wheel_revolution_data = -1;
static int hf_btatt_cycling_power_feature_accumulated_torque = -1;
static int hf_btatt_cycling_power_feature_pedal_power_balance = -1;
static int hf_btatt_ln_feature = -1;
static int hf_btatt_ln_feature_reserved = -1;
static int hf_btatt_ln_feature_position_status = -1;
static int hf_btatt_ln_feature_elevation_setting = -1;
static int hf_btatt_ln_feature_fix_rate_setting = -1;
static int hf_btatt_ln_feature_location_and_speed_characteristic_content_masking = -1;
static int hf_btatt_ln_feature_vertical_dilution_of_precision = -1;
static int hf_btatt_ln_feature_horizontal_dilution_of_precision = -1;
static int hf_btatt_ln_feature_estimated_vertical_position_error = -1;
static int hf_btatt_ln_feature_estimated_horizontal_position_error = -1;
static int hf_btatt_ln_feature_time_to_first_fix = -1;
static int hf_btatt_ln_feature_number_of_beacons_in_view = -1;
static int hf_btatt_ln_feature_number_of_beacons_in_solution = -1;
static int hf_btatt_ln_feature_estimated_time_of_arrival = -1;
static int hf_btatt_ln_feature_remaining_vertical_distance = -1;
static int hf_btatt_ln_feature_remaining_distance = -1;
static int hf_btatt_ln_feature_utc_time = -1;
static int hf_btatt_ln_feature_rolling_time = -1;
static int hf_btatt_ln_feature_heading = -1;
static int hf_btatt_ln_feature_elevation = -1;
static int hf_btatt_ln_feature_location = -1;
static int hf_btatt_ln_feature_total_distance = -1;
static int hf_btatt_ln_feature_instantaneous_speed = -1;
static int hf_btatt_body_composition_feature = -1;
static int hf_btatt_body_composition_feature_reserved = -1;
static int hf_btatt_body_composition_feature_height_measurement_resolution = -1;
static int hf_btatt_body_composition_feature_mass_measurement_resolution = -1;
static int hf_btatt_body_composition_feature_height = -1;
static int hf_btatt_body_composition_feature_weight = -1;
static int hf_btatt_body_composition_feature_impedance = -1;
static int hf_btatt_body_composition_feature_body_water_mass = -1;
static int hf_btatt_body_composition_feature_soft_lean_mass = -1;
static int hf_btatt_body_composition_feature_fat_free_mass = -1;
static int hf_btatt_body_composition_feature_muscle_mass = -1;
static int hf_btatt_body_composition_feature_muscle_percentage = -1;
static int hf_btatt_body_composition_feature_basal_metabolism = -1;
static int hf_btatt_body_composition_feature_multiple_users = -1;
static int hf_btatt_body_composition_feature_timestamp = -1;
static int hf_btatt_weight_scale_feature = -1;
static int hf_btatt_weight_scale_feature_reserved = -1;
static int hf_btatt_weight_scale_feature_height_measurement_resolution = -1;
static int hf_btatt_weight_scale_feature_weight_measurement_resolution = -1;
static int hf_btatt_weight_scale_feature_bmi = -1;
static int hf_btatt_weight_scale_feature_multiple_users = -1;
static int hf_btatt_weight_scale_feature_timestamp = -1;
static int hf_btatt_glucose_measurement_flags = -1;
static int hf_btatt_glucose_measurement_flags_reserved = -1;
static int hf_btatt_glucose_measurement_flags_context_information_follows = -1;
static int hf_btatt_glucose_measurement_flags_sensor_status_annunciation_present = -1;
static int hf_btatt_glucose_measurement_flags_glucose_concentration_units = -1;
static int hf_btatt_glucose_measurement_flags_glucose_concentration_type_and_sample_location_present = -1;
static int hf_btatt_glucose_measurement_flags_time_offset_present = -1;
static int hf_btatt_glucose_measurement_sequence_number = -1;
static int hf_btatt_glucose_measurement_base_time = -1;
static int hf_btatt_glucose_measurement_time_offset = -1;
static int hf_btatt_glucose_measurement_glucose_concentration_kg_per_l = -1;
static int hf_btatt_glucose_measurement_glucose_concentration_mol_per_l = -1;
static int hf_btatt_glucose_measurement_type_and_sample_location = -1;
static int hf_btatt_glucose_measurement_type_and_sample_location_type = -1;
static int hf_btatt_glucose_measurement_type_and_sample_location_sample_location = -1;
static int hf_btatt_glucose_measurement_sensor_status_annunciation = -1;
static int hf_btatt_glucose_measurement_sensor_status_annunciation_reserved = -1;
static int hf_btatt_glucose_measurement_sensor_status_annunciation_time_fault = -1;
static int hf_btatt_glucose_measurement_sensor_status_annunciation_general_fault = -1;
static int hf_btatt_glucose_measurement_sensor_status_annunciation_read_interrupted = -1;
static int hf_btatt_glucose_measurement_sensor_status_annunciation_temperature_too_low = -1;
static int hf_btatt_glucose_measurement_sensor_status_annunciation_temperature_too_high = -1;
static int hf_btatt_glucose_measurement_sensor_status_annunciation_result_too_lower = -1;
static int hf_btatt_glucose_measurement_sensor_status_annunciation_result_too_high = -1;
static int hf_btatt_glucose_measurement_sensor_status_annunciation_strip_type_incorrect = -1;
static int hf_btatt_glucose_measurement_sensor_status_annunciation_strip_insertion_error = -1;
static int hf_btatt_glucose_measurement_sensor_status_annunciation_size_insufficient = -1;
static int hf_btatt_glucose_measurement_sensor_status_annunciation_fault = -1;
static int hf_btatt_glucose_measurement_sensor_status_annunciation_battery_low = -1;
static int hf_btatt_bond_management_feature = -1;
static int hf_btatt_bond_management_feature_feature_extension = -1;
static int hf_btatt_bond_management_feature_reserved = -1;
static int hf_btatt_bond_management_feature_identify_yourself = -1;
static int hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_9 = -1;
static int hf_btatt_bond_management_feature_remove_all_but_the_active_bond_on_le_transport_only_server = -1;
static int hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_8 = -1;
static int hf_btatt_bond_management_feature_remove_all_but_the_active_bond_on_br_edr_transport_only_server = -1;
static int hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_7 = -1;
static int hf_btatt_bond_management_feature_remove_all_but_the_active_bond_on_br_edr_and_le_server = -1;
static int hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_6 = -1;
static int hf_btatt_bond_management_feature_remove_all_bonds_on_le_transport_only_server = -1;
static int hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_5 = -1;
static int hf_btatt_bond_management_feature_remove_all_bonds_on_br_edr_transport_only_server = -1;
static int hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_4 = -1;
static int hf_btatt_bond_management_feature_remove_all_bonds_on_br_edr_and_le_server = -1;
static int hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_3 = -1;
static int hf_btatt_bond_management_feature_delete_bond_of_current_le_transport_only_connection = -1;
static int hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_2 = -1;
static int hf_btatt_bond_management_feature_delete_bond_of_current_br_edr_transport_only_connection = -1;
static int hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_1 = -1;
static int hf_btatt_bond_management_feature_delete_bond_of_current_br_edr_and_le_connection = -1;
static int hf_btatt_bond_management_feature_nth = -1;
static int hf_btatt_bond_management_feature_nth_feature_extension = -1;
static int hf_btatt_bond_management_feature_nth_reserved = -1;
static int hf_btatt_bond_management_control_point_opcode = -1;
static int hf_btatt_bond_management_control_point_authorization_code = -1;
static int hf_btatt_temperature_measurement_flags = -1;
static int hf_btatt_temperature_measurement_flags_reserved = -1;
static int hf_btatt_temperature_measurement_flags_temperature_type = -1;
static int hf_btatt_temperature_measurement_flags_timestamp = -1;
static int hf_btatt_temperature_measurement_flags_temperature_unit = -1;
static int hf_btatt_temperature_measurement_value_celsius = -1;
static int hf_btatt_temperature_measurement_value_fahrenheit = -1;
static int hf_btatt_temperature_measurement_timestamp = -1;
static int hf_btatt_glucose_measurement_context_flags = -1;
static int hf_btatt_glucose_measurement_context_flags_extended_flags = -1;
static int hf_btatt_glucose_measurement_context_flags_hba1c = -1;
static int hf_btatt_glucose_measurement_context_flags_medication_value_units = -1;
static int hf_btatt_glucose_measurement_context_flags_medication_id_and_medication = -1;
static int hf_btatt_glucose_measurement_context_flags_exercise_duration_and_exercise_intensity = -1;
static int hf_btatt_glucose_measurement_context_flags_tester_health = -1;
static int hf_btatt_glucose_measurement_context_flags_meal = -1;
static int hf_btatt_glucose_measurement_context_flags_carbohydrate_id_and_carbohydrate = -1;
static int hf_btatt_glucose_measurement_context_sequence_number = -1;
static int hf_btatt_glucose_measurement_context_extended_flags = -1;
static int hf_btatt_glucose_measurement_context_extended_flags_reserved = -1;
static int hf_btatt_glucose_measurement_context_carbohydrate_id = -1;
static int hf_btatt_glucose_measurement_context_carbohydrate_kg = -1;
static int hf_btatt_glucose_measurement_context_meal = -1;
static int hf_btatt_glucose_measurement_context_tester_health = -1;
static int hf_btatt_glucose_measurement_context_tester = -1;
static int hf_btatt_glucose_measurement_context_health = -1;
static int hf_btatt_glucose_measurement_context_exercise_duration = -1;
static int hf_btatt_glucose_measurement_context_exercise_intensity = -1;
static int hf_btatt_glucose_measurement_context_medication_id = -1;
static int hf_btatt_glucose_measurement_context_medication_l = -1;
static int hf_btatt_glucose_measurement_context_medication_kg = -1;
static int hf_btatt_glucose_measurement_context_hba1c = -1;
static int hf_btatt_blood_pressure_measurement_flags = -1;
static int hf_btatt_blood_pressure_measurement_flags_reserved = -1;
static int hf_btatt_blood_pressure_measurement_flags_measurement_status = -1;
static int hf_btatt_blood_pressure_measurement_flags_user_id = -1;
static int hf_btatt_blood_pressure_measurement_flags_pulse_rate = -1;
static int hf_btatt_blood_pressure_measurement_flags_timestamp = -1;
static int hf_btatt_blood_pressure_measurement_flags_unit = -1;
static int hf_btatt_blood_pressure_measurement_compound_value_systolic_kpa = -1;
static int hf_btatt_blood_pressure_measurement_compound_value_diastolic_kpa = -1;
static int hf_btatt_blood_pressure_measurement_compound_value_mean_arterial_pressure_kpa = -1;
static int hf_btatt_blood_pressure_measurement_compound_value_systolic_mmhg = -1;
static int hf_btatt_blood_pressure_measurement_compound_value_diastolic_mmhg = -1;
static int hf_btatt_blood_pressure_measurement_compound_value_mean_arterial_pressure_mmhg = -1;
static int hf_btatt_blood_pressure_measurement_timestamp = -1;
static int hf_btatt_blood_pressure_measurement_pulse_rate = -1;
static int hf_btatt_blood_pressure_measurement_user_id = -1;
static int hf_btatt_blood_pressure_measurement_status = -1;
static int hf_btatt_blood_pressure_measurement_status_reserved = -1;
static int hf_btatt_blood_pressure_measurement_status_improper_measurement_position = -1;
static int hf_btatt_blood_pressure_measurement_status_pulse_rate_range_detection = -1;
static int hf_btatt_blood_pressure_measurement_status_irregular_pulse = -1;
static int hf_btatt_blood_pressure_measurement_status_cuff_fit_too_loose = -1;
static int hf_btatt_blood_pressure_measurement_status_body_movement = -1;
static int hf_btatt_heart_rate_measurement_flags = -1;
static int hf_btatt_heart_rate_measurement_flags_reserved = -1;
static int hf_btatt_heart_rate_measurement_flags_rr_interval = -1;
static int hf_btatt_heart_rate_measurement_flags_energy_expended = -1;
static int hf_btatt_heart_rate_measurement_flags_sensor_contact_status_support = -1;
static int hf_btatt_heart_rate_measurement_flags_sensor_contact_status_contact = -1;
static int hf_btatt_heart_rate_measurement_flags_value_16 = -1;
static int hf_btatt_heart_rate_measurement_value_8 = -1;
static int hf_btatt_heart_rate_measurement_value_16 = -1;
static int hf_btatt_heart_rate_measurement_energy_expended = -1;
static int hf_btatt_heart_rate_measurement_rr_intervals = -1;
static int hf_btatt_heart_rate_measurement_rr_interval = -1;
static int hf_btatt_record_access_control_point_opcode = -1;
static int hf_btatt_record_access_control_point_operator = -1;
static int hf_btatt_record_access_control_point_operand = -1;
static int hf_btatt_record_access_control_point_operand_filter_type = -1;
static int hf_btatt_record_access_control_point_operand_min_time_offset = -1;
static int hf_btatt_record_access_control_point_operand_max_time_offset = -1;
static int hf_btatt_record_access_control_point_operand_number_of_records = -1;
static int hf_btatt_record_access_control_point_request_opcode = -1;
static int hf_btatt_record_access_control_point_response_code = -1;
static int hf_btatt_value_trigger_setting_condition = -1;
static int hf_btatt_value_trigger_setting_analog = -1;
static int hf_btatt_value_trigger_setting_analog_one = -1;
static int hf_btatt_value_trigger_setting_analog_two = -1;
static int hf_btatt_digital = -1;
static int hf_btatt_analog = -1;
static int hf_btatt_location_name = -1;
static int hf_btatt_uncertainty = -1;
static int hf_btatt_uncertainty_reserved = -1;
static int hf_btatt_uncertainty_precision = -1;
static int hf_btatt_uncertainty_update_time = -1;
static int hf_btatt_uncertainty_stationary = -1;
static int hf_btatt_latitude = -1;
static int hf_btatt_longitude = -1;
static int hf_btatt_local_north_coordinate = -1;
static int hf_btatt_local_east_coordinate = -1;
static int hf_btatt_floor_number = -1;
static int hf_btatt_altitude = -1;
static int hf_btatt_indoor_positioning_configuration = -1;
static int hf_btatt_indoor_positioning_configuration_reserved = -1;
static int hf_btatt_indoor_positioning_configuration_location_name = -1;
static int hf_btatt_indoor_positioning_configuration_uncertainty = -1;
static int hf_btatt_indoor_positioning_configuration_floor_number = -1;
static int hf_btatt_indoor_positioning_configuration_altitude = -1;
static int hf_btatt_indoor_positioning_configuration_tx_power = -1;
static int hf_btatt_indoor_positioning_configuration_coordinate_system = -1;
static int hf_btatt_indoor_positioning_configuration_coordinates = -1;
static int hf_btatt_number_of_digitals = -1;
static int hf_btatt_time_trigger_setting_condition = -1;
static int hf_btatt_time_trigger_setting_value = -1;
static int hf_btatt_time_trigger_setting_value_count = -1;
static int hf_btatt_time_trigger_setting_value_time_interval = -1;
static int hf_btatt_rsc_measurement_flags = -1;
static int hf_btatt_rsc_measurement_flags_reserved = -1;
static int hf_btatt_rsc_measurement_flags_type_of_movement = -1;
static int hf_btatt_rsc_measurement_flags_total_distance_present = -1;
static int hf_btatt_rsc_measurement_flags_instantaneous_stride_length_present = -1;
static int hf_btatt_rsc_measurement_instantaneous_speed = -1;
static int hf_btatt_rsc_measurement_instantaneous_cadence = -1;
static int hf_btatt_rsc_measurement_instantaneous_stride_length = -1;
static int hf_btatt_rsc_measurement_total_distance = -1;
static int hf_btatt_sc_control_point_opcode = -1;
static int hf_btatt_sc_control_point_cumulative_value = -1;
static int hf_btatt_sc_control_point_request_opcode = -1;
static int hf_btatt_sc_control_point_response_value = -1;
static int hf_btatt_cycling_power_measurement_flags = -1;
static int hf_btatt_cycling_power_measurement_flags_reserved = -1;
static int hf_btatt_cycling_power_measurement_flags_offset_compensation_indicator = -1;
static int hf_btatt_cycling_power_measurement_flags_accumulated_energy = -1;
static int hf_btatt_cycling_power_measurement_flags_bottom_dead_spot_angle = -1;
static int hf_btatt_cycling_power_measurement_flags_top_dead_spot_angle = -1;
static int hf_btatt_cycling_power_measurement_flags_extreme_angles = -1;
static int hf_btatt_cycling_power_measurement_flags_extreme_torque_magnitudes = -1;
static int hf_btatt_cycling_power_measurement_flags_extreme_force_magnitudes = -1;
static int hf_btatt_cycling_power_measurement_flags_crank_revolution_data = -1;
static int hf_btatt_cycling_power_measurement_flags_wheel_revolution_data = -1;
static int hf_btatt_cycling_power_measurement_flags_accumulated_torque_source = -1;
static int hf_btatt_cycling_power_measurement_flags_accumulated_torque = -1;
static int hf_btatt_cycling_power_measurement_flags_pedal_power_balance_reference = -1;
static int hf_btatt_cycling_power_measurement_flags_pedal_power_balance = -1;
static int hf_btatt_cycling_power_measurement_instantaneous_power = -1;
static int hf_btatt_cycling_power_measurement_pedal_power_balance = -1;
static int hf_btatt_cycling_power_measurement_accumulated_torque = -1;
static int hf_btatt_cycling_power_measurement_wheel_revolution_data_cumulative_wheel_revolutions = -1;
static int hf_btatt_cycling_power_measurement_wheel_revolution_data_last_wheel_event_time = -1;
static int hf_btatt_cycling_power_measurement_crank_revolution_data_cumulative_crank_revolutions = -1;
static int hf_btatt_cycling_power_measurement_crank_revolution_data_last_crank_event_time = -1;
static int hf_btatt_cycling_power_measurement_extreme_force_magnitudes_maximum_force_magnitude = -1;
static int hf_btatt_cycling_power_measurement_extreme_force_magnitudes_minimum_force_magnitude = -1;
static int hf_btatt_cycling_power_measurement_extreme_torque_magnitudes_maximum_torque_magnitude = -1;
static int hf_btatt_cycling_power_measurement_extreme_torque_magnitudes_minimum_torque_magnitude = -1;
static int hf_btatt_cycling_power_measurement_extreme_angles = -1;
static int hf_btatt_cycling_power_measurement_extreme_angles_maximum = -1;
static int hf_btatt_cycling_power_measurement_extreme_angles_minimum = -1;
static int hf_btatt_cycling_power_measurement_top_dead_spot_angle = -1;
static int hf_btatt_cycling_power_measurement_bottom_dead_spot_angle = -1;
static int hf_btatt_cycling_power_measurement_accumulated_energy = -1;
static int hf_btatt_csc_measurement_flags = -1;
static int hf_btatt_csc_measurement_flags_reserved = -1;
static int hf_btatt_csc_measurement_flags_crank_revolution_data = -1;
static int hf_btatt_csc_measurement_flags_wheel_revolution_data = -1;
static int hf_btatt_csc_measurement_cumulative_wheel_revolutions = -1;
static int hf_btatt_csc_measurement_cumulative_crank_revolutions = -1;
static int hf_btatt_csc_measurement_last_event_time = -1;
static int hf_btatt_cycling_power_vector_flags = -1;
static int hf_btatt_cycling_power_vector_flags_reserved = -1;
static int hf_btatt_cycling_power_vector_flags_instantaneous_measurement_direction = -1;
static int hf_btatt_cycling_power_vector_flags_instantaneous_torque_magnitude_array = -1;
static int hf_btatt_cycling_power_vector_flags_instantaneous_force_magnitude_array = -1;
static int hf_btatt_cycling_power_vector_flags_first_crank_measurement_angle = -1;
static int hf_btatt_cycling_power_vector_flags_crank_revolution_data = -1;
static int hf_btatt_cycling_power_vector_crank_revolution_data_cumulative_crank_revolutions = -1;
static int hf_btatt_cycling_power_vector_crank_revolution_data_last_crank_event_time = -1;
static int hf_btatt_cycling_power_vector_first_crank_measurement_angle = -1;
static int hf_btatt_cycling_power_vector_instantaneous_force_magnitude_array = -1;
static int hf_btatt_cycling_power_vector_instantaneous_torque_magnitude_array = -1;
static int hf_btatt_cycling_power_control_point_opcode = -1;
static int hf_btatt_cycling_power_control_point_cumulative_value = -1;
static int hf_btatt_cycling_power_control_point_sensor_location = -1;
static int hf_btatt_cycling_power_control_point_crank_length = -1;
static int hf_btatt_cycling_power_control_point_chain_length = -1;
static int hf_btatt_cycling_power_control_point_chain_weight = -1;
static int hf_btatt_cycling_power_control_point_span_length = -1;
static int hf_btatt_cycling_power_control_point_content_mask = -1;
static int hf_btatt_cycling_power_control_point_content_mask_reserved = -1;
static int hf_btatt_cycling_power_control_point_content_mask_accumulated_energy = -1;
static int hf_btatt_cycling_power_control_point_content_mask_bottom_dead_spot_angle = -1;
static int hf_btatt_cycling_power_control_point_content_mask_top_dead_spot_angle = -1;
static int hf_btatt_cycling_power_control_point_content_mask_extreme_angles = -1;
static int hf_btatt_cycling_power_control_point_content_mask_extreme_magnitudes = -1;
static int hf_btatt_cycling_power_control_point_content_mask_crank_revolution_data = -1;
static int hf_btatt_cycling_power_control_point_content_mask_wheel_revolution_data = -1;
static int hf_btatt_cycling_power_control_point_content_mask_accumulated_torque = -1;
static int hf_btatt_cycling_power_control_point_content_mask_pedal_power_balance = -1;
static int hf_btatt_cycling_power_control_point_request_opcode = -1;
static int hf_btatt_cycling_power_control_point_response_value = -1;
static int hf_btatt_cycling_power_control_point_start_offset_compensation = -1;
static int hf_btatt_cycling_power_control_point_sampling_rate = -1;
static int hf_btatt_cycling_power_control_point_factory_calibration_date = -1;
static int hf_btatt_location_and_speed_flags = -1;
static int hf_btatt_location_and_speed_flags_reserved = -1;
static int hf_btatt_location_and_speed_flags_heading_source = -1;
static int hf_btatt_location_and_speed_flags_elevation_source = -1;
static int hf_btatt_location_and_speed_flags_speed_and_distance_format = -1;
static int hf_btatt_location_and_speed_flags_position_status = -1;
static int hf_btatt_location_and_speed_flags_utc_time = -1;
static int hf_btatt_location_and_speed_flags_rolling_time = -1;
static int hf_btatt_location_and_speed_flags_heading = -1;
static int hf_btatt_location_and_speed_flags_elevation = -1;
static int hf_btatt_location_and_speed_flags_location = -1;
static int hf_btatt_location_and_speed_flags_total_distance = -1;
static int hf_btatt_location_and_speed_flags_instantaneous_speed = -1;
static int hf_btatt_location_and_speed_instantaneous_speed = -1;
static int hf_btatt_location_and_speed_total_distance = -1;
static int hf_btatt_location_and_speed_location_latitude = -1;
static int hf_btatt_location_and_speed_location_longitude = -1;
static int hf_btatt_location_and_speed_elevation = -1;
static int hf_btatt_location_and_speed_heading = -1;
static int hf_btatt_location_and_speed_rolling_time = -1;
static int hf_btatt_location_and_speed_utc_time = -1;
static int hf_btatt_navigation_flags = -1;
static int hf_btatt_navigation_flags_reserved = -1;
static int hf_btatt_navigation_flags_destination_reached = -1;
static int hf_btatt_navigation_flags_waypoint_reached = -1;
static int hf_btatt_navigation_flags_navigation_indicator_type = -1;
static int hf_btatt_navigation_flags_heading_source = -1;
static int hf_btatt_navigation_flags_position_status = -1;
static int hf_btatt_navigation_flags_estimated_time_of_arrival = -1;
static int hf_btatt_navigation_flags_remaining_vertical_distance = -1;
static int hf_btatt_navigation_flags_remaining_distance = -1;
static int hf_btatt_navigation_bearing = -1;
static int hf_btatt_navigation_heading = -1;
static int hf_btatt_navigation_remaining_distance = -1;
static int hf_btatt_navigation_remaining_vertical_distance = -1;
static int hf_btatt_navigation_estimated_time_of_arrival = -1;
static int hf_btatt_position_quality_flags = -1;
static int hf_btatt_position_quality_flags_reserved = -1;
static int hf_btatt_position_quality_flags_position_status = -1;
static int hf_btatt_position_quality_flags_vdop = -1;
static int hf_btatt_position_quality_flags_hdop = -1;
static int hf_btatt_position_quality_flags_evpe = -1;
static int hf_btatt_position_quality_flags_ehpe = -1;
static int hf_btatt_position_quality_flags_time_to_first_fix = -1;
static int hf_btatt_position_quality_flags_number_of_beacons_in_view = -1;
static int hf_btatt_position_quality_flags_number_of_beacons_in_solution = -1;
static int hf_btatt_position_quality_number_of_beacons_in_solution = -1;
static int hf_btatt_position_quality_number_of_beacons_in_view = -1;
static int hf_btatt_position_quality_time_to_first_fix = -1;
static int hf_btatt_position_quality_ehpe = -1;
static int hf_btatt_position_quality_evpe = -1;
static int hf_btatt_position_quality_hdop = -1;
static int hf_btatt_position_quality_vdop = -1;
static int hf_btatt_ln_control_point_opcode = -1;
static int hf_btatt_ln_control_point_cumulative_value = -1;
static int hf_btatt_ln_control_point_content_mask = -1;
static int hf_btatt_ln_control_point_content_mask_reserved = -1;
static int hf_btatt_ln_control_point_content_mask_utc_time = -1;
static int hf_btatt_ln_control_point_content_mask_rolling_time = -1;
static int hf_btatt_ln_control_point_content_mask_heading = -1;
static int hf_btatt_ln_control_point_content_mask_elevation = -1;
static int hf_btatt_ln_control_point_content_mask_location = -1;
static int hf_btatt_ln_control_point_content_mask_total_distance = -1;
static int hf_btatt_ln_control_point_content_mask_instantaneous_speed = -1;
static int hf_btatt_ln_control_point_navigation_control = -1;
static int hf_btatt_ln_control_point_route_number = -1;
static int hf_btatt_ln_control_point_fix_rate = -1;
static int hf_btatt_ln_control_point_elevation = -1;
static int hf_btatt_ln_control_point_request_opcode = -1;
static int hf_btatt_ln_control_point_response_value = -1;
static int hf_btatt_ln_control_point_response_value_number_of_routes = -1;
static int hf_btatt_ln_control_point_response_value_name_of_route = -1;
static int hf_btatt_body_composition_measurement_flags = -1;
static int hf_btatt_body_composition_measurement_flags_reserved = -1;
static int hf_btatt_body_composition_measurement_flags_multiple_packet_measurement = -1;
static int hf_btatt_body_composition_measurement_flags_height = -1;
static int hf_btatt_body_composition_measurement_flags_weight = -1;
static int hf_btatt_body_composition_measurement_flags_impedance = -1;
static int hf_btatt_body_composition_measurement_flags_body_water_mass = -1;
static int hf_btatt_body_composition_measurement_flags_soft_lean_mass = -1;
static int hf_btatt_body_composition_measurement_flags_fat_free_mass = -1;
static int hf_btatt_body_composition_measurement_flags_muscle_mass = -1;
static int hf_btatt_body_composition_measurement_flags_muscle_percentage = -1;
static int hf_btatt_body_composition_measurement_flags_basal_metabolism = -1;
static int hf_btatt_body_composition_measurement_flags_user_id = -1;
static int hf_btatt_body_composition_measurement_flags_timestamp = -1;
static int hf_btatt_body_composition_measurement_flags_measurement_units = -1;
static int hf_btatt_body_composition_measurement_body_fat_percentage = -1;
static int hf_btatt_body_composition_measurement_timestamp = -1;
static int hf_btatt_body_composition_measurement_user_id = -1;
static int hf_btatt_body_composition_measurement_basal_metabolism = -1;
static int hf_btatt_body_composition_measurement_muscle_percentage = -1;
static int hf_btatt_body_composition_measurement_muscle_mass_lb = -1;
static int hf_btatt_body_composition_measurement_muscle_mass_kg = -1;
static int hf_btatt_body_composition_measurement_fat_free_mass_lb = -1;
static int hf_btatt_body_composition_measurement_fat_free_mass_kg = -1;
static int hf_btatt_body_composition_measurement_soft_lean_mass_lb = -1;
static int hf_btatt_body_composition_measurement_soft_lean_mass_kg = -1;
static int hf_btatt_body_composition_measurement_body_water_mass_lb = -1;
static int hf_btatt_body_composition_measurement_body_water_mass_kg = -1;
static int hf_btatt_body_composition_measurement_impedance = -1;
static int hf_btatt_body_composition_measurement_weight_lb = -1;
static int hf_btatt_body_composition_measurement_weight_kg = -1;
static int hf_btatt_body_composition_measurement_height_inches = -1;
static int hf_btatt_body_composition_measurement_height_meter = -1;
static int hf_btatt_weight_measurement_flags = -1;
static int hf_btatt_weight_measurement_flags_reserved = -1;
static int hf_btatt_weight_measurement_flags_bmi_and_height = -1;
static int hf_btatt_weight_measurement_flags_user_id = -1;
static int hf_btatt_weight_measurement_flags_timestamp = -1;
static int hf_btatt_weight_measurement_flags_measurement_units = -1;
static int hf_btatt_weight_measurement_weight_lb = -1;
static int hf_btatt_weight_measurement_weight_kg = -1;
static int hf_btatt_weight_measurement_timestamp = -1;
static int hf_btatt_weight_measurement_user_id = -1;
static int hf_btatt_weight_measurement_bmi = -1;
static int hf_btatt_weight_measurement_height_in = -1;
static int hf_btatt_weight_measurement_height_m = -1;
static int hf_btatt_user_control_point_opcode = -1;
static int hf_btatt_user_control_point_request_opcode = -1;
static int hf_btatt_user_control_point_response_value = -1;
static int hf_btatt_user_control_point_consent_code = -1;
static int hf_btatt_cgm_measurement_size = -1;
static int hf_btatt_cgm_measurement_flags = -1;
static int hf_btatt_cgm_measurement_flags_cgm_trend_information = -1;
static int hf_btatt_cgm_measurement_flags_cgm_quality = -1;
static int hf_btatt_cgm_measurement_flags_reserved = -1;
static int hf_btatt_cgm_measurement_flags_sensor_status_annunciation_warning = -1;
static int hf_btatt_cgm_measurement_flags_sensor_status_annunciation_cal_temp = -1;
static int hf_btatt_cgm_measurement_flags_sensor_status_annunciation_status = -1;
static int hf_btatt_cgm_measurement_glucose_concentration = -1;
static int hf_btatt_cgm_measurement_time_offset = -1;
static int hf_btatt_cgm_sensor_status_annunciation = -1;
static int hf_btatt_cgm_sensor_status_annunciation_status = -1;
static int hf_btatt_cgm_sensor_status_annunciation_status_reserved = -1;
static int hf_btatt_cgm_sensor_status_annunciation_status_general_device_fault_has_occurred_in_the_sensor = -1;
static int hf_btatt_cgm_sensor_status_annunciation_status_device_specific_alert = -1;
static int hf_btatt_cgm_sensor_status_annunciation_status_sensor_malfunction = -1;
static int hf_btatt_cgm_sensor_status_annunciation_status_sensor_type_incorrect_for_device = -1;
static int hf_btatt_cgm_sensor_status_annunciation_status_device_battery_low = -1;
static int hf_btatt_cgm_sensor_status_annunciation_status_session_stopped = -1;
static int hf_btatt_cgm_sensor_status_annunciation_cal_temp = -1;
static int hf_btatt_cgm_sensor_status_annunciation_cal_temp_reserved = -1;
static int hf_btatt_cgm_sensor_status_annunciation_cal_temp_sensor_temperature_too_low_for_valid_test_result_at_time_of_measurement = -1;
static int hf_btatt_cgm_sensor_status_annunciation_cal_temp_sensor_temperature_too_high_for_valid_test_result_at_time_of_measurement = -1;
static int hf_btatt_cgm_sensor_status_annunciation_cal_temp_calibration_required = -1;
static int hf_btatt_cgm_sensor_status_annunciation_cal_temp_calibration_recommended = -1;
static int hf_btatt_cgm_sensor_status_annunciation_cal_temp_calibration_not_allowed = -1;
static int hf_btatt_cgm_sensor_status_annunciation_cal_temp_time_synchronization_between_sensor_and_collector_required = -1;
static int hf_btatt_cgm_sensor_status_annunciation_warning = -1;
static int hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_higher_than_the_device_can_process = -1;
static int hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_lower_than_the_device_can_process = -1;
static int hf_btatt_cgm_sensor_status_annunciation_warning_sensor_rate_of_increase_exceeded = -1;
static int hf_btatt_cgm_sensor_status_annunciation_warning_sensor_rate_of_decrease_exceeded = -1;
static int hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_higher_than_the_hyper_level = -1;
static int hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_lower_than_the_hypo_level = -1;
static int hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_higher_than_the_patient_high_level = -1;
static int hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_lower_than_the_patient_low_level = -1;
static int hf_btatt_cgm_measurement_trend_information = -1;
static int hf_btatt_cgm_measurement_quality = -1;
static int hf_btatt_cgm_e2e_crc = -1;
static int hf_btatt_cgm_feature_feature = -1;
static int hf_btatt_cgm_feature_feature_reserved = -1;
static int hf_btatt_cgm_feature_feature_quality = -1;
static int hf_btatt_cgm_feature_feature_trend_information = -1;
static int hf_btatt_cgm_feature_feature_multiple_sessions = -1;
static int hf_btatt_cgm_feature_feature_multiple_bond = -1;
static int hf_btatt_cgm_feature_feature_e2e_crc = -1;
static int hf_btatt_cgm_feature_feature_general_device_fault = -1;
static int hf_btatt_cgm_feature_feature_sensor_type_error_detection = -1;
static int hf_btatt_cgm_feature_feature_low_battery_detection = -1;
static int hf_btatt_cgm_feature_feature_sensor_result_high_low_detection = -1;
static int hf_btatt_cgm_feature_feature_sensor_temperature_high_low_detection = -1;
static int hf_btatt_cgm_feature_feature_sensor_malfunction_detection = -1;
static int hf_btatt_cgm_feature_feature_device_specific_alert = -1;
static int hf_btatt_cgm_feature_feature_rate_of_increase_decrease_alerts = -1;
static int hf_btatt_cgm_feature_feature_hyper_alerts = -1;
static int hf_btatt_cgm_feature_feature_hypo_alerts = -1;
static int hf_btatt_cgm_feature_feature_patient_high_low_alerts = -1;
static int hf_btatt_cgm_feature_feature_calibration = -1;
static int hf_btatt_cgm_type_and_sample_location = -1;
static int hf_btatt_cgm_type = -1;
static int hf_btatt_cgm_sample_location = -1;
static int hf_btatt_cgm_time_offset = -1;
static int hf_btatt_cgm_status = -1;
static int hf_btatt_cgm_session_start_time = -1;
static int hf_btatt_cgm_session_run_time = -1;
static int hf_btatt_cgm_specific_ops_control_point_opcode = -1;
static int hf_btatt_cgm_specific_ops_control_point_operand = -1;
static int hf_btatt_cgm_specific_ops_control_point_operand_communication_interval = -1;
static int hf_btatt_cgm_specific_ops_control_point_calibration_glucose_concentration = -1;
static int hf_btatt_cgm_specific_ops_control_point_calibration_time = -1;
static int hf_btatt_cgm_specific_ops_control_point_next_calibration_time = -1;
static int hf_btatt_cgm_specific_ops_control_point_calibration_data_record_number = -1;
static int hf_btatt_cgm_specific_ops_control_point_calibration_status = -1;
static int hf_btatt_cgm_specific_ops_control_point_calibration_status_reserved = -1;
static int hf_btatt_cgm_specific_ops_control_point_calibration_status_pending = -1;
static int hf_btatt_cgm_specific_ops_control_point_calibration_status_out_of_range = -1;
static int hf_btatt_cgm_specific_ops_control_point_calibration_status_rejected = -1;
static int hf_btatt_cgm_specific_ops_control_point_operand_calibration_data_record_number = -1;
static int hf_btatt_cgm_specific_ops_control_point_operand_alert_level = -1;
static int hf_btatt_cgm_specific_ops_control_point_operand_alert_level_rate = -1;
static int hf_btatt_cgm_specific_ops_control_point_request_opcode = -1;
static int hf_btatt_cgm_specific_ops_control_point_response_code = -1;
static int hf_btatt_uri = -1;
static int hf_btatt_http_headers = -1;
static int hf_btatt_http_status_code = -1;
static int hf_btatt_http_data_status = -1;
static int hf_btatt_http_data_status_reserved = -1;
static int hf_btatt_http_data_status_body_truncated = -1;
static int hf_btatt_http_data_status_body_received = -1;
static int hf_btatt_http_data_status_headers_truncated = -1;
static int hf_btatt_http_data_status_headers_received = -1;
static int hf_btatt_http_entity_body = -1;
static int hf_btatt_http_control_point_opcode = -1;
static int hf_btatt_https_security = -1;
static int hf_btatt_tds_opcode = -1;
static int hf_btatt_tds_result_code = -1;
static int hf_btatt_tds_organization_id = -1;
static int hf_btatt_tds_data = -1;
static int hf_btatt_ots_feature_oacp = -1;
static int hf_btatt_ots_feature_oacp_reserved = -1;
static int hf_btatt_ots_feature_oacp_abort = -1;
static int hf_btatt_ots_feature_oacp_patching_of_object = -1;
static int hf_btatt_ots_feature_oacp_truncation_of_objects = -1;
static int hf_btatt_ots_feature_oacp_appending_additional_data_to_object = -1;
static int hf_btatt_ots_feature_oacp_write = -1;
static int hf_btatt_ots_feature_oacp_read = -1;
static int hf_btatt_ots_feature_oacp_execute = -1;
static int hf_btatt_ots_feature_oacp_calculate_checksum = -1;
static int hf_btatt_ots_feature_oacp_delete = -1;
static int hf_btatt_ots_feature_oacp_create = -1;
static int hf_btatt_ots_feature_olcp = -1;
static int hf_btatt_ots_feature_olcp_reserved = -1;
static int hf_btatt_ots_feature_olcp_clear_marking = -1;
static int hf_btatt_ots_feature_olcp_request_number_of_objects = -1;
static int hf_btatt_ots_feature_olcp_order = -1;
static int hf_btatt_ots_feature_olcp_go_to = -1;
static int hf_btatt_ots_object_name = -1;
static int hf_btatt_ots_current_size = -1;
static int hf_btatt_ots_allocated_size = -1;
static int hf_btatt_ots_object_id = -1;
static int hf_btatt_ots_properties = -1;
static int hf_btatt_ots_properties_reserved = -1;
static int hf_btatt_ots_properties_mark = -1;
static int hf_btatt_ots_properties_patch = -1;
static int hf_btatt_ots_properties_truncate = -1;
static int hf_btatt_ots_properties_append = -1;
static int hf_btatt_ots_properties_write = -1;
static int hf_btatt_ots_properties_read = -1;
static int hf_btatt_ots_properties_execute = -1;
static int hf_btatt_ots_properties_delete = -1;
static int hf_btatt_ots_flags = -1;
static int hf_btatt_ots_flags_reserved = -1;
static int hf_btatt_ots_flags_object_deletion = -1;
static int hf_btatt_ots_flags_object_creation = -1;
static int hf_btatt_ots_flags_change_occured_to_the_object_metadata = -1;
static int hf_btatt_ots_flags_change_occured_to_the_object_contents = -1;
static int hf_btatt_ots_flags_source_of_change = -1;
static int hf_btatt_ots_action_opcode = -1;
static int hf_btatt_ots_size = -1;
static int hf_btatt_ots_offset = -1;
static int hf_btatt_ots_length = -1;
static int hf_btatt_ots_execute_data = -1;
static int hf_btatt_ots_action_response_opcode = -1;
static int hf_btatt_ots_action_result_code = -1;
static int hf_btatt_ots_checksum = -1;
static int hf_btatt_ots_list_opcode = -1;
static int hf_btatt_ots_list_order = -1;
static int hf_btatt_ots_list_response_opcode = -1;
static int hf_btatt_ots_list_result_code = -1;
static int hf_btatt_ots_list_total_number_of_objects = -1;
static int hf_btatt_ots_filter = -1;
static int hf_btatt_ots_name_string = -1;
static int hf_btatt_ots_size_from = -1;
static int hf_btatt_ots_size_to = -1;
static int hf_btatt_ots_object_first_created = -1;
static int hf_btatt_ots_object_last_modified = -1;
static int hf_btatt_plx_spot_check_measurement_flags = -1;
static int hf_btatt_plx_spot_check_measurement_flags_reserved = -1;
static int hf_btatt_plx_spot_check_measurement_flags_device_clock_is_not_set = -1;
static int hf_btatt_plx_spot_check_measurement_flags_pulse_amplitude_index = -1;
static int hf_btatt_plx_spot_check_measurement_flags_device_and_sensor_status = -1;
static int hf_btatt_plx_spot_check_measurement_flags_measurement_status = -1;
static int hf_btatt_plx_spot_check_measurement_flags_timestamp = -1;
static int hf_btatt_plx_spo2 = -1;
static int hf_btatt_plx_pulse_rate = -1;
static int hf_btatt_plx_spot_check_measurement_timestamp = -1;
static int hf_btatt_plx_measurement_status = -1;
static int hf_btatt_plx_measurement_status_invalid_measurement_detected = -1;
static int hf_btatt_plx_measurement_status_questionable_measurement_detected = -1;
static int hf_btatt_plx_measurement_status_measurement_unavailable = -1;
static int hf_btatt_plx_measurement_status_calibration_ongoing = -1;
static int hf_btatt_plx_measurement_status_data_for_testing = -1;
static int hf_btatt_plx_measurement_status_data_for_demonstration = -1;
static int hf_btatt_plx_measurement_status_data_from_measurement_storage = -1;
static int hf_btatt_plx_measurement_status_fully_qualified_data = -1;
static int hf_btatt_plx_measurement_status_validated_data = -1;
static int hf_btatt_plx_measurement_status_early_estimated_data = -1;
static int hf_btatt_plx_measurement_status_measurement_ongoing = -1;
static int hf_btatt_plx_measurement_status_reserved = -1;
static int hf_btatt_plx_device_and_sensor_status = -1;
static int hf_btatt_plx_device_and_sensor_status_reserved = -1;
static int hf_btatt_plx_device_and_sensor_status_sensor_disconnected = -1;
static int hf_btatt_plx_device_and_sensor_status_sensor_malfunctioning = -1;
static int hf_btatt_plx_device_and_sensor_status_sensor_displaced = -1;
static int hf_btatt_plx_device_and_sensor_status_unknown_sensor_connected = -1;
static int hf_btatt_plx_device_and_sensor_status_sensor_unconnected_to_user = -1;
static int hf_btatt_plx_device_and_sensor_status_sensor_interference_detected = -1;
static int hf_btatt_plx_device_and_sensor_status_signal_analysis_ongoing = -1;
static int hf_btatt_plx_device_and_sensor_status_questionable_pulse_detected = -1;
static int hf_btatt_plx_device_and_sensor_status_non_pulsatile_signal_detected = -1;
static int hf_btatt_plx_device_and_sensor_status_erratic_signal_detected = -1;
static int hf_btatt_plx_device_and_sensor_status_low_perfusion_detected = -1;
static int hf_btatt_plx_device_and_sensor_status_poor_signal_detected = -1;
static int hf_btatt_plx_device_and_sensor_status_inadequate_signal_detected = -1;
static int hf_btatt_plx_device_and_sensor_status_signal_processing_irregularity_detected = -1;
static int hf_btatt_plx_device_and_sensor_status_equipment_malfunction_detected = -1;
static int hf_btatt_plx_device_and_sensor_status_extended_display_update_ongoing = -1;
static int hf_btatt_plx_pulse_amplitude_index = -1;
static int hf_btatt_plx_spo2pr_spot_check = -1;
static int hf_btatt_plx_spo2pr_normal = -1;
static int hf_btatt_plx_spo2pr_fast = -1;
static int hf_btatt_plx_spo2pr_slow = -1;
static int hf_btatt_plx_continuous_measurement_flags = -1;
static int hf_btatt_plx_continuous_measurement_flags_reserved = -1;
static int hf_btatt_plx_continuous_measurement_flags_pulse_amplitude_index = -1;
static int hf_btatt_plx_continuous_measurement_flags_device_and_sensor_status = -1;
static int hf_btatt_plx_continuous_measurement_flags_measurement_status = -1;
static int hf_btatt_plx_continuous_measurement_flags_spo2pr_slow = -1;
static int hf_btatt_plx_continuous_measurement_flags_spo2pr_fast = -1;
static int hf_btatt_plx_features_supported_features = -1;
static int hf_btatt_plx_features_supported_features_reserved = -1;
static int hf_btatt_plx_features_supported_features_multiple_bonds = -1;
static int hf_btatt_plx_features_supported_features_pulse_amplitude_index = -1;
static int hf_btatt_plx_features_supported_features_spo2pr_slow = -1;
static int hf_btatt_plx_features_supported_features_spo2pr_fast = -1;
static int hf_btatt_plx_features_supported_features_timestamp_storage_for_spot_check = -1;
static int hf_btatt_plx_features_supported_features_measurement_storage_for_spot_check = -1;
static int hf_btatt_plx_features_supported_features_device_and_sensor_status = -1;
static int hf_btatt_plx_features_supported_features_measurement_status = -1;
static int hf_gatt_nordic_uart_tx = -1;
static int hf_gatt_nordic_uart_rx = -1;
static int hf_gatt_nordic_dfu_packet = -1;
static int hf_gatt_nordic_dfu_control_point_opcode = -1;
static int hf_gatt_nordic_dfu_control_point_init_packet = -1;
static int hf_gatt_nordic_dfu_control_point_number_of_bytes = -1;
static int hf_gatt_nordic_dfu_control_point_image_type = -1;
static int hf_gatt_nordic_dfu_control_point_number_of_packets = -1;
static int hf_gatt_nordic_dfu_control_point_request_opcode = -1;
static int hf_gatt_nordic_dfu_control_point_response_value = -1;
static int hf_btatt_valid_range_lower_inclusive_value = -1;
static int hf_btatt_valid_range_upper_inclusive_value = -1;
static int hf_request_in_frame = -1;
static int hf_response_in_frame = -1;

static int btatt_tap_handles = -1;

static const int *hfx_btatt_opcode[] = {
    &hf_btatt_opcode_authentication_signature,
    &hf_btatt_opcode_command,
    &hf_btatt_opcode_method,
    NULL
};

static const int *hfx_btatt_characteristic_properties[] = {
    &hf_btatt_characteristic_properties_extended_properties,
    &hf_btatt_characteristic_properties_authenticated_signed_writes,
    &hf_btatt_characteristic_properties_indicate,
    &hf_btatt_characteristic_properties_notify,
    &hf_btatt_characteristic_properties_write,
    &hf_btatt_characteristic_properties_write_without_response,
    &hf_btatt_characteristic_properties_read,
    &hf_btatt_characteristic_properties_broadcast,
    NULL
};

static const int *hfx_btatt_characteristic_configuration_client[] = {
    &hf_btatt_characteristic_configuration_client_reserved,
    &hf_btatt_characteristic_configuration_client_indication,
    &hf_btatt_characteristic_configuration_client_notification,
    NULL
};

static const int *hfx_btatt_characteristic_configuration_server[] = {
    &hf_btatt_characteristic_configuration_server_reserved,
    &hf_btatt_characteristic_configuration_server_broadcast,
    NULL
};

static const int *hfx_btatt_hogp_flags[] = {
    &hf_btatt_hogp_flags_reserved,
    &hf_btatt_hogp_flags_normally_connectable,
    &hf_btatt_hogp_flags_remote_wake,
    NULL
};

static const int *hfx_btatt_characteristic_extended_properties[] = {
    &hf_btatt_characteristic_extended_properties_reserved,
    &hf_btatt_characteristic_extended_properties_writable_auxiliaries,
    &hf_btatt_characteristic_extended_properties_reliable_write,
    NULL
};

static const int *hfx_btatt_appearance[] = {
    &hf_btatt_appearance_category,
    &hf_btatt_appearance_subcategory,
    NULL
};

static const int *hfx_btatt_appearance_watch[] = {
    &hf_btatt_appearance_category,
    &hf_btatt_appearance_subcategory_watch,
    NULL
};

static const int *hfx_btatt_appearance_thermometer[] = {
    &hf_btatt_appearance_category,
    &hf_btatt_appearance_subcategory_thermometer,
    NULL
};

static const int *hfx_btatt_appearance_heart_rate[] = {
    &hf_btatt_appearance_category,
    &hf_btatt_appearance_subcategory_heart_rate,
    NULL
};

static const int *hfx_btatt_appearance_blood_pressure[] = {
    &hf_btatt_appearance_category,
    &hf_btatt_appearance_subcategory_blood_pressure,
    NULL
};

static const int *hfx_btatt_appearance_hid[] = {
    &hf_btatt_appearance_category,
    &hf_btatt_appearance_subcategory_hid,
    NULL
};

static const int *hfx_btatt_appearance_running_walking_sensor[] = {
    &hf_btatt_appearance_category,
    &hf_btatt_appearance_subcategory_running_walking_sensor,
    NULL
};

static const int *hfx_btatt_appearance_cycling[] = {
    &hf_btatt_appearance_category,
    &hf_btatt_appearance_subcategory_cycling,
    NULL
};

static const int *hfx_btatt_appearance_pulse_oximeter[] = {
    &hf_btatt_appearance_category,
    &hf_btatt_appearance_subcategory_pulse_oximeter,
    NULL
};

static const int *hfx_btatt_appearance_outdoor_sports_activity[] = {
    &hf_btatt_appearance_category,
    &hf_btatt_appearance_subcategory_outdoor_sports_activity,
    NULL
};

static const int *hfx_btatt_time_adjust_reason[] = {
    &hf_btatt_time_adjust_reason_reserved,
    &hf_btatt_time_adjust_reason_change_of_dst,
    &hf_btatt_time_adjust_reason_change_of_timezone,
    &hf_btatt_time_adjust_reason_external_reference_time_update,
    &hf_btatt_time_adjust_reason_manual_time_update,
    NULL
};

static const int *hfx_btatt_alert_status[] = {
    &hf_btatt_alert_status_reserved,
    &hf_btatt_alert_status_display_alert_status,
    &hf_btatt_alert_status_vibrate_state,
    &hf_btatt_alert_status_ringer_state,
    NULL
};

static const int *hfx_btatt_alert_category_id_bitmask_1[] = {
    &hf_btatt_alert_category_id_bitmask_1_schedule,
    &hf_btatt_alert_category_id_bitmask_1_voice_mail,
    &hf_btatt_alert_category_id_bitmask_1_sms_mms,
    &hf_btatt_alert_category_id_bitmask_1_missed_call,
    &hf_btatt_alert_category_id_bitmask_1_call,
    &hf_btatt_alert_category_id_bitmask_1_news,
    &hf_btatt_alert_category_id_bitmask_1_email,
    &hf_btatt_alert_category_id_bitmask_1_simple_alert,
    NULL
};

static const int *hfx_btatt_alert_category_id_bitmask_2[] = {
    &hf_btatt_alert_category_id_bitmask_2_reserved,
    &hf_btatt_alert_category_id_bitmask_2_instant_message,
    &hf_btatt_alert_category_id_bitmask_2_high_prioritized_alert,
    NULL
};

static const int *hfx_btatt_blood_pressure_feature[] = {
    &hf_btatt_blood_pressure_feature_reserved,
    &hf_btatt_blood_pressure_feature_multiple_bond,
    &hf_btatt_blood_pressure_feature_measurement_position_detection,
    &hf_btatt_blood_pressure_feature_puls_rate_range,
    &hf_btatt_blood_pressure_feature_irregular_pulse_detection,
    &hf_btatt_blood_pressure_feature_cuff_fit_detection,
    &hf_btatt_blood_pressure_feature_body_movement_detection,
    NULL
};

static const int *hfx_btatt_glucose_feature[] = {
    &hf_btatt_glucose_feature_reserved,
    &hf_btatt_glucose_feature_multiple_bond,
    &hf_btatt_glucose_feature_time_fault,
    &hf_btatt_glucose_feature_general_device_fault,
    &hf_btatt_glucose_feature_sensor_read_interrupt_detection,
    &hf_btatt_glucose_feature_sensor_temperature_high_low_detection,
    &hf_btatt_glucose_feature_sensor_result_high_low_detection,
    &hf_btatt_glucose_feature_sensor_strip_type_error_detection,
    &hf_btatt_glucose_feature_sensor_strip_insertion_error_detection,
    &hf_btatt_glucose_feature_sensor_sample_size,
    &hf_btatt_glucose_feature_sensor_malfunction_detection,
    &hf_btatt_glucose_feature_low_battery_detection_during_measurement,
    NULL
};

static const int *hfx_btatt_rsc_feature[] = {
    &hf_btatt_rsc_feature_reserved,
    &hf_btatt_rsc_feature_multiple_sensor_locations,
    &hf_btatt_rsc_feature_calibration_procedure,
    &hf_btatt_rsc_feature_walking_or_running_status,
    &hf_btatt_rsc_feature_total_distance_measurement,
    &hf_btatt_rsc_feature_instantaneous_stride_length_measurement,
    NULL
};

static const int *hfx_btatt_csc_feature[] = {
    &hf_btatt_csc_feature_reserved,
    &hf_btatt_csc_feature_multiple_sensor_locations,
    &hf_btatt_csc_feature_crank_revolution_data,
    &hf_btatt_csc_feature_wheel_revolution_data,
    NULL
};

static const int *hfx_btatt_descriptor_value_changed_flags[] = {
    &hf_btatt_descriptor_value_changed_flags_reserved,
    &hf_btatt_descriptor_value_changed_flags_change_to_characteristic_user_description_descriptor,
    &hf_btatt_descriptor_value_changed_flags_change_to_es_measurement_descriptor,
    &hf_btatt_descriptor_value_changed_flags_change_to_es_configuration_descriptor,
    &hf_btatt_descriptor_value_changed_flags_change_to_one_or_more_es_trigger_setting_descriptors,
    &hf_btatt_descriptor_value_changed_flags_source_of_change,
    NULL
};

static const int *hfx_btatt_cycling_power_feature[] = {
    &hf_btatt_cycling_power_feature_reserved,
    &hf_btatt_cycling_power_feature_factory_calibration_date,
    &hf_btatt_cycling_power_feature_instantaneous_measurement_direction,
    &hf_btatt_cycling_power_feature_sensor_measurement_context,
    &hf_btatt_cycling_power_feature_span_length_adjustment,
    &hf_btatt_cycling_power_feature_chain_weight_adjustment,
    &hf_btatt_cycling_power_feature_chain_length_adjustment,
    &hf_btatt_cycling_power_feature_crank_length_adjustment,
    &hf_btatt_cycling_power_feature_multiple_sensor_locations,
    &hf_btatt_cycling_power_feature_cycling_power_measurement_characteristic_content_masking,
    &hf_btatt_cycling_power_feature_offset_compensation,
    &hf_btatt_cycling_power_feature_offset_compensation_indicator,
    &hf_btatt_cycling_power_feature_accumulated_energy,
    &hf_btatt_cycling_power_feature_top_and_bottom_dead_spot_angles,
    &hf_btatt_cycling_power_feature_extreme_angles,
    &hf_btatt_cycling_power_feature_extreme_magnitudes,
    &hf_btatt_cycling_power_feature_crank_revolution_data,
    &hf_btatt_cycling_power_feature_wheel_revolution_data,
    &hf_btatt_cycling_power_feature_accumulated_torque,
    &hf_btatt_cycling_power_feature_pedal_power_balance,
    NULL
};

static const int *hfx_btatt_ln_feature[] = {
    &hf_btatt_ln_feature_reserved,
    &hf_btatt_ln_feature_position_status,
    &hf_btatt_ln_feature_elevation_setting,
    &hf_btatt_ln_feature_fix_rate_setting,
    &hf_btatt_ln_feature_location_and_speed_characteristic_content_masking,
    &hf_btatt_ln_feature_vertical_dilution_of_precision,
    &hf_btatt_ln_feature_horizontal_dilution_of_precision,
    &hf_btatt_ln_feature_estimated_vertical_position_error,
    &hf_btatt_ln_feature_estimated_horizontal_position_error,
    &hf_btatt_ln_feature_time_to_first_fix,
    &hf_btatt_ln_feature_number_of_beacons_in_view,
    &hf_btatt_ln_feature_number_of_beacons_in_solution,
    &hf_btatt_ln_feature_estimated_time_of_arrival,
    &hf_btatt_ln_feature_remaining_vertical_distance,
    &hf_btatt_ln_feature_remaining_distance,
    &hf_btatt_ln_feature_utc_time,
    &hf_btatt_ln_feature_rolling_time,
    &hf_btatt_ln_feature_heading,
    &hf_btatt_ln_feature_elevation,
    &hf_btatt_ln_feature_location,
    &hf_btatt_ln_feature_total_distance,
    &hf_btatt_ln_feature_instantaneous_speed,
    NULL
};

static const int *hfx_btatt_body_composition_feature[] = {
    &hf_btatt_body_composition_feature_reserved,
    &hf_btatt_body_composition_feature_height_measurement_resolution,
    &hf_btatt_body_composition_feature_mass_measurement_resolution,
    &hf_btatt_body_composition_feature_height,
    &hf_btatt_body_composition_feature_weight,
    &hf_btatt_body_composition_feature_impedance,
    &hf_btatt_body_composition_feature_body_water_mass,
    &hf_btatt_body_composition_feature_soft_lean_mass,
    &hf_btatt_body_composition_feature_fat_free_mass,
    &hf_btatt_body_composition_feature_muscle_mass,
    &hf_btatt_body_composition_feature_muscle_percentage,
    &hf_btatt_body_composition_feature_basal_metabolism,
    &hf_btatt_body_composition_feature_multiple_users,
    &hf_btatt_body_composition_feature_timestamp,
    NULL
};

static const int *hfx_btatt_weight_scale_feature[] = {
    &hf_btatt_weight_scale_feature_reserved,
    &hf_btatt_weight_scale_feature_height_measurement_resolution,
    &hf_btatt_weight_scale_feature_weight_measurement_resolution,
    &hf_btatt_weight_scale_feature_bmi,
    &hf_btatt_weight_scale_feature_multiple_users,
    &hf_btatt_weight_scale_feature_timestamp,
    NULL
};

static const int *hfx_btatt_glucose_measurement_flags[] = {
    &hf_btatt_glucose_measurement_flags_reserved,
    &hf_btatt_glucose_measurement_flags_context_information_follows,
    &hf_btatt_glucose_measurement_flags_sensor_status_annunciation_present,
    &hf_btatt_glucose_measurement_flags_glucose_concentration_units,
    &hf_btatt_glucose_measurement_flags_glucose_concentration_type_and_sample_location_present,
    &hf_btatt_glucose_measurement_flags_time_offset_present,
    NULL
};

static const int *hfx_btatt_glucose_measurement_type_and_sample_location[] = {
    &hf_btatt_glucose_measurement_type_and_sample_location_type,
    &hf_btatt_glucose_measurement_type_and_sample_location_sample_location,
    NULL
};

static const int *hfx_btatt_glucose_measurement_sensor_status_annunciation[] = {
    &hf_btatt_glucose_measurement_sensor_status_annunciation_reserved,
    &hf_btatt_glucose_measurement_sensor_status_annunciation_time_fault,
    &hf_btatt_glucose_measurement_sensor_status_annunciation_general_fault,
    &hf_btatt_glucose_measurement_sensor_status_annunciation_read_interrupted,
    &hf_btatt_glucose_measurement_sensor_status_annunciation_temperature_too_low,
    &hf_btatt_glucose_measurement_sensor_status_annunciation_temperature_too_high,
    &hf_btatt_glucose_measurement_sensor_status_annunciation_result_too_lower,
    &hf_btatt_glucose_measurement_sensor_status_annunciation_result_too_high,
    &hf_btatt_glucose_measurement_sensor_status_annunciation_strip_type_incorrect,
    &hf_btatt_glucose_measurement_sensor_status_annunciation_strip_insertion_error,
    &hf_btatt_glucose_measurement_sensor_status_annunciation_size_insufficient,
    &hf_btatt_glucose_measurement_sensor_status_annunciation_fault,
    &hf_btatt_glucose_measurement_sensor_status_annunciation_battery_low,
    NULL
};

static const int *hfx_btatt_bond_management_feature[] = {
    &hf_btatt_bond_management_feature_feature_extension,
    &hf_btatt_bond_management_feature_reserved,
    &hf_btatt_bond_management_feature_identify_yourself,
    &hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_9,
    &hf_btatt_bond_management_feature_remove_all_but_the_active_bond_on_le_transport_only_server,
    &hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_8,
    &hf_btatt_bond_management_feature_remove_all_but_the_active_bond_on_br_edr_transport_only_server,
    &hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_7,
    &hf_btatt_bond_management_feature_remove_all_but_the_active_bond_on_br_edr_and_le_server,
    &hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_6,
    &hf_btatt_bond_management_feature_remove_all_bonds_on_le_transport_only_server,
    &hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_5,
    &hf_btatt_bond_management_feature_remove_all_bonds_on_br_edr_transport_only_server,
    &hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_4,
    &hf_btatt_bond_management_feature_remove_all_bonds_on_br_edr_and_le_server,
    &hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_3,
    &hf_btatt_bond_management_feature_delete_bond_of_current_le_transport_only_connection,
    &hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_2,
    &hf_btatt_bond_management_feature_delete_bond_of_current_br_edr_transport_only_connection,
    &hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_1,
    &hf_btatt_bond_management_feature_delete_bond_of_current_br_edr_and_le_connection,
    NULL
};

static const int *hfx_btatt_bond_management_feature_nth[] = {
    &hf_btatt_bond_management_feature_nth_feature_extension,
    &hf_btatt_bond_management_feature_nth_reserved,
    NULL
};

static const int *hfx_btatt_temperature_measurement_flags[] = {
    &hf_btatt_temperature_measurement_flags_reserved,
    &hf_btatt_temperature_measurement_flags_temperature_type,
    &hf_btatt_temperature_measurement_flags_timestamp,
    &hf_btatt_temperature_measurement_flags_temperature_unit,
    NULL
};

static const int *hfx_btatt_glucose_measurement_context_flags[] = {
    &hf_btatt_glucose_measurement_context_flags_extended_flags,
    &hf_btatt_glucose_measurement_context_flags_hba1c,
    &hf_btatt_glucose_measurement_context_flags_medication_value_units,
    &hf_btatt_glucose_measurement_context_flags_medication_id_and_medication,
    &hf_btatt_glucose_measurement_context_flags_exercise_duration_and_exercise_intensity,
    &hf_btatt_glucose_measurement_context_flags_tester_health,
    &hf_btatt_glucose_measurement_context_flags_meal,
    &hf_btatt_glucose_measurement_context_flags_carbohydrate_id_and_carbohydrate,
    NULL
};

static const int *hfx_btatt_glucose_measurement_context_extended_flags[] = {
    &hf_btatt_glucose_measurement_context_extended_flags_reserved,
    NULL
};

static const int *hfx_btatt_glucose_measurement_context_tester_health[] = {
    &hf_btatt_glucose_measurement_context_tester,
    &hf_btatt_glucose_measurement_context_health,
    NULL
};

static const int *hfx_btatt_blood_pressure_measurement_flags[] = {
    &hf_btatt_blood_pressure_measurement_flags_reserved,
    &hf_btatt_blood_pressure_measurement_flags_measurement_status,
    &hf_btatt_blood_pressure_measurement_flags_user_id,
    &hf_btatt_blood_pressure_measurement_flags_pulse_rate,
    &hf_btatt_blood_pressure_measurement_flags_timestamp,
    &hf_btatt_blood_pressure_measurement_flags_unit,
    NULL
};

static const int *hfx_btatt_blood_pressure_measurement_status[] = {
    &hf_btatt_blood_pressure_measurement_status_reserved,
    &hf_btatt_blood_pressure_measurement_status_improper_measurement_position,
    &hf_btatt_blood_pressure_measurement_status_pulse_rate_range_detection,
    &hf_btatt_blood_pressure_measurement_status_irregular_pulse,
    &hf_btatt_blood_pressure_measurement_status_cuff_fit_too_loose,
    &hf_btatt_blood_pressure_measurement_status_body_movement,
    NULL
};

static const int *hfx_btatt_heart_rate_measurement_flags[] = {
    &hf_btatt_heart_rate_measurement_flags_reserved,
    &hf_btatt_heart_rate_measurement_flags_rr_interval,
    &hf_btatt_heart_rate_measurement_flags_energy_expended,
    &hf_btatt_heart_rate_measurement_flags_sensor_contact_status_support,
    &hf_btatt_heart_rate_measurement_flags_sensor_contact_status_contact,
    &hf_btatt_heart_rate_measurement_flags_value_16,
    NULL
};

static const int *hfx_btatt_uncertainty[] = {
    &hf_btatt_uncertainty_reserved,
    &hf_btatt_uncertainty_precision,
    &hf_btatt_uncertainty_update_time,
    &hf_btatt_uncertainty_stationary,
    NULL
};

static const int *hfx_btatt_indoor_positioning_configuration[] = {
    &hf_btatt_indoor_positioning_configuration_reserved,
    &hf_btatt_indoor_positioning_configuration_location_name,
    &hf_btatt_indoor_positioning_configuration_uncertainty,
    &hf_btatt_indoor_positioning_configuration_floor_number,
    &hf_btatt_indoor_positioning_configuration_altitude,
    &hf_btatt_indoor_positioning_configuration_tx_power,
    &hf_btatt_indoor_positioning_configuration_coordinate_system,
    &hf_btatt_indoor_positioning_configuration_coordinates,
    NULL
};

static const int *hfx_btatt_rsc_measurement_flags[] = {
    &hf_btatt_rsc_measurement_flags_reserved,
    &hf_btatt_rsc_measurement_flags_type_of_movement,
    &hf_btatt_rsc_measurement_flags_total_distance_present,
    &hf_btatt_rsc_measurement_flags_instantaneous_stride_length_present,
    NULL
};

static const int *hfx_btatt_cycling_power_measurement_flags[] = {
    &hf_btatt_cycling_power_measurement_flags_reserved,
    &hf_btatt_cycling_power_measurement_flags_offset_compensation_indicator,
    &hf_btatt_cycling_power_measurement_flags_accumulated_energy,
    &hf_btatt_cycling_power_measurement_flags_bottom_dead_spot_angle,
    &hf_btatt_cycling_power_measurement_flags_top_dead_spot_angle,
    &hf_btatt_cycling_power_measurement_flags_extreme_angles,
    &hf_btatt_cycling_power_measurement_flags_extreme_torque_magnitudes,
    &hf_btatt_cycling_power_measurement_flags_extreme_force_magnitudes,
    &hf_btatt_cycling_power_measurement_flags_crank_revolution_data,
    &hf_btatt_cycling_power_measurement_flags_wheel_revolution_data,
    &hf_btatt_cycling_power_measurement_flags_accumulated_torque_source,
    &hf_btatt_cycling_power_measurement_flags_accumulated_torque,
    &hf_btatt_cycling_power_measurement_flags_pedal_power_balance_reference,
    &hf_btatt_cycling_power_measurement_flags_pedal_power_balance,
    NULL
};

static const int *hfx_btatt_cycling_power_measurement_extreme_angles[] = {
    &hf_btatt_cycling_power_measurement_extreme_angles_maximum,
    &hf_btatt_cycling_power_measurement_extreme_angles_minimum,
    NULL
};

static const int *hfx_btatt_csc_measurement_flags[] = {
    &hf_btatt_csc_measurement_flags_reserved,
    &hf_btatt_csc_measurement_flags_crank_revolution_data,
    &hf_btatt_csc_measurement_flags_wheel_revolution_data,
    NULL
};

static const int *hfx_btatt_cycling_power_vector_flags[] = {
    &hf_btatt_cycling_power_vector_flags_reserved,
    &hf_btatt_cycling_power_vector_flags_instantaneous_measurement_direction,
    &hf_btatt_cycling_power_vector_flags_instantaneous_torque_magnitude_array,
    &hf_btatt_cycling_power_vector_flags_instantaneous_force_magnitude_array,
    &hf_btatt_cycling_power_vector_flags_first_crank_measurement_angle,
    &hf_btatt_cycling_power_vector_flags_crank_revolution_data,
    NULL
};

static const int *hfx_btatt_cycling_power_control_point_content_mask[] = {
    &hf_btatt_cycling_power_control_point_content_mask_reserved,
    &hf_btatt_cycling_power_control_point_content_mask_accumulated_energy,
    &hf_btatt_cycling_power_control_point_content_mask_bottom_dead_spot_angle,
    &hf_btatt_cycling_power_control_point_content_mask_top_dead_spot_angle,
    &hf_btatt_cycling_power_control_point_content_mask_extreme_angles,
    &hf_btatt_cycling_power_control_point_content_mask_extreme_magnitudes,
    &hf_btatt_cycling_power_control_point_content_mask_crank_revolution_data,
    &hf_btatt_cycling_power_control_point_content_mask_wheel_revolution_data,
    &hf_btatt_cycling_power_control_point_content_mask_accumulated_torque,
    &hf_btatt_cycling_power_control_point_content_mask_pedal_power_balance,
    NULL
};

static const int *hfx_btatt_location_and_speed_flags[] = {
    &hf_btatt_location_and_speed_flags_reserved,
    &hf_btatt_location_and_speed_flags_heading_source,
    &hf_btatt_location_and_speed_flags_elevation_source,
    &hf_btatt_location_and_speed_flags_speed_and_distance_format,
    &hf_btatt_location_and_speed_flags_position_status,
    &hf_btatt_location_and_speed_flags_utc_time,
    &hf_btatt_location_and_speed_flags_rolling_time,
    &hf_btatt_location_and_speed_flags_heading,
    &hf_btatt_location_and_speed_flags_elevation,
    &hf_btatt_location_and_speed_flags_location,
    &hf_btatt_location_and_speed_flags_total_distance,
    &hf_btatt_location_and_speed_flags_instantaneous_speed,
    NULL
};

static const int *hfx_btatt_navigation_flags[] = {
    &hf_btatt_navigation_flags_reserved,
    &hf_btatt_navigation_flags_destination_reached,
    &hf_btatt_navigation_flags_waypoint_reached,
    &hf_btatt_navigation_flags_navigation_indicator_type,
    &hf_btatt_navigation_flags_heading_source,
    &hf_btatt_navigation_flags_position_status,
    &hf_btatt_navigation_flags_estimated_time_of_arrival,
    &hf_btatt_navigation_flags_remaining_vertical_distance,
    &hf_btatt_navigation_flags_remaining_distance,
    NULL
};

static const int *hfx_btatt_position_quality_flags[] = {
    &hf_btatt_position_quality_flags_reserved,
    &hf_btatt_position_quality_flags_position_status,
    &hf_btatt_position_quality_flags_vdop,
    &hf_btatt_position_quality_flags_hdop,
    &hf_btatt_position_quality_flags_evpe,
    &hf_btatt_position_quality_flags_ehpe,
    &hf_btatt_position_quality_flags_time_to_first_fix,
    &hf_btatt_position_quality_flags_number_of_beacons_in_view,
    &hf_btatt_position_quality_flags_number_of_beacons_in_solution,
    NULL
};

static const int *hfx_btatt_ln_control_point_content_mask[] = {
    &hf_btatt_ln_control_point_content_mask_reserved,
    &hf_btatt_ln_control_point_content_mask_utc_time,
    &hf_btatt_ln_control_point_content_mask_rolling_time,
    &hf_btatt_ln_control_point_content_mask_heading,
    &hf_btatt_ln_control_point_content_mask_elevation,
    &hf_btatt_ln_control_point_content_mask_location,
    &hf_btatt_ln_control_point_content_mask_total_distance,
    &hf_btatt_ln_control_point_content_mask_instantaneous_speed,
    NULL
};

static const int *hfx_btatt_body_composition_measurement_flags[] = {
    &hf_btatt_body_composition_measurement_flags_reserved,
    &hf_btatt_body_composition_measurement_flags_multiple_packet_measurement,
    &hf_btatt_body_composition_measurement_flags_height,
    &hf_btatt_body_composition_measurement_flags_weight,
    &hf_btatt_body_composition_measurement_flags_impedance,
    &hf_btatt_body_composition_measurement_flags_body_water_mass,
    &hf_btatt_body_composition_measurement_flags_soft_lean_mass,
    &hf_btatt_body_composition_measurement_flags_fat_free_mass,
    &hf_btatt_body_composition_measurement_flags_muscle_mass,
    &hf_btatt_body_composition_measurement_flags_muscle_percentage,
    &hf_btatt_body_composition_measurement_flags_basal_metabolism,
    &hf_btatt_body_composition_measurement_flags_user_id,
    &hf_btatt_body_composition_measurement_flags_timestamp,
    &hf_btatt_body_composition_measurement_flags_measurement_units,
    NULL
};

static const int *hfx_btatt_weight_measurement_flags[] = {
    &hf_btatt_weight_measurement_flags_reserved,
    &hf_btatt_weight_measurement_flags_bmi_and_height,
    &hf_btatt_weight_measurement_flags_user_id,
    &hf_btatt_weight_measurement_flags_timestamp,
    &hf_btatt_weight_measurement_flags_measurement_units,
    NULL
};

static const int *hfx_btatt_cgm_measurement_flags[] = {
    &hf_btatt_cgm_measurement_flags_cgm_trend_information,
    &hf_btatt_cgm_measurement_flags_cgm_quality,
    &hf_btatt_cgm_measurement_flags_reserved,
    &hf_btatt_cgm_measurement_flags_sensor_status_annunciation_warning,
    &hf_btatt_cgm_measurement_flags_sensor_status_annunciation_cal_temp,
    &hf_btatt_cgm_measurement_flags_sensor_status_annunciation_status,
    NULL
};

static const int *hfx_btatt_cgm_sensor_status_annunciation_status[] = {
    &hf_btatt_cgm_sensor_status_annunciation_status_reserved,
    &hf_btatt_cgm_sensor_status_annunciation_status_general_device_fault_has_occurred_in_the_sensor,
    &hf_btatt_cgm_sensor_status_annunciation_status_device_specific_alert,
    &hf_btatt_cgm_sensor_status_annunciation_status_sensor_malfunction,
    &hf_btatt_cgm_sensor_status_annunciation_status_sensor_type_incorrect_for_device,
    &hf_btatt_cgm_sensor_status_annunciation_status_device_battery_low,
    &hf_btatt_cgm_sensor_status_annunciation_status_session_stopped,
    NULL
};

static const int *hfx_btatt_cgm_sensor_status_annunciation_cal_temp[] = {
    &hf_btatt_cgm_sensor_status_annunciation_cal_temp_reserved,
    &hf_btatt_cgm_sensor_status_annunciation_cal_temp_sensor_temperature_too_low_for_valid_test_result_at_time_of_measurement,
    &hf_btatt_cgm_sensor_status_annunciation_cal_temp_sensor_temperature_too_high_for_valid_test_result_at_time_of_measurement,
    &hf_btatt_cgm_sensor_status_annunciation_cal_temp_calibration_required,
    &hf_btatt_cgm_sensor_status_annunciation_cal_temp_calibration_recommended,
    &hf_btatt_cgm_sensor_status_annunciation_cal_temp_calibration_not_allowed,
    &hf_btatt_cgm_sensor_status_annunciation_cal_temp_time_synchronization_between_sensor_and_collector_required,
    NULL
};

static const int *hfx_btatt_cgm_sensor_status_annunciation_warning[] = {
    &hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_higher_than_the_device_can_process,
    &hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_lower_than_the_device_can_process,
    &hf_btatt_cgm_sensor_status_annunciation_warning_sensor_rate_of_increase_exceeded,
    &hf_btatt_cgm_sensor_status_annunciation_warning_sensor_rate_of_decrease_exceeded,
    &hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_higher_than_the_hyper_level,
    &hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_lower_than_the_hypo_level,
    &hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_higher_than_the_patient_high_level,
    &hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_lower_than_the_patient_low_level,
    NULL
};

static const int *hfx_btatt_cgm_feature_feature[] = {
    &hf_btatt_cgm_feature_feature_reserved,
    &hf_btatt_cgm_feature_feature_quality,
    &hf_btatt_cgm_feature_feature_trend_information,
    &hf_btatt_cgm_feature_feature_multiple_sessions,
    &hf_btatt_cgm_feature_feature_multiple_bond,
    &hf_btatt_cgm_feature_feature_e2e_crc,
    &hf_btatt_cgm_feature_feature_general_device_fault,
    &hf_btatt_cgm_feature_feature_sensor_type_error_detection,
    &hf_btatt_cgm_feature_feature_low_battery_detection,
    &hf_btatt_cgm_feature_feature_sensor_result_high_low_detection,
    &hf_btatt_cgm_feature_feature_sensor_temperature_high_low_detection,
    &hf_btatt_cgm_feature_feature_sensor_malfunction_detection,
    &hf_btatt_cgm_feature_feature_device_specific_alert,
    &hf_btatt_cgm_feature_feature_rate_of_increase_decrease_alerts,
    &hf_btatt_cgm_feature_feature_hyper_alerts,
    &hf_btatt_cgm_feature_feature_hypo_alerts,
    &hf_btatt_cgm_feature_feature_patient_high_low_alerts,
    &hf_btatt_cgm_feature_feature_calibration,
    NULL
};

static const int *hfx_btatt_cgm_type_and_sample_location[] = {
    &hf_btatt_cgm_type,
    &hf_btatt_cgm_sample_location,
    NULL
};

static const int *hfx_btatt_cgm_specific_ops_control_point_calibration_status[] = {
    &hf_btatt_cgm_specific_ops_control_point_calibration_status_reserved,
    &hf_btatt_cgm_specific_ops_control_point_calibration_status_pending,
    &hf_btatt_cgm_specific_ops_control_point_calibration_status_out_of_range,
    &hf_btatt_cgm_specific_ops_control_point_calibration_status_rejected,
    NULL
};

static const int *hfx_btatt_http_data_status[] = {
    &hf_btatt_http_data_status_reserved,
    &hf_btatt_http_data_status_body_truncated,
    &hf_btatt_http_data_status_body_received,
    &hf_btatt_http_data_status_headers_truncated,
    &hf_btatt_http_data_status_headers_received,
    NULL
};

static const int *hfx_btatt_ots_feature_oacp[] = {
    &hf_btatt_ots_feature_oacp_reserved,
    &hf_btatt_ots_feature_oacp_abort,
    &hf_btatt_ots_feature_oacp_patching_of_object,
    &hf_btatt_ots_feature_oacp_truncation_of_objects,
    &hf_btatt_ots_feature_oacp_appending_additional_data_to_object,
    &hf_btatt_ots_feature_oacp_write,
    &hf_btatt_ots_feature_oacp_read,
    &hf_btatt_ots_feature_oacp_execute,
    &hf_btatt_ots_feature_oacp_calculate_checksum,
    &hf_btatt_ots_feature_oacp_delete,
    &hf_btatt_ots_feature_oacp_create,
    NULL
};

static const int *hfx_btatt_ots_feature_olcp[] = {
    &hf_btatt_ots_feature_olcp_reserved,
    &hf_btatt_ots_feature_olcp_clear_marking,
    &hf_btatt_ots_feature_olcp_request_number_of_objects,
    &hf_btatt_ots_feature_olcp_order,
    &hf_btatt_ots_feature_olcp_go_to,
    NULL
};

static const int *hfx_btatt_ots_properties[] = {
    &hf_btatt_ots_properties_reserved,
    &hf_btatt_ots_properties_mark,
    &hf_btatt_ots_properties_patch,
    &hf_btatt_ots_properties_truncate,
    &hf_btatt_ots_properties_append,
    &hf_btatt_ots_properties_write,
    &hf_btatt_ots_properties_read,
    &hf_btatt_ots_properties_execute,
    &hf_btatt_ots_properties_delete,
    NULL
};


static const int *hfx_btatt_ots_flags[] = {
    &hf_btatt_ots_flags_reserved,
    &hf_btatt_ots_flags_object_deletion,
    &hf_btatt_ots_flags_object_creation,
    &hf_btatt_ots_flags_change_occured_to_the_object_metadata,
    &hf_btatt_ots_flags_change_occured_to_the_object_contents,
    &hf_btatt_ots_flags_source_of_change,
    NULL
};

static const int *hfx_btatt_plx_spot_check_measurement_flags[] = {
    &hf_btatt_plx_spot_check_measurement_flags_reserved,
    &hf_btatt_plx_spot_check_measurement_flags_device_clock_is_not_set,
    &hf_btatt_plx_spot_check_measurement_flags_pulse_amplitude_index,
    &hf_btatt_plx_spot_check_measurement_flags_device_and_sensor_status,
    &hf_btatt_plx_spot_check_measurement_flags_measurement_status,
    &hf_btatt_plx_spot_check_measurement_flags_timestamp,
    NULL
};

static const int *hfx_btatt_plx_measurement_status[] = {
    &hf_btatt_plx_measurement_status_invalid_measurement_detected,
    &hf_btatt_plx_measurement_status_questionable_measurement_detected,
    &hf_btatt_plx_measurement_status_measurement_unavailable,
    &hf_btatt_plx_measurement_status_calibration_ongoing,
    &hf_btatt_plx_measurement_status_data_for_testing,
    &hf_btatt_plx_measurement_status_data_for_demonstration,
    &hf_btatt_plx_measurement_status_data_from_measurement_storage,
    &hf_btatt_plx_measurement_status_fully_qualified_data,
    &hf_btatt_plx_measurement_status_validated_data,
    &hf_btatt_plx_measurement_status_early_estimated_data,
    &hf_btatt_plx_measurement_status_measurement_ongoing,
    &hf_btatt_plx_measurement_status_reserved,
    NULL
};

static const int *hfx_btatt_plx_device_and_sensor_status[] = {
    &hf_btatt_plx_device_and_sensor_status_reserved,
    &hf_btatt_plx_device_and_sensor_status_sensor_disconnected,
    &hf_btatt_plx_device_and_sensor_status_sensor_malfunctioning,
    &hf_btatt_plx_device_and_sensor_status_sensor_displaced,
    &hf_btatt_plx_device_and_sensor_status_unknown_sensor_connected,
    &hf_btatt_plx_device_and_sensor_status_sensor_unconnected_to_user,
    &hf_btatt_plx_device_and_sensor_status_sensor_interference_detected,
    &hf_btatt_plx_device_and_sensor_status_signal_analysis_ongoing,
    &hf_btatt_plx_device_and_sensor_status_questionable_pulse_detected,
    &hf_btatt_plx_device_and_sensor_status_non_pulsatile_signal_detected,
    &hf_btatt_plx_device_and_sensor_status_erratic_signal_detected,
    &hf_btatt_plx_device_and_sensor_status_low_perfusion_detected,
    &hf_btatt_plx_device_and_sensor_status_poor_signal_detected,
    &hf_btatt_plx_device_and_sensor_status_inadequate_signal_detected,
    &hf_btatt_plx_device_and_sensor_status_signal_processing_irregularity_detected,
    &hf_btatt_plx_device_and_sensor_status_equipment_malfunction_detected,
    &hf_btatt_plx_device_and_sensor_status_extended_display_update_ongoing,
    NULL
};

static const int *hfx_btatt_plx_continuous_measurement_flags[] = {
    &hf_btatt_plx_continuous_measurement_flags_reserved,
    &hf_btatt_plx_continuous_measurement_flags_pulse_amplitude_index,
    &hf_btatt_plx_continuous_measurement_flags_device_and_sensor_status,
    &hf_btatt_plx_continuous_measurement_flags_measurement_status,
    &hf_btatt_plx_continuous_measurement_flags_spo2pr_slow,
    &hf_btatt_plx_continuous_measurement_flags_spo2pr_fast,
    NULL
};

static const int *hfx_btatt_plx_features_supported_features[] = {
    &hf_btatt_plx_features_supported_features_reserved,
    &hf_btatt_plx_features_supported_features_multiple_bonds,
    &hf_btatt_plx_features_supported_features_pulse_amplitude_index,
    &hf_btatt_plx_features_supported_features_spo2pr_slow,
    &hf_btatt_plx_features_supported_features_spo2pr_fast,
    &hf_btatt_plx_features_supported_features_timestamp_storage_for_spot_check,
    &hf_btatt_plx_features_supported_features_measurement_storage_for_spot_check,
    &hf_btatt_plx_features_supported_features_device_and_sensor_status,
    &hf_btatt_plx_features_supported_features_measurement_status,
    NULL
};

/* Initialize the subtree pointers */
static gint ett_btatt = -1;
static gint ett_btatt_list = -1;
static gint ett_btatt_value = -1;
static gint ett_btatt_opcode = -1;
static gint ett_btatt_handle = -1;
static gint ett_btatt_characteristic_properties = -1;
static gint ett_btgatt = -1;

static expert_field ei_btatt_uuid_format_unknown = EI_INIT;
static expert_field ei_btatt_handle_too_few = EI_INIT;
static expert_field ei_btatt_mtu_exceeded = EI_INIT;
static expert_field ei_btatt_mtu_full = EI_INIT;
static expert_field ei_btatt_consent_out_of_bounds = EI_INIT;
static expert_field ei_btatt_cgm_size_too_small = EI_INIT;
static expert_field ei_btatt_opcode_invalid_request = EI_INIT;
static expert_field ei_btatt_opcode_invalid_response = EI_INIT;
       expert_field ei_btatt_invalid_usage = EI_INIT;
static expert_field ei_btatt_bad_data = EI_INIT;
static expert_field ei_btatt_unexpected_data = EI_INIT;
static expert_field ei_btatt_undecoded = EI_INIT;

static wmem_tree_t *mtus = NULL;
static wmem_tree_t *requests = NULL;
static wmem_tree_t *fragments = NULL;
static wmem_tree_t *handle_to_uuid = NULL;

static dissector_handle_t btatt_handle;
static dissector_handle_t btgatt_handle;
static dissector_handle_t http_handle;
static dissector_handle_t usb_hid_boot_keyboard_input_report_handle;
static dissector_handle_t usb_hid_boot_keyboard_output_report_handle;
static dissector_handle_t usb_hid_boot_mouse_input_report_handle;

static dissector_table_t att_handle_dissector_table;

extern value_string_ext ext_usb_vendors_vals;

/* Opcodes */
static const value_string opcode_vals[] = {
    {0x01, "Error Response"},
    {0x02, "Exchange MTU Request"},
    {0x03, "Exchange MTU Response"},
    {0x04, "Find Information Request"},
    {0x05, "Find Information Response"},
    {0x06, "Find By Type Value Request"},
    {0x07, "Find By Type Value Response"},
    {0x08, "Read By Type Request"},
    {0x09, "Read By Type Response"},
    {0x0a, "Read Request"},
    {0x0b, "Read Response"},
    {0x0c, "Read Blob Request"},
    {0x0d, "Read Blob Response"},
    {0x0e, "Read Multiple Request"},
    {0x0f, "Read Multiple Response"},
    {0x10, "Read By Group Type Request"},
    {0x11, "Read By Group Type Response"},
    {0x12, "Write Request"},
    {0x13, "Write Response"},
    {0x16, "Prepare Write Request"},
    {0x17, "Prepare Write Response"},
    {0x18, "Execute Write Request"},
    {0x19, "Execute Write Response"},
    {0x1B, "Handle Value Notification"},
    {0x1D, "Handle Value Indication"},
    {0x1E, "Handle Value Confirmation"},
    {0x52, "Write Command"},
    {0xD2, "Signed Write Command"},
    {0x0, NULL}
};

#define ATT_OPCODE_READ_BY_TYPE_REQUEST         0x08
#define ATT_OPCODE_READ_BY_TYPE_RESPONSE        0x09

#define ATT_OPCODE_READ_REQUEST                 0x0A
#define ATT_OPCODE_READ_RESPONSE                0x0B
#define ATT_OPCODE_READ_BLOB_REQUEST            0x0C
#define ATT_OPCODE_READ_BLOB_RESPONSE           0x0D
#define ATT_OPCODE_READ_MULTIPLE_REQUEST        0x0E
#define ATT_OPCODE_READ_MULTIPLE_RESPONSE       0x0F

#define ATT_OPCODE_READ_BY_GROUP_TYPE_REQUEST   0x10
#define ATT_OPCODE_READ_BY_GROUP_TYPE_RESPONSE  0x11

#define ATT_OPCODE_WRITE_REQUEST                0x12
#define ATT_OPCODE_WRITE_RESPONSE               0x13
#define ATT_OPCODE_WRITE_PREPARE_REQUEST        0x16
#define ATT_OPCODE_WRITE_PREPARE_RESPONSE       0x17
#define ATT_OPCODE_WRITE_COMMAND                0x52
#define ATT_OPCODE_WRITE_SIGNED_COMMAND         0xD2

#define ATT_OPCODE_HANDLE_VALUE_NOTIFICATION    0x1B
#define ATT_OPCODE_HANDLE_VALUE_INDICATION      0x1D
#define ATT_OPCODE_HANDLE_VALUE_CONFIRMATION    0x1E

#define GATT_SERVICE_GENERIC_ACCESS_PROFILE         0x1800
#define GATT_SERVICE_GENERIC_ATTRIBUTE_PROFILE      0x1801
#define GATT_SERVICE_IMMEDIATE_ALERT                0x1802
#define GATT_SERVICE_LINK_LOSS                      0x1803
#define GATT_SERVICE_TX_POWER                       0x1804
#define GATT_SERVICE_CURRENT_TIME_SERVICE           0x1805
#define GATT_SERVICE_REFERENCE_TIME_UPDATE_SERVICE  0x1806
#define GATT_SERVICE_NEXT_DST_CHANGE_SERVICE        0x1807
#define GATT_SERVICE_GLUCOSE                        0x1808
#define GATT_SERVICE_HEALTH_THERMOMETER             0x1809
#define GATT_SERVICE_DEVICE_INFORMATION             0x180A
#define GATT_SERVICE_HEART_RATE                     0x180D
#define GATT_SERVICE_PHONE_ALERT_STATUS_SERVICE     0x180E
#define GATT_SERVICE_BATTERY_SERVICE                0x180F
#define GATT_SERVICE_BLOOD_PRESSURE                 0x1810
#define GATT_SERVICE_ALERT_NOTIFICATION_SERVICE     0x1811
#define GATT_SERVICE_HUMAN_INTERFACE_DEVICE         0x1812
#define GATT_SERVICE_SCAN_PARAMETERS                0x1813
#define GATT_SERVICE_RUNNING_SPEED_AND_CADENCE      0x1814
#define GATT_SERVICE_AUTOMATION_IO                  0x1815
#define GATT_SERVICE_CYCLING_SPEED_AND_CADENCE      0x1816
#define GATT_SERVICE_CYCLING_POWER                  0x1818
#define GATT_SERVICE_LOCATION_AND_NAVIGATION        0x1819
#define GATT_SERVICE_ENVIRONMENTAL_SENSING          0x181A
#define GATT_SERVICE_BODY_COMPOSITION               0x181B
#define GATT_SERVICE_USER_DATA                      0x181C
#define GATT_SERVICE_WEIGHT_SCALE                   0x181D
#define GATT_SERVICE_BOND_MANAGEMENT                0x181E
#define GATT_SERVICE_CONTINUOUS_GLUCOSE_MONITORING  0x181F
#define GATT_SERVICE_INTERNET_PROTOCOL_SUPPORT      0x1820
#define GATT_SERVICE_INDOOR_POSITIONING             0x1821
#define GATT_SERVICE_PULSE_OXIMETER                 0x1822
#define GATT_SERVICE_HTTP_PROXY                     0x1823
#define GATT_SERVICE_TRANSPORT_DISCOVERY            0x1824
#define GATT_SERVICE_OBJECT_TRANSFER                0x1825

/* Error codes */
static const value_string error_code_vals[] = {
    {0x01, "Invalid Handle"},
    {0x02, "Read Not Permitted"},
    {0x03, "Write Not Permitted"},
    {0x04, "Invalid PDU"},
    {0x05, "Insufficient Authentication"},
    {0x06, "Request Not Supported"},
    {0x07, "Invalid Offset"},
    {0x08, "Insufficient Authorization"},
    {0x09, "Prepare Queue Full"},
    {0x0A, "Attribute Not Found"},
    {0x0B, "Attribute Not Long"},
    {0x0C, "Insufficient Encryption Key Size"},
    {0x0D, "Invalid Attribute Value Length"},
    {0x0E, "Unlikely Error"},
    {0x0F, "Insufficient Encryption"},
    {0x10, "Unsupported Group Type"},
    {0x11, "Insufficient Resources"},
    {0x80, "Application Error 0x80"},
    {0x81, "Application Error 0x81"},
    {0x82, "Application Error 0x82"},
    {0x83, "Application Error 0x83"},
    {0x84, "Application Error 0x84"},
    {0x85, "Application Error 0x85"},
    {0x86, "Application Error 0x86"},
    {0x87, "Application Error 0x87"},
    {0x88, "Application Error 0x88"},
    {0x89, "Application Error 0x89"},
    {0x8A, "Application Error 0x8A"},
    {0x8B, "Application Error 0x8B"},
    {0x8C, "Application Error 0x8C"},
    {0x8D, "Application Error 0x8D"},
    {0x8E, "Application Error 0x8E"},
    {0x8F, "Application Error 0x8F"},
    {0x90, "Application Error 0x90"},
    {0x91, "Application Error 0x91"},
    {0x92, "Application Error 0x92"},
    {0x93, "Application Error 0x93"},
    {0x94, "Application Error 0x94"},
    {0x95, "Application Error 0x95"},
    {0x96, "Application Error 0x96"},
    {0x97, "Application Error 0x97"},
    {0x98, "Application Error 0x98"},
    {0x99, "Application Error 0x99"},
    {0x9A, "Application Error 0x9A"},
    {0x9B, "Application Error 0x9B"},
    {0x9C, "Application Error 0x9C"},
    {0x9D, "Application Error 0x9D"},
    {0x9E, "Application Error 0x9E"},
    {0x9F, "Application Error 0x9F"},
    {0xFD, "Improper Client Characteristic Configuration Descriptor"},
    {0xFE, "Procedure Already In Progress"},
    {0xFF, "Out of Range"},
    {0x0, NULL}
};

static const value_string error_code_aios_vals[] = {
    {0x80, "Trigger Condition Value not Supported"},
    {0x0, NULL}
};

static const value_string error_code_ans_vals[] = {
    {0xA0, "Command not Supported"},
    {0x0, NULL}
};

static const value_string error_code_bms_vals[] = {
    {0x80, "Opcode not Supported"},
    {0x81, "Operation Failed"},
    {0x0, NULL}
};

static const value_string error_code_cgms_vals[] = {
    {0x80, "Missing CRC"},
    {0x81, "Invalid CRC"},
    {0x0, NULL}
};

static const value_string error_code_cps_vals[] = {
    {0x80, "Inappropriate Connection Parameters"},
    {0x0, NULL}
};

static const value_string error_code_cscs_vals[] = {
    {0x80, "Procedure Already in Progress"},
    {0x81, "Client Characteristic Configuration Descriptor Improperly Configured"},
    {0x0, NULL}
};

static const value_string error_code_cts_vals[] = {
    {0x80, "Data Field Ignored"},
    {0x0, NULL}
};

static const value_string error_code_ess_vals[] = {
    {0x80, "Write Request Rejected"},
    {0x81, "Condition not Supported"},
    {0x0, NULL}
};

static const value_string error_code_gls_vals[] = {
    {0x80, "Procedure Already in Progress"},
    {0x81, "Client Characteristic Configuration Descriptor Improperly Configured"},
    {0x0, NULL}
};

static const value_string error_code_hps_vals[] = {
    {0x81, "Invalid Request"},
    {0x82, "Network not Available"},
    {0x0, NULL}
};

static const value_string error_code_hrs_vals[] = {
    {0x80, "Control Point not Supported"},
    {0x0, NULL}
};

static const value_string error_code_hts_vals[] = {
    {0x80, "Out of Range"},
    {0x0, NULL}
};

static const value_string error_code_ips_vals[] = {
    {0x80, "Invalid Value"},
    {0x0, NULL}
};

static const value_string error_code_ots_vals[] = {
    {0x80, "Write Request Rejected"},
    {0x81, "Object not Selected"},
    {0x82, "Concurrency Limit Exceeded"},
    {0x83, "Object Name Already Exists"},
    {0x0, NULL}
};

static const value_string error_code_rscs_vals[] = {
    {0x80, "Procedure Already in Progress"},
    {0x81, "Client Characteristic Configuration Descriptor Improperly Configured"},
    {0x0, NULL}
};

static const value_string error_code_uds_vals[] = {
    {0x80, "User Data Access not Permitted"},
    {0x0, NULL}
};

static const value_string uuid_format_vals[] = {
    {0x01, "16-bit UUIDs"},
    {0x02, "128-bit UUIDs"},
    {0x0, NULL}
};

static const value_string flags_vals[] = {
    {0x00, "Cancel All"},
    {0x01, "Immediately Write All"},
    {0x0, NULL}
};

static const value_string hogp_protocol_mode_vals[] = {
    {0x00, "Boot Protocol Mode"},
    {0x01, "Report Protocol Mode"},
    {0x0, NULL}
};

static const value_string report_reference_report_type_vals[] = {
    {0x01, "Input Report"},
    {0x02, "Output Report"},
    {0x03, "Feature Report"},
    {0x0, NULL}
};

static const value_string characteristic_presentation_format_vals[] = {
    {0x01, "unsigned 1-bit"},
    {0x02, "unsigned 2-bit integer"},
    {0x03, "unsigned 4-bit integer"},
    {0x04, "unsigned 8-bit integer"},
    {0x05, "unsigned 12-bit integer"},
    {0x06, "unsigned 16-bit integer"},
    {0x07, "unsigned 24-bit integer"},
    {0x08, "unsigned 32-bit integer"},
    {0x09, "unsigned 48-bit integer"},
    {0x0A, "unsigned 64-bit integer"},
    {0x0B, "unsigned 128-bit integer"},
    {0x0C, "signed 8-bit integer"},
    {0x0D, "signed 12-bit integer"},
    {0x0E, "signed 16-bit integer"},
    {0x0F, "signed 24-bit integer"},
    {0x10, "signed 32-bit integer"},
    {0x11, "signed 48-bit integer"},
    {0x12, "signed 64-bit integer"},
    {0x13, "signed 128-bit integer"},
    {0x14, "IEEE-754 32-bit floating point"},
    {0x15, "IEEE-754 64-bit floating point"},
    {0x16, "IEEE-11073 16-bit SFLOAT"},
    {0x17, "IEEE-11073 32-bit FLOAT"},
    {0x18, "IEEE-20601 format"},
    {0x19, "UTF-8 string"},
    {0x1A, "UTF-16 string"},
    {0x1B, "Opaque structure"},
    {0x0, NULL}
};

static const value_string characteristic_presentation_namespace_vals[] = {
    {0x01, "Bluetooth SIG"},
    {0x0, NULL}
};

static const value_string characteristic_presentation_namespace_description_btsig_vals[] = {
    {0x0000, "unknown"},
    {0x0001, "first"},
    {0x0002, "second"},
    {0x0003, "third"},
    {0x0004, "fourth"},
    {0x0005, "fifth"},
    {0x0006, "sixth"},
    {0x0007, "seventh"},
    {0x0008, "eighth"},
    {0x0009, "nineth"},
    {0x000a, "tenth"},
    {0x000b, "eleventh"},
    {0x000c, "twelveth"},
    {0x000d, "thirteenth"},
    {0x000e, "fourteenth"},
    {0x000f, "fifteenth"},
    {0x0010, "sixteenth"},
    {0x0011, "seventeenth"},
    {0x0012, "eighteenth"},
    {0x0013, "nineteenth"},
    {0x0014, "twentieth"},
    {0x0015, "twenty-first"},
    {0x0016, "twenty-second"},
    {0x0017, "twenty-third"},
    {0x0018, "twenty-fourth"},
    {0x0019, "twenty-fifth"},
    {0x001a, "twenty-sixth"},
    {0x001b, "twenty-seventh"},
    {0x001c, "twenty-eighth"},
    {0x001d, "twenty-nineth"},
    {0x001e, "thirtieth"},
    {0x001f, "thirty-first"},
    {0x0020, "thirty-second"},
    {0x0021, "thirty-third"},
    {0x0022, "thirty-fourth"},
    {0x0023, "thirty-fifth"},
    {0x0024, "thirty-sixth"},
    {0x0025, "thirty-seventh"},
    {0x0026, "thirty-eighth"},
    {0x0027, "thirty-nineth"},
    {0x0028, "fortieth"},
    {0x0029, "fourty-first"},
    {0x002a, "fourty-second"},
    {0x002b, "fourty-third"},
    {0x002c, "fourty-fourth"},
    {0x002d, "fourty-fifth"},
    {0x002e, "fourty-sixth"},
    {0x002f, "fourty-seventh"},
    {0x0030, "fourty-eighth"},
    {0x0031, "fourty-nineth"},
    {0x0032, "fiftieth"},
    {0x0033, "fifty-first"},
    {0x0034, "fifty-second"},
    {0x0035, "fifty-third"},
    {0x0036, "fifty-fourth"},
    {0x0037, "fifty-fifth"},
    {0x0038, "fifty-sixth"},
    {0x0039, "fifty-seventh"},
    {0x003a, "fifty-eighth"},
    {0x003b, "fifty-nineth"},
    {0x003c, "sixtieth"},
    {0x003d, "sixty-first"},
    {0x003e, "sixty-second"},
    {0x003f, "sixty-third"},
    {0x0040, "sixty-fourth"},
    {0x0041, "sixty-fifth"},
    {0x0042, "sixty-sixth"},
    {0x0043, "sixty-seventh"},
    {0x0044, "sixty-eighth"},
    {0x0045, "sixty-nineth"},
    {0x0046, "seventieth"},
    {0x0047, "seventy-first"},
    {0x0048, "seventy-second"},
    {0x0049, "seventy-third"},
    {0x004a, "seventy-fourth"},
    {0x004b, "seventy-fifth"},
    {0x004c, "seventy-sixth"},
    {0x004d, "seventy-seventh"},
    {0x004e, "seventy-eighth"},
    {0x004f, "seventy-nineth"},
    {0x0050, "eightieth"},
    {0x0051, "eighty-first"},
    {0x0052, "eighty-second"},
    {0x0053, "eighty-third"},
    {0x0054, "eighty-fourth"},
    {0x0055, "eighty-fifth"},
    {0x0056, "eighty-sixth"},
    {0x0057, "eighty-seventh"},
    {0x0058, "eighty-eighth"},
    {0x0059, "eighty-nineth"},
    {0x005a, "ninetieth"},
    {0x005b, "ninety-first"},
    {0x005c, "ninety-second"},
    {0x005d, "ninety-third"},
    {0x005e, "ninety-fourth"},
    {0x005f, "ninety-fifth"},
    {0x0060, "ninety-sixth"},
    {0x0061, "ninety-seventh"},
    {0x0062, "ninety-eighth"},
    {0x0063, "ninety-nineth"},
    {0x0064, "one-hundredth"},
    {0x0065, "one-hundred-and-first"},
    {0x0066, "one-hundred-and-second"},
    {0x0067, "one-hundred-and-third"},
    {0x0068, "one-hundred-and-fourth"},
    {0x0069, "one-hundred-and-fifth"},
    {0x006a, "one-hundred-and-sixth"},
    {0x006b, "one-hundred-and-seventh"},
    {0x006c, "one-hundred-and-eighth"},
    {0x006d, "one-hundred-and-nineth"},
    {0x006e, "one-hundred-and-tenth"},
    {0x006f, "one-hundred-and-eleventh"},
    {0x0070, "one-hundred-and-twelveth"},
    {0x0071, "one-hundred-and-thirteenth"},
    {0x0072, "one-hundred-and-fourteenth"},
    {0x0073, "one-hundred-and-fifteenth"},
    {0x0074, "one-hundred-and-sixteenth"},
    {0x0075, "one-hundred-and-seventeenth"},
    {0x0076, "one-hundred-and-eighteenth"},
    {0x0077, "one-hundred-and-nineteenth"},
    {0x0078, "one-hundred-twentieth"},
    {0x0079, "one-hundred-and-twenty-first"},
    {0x007a, "one-hundred-and-twenty-second"},
    {0x007b, "one-hundred-and-twenty-third"},
    {0x007c, "one-hundred-and-twenty-fourth"},
    {0x007d, "one-hundred-and-twenty-fifth"},
    {0x007e, "one-hundred-and-twenty-sixth"},
    {0x007f, "one-hundred-and-twenty-seventh"},
    {0x0080, "one-hundred-and-twenty-eighth"},
    {0x0081, "one-hundred-and-twenty-nineth"},
    {0x0082, "one-hundred-thirtieth"},
    {0x0083, "one-hundred-and-thirty-first"},
    {0x0084, "one-hundred-and-thirty-second"},
    {0x0085, "one-hundred-and-thirty-third"},
    {0x0086, "one-hundred-and-thirty-fourth"},
    {0x0087, "one-hundred-and-thirty-fifth"},
    {0x0088, "one-hundred-and-thirty-sixth"},
    {0x0089, "one-hundred-and-thirty-seventh"},
    {0x008a, "one-hundred-and-thirty-eighth"},
    {0x008b, "one-hundred-and-thirty-nineth"},
    {0x008c, "one-hundred-fortieth"},
    {0x008d, "one-hundred-and-fourty-first"},
    {0x008e, "one-hundred-and-fourty-second"},
    {0x008f, "one-hundred-and-fourty-third"},
    {0x0090, "one-hundred-and-fourty-fourth"},
    {0x0091, "one-hundred-and-fourty-fifth"},
    {0x0092, "one-hundred-and-fourty-sixth"},
    {0x0093, "one-hundred-and-fourty-seventh"},
    {0x0094, "one-hundred-and-fourty-eighth"},
    {0x0095, "one-hundred-and-fourty-nineth"},
    {0x0096, "one-hundred-fiftieth"},
    {0x0097, "one-hundred-and-fifty-first"},
    {0x0098, "one-hundred-and-fifty-second"},
    {0x0099, "one-hundred-and-fifty-third"},
    {0x009a, "one-hundred-and-fifty-fourth"},
    {0x009b, "one-hundred-and-fifty-fifth"},
    {0x009c, "one-hundred-and-fifty-sixth"},
    {0x009d, "one-hundred-and-fifty-seventh"},
    {0x009e, "one-hundred-and-fifty-eighth"},
    {0x009f, "one-hundred-and-fifty-nineth"},
    {0x00a0, "one-hundred-sixtieth"},
    {0x00a1, "one-hundred-and-sixty-first"},
    {0x00a2, "one-hundred-and-sixty-second"},
    {0x00a3, "one-hundred-and-sixty-third"},
    {0x00a4, "one-hundred-and-sixty-fourth"},
    {0x00a5, "one-hundred-and-sixty-fifth"},
    {0x00a6, "one-hundred-and-sixty-sixth"},
    {0x00a7, "one-hundred-and-sixty-seventh"},
    {0x00a8, "one-hundred-and-sixty-eighth"},
    {0x00a9, "one-hundred-and-sixty-nineth"},
    {0x00aa, "one-hundred-seventieth"},
    {0x00ab, "one-hundred-and-seventy-first"},
    {0x00ac, "one-hundred-and-seventy-second"},
    {0x00ad, "one-hundred-and-seventy-third"},
    {0x00ae, "one-hundred-and-seventy-fourth"},
    {0x00af, "one-hundred-and-seventy-fifth"},
    {0x00b0, "one-hundred-and-seventy-sixth"},
    {0x00b1, "one-hundred-and-seventy-seventh"},
    {0x00b2, "one-hundred-and-seventy-eighth"},
    {0x00b3, "one-hundred-and-seventy-nineth"},
    {0x00b4, "one-hundred-eightieth"},
    {0x00b5, "one-hundred-and-eighty-first"},
    {0x00b6, "one-hundred-and-eighty-second"},
    {0x00b7, "one-hundred-and-eighty-third"},
    {0x00b8, "one-hundred-and-eighty-fourth"},
    {0x00b9, "one-hundred-and-eighty-fifth"},
    {0x00ba, "one-hundred-and-eighty-sixth"},
    {0x00bb, "one-hundred-and-eighty-seventh"},
    {0x00bc, "one-hundred-and-eighty-eighth"},
    {0x00bd, "one-hundred-and-eighty-nineth"},
    {0x00be, "one-hundred-ninetieth"},
    {0x00bf, "one-hundred-and-ninety-first"},
    {0x00c0, "one-hundred-and-ninety-second"},
    {0x00c1, "one-hundred-and-ninety-third"},
    {0x00c2, "one-hundred-and-ninety-fourth"},
    {0x00c3, "one-hundred-and-ninety-fifth"},
    {0x00c4, "one-hundred-and-ninety-sixth"},
    {0x00c5, "one-hundred-and-ninety-seventh"},
    {0x00c6, "one-hundred-and-ninety-eighth"},
    {0x00c7, "one-hundred-and-ninety-nineth"},
    {0x00c8, "two-hundredth"},
    {0x00c9, "two-hundred-and-first"},
    {0x00ca, "two-hundred-and-second"},
    {0x00cb, "two-hundred-and-third"},
    {0x00cc, "two-hundred-and-fourth"},
    {0x00cd, "two-hundred-and-fifth"},
    {0x00ce, "two-hundred-and-sixth"},
    {0x00cf, "two-hundred-and-seventh"},
    {0x00d0, "two-hundred-and-eighth"},
    {0x00d1, "two-hundred-and-nineth"},
    {0x00d2, "two-hundred-and-tenth"},
    {0x00d3, "two-hundred-and-eleventh"},
    {0x00d4, "two-hundred-and-twelveth"},
    {0x00d5, "two-hundred-and-thirteenth"},
    {0x00d6, "two-hundred-and-fourteenth"},
    {0x00d7, "two-hundred-and-fifteenth"},
    {0x00d8, "two-hundred-and-sixteenth"},
    {0x00d9, "two-hundred-and-seventeenth"},
    {0x00da, "two-hundred-and-eighteenth"},
    {0x00db, "two-hundred-and-nineteenth"},
    {0x00dc, "two-hundred-twentieth"},
    {0x00dd, "two-hundred-and-twenty-first"},
    {0x00de, "two-hundred-and-twenty-second"},
    {0x00df, "two-hundred-and-twenty-third"},
    {0x00e0, "two-hundred-and-twenty-fourth"},
    {0x00e1, "two-hundred-and-twenty-fifth"},
    {0x00e2, "two-hundred-and-twenty-sixth"},
    {0x00e3, "two-hundred-and-twenty-seventh"},
    {0x00e4, "two-hundred-and-twenty-eighth"},
    {0x00e5, "two-hundred-and-twenty-nineth"},
    {0x00e6, "two-hundred-thirtieth"},
    {0x00e7, "two-hundred-and-thirty-first"},
    {0x00e8, "two-hundred-and-thirty-second"},
    {0x00e9, "two-hundred-and-thirty-third"},
    {0x00ea, "two-hundred-and-thirty-fourth"},
    {0x00eb, "two-hundred-and-thirty-fifth"},
    {0x00ec, "two-hundred-and-thirty-sixth"},
    {0x00ed, "two-hundred-and-thirty-seventh"},
    {0x00ee, "two-hundred-and-thirty-eighth"},
    {0x00ef, "two-hundred-and-thirty-nineth"},
    {0x00f0, "two-hundred-fortieth"},
    {0x00f1, "two-hundred-and-fourty-first"},
    {0x00f2, "two-hundred-and-fourty-second"},
    {0x00f3, "two-hundred-and-fourty-third"},
    {0x00f4, "two-hundred-and-fourty-fourth"},
    {0x00f5, "two-hundred-and-fourty-fifth"},
    {0x00f6, "two-hundred-and-fourty-sixth"},
    {0x00f7, "two-hundred-and-fourty-seventh"},
    {0x00f8, "two-hundred-and-fourty-eighth"},
    {0x00f9, "two-hundred-and-fourty-nineth"},
    {0x00fa, "two-hundred-fiftieth"},
    {0x00fb, "two-hundred-and-fifty-first"},
    {0x00fc, "two-hundred-and-fifty-second"},
    {0x00fd, "two-hundred-and-fifty-third"},
    {0x00fe, "two-hundred-and-fifty-fourth"},
    {0x00ff, "two-hundred-and-fifty-fifth"},
    {0x0100, "front"},
    {0x0101, "back"},
    {0x0102, "top"},
    {0x0103, "bottom"},
    {0x0104, "upper"},
    {0x0105, "lower"},
    {0x0106, "main"},
    {0x0107, "backup"},
    {0x0108, "auxiliary"},
    {0x0109, "supplementary"},
    {0x010A, "flash"},
    {0x010B, "inside"},
    {0x010C, "outside"},
    {0x010D, "left"},
    {0x010E, "right"},
    {0x010F, "internal"},
    {0x0110, "external"},
    {0x0, NULL}
};

static const value_string esp_trigger_logic_vals[] = {
    {0x00, "Boolean AND"},
    {0x01, "Boolean OR"},
    {0x0, NULL}
};

static const value_string esp_condition_vals[] = {
    {0x00, "Trigger inactive"},
    {0x01, "Use a fixed time interval between"},
    {0x02, "No less than the specified time between"},
    {0x03, "When value changes compared to"},
    {0x04, "While less than the specified value"},
    {0x05, "While less than or equal to the specified"},
    {0x06, "While greater than the specified value"},
    {0x07, "While greater than or equal to the"},
    {0x08, "While equal to the specified value"},
    {0x09, "While not equal to the specified value"},
    {0x0, NULL}
};

static const value_string esp_sampling_function_vals[] = {
    {0x00, "Unspecified"},
    {0x01, "Instantaneous"},
    {0x02, "Arithmetic Mean"},
    {0x03, "RMS"},
    {0x04, "Maximum"},
    {0x05, "Minimum"},
    {0x06, "Accumulated"},
    {0x07, "Count"},
    {0x0, NULL}
};

static const value_string esp_application_vals[] = {
    {0x00, "Unspecified"},
    {0x01, "Air"},
    {0x02, "Water"},
    {0x03, "Barometric"},
    {0x04, "Soil"},
    {0x05, "Infrared"},
    {0x06, "Map Database"},
    {0x07, "Barometric Elevation Source"},
    {0x08, "GPS only Elevation Source"},
    {0x09, "GPS and Map database Elevation Source"},
    {0x0A, "Vertical datum Elevation Source"},
    {0x0B, "Onshore"},
    {0x0C, "Onboard vessel or vehicle"},
    {0x0D, "Front"},
    {0x0E, "Back/Rear"},
    {0x0F, "Upper"},
    {0x10, "Lower"},
    {0x11, "Primary"},
    {0x12, "Secondary"},
    {0x13, "Outdoor"},
    {0x14, "Indoor"},
    {0x15, "Top"},
    {0x16, "Bottom"},
    {0x17, "Main"},
    {0x18, "Backup"},
    {0x19, "Auxiliary"},
    {0x1A, "Supplementary"},
    {0x1B, "Inside"},
    {0x1C, "Outside"},
    {0x1D, "Left"},
    {0x1E, "Right"},
    {0x1F, "Internal"},
    {0x20, "External"},
    {0x21, "Solar"},
    {0x0, NULL}
};

static const value_string appearance_category_vals[] = {
    {0x01, "Phone"},
    {0x02, "Computer"},
    {0x03, "Watch"},
    {0x04, "Clock"},
    {0x05, "Display"},
    {0x06, "Remote Control"},
    {0x07, "Eye Glasses"},
    {0x08, "Tag"},
    {0x09, "Keyring"},
    {0x0A, "Media Player"},
    {0x0B, "Barcode Scanner"},
    {0x0C, "Thermometer"},
    {0x0D, "Heart Rate Sensor"},
    {0x0E, "Blood Pressure"},
    {0x0F, "Human Interface Device"},
    {0x10, "Glucose Meter"},
    {0x11, "Running Walking Sensor"},
    {0x12, "Cycling"},
    {0x31, "Pulse Oximeter"},
    {0x32, "Weight Scale"},
    {0x51, "Outdoor Sports Activity"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_generic_vals[] = {
    {0x00, "Generic"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_watch_vals[] = {
    {0x00, "Generic"},
    {0x01, "Sports Watch"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_thermometer_vals[] = {
    {0x00, "Generic"},
    {0x01, "Ear"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_heart_rate_vals[] = {
    {0x00, "Generic"},
    {0x01, "Heart Rate Belt"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_blood_pressure_vals[] = {
    {0x00, "Generic"},
    {0x01, "Arm"},
    {0x02, "Wrist"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_hid_vals[] = {
    {0x00, "Generic"},
    {0x01, "Keyboard"},
    {0x02, "Mouse"},
    {0x03, "Joystick"},
    {0x04, "Gamepad"},
    {0x05, "Digitizer Tablet"},
    {0x06, "Card Reader"},
    {0x07, "Digital Pen"},
    {0x08, "Barcode"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_running_walking_sensor_vals[] = {
    {0x00, "Generic"},
    {0x01, "In-Shoe"},
    {0x02, "On-Shoe"},
    {0x03, "On-Hip"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_cycling_vals[] = {
    {0x00, "Generic"},
    {0x01, "Cycling Computer"},
    {0x02, "Speed Sensor"},
    {0x03, "Cadence Sensor"},
    {0x04, "Power Sensor"},
    {0x05, "Speed and Cadence Sensor"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_pulse_oximeter_vals[] = {
    {0x00, "Generic"},
    {0x01, "Fingertip"},
    {0x02, "Wrist Worn"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_outdoor_sports_activity_vals[] = {
    {0x00, "Generic"},
    {0x01, "Location Display Device"},
    {0x02, "Location and Navigation Display Device"},
    {0x03, "Location Pod"},
    {0x04, "Location and Navigation Pod"},
    {0x0, NULL}
};

static const value_string alert_level_vals[] = {
    {0x00, "No Alert"},
    {0x01, "Mild Alert"},
    {0x02, "High Alert"},
    {0x0, NULL}
};

static const value_string dst_offset_vals[] = {
    {0x00, "Standard Time"},
    {0x02, "Half an Hour Daylight Time (+0.5h)"},
    {0x04, "Daylight Time (+1h)"},
    {0x08, "Double Daylight Time (+2h)"},
    {0xFF, "DST is not known"},
    {0x0, NULL}
};

static const value_string timezone_vals[] = {
    {-128, "Time zone offset is not known"},
    {-48, "UTC-12:00"},
    {-44, "UTC-11:00"},
    {-40, "UTC-10:00"},
    {-38, "UTC-9:30"},
    {-36, "UTC-9:00"},
    {-32, "UTC-8:00"},
    {-28, "UTC-7:00"},
    {-24, "UTC-6:00"},
    {-20, "UTC-5:00"},
    {-18, "UTC-4:30"},
    {-16, "UTC-4:00"},
    {-14, "UTC-3:30"},
    {-12, "UTC-3:00"},
    {-8,  "UTC-2:00"},
    {-4,  "UTC-1:00"},
    {0,   "UTC+0:00"},
    {4,   "UTC+1:00"},
    {8,   "UTC+2:00"},
    {12,  "UTC+3:00"},
    {14,  "UTC+3:30"},
    {16,  "UTC+4:00"},
    {18,  "UTC+4:30"},
    {20,  "UTC+5:00"},
    {22,  "UTC+5:30"},
    {23,  "UTC+5:45"},
    {24,  "UTC+6:00"},
    {26,  "UTC+6:30"},
    {28,  "UTC+7:00"},
    {32,  "UTC+8:00"},
    {35,  "UTC+8:45"},
    {36,  "UTC+9:00"},
    {38,  "UTC+9:30"},
    {40,  "UTC+10:00"},
    {42,  "UTC+10:30"},
    {44,  "UTC+11:00"},
    {46,  "UTC+11:30"},
    {48,  "UTC+12:00"},
    {51,  "UTC+12:45"},
    {52,  "UTC+13:00"},
    {56,  "UTC+14:00"},
    {0x0, NULL}
};

static const value_string time_source_vals[] = {
    {0x00, "Unknown"},
    {0x01, "Network Time Protocol"},
    {0x02, "GPS"},
    {0x03, "Radio Time Signal"},
    {0x04, "Manual"},
    {0x05, "Atomic Clock"},
    {0x06, "Cellular Network"},
    {0x0, NULL}
};

static const value_string time_update_control_point_vals[] = {
    {0x01, "Get Reference Update"},
    {0x02, "Cancel Reference Update"},
    {0x0, NULL}
};

static const value_string time_current_state_vals[] = {
    {0x00, "Idle"},
    {0x01, "Update Pending"},
    {0x0, NULL}
};

static const value_string time_result_vals[] = {
    {0x00, "Successful"},
    {0x01, "Canceled"},
    {0x02, "No Connection To Reference"},
    {0x03, "Reference responded with an error"},
    {0x04, "Timeout"},
    {0x05, "Update not attempted after reset"},
    {0x0, NULL}
};

static const value_string temperature_type_vals[] = {
    {0x01, "Armpit"},
    {0x02, "Body (general)"},
    {0x03, "Ear (usually ear lobe)"},
    {0x04, "Finger"},
    {0x05, "Gastro-intestinal Tract"},
    {0x06, "Mouth"},
    {0x07, "Rectum"},
    {0x08, "Toe"},
    {0x09, "Tympanum (ear drum)"},
    {0x0, NULL}
};

static const value_string scan_refresh_vals[] = {
    {0x00, "Server Requires Refresh"},
    {0x0, NULL}
};

static const value_string body_sensor_location_vals[] = {
    {0x00, "Other"},
    {0x01, "Chest"},
    {0x02, "Wrist"},
    {0x03, "Finger"},
    {0x04, "Hand"},
    {0x05, "Ear Lobe"},
    {0x06, "Foot"},
    {0x0, NULL}
};

static const value_string heart_rate_control_point_vals[] = {
    {0x01, "Reset Energy Expended"},
    {0x0, NULL}
};

static const value_string ringer_control_point_vals[] = {
    {0x01, "Silent Mode"},
    {0x02, "Mute Once"},
    {0x03, "Cancel Silent Mode"},
    {0x0, NULL}
};

static const value_string ringer_setting_vals[] = {
    {0x00, "Ringer Silent"},
    {0x01, "Ringer Normal"},
    {0x0, NULL}
};

static const value_string alert_category_id_vals[] = {
    {0x00, "Simple Alert: General text alert or non-text alert"},
    {0x01, "Email: Alert when Email messages arrives"},
    {0x02, "News: News feeds such as RSS, Atom"},
    {0x03, "Call: Incoming call"},
    {0x04, "Missed call: Missed Call"},
    {0x05, "SMS/MMS: SMS/MMS message arrives"},
    {0x06, "Voice mail: Voice mail"},
    {0x07, "Schedule: Alert occurred on calendar, planner"},
    {0x08, "High Prioritized Alert: Alert that should be handled as high priority"},
    {0x09, "Instant Message: Alert for incoming instant messages"},
    {0xFB, "Defined by service specification"},
    {0xFC, "Defined by service specification"},
    {0xFD, "Defined by service specification"},
    {0xFE, "Defined by service specification"},
    {0xFF, "Defined by service specification"},
    {0x0, NULL}
};

static const value_string alert_command_id_vals[] = {
    {0x00, "Enable New Incoming Alert Notification"},
    {0x01, "Enable Unread Category Status Notification"},
    {0x02, "Disable New Incoming Alert Notification"},
    {0x03, "Disable Unread Category Status Notification"},
    {0x04, "Notify New Incoming Alert immediately"},
    {0x05, "Notify Unread Category Status immediately"},
    {0x0, NULL}
};

static const value_string hid_control_point_command_vals[] = {
    {0x00, "Suspend"},
    {0x01, "Exit Suspend"},
    {0x0, NULL}
};

static const value_string pnp_id_vendor_id_source_vals[] = {
    {0x01,   "Bluetooth SIG"},
    {0x02,   "USB Implementer's Forum"},
    {0x0, NULL}
};

static const value_string sensor_location_vals[] = {
    {0x00,   "Other"},
    {0x01,   "Top of shoe"},
    {0x02,   "In shoe"},
    {0x03,   "Hip"},
    {0x04,   "Front Wheel"},
    {0x05,   "Left Crank"},
    {0x06,   "Right Crank"},
    {0x07,   "Left Pedal"},
    {0x08,   "Right Pedal"},
    {0x09,   "Front Hub"},
    {0x0A,   "Rear Dropout"},
    {0x0B,   "Chainstay"},
    {0x0C,   "Rear Wheel"},
    {0x0D,   "Rear Hub"},
    {0x0E,   "Chest"},
    {0x0, NULL}
};

static const value_string gender_vals[] = {
    {0x00,   "Male"},
    {0x01,   "Female"},
    {0x02,   "Unspecified"},
    {0x0, NULL}
};

static const value_string sport_type_for_aerobic_and_anaerobic_thresholds_vals[] = {
    {0x00,   "Unspecified"},
    {0x01,   "Running (Treadmill)"},
    {0x02,   "Cycling (Ergometer)"},
    {0x03,   "Rowing (Ergometer)"},
    {0x04,   "Cross Training (Elliptical)"},
    {0x05,   "Climbing"},
    {0x06,   "Skiing"},
    {0x07,   "Skating"},
    {0x08,   "Arm exercising"},
    {0x09,   "Lower body exercising"},
    {0x0A,   "Upper body exercising"},
    {0x0B,   "Whole body exercising"},
    {0x0, NULL}
};

static const value_string barometric_pressure_trend_vals[] = {
    {0x00,   "Unknown"},
    {0x01,   "Continuously falling"},
    {0x02,   "Continuously rising"},
    {0x03,   "Falling, then steady"},
    {0x04,   "Rising, then steady"},
    {0x05,   "Falling before a lesser rise"},
    {0x06,   "Falling before a greater rise"},
    {0x07,   "Rising before a greater fall"},
    {0x08,   "Rising before a lesser fall"},
    {0x09,   "Steady"},
    {0x0, NULL}
};

static const value_string central_address_resolution_vals[] = {
    {0x00,   "Not Supported"},
    {0x01,   "Supported"},
    {0x0, NULL}
};

static const value_string cycling_power_feature_sensor_measurement_context_vals[] = {
    {0x00,   "Force Based"},
    {0x01,   "Torque Based"},
    {0x0, NULL}
};

static const value_string body_composition_feature_mass_measurement_resolution_vals[] = {
    {0x00,   "Not Specified"},
    {0x01,   "Resolution of 0.5 kg or 1 lb"},
    {0x02,   "Resolution of 0.2 kg or 0.5 lb"},
    {0x03,   "Resolution of 0.1 kg or 0.2 lb"},
    {0x04,   "Resolution of 0.05 kg or 0.1 lb"},
    {0x05,   "Resolution of 0.02 kg or 0.05 lb"},
    {0x06,   "Resolution of 0.01 kg or 0.02 lb"},
    {0x07,   "Resolution of 0.005 kg or 0.01 lb"},
    {0x0, NULL}
};

static const value_string body_composition_feature_height_measurement_resolution_vals[] = {
    {0x00,   "Not Specified"},
    {0x01,   "Resolution of 0.01 meter or 1 inch"},
    {0x02,   "Resolution of 0.005 meter or 0.5 inch"},
    {0x03,   "Resolution of 0.001 meter or 0.1 inch"},
    {0x0, NULL}
};

static const value_string weight_scale_feature_height_measurement_resolution_vals[] = {
    {0x00,   "Not Specified"},
    {0x01,   "Resolution of 0.01 meter or 1 inch"},
    {0x02,   "Resolution of 0.005 meter or 0.5 inch"},
    {0x03,   "Resolution of 0.001 meter or 0.1 inch"},
    {0x0, NULL}
};

static const value_string weight_scale_feature_weight_measurement_resolution_vals[] = {
    {0x00,   "Not Specified"},
    {0x01,   "Resolution of 0.5 kg or 1 lb"},
    {0x02,   "Resolution of 0.2 kg or 0.5 lb"},
    {0x03,   "Resolution of 0.1 kg or 0.2 lb"},
    {0x04,   "Resolution of 0.05 kg or 0.1 lb"},
    {0x05,   "Resolution of 0.02 kg or 0.05 lb"},
    {0x06,   "Resolution of 0.01 kg or 0.02 lb"},
    {0x07,   "Resolution of 0.005 kg or 0.01 lb"},
    {0x0, NULL}
};

static const value_string glucose_measurement_flags_glucose_concentration_units_vals[] = {
    {0x00,   "kg/L"},
    {0x01,   "mol/L"},
    {0x0, NULL}
};

static const value_string glucose_measurement_type_and_sample_location_type_vals[] = {
    {0x01,   "Capillary Whole Blood"},
    {0x02,   "Capillary Plasma"},
    {0x03,   "Venous Whole Blood"},
    {0x04,   "Venous Plasma"},
    {0x05,   "Arterial Whole Blood"},
    {0x06,   "Arterial Plasma"},
    {0x07,   "Undetermined Whole Blood"},
    {0x08,   "Undetermined Plasma"},
    {0x09,   "Interstitial Fluid"},
    {0x0A,   "Control Solution"},
    {0x0, NULL}
};

static const value_string glucose_measurement_type_and_sample_location_sample_location_vals[] = {
    {0x01,   "Finger"},
    {0x02,   "Alternate Site Test"},
    {0x03,   "Earlobe"},
    {0x04,   "Control Solution"},
    {0x0F,   "Sample Location Value Not Available"},
    {0x0, NULL}
};

static const value_string bond_management_control_point_opcode_vals[] = {
    {0x01,   "Delete bond of requesting device (BR/EDR and LE)"},
    {0x02,   "Delete bond of requesting device (BR/EDR transport only)"},
    {0x03,   "Delete bond of requesting device (LE transport only)"},
    {0x04,   "Delete all bonds on server (BR/EDR and LE)"},
    {0x05,   "Delete all bonds on server (BR/EDR transport only)"},
    {0x06,   "Delete all bonds on server (LE transport only)"},
    {0x07,   "Delete all but the active bond on server (BR/EDR and LE)"},
    {0x08,   "Delete all but the active bond on server (BR/EDR transport only)"},
    {0x09,   "Delete all but the active bond on server (LE transport only)"},
    {0x0, NULL}
};

static const value_string temperature_measurement_flags_temperature_unit_vals[] = {
    {0x00,   "Celsius"},
    {0x01,   "Fahrenheit"},
    {0x0, NULL}
};

static const value_string glucose_measurement_context_flags_medication_value_units_vals[] = {
    {0x00,   "Kilograms"},
    {0x01,   "Liters"},
    {0x0, NULL}
};

static const value_string glucose_measurement_context_carbohydrate_id_vals[] = {
    {0x01,   "Breakfast"},
    {0x02,   "Lunch"},
    {0x03,   "Dinner"},
    {0x04,   "Snack"},
    {0x05,   "Drink"},
    {0x06,   "Supper"},
    {0x07,   "Brunch"},
    {0x0, NULL}
};

static const value_string glucose_measurement_context_meal_vals[] = {
    {0x01,   "Preprandial (before meal)"},
    {0x02,   "Postprandial (after meal)"},
    {0x03,   "Fasting"},
    {0x04,   "Casual (snacks, drinks, etc.)"},
    {0x05,   "Bedtime"},
    {0x0, NULL}
};

static const value_string glucose_measurement_context_tester_vals[] = {
    { 1,   "Self"},
    { 2,   "Health Care Professional"},
    { 3,   "Lab Test"} ,
    {15,   "Tester Value not Available"},
    {0x0, NULL}
};

static const value_string glucose_measurement_context_health_vals[] = {
    { 1,   "Minor Health Issues"},
    { 2,   "Major Health Issues"},
    { 3,   "During Menses"},
    { 4,   "Under Stress"},
    { 5,   "No Health Issues"},
    {15,   "Health Value not Available"},
    {0x0, NULL}
};

static const value_string glucose_measurement_context_medication_id_vals[] = {
    { 1,   "Rapid Acting Insulin"},
    { 2,   "Short Acting Insulin"},
    { 3,   "Intermediate Acting Insulin"},
    { 4,   "Long Acting Insulin"},
    { 5,   "Pre-mixed Insulin"},
    {0x0, NULL}
};

static const value_string blood_pressure_measurement_unit_vals[] = {
    { 0,   "mmHg"},
    { 1,   "kPa"},
    {0x0, NULL}
};

static const value_string blood_pressure_measurement_status_pulse_rate_range_detection_vals[] = {
    { 0,   "Pulse rate is within the range"},
    { 1,   "Pulse rate exceeds upper limit"},
    { 2,   "Pulse rate is less than lower limit"},
    { 3,   "Reserved"},
    {0x0, NULL}
};

static const value_string record_access_control_point_opcode_vals[] = {
    { 0,   "Reserved"},
    { 1,   "Report Stored Records"},
    { 2,   "Delete Stored Records"},
    { 3,   "Abort Operation"},
    { 4,   "Report Number of Stored Records"},
    { 5,   "Number of Stored Records Response"},
    { 6,   "Response Code"},
    {0x0, NULL}
};

static const value_string record_access_control_point_operator_vals[] = {
    { 0,   "Null"},
    { 1,   "All Records"},
    { 2,   "Less than or equal to"},
    { 3,   "Greater than or equal to"},
    { 4,   "Within range of (inclusive)"},
    { 5,   "First record(i.e. oldest record)"},
    { 6,   "Last record (i.e. most recent record)"},
    {0x0, NULL}
};

static const value_string record_access_control_point_operand_filter_type_vals[] = {
    { 0x00,   "Reserved"},
    { 0x01,   "Sequence Number"},
    { 0x02,   "User Facing Time (Base Time + Offset Time)"},
    {0x0, NULL}
};

static const value_string record_access_control_point_response_code_vals[] = {
    { 0x00,   "Reserved"},
    { 0x01,   "Success"},
    { 0x02,   "Op Code not supported"},
    { 0x03,   "Invalid Operator"},
    { 0x04,   "Operator not supported"},
    { 0x05,   "Invalid Operand"},
    { 0x06,   "No records found"},
    { 0x07,   "Abort unsuccessful"},
    { 0x08,   "Procedure not completed"},
    { 0x09,   "Operand not supported"},
    {0x0, NULL}
};

static const value_string value_trigger_setting_condition_vals[] = {
    { 0x00,   "None"},
    { 0x01,   "Analog - Crossed a boundary"},
    { 0x02,   "Analog - On the boundary"},
    { 0x03,   "Analog - Exceeds a boundary"},
    { 0x04,   "Bitmask"},
    { 0x05,   "Analog Interval - Inside or outside the boundaries"},
    { 0x06,   "Analog Interval - On the boundaries"},
    { 0x07,   "No value trigger"},
    {0x0, NULL}
};


static const value_string digital_vals[] = {
    { 0x00,   "Inactive"},
    { 0x01,   "Active"},
    { 0x02,   "Tri-state"},
    { 0x03,   "Output-state"},
    {0x0, NULL}
};


const value_string btatt_ips_uncertainty_stationary_vals[] = {
    { 0x00,   "Stationary"},
    { 0x01,   "Mobile"},
    {0x0, NULL}
};


const value_string btatt_ips_uncertainty_update_time_vals[] = {
    { 0x00,   "Up to 3s"},
    { 0x01,   "Up to 4s"},
    { 0x02,   "Up to 6s"},
    { 0x03,   "Up to 12s"},
    { 0x04,   "Up to 28s"},
    { 0x05,   "Up to 89s"},
    { 0x06,   "Up to 426s"},
    { 0x07,   "3541s"},
    {0x0, NULL}
};


const value_string btatt_ips_uncertainty_precision_vals[] = {
    { 0x00,   "Less than 0.1m"},
    { 0x01,   "0.1-1m"},
    { 0x02,   "1-2m"},
    { 0x03,   "2-5m"},
    { 0x04,   "5-10m"},
    { 0x05,   "10-50m"},
    { 0x06,   "Greater than 50m"},
    { 0x07,   "N/A"},
    {0x0, NULL}
};


const value_string btatt_ips_coordinate_system[] = {
    { 0x00,   "WGS84 Coordinate System"},
    { 0x01,   "Local Coordinate System"},
    {0x0, NULL}
};


static const value_string time_trigger_setting_condition_vals[] = {
    { 0x00,   "No time-based triggering used"},
    { 0x01,   "Indicates or notifies unconditionally after a settable time"},
    { 0x02,   "Not indicated or notified more often than a settable time"},
    { 0x03,   "Changed more often than"},
    {0x0, NULL}
};


static const value_string rsc_measurement_flags_type_of_movement_vals[] = {
    { 0x00,   "Walking"},
    { 0x01,   "Running"},
    {0x0, NULL}
};

static const value_string sc_control_point_opcode_vals[] = {
    { 0x01,   "Set Cumulative Value"},
    { 0x02,   "Start Sensor Calibration"},
    { 0x03,   "Update Sensor Location"},
    { 0x04,   "Request Supported Sensor Locations"},
    { 0x10,   "Response Code"},
    {0x0, NULL}
};

static const value_string sc_control_point_response_value_vals[] = {
    { 0x01,   "Success"},
    { 0x02,   "Opcode not Supported"},
    { 0x03,   "Invalid Parameter"},
    { 0x04,   "Operation Failed"},
    {0x0, NULL}
};

static const value_string cycling_power_measurement_flags_accumulated_torque_source_vals[] = {
    { 0x00,   "Wheel Based"},
    { 0x01,   "Crank Based"},
    {0x0, NULL}
};

static const value_string cycling_power_vector_flags_instantaneous_measurement_direction_vals[] = {
    { 0x00,   "Unknown"},
    { 0x01,   "Tangential Component"},
    { 0x02,   "Radial Component"},
    { 0x03,   "Lateral Component"},
    {0x0, NULL}
};

static const value_string cycling_power_control_point_opcode[] = {
    { 0x01,   "Set Cumulative Value"},
    { 0x02,   "Update Sensor Location"},
    { 0x03,   "Request Supported Sensor Locations"},
    { 0x04,   "Set Crank Length"},
    { 0x05,   "Request Crank Length"},
    { 0x06,   "Set Chain Length"},
    { 0x07,   "Request Chain Length"},
    { 0x08,   "Set Chain Weight"},
    { 0x09,   "Request Chain Weight"},
    { 0x0A,   "Set Span Length"},
    { 0x0B,   "Request Span Length"},
    { 0x0C,   "Start Offset Compensation"},
    { 0x0D,   "Mask Cycling Power Measurement Characteristic Content"},
    { 0x0E,   "Request Sampling Rate"},
    { 0x0F,   "Request Factory Calibration Date"},
    { 0x20,   "Response Code"},
    {0x0, NULL}
};

static const value_string cycling_power_control_point_response_value[] = {
    { 0x01,   "Success"},
    { 0x02,   "Opcode not Supported"},
    { 0x03,   "Invalid Parameter"},
    { 0x04,   "Operation Failed"},
    {0x0, NULL}
};

static const value_string location_and_speed_flags_elevation_source_vals[] = {
    { 0x00,   "Positioning System"},
    { 0x01,   "Barometric Air Pressure"},
    { 0x02,   "Database Service (or similar)"},
    { 0x03,   "Other"},
    {0x0, NULL}
};

static const value_string flags_position_status_vals[] = {
    { 0x00,   "No Position"},
    { 0x01,   "Position Ok"},
    { 0x02,   "Estimated Position"},
    { 0x03,   "Last Known Position"},
    {0x0, NULL}
};

static const value_string ln_control_point_opcode[] = {
    { 0x01,   "Set Cumulative Value"},
    { 0x02,   "Mask Location and Speed Characteristic Content"},
    { 0x03,   "Navigation Control"},
    { 0x04,   "Request Number of Routes"},
    { 0x05,   "Request Name of Route"},
    { 0x06,   "Select Route"},
    { 0x07,   "Set Fix Rate"},
    { 0x08,   "Set Elevation"},
    { 0x20,   "Response Code"},
    {0x0, NULL}
};

static const value_string ln_control_point_navigation_control_vals[] = {
    { 0x00,   "Stop Notification of the Navigation characteristic. Stop Navigation."},
    { 0x01,   "Start Notification of the Navigation characteristic. Start Navigation to the first waypoint on a route."},
    { 0x02,   "Stop Notification of the Navigation characteristic. Pause Navigation keeping the next waypoint on the route in the memory for continuing the navigation later."},
    { 0x03,   "Start Notification of the Navigation characteristic. Continue Navigation from the point where navigation was paused to the next waypoint on the route."},
    { 0x04,   "Notification of the Navigation characteristic not affected. Skip Waypoint: disregard next waypoint and continue navigation to the waypoint following next waypoint on the route."},
    { 0x05,   "Start Notification of the Navigation characteristic. Select Nearest Waypoint on a Route: measure the distance to all waypoints on the route, and start navigation to the closest or optimal waypoint on the route (left to the implementation) and from there to waypoints following next waypoint along the route."},
    {0x0, NULL}
};

static const value_string ln_control_point_response_value[] = {
    { 0x01,   "Success"},
    { 0x02,   "Opcode not Supported"},
    { 0x03,   "Invalid Parameter"},
    { 0x04,   "Operation Failed"},
    {0x0, NULL}
};

static const value_string body_composition_measurement_flags_measurement_units_vals[] = {
    { 0,   "SI (kg & m)"},
    { 1,   "Imperial (lb & in)"},
    {0x0, NULL}
};

static const value_string user_control_point_opcode_vals[] = {
    { 0x01,   "Register New User"},
    { 0x02,   "Consent"},
    { 0x03,   "Delete User Data"},
    { 0x20,   "Response Code"},
    {0x0, NULL}
};

static const value_string user_control_point_response_value_vals[] = {
    { 0x01,   "Success"},
    { 0x02,   "Opcode not Supported"},
    { 0x03,   "Invalid Parameter"},
    { 0x04,   "Operation Failed"},
    { 0x04,   "User not Authorized"},
    {0x0, NULL}
};

static const value_string cgm_feature_type_vals[] = {
    { 0x01,   "Capillary Whole Blood"},
    { 0x02,   "Capillary Plasma"},
    { 0x03,   "Capillary Whole Blood"},
    { 0x04,   "Venous Plasma"},
    { 0x05,   "Arterial Whole Blood"},
    { 0x06,   "Arterial Plasma"},
    { 0x07,   "Undetermined Whole Blood"},
    { 0x08,   "Undetermined Plasma"},
    { 0x09,   "Interstitial Fluid (ISF)"},
    { 0x0A,   "Control Solution"},
    {0x0, NULL}
};

static const value_string cgm_feature_sample_location_vals[] = {
    { 0x01,   "Finger"},
    { 0x02,   "Alternate Site Test (AST)"},
    { 0x03,   "Earlobe"},
    { 0x04,   "Control Solution"},
    { 0x05,   "Subcutaneous Tissue"},
    { 0x0F,   "Sample Location Value not Available"},
    {0x0, NULL}
};

static const value_string cgm_specific_ops_control_point_opcode_vals[] = {
    { 0x01,   "Set CGM Communication Interval"},
    { 0x02,   "Get CGM Communication Interval"},
    { 0x03,   "CGM Communication Interval response"},
    { 0x04,   "Set Glucose Calibration Value"},
    { 0x05,   "Get Glucose Calibration Value"},
    { 0x06,   "Glucose Calibration Value response"},
    { 0x07,   "Set Patient High Alert Level"},
    { 0x08,   "Get Patient High Alert Level"},
    { 0x09,   "Patient High Alert Level Response"},
    { 0x0A,   "Set Patient Low Alert Level"},
    { 0x0B,   "Get Patient Low Alert Level"},
    { 0x0C,   "Patient Low Alert Level Response"},
    { 0x0D,   "Set Hypo Alert Level"},
    { 0x0E,   "Get Hypo Alert Level"},
    { 0x0F,   "Hypo Alert Level Response"},
    { 0x10,   "Set Hyper Alert Level"},
    { 0x11,   "Get Hyper Alert Level"},
    { 0x12,   "Hyper Alert Level Response"},
    { 0x13,   "Set Rate of Decrease Alert Level"},
    { 0x14,   "Get Rate of Decrease Alert Level"},
    { 0x15,   "Rate of Decrease Alert Level Response"},
    { 0x16,   "Set Rate of Increase Alert Level"},
    { 0x17,   "Get Rate of Increase Alert Level"},
    { 0x18,   "Rate of Increase Alert Level Response"},
    { 0x19,   "Reset Device Specific Alert"},
    { 0x1A,   "Start the Session"},
    { 0x1B,   "Stop the Session"},
    { 0x1C,   "Response Code"},
    {0x0, NULL}
};

static const value_string cgm_specific_ops_control_point_response_code_vals[] = {
    { 0x01,   "Success"},
    { 0x02,   "Op Code not Supported"},
    { 0x03,   "Invalid Operand"},
    { 0x04,   "Procedure not Completed"},
    { 0x05,   "Parameter Out of Range"},
    {0x0, NULL}
};

static const value_string nordic_dfu_control_point_opcode_vals[] = {
    { 0x01,   "Start DFU"},
    { 0x02,   "Initialize DFU Parameters"},
    { 0x03,   "Receive Firmware Image"},
    { 0x04,   "Validate Firmware"},
    { 0x05,   "Activate Image and Reset"},
    { 0x06,   "Reset System"},
    { 0x07,   "Report Received Image Size"},
    { 0x08,   "Packet Receipt Notification Request"},
    { 0x10,   "Response Code"},
    { 0x11,   "Packet Receipt Notification"},
    {0x0, NULL}
};

static const value_string nordic_dfu_control_point_image_type_vals[] = {
    { 0x00,   "No Image"},
    { 0x01,   "SoftDevice"},
    { 0x02,   "Bootloader"},
    { 0x03,   "Bootloader+SoftDevice"},
    { 0x04,   "Application"},
    { 0x05,   "Other Image Combination - currently not supported"},
    { 0x06,   "Other Image Combination - currently not supported"},
    { 0x07,   "Other Image Combination - currently not supported"},
    {0x0, NULL}
};

static const value_string nordic_dfu_control_point_init_packet_vals[] = {
    { 0x00,   "Receive Init Packet"},
    { 0x01,   "Init Packet Complete"},
    {0x0, NULL}
};

static const value_string nordic_dfu_control_point_response_value_vals[] = {
    { 0x01,   "Success"},
    { 0x02,   "Invalid State"},
    { 0x03,   "Not Supported"},
    { 0x04,   "Data Size Exceeds Limit"},
    { 0x05,   "CRC Error"},
    { 0x06,   "Operation Failed"},
    {0x0, NULL}
};

static const value_string https_security_vals[] = {
    { 0x00,   "False"},
    { 0x01,   "True"},
    {0x0, NULL}
};

static const value_string http_control_point_opcode_vals[] = {
    { 0x01,   "HTTP GET Request"},
    { 0x02,   "HTTP HEAD Request"},
    { 0x03,   "HTTP POST Request"},
    { 0x04,   "HTTP PUT Request"},
    { 0x05,   "HTTP DELETE Request"},
    { 0x06,   "HTTPS GET Request"},
    { 0x07,   "HTTPS HEAD Request"},
    { 0x08,   "HTTPS POST Request"},
    { 0x09,   "HTTPS PUT Request"},
    { 0x0A,   "HTTPS DELETE Request"},
    { 0x0B,   "HTTP Request Cancel"},
    {0x0, NULL}
};

const value_string tds_organization_id_vals[] = {
    { 0x00, "RFU" },
    { 0x01, "Bluetooth SIG" },
    {0, NULL }
};

static const value_string tds_opcode_vals[] = {
    { 0x00, "RFU" },
    { 0x01, "Activate Transport" },
    {0, NULL }
};

static const value_string tds_result_code_vals[] = {
    { 0x00, "Success" },
    { 0x01, "Opcode not Supported" },
    { 0x02, "Invalid Parameter" },
    { 0x03, "Unsupported Organization ID" },
    { 0x04, "Operation Failed" },
    {0, NULL }
};

static const value_string ots_action_opcode_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Create" },
    { 0x02, "Delete" },
    { 0x03, "Calculate Checksum" },
    { 0x04, "Execute" },
    { 0x05, "Read" },
    { 0x06, "Write" },
    { 0x07, "Abort" },
    { 0x60, "Response Code" },
    {0, NULL }
};

static const value_string ots_action_result_code_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Success" },
    { 0x02, "Opcode not Supported" },
    { 0x03, "Invalid Parameter" },
    { 0x04, "Insufficient Resources" },
    { 0x05, "Invalid Object" },
    { 0x06, "Channel Unavailable" },
    { 0x07, "Unsupported Type" },
    { 0x08, "Procedure not Permitted" },
    { 0x09, "Object Locked" },
    { 0x0A, "Operation Failed" },
    {0, NULL }
};

static const value_string ots_list_opcode_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "First" },
    { 0x02, "Last" },
    { 0x03, "Previous" },
    { 0x04, "Next" },
    { 0x05, "Go To" },
    { 0x06, "Order" },
    { 0x07, "Request Number of Objects" },
    { 0x08, "Clear Marking" },
    { 0x70, "Response Code" },
    {0, NULL }
};

static const value_string ots_list_order_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Name, Ascending" },
    { 0x02, "Type, Ascending" },
    { 0x03, "Current Size Ascending" },
    { 0x04, "First-created Timestamp, Ascending" },
    { 0x05, "Last-modified Timestamp, Ascending" },
    { 0x11, "Name, Descending" },
    { 0x12, "Type, Descending" },
    { 0x13, "Current Size Descending" },
    { 0x14, "First-created Timestamp, Descending" },
    { 0x15, "Last-modified Timestamp, Descending" },
    {0, NULL }
};

static const value_string ots_list_result_code_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Success" },
    { 0x02, "Opcode not Supported" },
    { 0x03, "Invalid Parameter" },
    { 0x04, "Operation Failed" },
    { 0x05, "Out of Bounds" },
    { 0x06, "Too Many Objects" },
    { 0x07, "No Object" },
    { 0x08, "Object ID not Found" },
    {0, NULL }
};

static const value_string ots_filter_vals[] = {
    { 0x00, "No Filter" },
    { 0x01, "Name Starts With" },
    { 0x02, "Name Ends With" },
    { 0x03, "Name Contains" },
    { 0x04, "Name is Exactly" },
    { 0x05, "Object Type" },
    { 0x06, "Created Between" },
    { 0x07, "Modified Between" },
    { 0x08, "Current Size Between" },
    { 0x09, "Allocated Size Between" },
    { 0x0A, "Marked Objects" },
    {0, NULL }
};


static const true_false_string control_point_mask_value_tfs = {
    "Leave as Default",
    "Turn Off" };

static const true_false_string flags_heading_source_tfs = {
    "Magnetic Compass",
    "Movement" };

static const true_false_string location_and_speed_flags_speed_and_distance_format_tfs = {
    "3D",
    "2D" };

static const true_false_string navigation_indicator_type_tfs = {
    "To Destination",
    "To Waypoint" };

static const true_false_string weight_measurement_flags_measurement_units_tfs = {
    "Imperial (lb & in)",
    "SI (kg & m)" };


union request_parameters_union {
    void *data;

    struct _read_write {
        guint16  handle;
        guint16  offset;
    } read_write;

    struct _read_multiple {
        guint     number_of_handles;
        guint16  *handle;
    } read_multiple;

    struct _mtu {
        guint16  mtu;
    } mtu;

    struct _read_by_type {
        guint16  starting_handle;
        guint16  ending_handle;
        bluetooth_uuid_t uuid;
    } read_by_type;

    struct _find_information {
        guint16  starting_handle;
        guint16  ending_handle;
    } find_information;
};

typedef struct _request_data_t {
    guint8                          opcode;
    guint32                         request_in_frame;
    guint32                         response_in_frame;

    union request_parameters_union  parameters;
} request_data_t;

enum attribute_type {
    ATTRIBUTE_TYPE_SERVICE,
    ATTRIBUTE_TYPE_CHARACTERISTIC,
    ATTRIBUTE_TYPE_OTHER
};

typedef struct _handle_data_t {
    bluetooth_uuid_t uuid;

    enum attribute_type type;
} handle_data_t;


typedef struct _mtu_data_t {
    guint  mtu;
} mtu_data_t;

typedef struct _fragment_data_t {
    guint    length;
    guint    offset;
    gint     data_in_frame;
    guint8  *data;
} fragment_data_t;


void proto_register_btatt(void);
void proto_reg_handoff_btatt(void);

void proto_register_btgatt(void);
void proto_reg_handoff_btgatt(void);

#define PROTO_DATA_BTATT_HANDLE   0x00

static void btatt_handle_prompt(packet_info *pinfo, gchar* result)
{
    guint16 *value_data;

    value_data = (guint16 *) p_get_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_HANDLE);
    if (value_data)
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "ATT Handle 0x%04x as", (guint) *value_data);
    else
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown ATT Handle");
}

static gpointer btatt_handle_value(packet_info *pinfo)
{
    guint16 *value_data;

    value_data = (guint16 *) p_get_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_HANDLE);

    if (value_data)
        return GUINT_TO_POINTER((gulong)*value_data);

    return NULL;
}

static gboolean is_readable_request(guint8 opcode)
{
    return (opcode == ATT_OPCODE_READ_REQUEST ||
            opcode == ATT_OPCODE_READ_BLOB_REQUEST ||
            opcode == ATT_OPCODE_READ_BY_TYPE_REQUEST ||
            opcode == ATT_OPCODE_READ_MULTIPLE_REQUEST);
}

static gboolean is_readable_response(guint8 opcode)
{
    return (opcode == ATT_OPCODE_READ_RESPONSE ||
            opcode == ATT_OPCODE_READ_BLOB_RESPONSE ||
            opcode == ATT_OPCODE_READ_BY_TYPE_RESPONSE ||
            opcode == ATT_OPCODE_READ_MULTIPLE_RESPONSE);
}

static gboolean is_writeable_request(guint8 opcode)
{
    return (opcode == ATT_OPCODE_WRITE_REQUEST ||
            opcode == ATT_OPCODE_WRITE_PREPARE_REQUEST);
}

static gboolean is_writeable_response(guint8 opcode)
{
    return (opcode == ATT_OPCODE_WRITE_RESPONSE ||
            opcode == ATT_OPCODE_WRITE_PREPARE_RESPONSE);
}

gboolean bluetooth_gatt_has_no_parameter(guint8 opcode)
{
    return is_readable_request(opcode) ||
            opcode == ATT_OPCODE_WRITE_RESPONSE ||
            opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION;
}

static request_data_t *
get_request(tvbuff_t *tvb, gint offset, packet_info *pinfo, guint8 opcode,
        bluetooth_data_t *bluetooth_data)
{
    request_data_t  *request_data;
    wmem_tree_key_t  key[4];
    wmem_tree_t     *sub_wmemtree;
    gint             frame_number;

    key[0].length = 1;
    key[0].key    = &bluetooth_data->interface_id;
    key[1].length = 1;
    key[1].key    = &bluetooth_data->adapter_id;
    key[2].length = 0;
    key[2].key    = NULL;

    frame_number = pinfo->num;

    sub_wmemtree = (wmem_tree_t *) wmem_tree_lookup32_array(requests, key);
    request_data = (sub_wmemtree) ? (request_data_t *) wmem_tree_lookup32_le(sub_wmemtree, frame_number) : NULL;
    if (request_data && request_data->request_in_frame == pinfo->num)
        return request_data;

    if (request_data) do {
        frame_number = request_data->request_in_frame - 1;

        if (request_data->request_in_frame == pinfo->num)
            break;

      switch (opcode) {
      case 0x01: /* Error Response */
          if (tvb_captured_length_remaining(tvb, offset) < 1)
              return NULL;
          opcode = tvb_get_guint8(tvb, 1) + 1;
          /* No break */
      case 0x03: /* Exchange MTU Response */
      case 0x05: /* Find Information Response */
      case 0x07: /* Find By Type Value Response */
      case 0x09: /* Read By Type Response */
      case 0x0b: /* Read Response */
      case 0x0d: /* Read Blob Response */
      case 0x0f: /* Read Multiple Response */
      case 0x11: /* Read By Group Type Response */
      case 0x13: /* Write Response */
      case 0x17: /* Prepare Write Response */
      case 0x19: /* Execute Write Response */
      case 0x1E: /* Handle Value Confirmation */
          if (request_data->opcode == opcode -1)
              return request_data;

          break;
      }
    } while(0);

    request_data = (sub_wmemtree) ? (request_data_t *) wmem_tree_lookup32_le(sub_wmemtree, frame_number) : NULL;

    if (!request_data)
        return NULL;

    if (request_data->request_in_frame == pinfo->num)
        return request_data;

    switch (opcode) {
    case 0x01: /* Error Response */
        if (tvb_captured_length_remaining(tvb, offset) < 1)
            return NULL;
        opcode = tvb_get_guint8(tvb, 1) + 1;
        /* No break */
    case 0x03: /* Exchange MTU Response */
    case 0x05: /* Find Information Response */
    case 0x07: /* Find By Type Value Response */
    case 0x09: /* Read By Type Response */
    case 0x0b: /* Read Response */
    case 0x0d: /* Read Blob Response */
    case 0x0f: /* Read Multiple Response */
    case 0x11: /* Read By Group Type Response */
    case 0x13: /* Write Response */
    case 0x17: /* Prepare Write Response */
    case 0x19: /* Execute Write Response */
    case 0x1E: /* Handle Value Confirmation */
        if (request_data->opcode == opcode -1)
            return request_data;

        break;
    case 0x1B: /* Handle Value Notification */
    case 0x52: /* Write Command */
    case 0xD2: /* Signed Write Command */
        /* There is no response for them */
        return NULL;
    case 0x02: /* Exchange MTU Request */
    case 0x04: /* Find Information Request */
    case 0x06: /* Find By Type Value Request */
    case 0x08: /* Read By Type Request */
    case 0x0a: /* Read Request */
    case 0x0c: /* Read Blob Request */
    case 0x0e: /* Read Multiple Request */
    case 0x10: /* Read By Group Type Request */
    case 0x12: /* Write Request */
    case 0x16: /* Prepare Write Request */
    case 0x18: /* Execute Write Request */
    case 0x1D: /* Handle Value Indication */
        /* This should never happen */
    default:
        return NULL;
    }

    return NULL;
}

static void
save_request(packet_info *pinfo, guint8 opcode, union request_parameters_union parameters,
        bluetooth_data_t *bluetooth_data)
{
    wmem_tree_key_t  key[4];
    guint32          frame_number;
    request_data_t  *request_data;

    frame_number = pinfo->num;

    key[0].length = 1;
    key[0].key    = &bluetooth_data->interface_id;
    key[1].length = 1;
    key[1].key    = &bluetooth_data->adapter_id;
    key[2].length = 1;
    key[2].key    = &frame_number;
    key[3].length = 0;
    key[3].key    = NULL;

    request_data = wmem_new(wmem_file_scope(), request_data_t);
    request_data->opcode = opcode;
    request_data->request_in_frame = frame_number;
    request_data->response_in_frame = 0;

    request_data->parameters = parameters;

    wmem_tree_insert32_array(requests, key, request_data);
}

static void
save_handle(packet_info *pinfo, bluetooth_uuid_t uuid, guint32 handle,
        enum attribute_type  attribute_type, bluetooth_data_t *bluetooth_data)
{
    if (!handle && uuid.size != 2 && uuid.size != 16)
        return;

    if (have_tap_listener(btatt_tap_handles)) {
        tap_handles_t  *tap_handles;

        tap_handles = wmem_new(wmem_packet_scope(), tap_handles_t);
        tap_handles->handle = handle;
        tap_handles->uuid = uuid;
        tap_queue_packet(btatt_tap_handles, pinfo, tap_handles);
    }

    if (!pinfo->fd->flags.visited && bluetooth_data) {
        wmem_tree_key_t  key[5];
        guint32          frame_number;
        handle_data_t   *handle_data;

        frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key    = &bluetooth_data->interface_id;
        key[1].length = 1;
        key[1].key    = &bluetooth_data->adapter_id;
        key[2].length = 1;
        key[2].key    = &handle;
        key[3].length = 1;
        key[3].key    = &frame_number;
        key[4].length = 0;
        key[4].key    = NULL;

        handle_data = wmem_new(wmem_file_scope(), handle_data_t);
        handle_data->uuid = uuid;
        handle_data->type = attribute_type;

        wmem_tree_insert32_array(handle_to_uuid, key, handle_data);
    }
}

static bluetooth_uuid_t
get_uuid_from_handle(packet_info *pinfo, guint32 handle,
        bluetooth_data_t *bluetooth_data)
{
    wmem_tree_key_t  key[4];
    guint32          frame_number;
    handle_data_t   *handle_data;
    wmem_tree_t     *sub_wmemtree;
    bluetooth_uuid_t uuid;

    memset(&uuid, 0, sizeof uuid);

    frame_number = pinfo->num;

    key[0].length = 1;
    key[0].key    = &bluetooth_data->interface_id;
    key[1].length = 1;
    key[1].key    = &bluetooth_data->adapter_id;
    key[2].length = 1;
    key[2].key    = &handle;
    key[3].length = 0;
    key[3].key    = NULL;

    sub_wmemtree = (wmem_tree_t *) wmem_tree_lookup32_array(handle_to_uuid, key);
    handle_data = (sub_wmemtree) ? (handle_data_t *) wmem_tree_lookup32_le(sub_wmemtree, frame_number) : NULL;

    if (handle_data)
        uuid = handle_data->uuid;

    return uuid;
}

static bluetooth_uuid_t
get_service_uuid_from_handle(packet_info *pinfo, guint32 handle,
        bluetooth_data_t *bluetooth_data)
{
    wmem_tree_key_t  key[4];
    guint32          frame_number;
    handle_data_t   *handle_data;
    wmem_tree_t     *sub_wmemtree;
    bluetooth_uuid_t uuid;

    memset(&uuid, 0, sizeof uuid);

    frame_number = pinfo->num;

    key[0].length = 1;
    key[0].key    = &bluetooth_data->interface_id;
    key[1].length = 1;
    key[1].key    = &bluetooth_data->adapter_id;
    key[2].length = 1;
    key[2].key    = &handle;
    key[3].length = 0;
    key[3].key    = NULL;

    while (handle > 0) {
        sub_wmemtree = (wmem_tree_t *) wmem_tree_lookup32_array(handle_to_uuid, key);
        handle_data = (sub_wmemtree) ? (handle_data_t *) wmem_tree_lookup32_le(sub_wmemtree, frame_number) : NULL;

        if (handle_data && handle_data->type == ATTRIBUTE_TYPE_SERVICE) {
            uuid = handle_data->uuid;
            return uuid;
        }

        handle -= 1;
    }

    return uuid;
}

static bluetooth_uuid_t
get_characteristic_uuid_from_handle(packet_info *pinfo, guint32 handle,
        bluetooth_data_t *bluetooth_data)
{
    wmem_tree_key_t  key[4];
    guint32          frame_number;
    handle_data_t   *handle_data;
    wmem_tree_t     *sub_wmemtree;
    bluetooth_uuid_t uuid;

    memset(&uuid, 0, sizeof uuid);

    frame_number = pinfo->num;

    key[0].length = 1;
    key[0].key    = &bluetooth_data->interface_id;
    key[1].length = 1;
    key[1].key    = &bluetooth_data->adapter_id;
    key[2].length = 1;
    key[2].key    = &handle;
    key[3].length = 0;
    key[3].key    = NULL;

    while (handle > 0) {
        sub_wmemtree = (wmem_tree_t *) wmem_tree_lookup32_array(handle_to_uuid, key);
        handle_data = (sub_wmemtree) ? (handle_data_t *) wmem_tree_lookup32_le(sub_wmemtree, frame_number) : NULL;

        if (handle_data && handle_data->type == ATTRIBUTE_TYPE_SERVICE)
            return uuid;

        if (handle_data && handle_data->type == ATTRIBUTE_TYPE_CHARACTERISTIC) {
            uuid = handle_data->uuid;
            return uuid;
        }

        handle -= 1;
    }

    return uuid;
}

static void col_append_info_by_handle(packet_info *pinfo, guint16 handle, bluetooth_data_t *bluetooth_data)
{
    bluetooth_uuid_t   service_uuid;
    bluetooth_uuid_t   characteristic_uuid;
    bluetooth_uuid_t   uuid;

    service_uuid = get_service_uuid_from_handle(pinfo, handle, bluetooth_data);
    characteristic_uuid = get_characteristic_uuid_from_handle(pinfo, handle, bluetooth_data);
    uuid = get_uuid_from_handle(pinfo, handle, bluetooth_data);

    if (!memcmp(&service_uuid, &uuid, sizeof(uuid))) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x (%s)",
                handle, print_uuid(&uuid));
    } else if (!memcmp(&characteristic_uuid, &uuid, sizeof(uuid))) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x (%s: %s)",
                handle, print_uuid(&service_uuid), print_uuid(&uuid));
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x (%s: %s: %s)",
                handle, print_uuid(&service_uuid), print_uuid(&characteristic_uuid), print_uuid(&uuid));
    }
}

static gint dissect_gatt_uuid(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
    proto_item       *sub_item;
    bluetooth_uuid_t  sub_uuid;

    if (tvb_reported_length_remaining(tvb, offset) == 2) {
        proto_tree_add_item(tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        sub_uuid = get_uuid(tvb, offset, 2);
        offset += 2;
    } else if (tvb_reported_length_remaining(tvb, offset) == 16) {
        sub_item = proto_tree_add_item(tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
        sub_uuid = get_uuid(tvb, offset, 16);
        proto_item_append_text(sub_item, " (%s)", print_uuid(&sub_uuid));
        offset += 16;
    } else {
        sub_item = proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
        expert_add_info(pinfo, sub_item, &ei_btatt_bad_data);
        offset = tvb_captured_length(tvb);
    }

    return offset;
}

static int
dissect_handle(proto_tree *tree, packet_info *pinfo, gint hf,
        tvbuff_t *tvb, gint offset, bluetooth_data_t *bluetooth_data,
        bluetooth_uuid_t *uuid, gint32 handle)
{
    proto_item        *handle_item;
    proto_item        *sub_item;
    proto_tree        *sub_tree;
    bluetooth_uuid_t   service_uuid;
    bluetooth_uuid_t   characteristic_uuid;
    bluetooth_uuid_t   attribute_uuid;

    if (handle == HANDLE_TVB) {
        handle_item = proto_tree_add_item(tree, hf, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        handle = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    } else if (handle >= 0 && handle <= G_MAXUINT16) {
        handle_item = proto_tree_add_uint(tree, hf, tvb, 0, 0, handle);
        PROTO_ITEM_SET_GENERATED(handle_item);
    } else {
        DISSECTOR_ASSERT_NOT_REACHED();
    }

    service_uuid = get_service_uuid_from_handle(pinfo, (guint16) handle, bluetooth_data);
    characteristic_uuid = get_characteristic_uuid_from_handle(pinfo, (guint16) handle, bluetooth_data);
    attribute_uuid = get_uuid_from_handle(pinfo, (guint16) handle, bluetooth_data);

    if (memcmp(&service_uuid, &attribute_uuid, sizeof(attribute_uuid))) {
        if (service_uuid.size == 2 || service_uuid.size == 16) {
            proto_item_append_text(handle_item, " (%s", print_uuid(&service_uuid));
            sub_tree = proto_item_add_subtree(handle_item, ett_btatt_handle);

            if (service_uuid.size == 2)
                sub_item = proto_tree_add_uint(sub_tree, hf_btatt_service_uuid16, tvb, 0, 0, service_uuid.bt_uuid);
            else
                sub_item = proto_tree_add_bytes_with_length(sub_tree, hf_btatt_service_uuid128, tvb, 0, 0, service_uuid.data, 16);

            PROTO_ITEM_SET_GENERATED(sub_item);
        }
    } else {
        proto_item_append_text(handle_item, " (");
    }

    if (memcmp(&characteristic_uuid, &attribute_uuid, sizeof(attribute_uuid))) {
        if (characteristic_uuid.size == 2 || characteristic_uuid.size == 16) {
            proto_item_append_text(handle_item, ": %s", print_uuid(&characteristic_uuid));
            sub_tree = proto_item_add_subtree(handle_item, ett_btatt_handle);

            if (characteristic_uuid.size == 2)
                sub_item = proto_tree_add_uint(sub_tree, hf_btatt_characteristic_uuid16, tvb, 0, 0, characteristic_uuid.bt_uuid);
            else
                sub_item = proto_tree_add_bytes_with_length(sub_tree, hf_btatt_characteristic_uuid128, tvb, 0, 0, characteristic_uuid.data, 16);

            PROTO_ITEM_SET_GENERATED(sub_item);
        }
    }

    if (memcmp(&service_uuid, &attribute_uuid, sizeof(attribute_uuid)))
        proto_item_append_text(handle_item, ": %s)", print_uuid(&attribute_uuid));
    else
        proto_item_append_text(handle_item, "%s)", print_uuid(&attribute_uuid));
    if (attribute_uuid.size == 2 || attribute_uuid.size == 16) {
        sub_tree = proto_item_add_subtree(handle_item, ett_btatt_handle);

        if (attribute_uuid.size == 2)
            sub_item = proto_tree_add_uint(sub_tree, hf_btatt_uuid16, tvb, 0, 0, attribute_uuid.bt_uuid);
        else
            sub_item = proto_tree_add_bytes_with_length(sub_tree, hf_btatt_uuid128, tvb, 0, 0, attribute_uuid.data, 16);

        PROTO_ITEM_SET_GENERATED(sub_item);
    }

    if (uuid)
        *uuid = attribute_uuid;

    return offset + 2;
}

static gint
dissect_attribute_value(proto_tree *tree, proto_item *patron_item, packet_info *pinfo, tvbuff_t *old_tvb,
        gint old_offset, gint length, guint16 handle, bluetooth_uuid_t uuid, btatt_data_t *att_data)
{
    proto_item  *sub_item;
    proto_tree  *sub_tree = NULL;
    tvbuff_t    *tvb;
    gint         offset = 0;
    bluetooth_uuid_t sub_uuid;
    bluetooth_uuid_t service_uuid;
    guint16      sub_handle;
    guint32      value;
    guint32      flags;
    guint32      operator_value;
    guint32      opcode;
    guint32      operand_offset;
    const gint  **hfs;
    bluetooth_data_t *bluetooth_data = NULL;

    tvb = tvb_new_subset(old_tvb, old_offset, length, length);

    DISSECTOR_ASSERT(att_data);

    bluetooth_data = att_data->bluetooth_data;

    if (p_get_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_HANDLE) == NULL) {
        guint16 *value_data;

        value_data = wmem_new(wmem_file_scope(), guint16);
        *value_data = handle;

        p_add_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_HANDLE, value_data);
    }

    if (dissector_try_uint_new(att_handle_dissector_table, handle, tvb, pinfo, tree, TRUE, att_data))
        return old_offset + length;

    if (p_get_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_SERVICE_UUID) == NULL) {
        guint8 *value_data;

        value_data = wmem_strdup(wmem_file_scope(), print_numeric_uuid(&uuid));

        p_add_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_SERVICE_UUID, value_data);
    }

    if (dissector_try_string(bluetooth_uuid_table, print_numeric_uuid(&uuid), tvb, pinfo, tree, att_data))
        return old_offset + length;
    else if (!uuid.bt_uuid) {
        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            return old_offset;

        proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);

        return old_offset + tvb_captured_length(tvb);
    }

    service_uuid = get_service_uuid_from_handle(pinfo, handle, bluetooth_data);

    switch (uuid.bt_uuid) {
    case 0x2800: /* GATT Primary Service Declaration */
    case 0x2801: /* GATT Secondary Service Declaration */
        if (is_readable_request(att_data->opcode) || att_data->opcode == ATT_OPCODE_READ_BY_GROUP_TYPE_REQUEST)
            break;

        if (!is_readable_response(att_data->opcode) && att_data->opcode != ATT_OPCODE_READ_BY_GROUP_TYPE_RESPONSE)
            expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        if (tvb_reported_length_remaining(tvb, offset) == 2) {
            proto_tree_add_item(tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            sub_uuid = get_uuid(tvb, offset, 2);
            proto_item_append_text(patron_item, ", UUID: %s", print_uuid(&sub_uuid));
            offset += 2;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", print_uuid(&sub_uuid));

            save_handle(pinfo, sub_uuid, handle, ATTRIBUTE_TYPE_SERVICE, bluetooth_data);
        } else if (tvb_reported_length_remaining(tvb, offset) == 16) {
            proto_tree_add_item(tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
            sub_uuid = get_uuid(tvb, offset, 16);
            proto_item_append_text(patron_item, ", UUID128: %s", print_uuid(&sub_uuid));
            offset += 16;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", print_uuid(&sub_uuid));

            save_handle(pinfo, sub_uuid, handle, ATTRIBUTE_TYPE_SERVICE, bluetooth_data);
        } else {
            sub_item = proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_btatt_bad_data);
            offset = tvb_captured_length(tvb);
        }

        break;
    case 0x2802: /* GATT Include Declaration */
        if (is_readable_request(att_data->opcode))
            break;

        if (!is_readable_response(att_data->opcode))
            expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        offset = dissect_handle(tree, pinfo, hf_btatt_included_service_handle, tvb, offset, bluetooth_data, NULL, HANDLE_TVB);
        sub_handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(tree, hf_btatt_ending_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        sub_uuid = get_uuid(tvb, offset, 2);
        proto_item_append_text(patron_item, ", Included Handle: 0x%04x, UUID: %s", sub_handle, print_uuid(&sub_uuid));
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", print_uuid(&sub_uuid));

        save_handle(pinfo, sub_uuid, sub_handle, ATTRIBUTE_TYPE_OTHER, bluetooth_data);

        break;
    case 0x2803: /* GATT Characteristic Declaration*/
        if (is_readable_request(att_data->opcode) || att_data->opcode == ATT_OPCODE_READ_BY_TYPE_REQUEST)
            break;

        if (!is_readable_response(att_data->opcode) && att_data->opcode != ATT_OPCODE_READ_BY_TYPE_RESPONSE)
            expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_characteristic_properties, ett_btatt_characteristic_properties,  hfx_btatt_characteristic_properties, ENC_NA);
        offset += 1;

        offset = dissect_handle(tree, pinfo, hf_btatt_characteristic_value_handle, tvb, offset, bluetooth_data, NULL, HANDLE_TVB);
        sub_handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

        if (tvb_reported_length_remaining(tvb, offset) == 16) {
            proto_tree_add_item(tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
            sub_uuid = get_uuid(tvb, offset, 16);
            proto_item_append_text(patron_item, ", Characteristic Handle: 0x%04x, UUID128: %s", tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN), print_uuid(&sub_uuid));
            offset += 16;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", print_uuid(&sub_uuid));

            save_handle(pinfo, sub_uuid, sub_handle, ATTRIBUTE_TYPE_CHARACTERISTIC, bluetooth_data);
        } else if (tvb_reported_length_remaining(tvb, offset) == 2) {
            proto_tree_add_item(tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            sub_uuid = get_uuid(tvb, offset, 2);
            proto_item_append_text(patron_item, ", Characteristic Handle: 0x%04x, UUID: %s", sub_handle, print_uuid(&sub_uuid));
            offset += 2;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", print_uuid(&sub_uuid));

            save_handle(pinfo, sub_uuid, sub_handle, ATTRIBUTE_TYPE_CHARACTERISTIC, bluetooth_data);
        } else {
            sub_item = proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_btatt_bad_data);
            offset = tvb_captured_length(tvb);
        }

        break;
    case 0x2900: /* Characteristic Extended Properties */
        if (is_readable_request(att_data->opcode))
            break;

        if (!is_readable_response(att_data->opcode))
            expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_characteristic_extended_properties, ett_btatt_value, hfx_btatt_characteristic_extended_properties, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2901: /* Characteristic User Description */
        if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
            break;

        if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode))
            expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_characteristic_user_description, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2902: /* GATT: Client Characteristic Configuration */
        if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
            break;

        if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode))
            expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_characteristic_configuration_client, ett_btatt_value, hfx_btatt_characteristic_configuration_client, ENC_LITTLE_ENDIAN);
        value = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset += 2;

        {
        bluetooth_uuid_t   characteristic_uuid;

        characteristic_uuid = get_characteristic_uuid_from_handle(pinfo, handle, bluetooth_data);

        if (value & 0x1) switch (characteristic_uuid.bt_uuid) { /* Notification */
        case 0x2A05: /* Service Changed */
        case 0x2A1C: /* Temperature Measurement */
        case 0x2A21: /* Measurement Interval */
        case 0x2A35: /* Blood Pressure Measurement */
        case 0x2A52: /* Record Access Control Point */
        case 0x2A55: /* SC Control Point */
        case 0x2A66: /* Cycling Power Control Point */
        case 0x2A6B: /* LN Control Point */
        case 0x2A99: /* Database Change Increment */
        case 0x2A9C: /* Body Composition Measurement */
        case 0x2A9D: /* Weight Measurement */
        case 0x2A9F: /* User Control Point */
        case 0x2ABC: /* TDS Control Point */
        case 0x2AC5: /* Object Action Control Point */
        case 0x2AC6: /* Object List Control Point */
        case 0x2AC8: /* Object Changed */
            expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
            break;

        case 0x2A18: /* Glucose Measurement */
        case 0x2A19: /* Battery Level */
        case 0x2A1E: /* Intermediate Temperature */
        case 0x2A22: /* Boot Keyboard Input Report */
        case 0x2A2C: /* Magnetic Declination */
        case 0x2A2B: /* Current Time */
        case 0x2A31: /* Scan Refresh */
        case 0x2A33: /* Boot Mouse Input Report */
        case 0x2A34: /* Glucose Measurement Context */
        case 0x2A36: /* Intermediate Cuff Pressure */
        case 0x2A37: /* Heart Rate Measurement */
        case 0x2A3F: /* Alert Status */
        case 0x2A45: /* Unread Alert Status */
        case 0x2A46: /* New Alert */
        case 0x2A4D: /* Report */
        case 0x2A53: /* RSC Measurement */
        case 0x2A56: /* Digital */
        case 0x2A58: /* Analog */
        case 0x2A5A: /* Aggregate */
        case 0x2A5B: /* CSC Measurement */
        case 0x2A63: /* Cycling Power Measurement */
        case 0x2A64: /* Cycling Power Vector */
        case 0x2A67: /* Location and Speed */
        case 0x2A68: /* Navigation */
        case 0x2A6C: /* Elevation */
        case 0x2A6D: /* Pressure */
        case 0x2A6E: /* Temperature */
        case 0x2A6F: /* Humidity */
        case 0x2A70: /* True Wind Speed */
        case 0x2A71: /* True Wind Direction */
        case 0x2A72: /* Apparent Wind Speed */
        case 0x2A73: /* Apparent Wind Direction */
        case 0x2A74: /* Gust Factor */
        case 0x2A75: /* Pollen Concentration */
        case 0x2A76: /* UV Index */
        case 0x2A77: /* Irradiance */
        case 0x2A78: /* Rainfall */
        case 0x2A79: /* Wind Chill */
        case 0x2A7A: /* Heat Index */
        case 0x2A7B: /* Dew Point */
        case 0x2AA0: /* Magnetic Flux Density - 2D */
        case 0x2AA1: /* Magnetic Flux Density - 3D */
        case 0x2AA3: /* Barometric Pressure Trend */
        case 0x2AA7: /* CGM Measurement */
        case 0x2AB8: /* HTTP Status Code */
        default:
            /* Supported */
            break;
        }

        if (value & 0x2) switch (characteristic_uuid.bt_uuid) { /* Indication */
        case 0x2A18: /* Glucose Measurement */
        case 0x2A19: /* Battery Level */
        case 0x2A1E: /* Intermediate Temperature */
        case 0x2A22: /* Boot Keyboard Input Report */
        case 0x2A2B: /* Current Time */
        case 0x2A2C: /* Magnetic Declination */
        case 0x2A31: /* Scan Refresh */
        case 0x2A33: /* Boot Mouse Input Report */
        case 0x2A34: /* Glucose Measurement Context */
        case 0x2A36: /* Intermediate Cuff Pressure */
        case 0x2A37: /* Heart Rate Measurement */
        case 0x2A3F: /* Alert Status */
        case 0x2A45: /* Unread Alert Status */
        case 0x2A46: /* New Alert */
        case 0x2A4D: /* Report */
        case 0x2A53: /* RSC Measurement */
        case 0x2A5B: /* CSC Measurement */
        case 0x2A63: /* Cycling Power Measurement */
        case 0x2A64: /* Cycling Power Vector */
        case 0x2A67: /* Location and Speed */
        case 0x2A68: /* Navigation */
        case 0x2A6C: /* Elevation */
        case 0x2A6D: /* Pressure */
        case 0x2A6E: /* Temperature */
        case 0x2A6F: /* Humidity */
        case 0x2A70: /* True Wind Speed */
        case 0x2A71: /* True Wind Direction */
        case 0x2A72: /* Apparent Wind Speed */
        case 0x2A73: /* Apparent Wind Direction */
        case 0x2A74: /* Gust Factor */
        case 0x2A75: /* Pollen Concentration */
        case 0x2A76: /* UV Index */
        case 0x2A77: /* Irradiance */
        case 0x2A78: /* Rainfall */
        case 0x2A79: /* Wind Chill */
        case 0x2A7A: /* Heat Index */
        case 0x2A7B: /* Dew Point */
        case 0x2AA0: /* Magnetic Flux Density - 2D */
        case 0x2AA1: /* Magnetic Flux Density - 3D */
        case 0x2AA3: /* Barometric Pressure Trend */
        case 0x2AA7: /* CGM Measurement */
        case 0x2AB8: /* HTTP Status Code */
            expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
            break;

        case 0x2A05: /* Service Changed */
        case 0x2A1C: /* Temperature Measurement */
        case 0x2A21: /* Measurement Interval */
        case 0x2A35: /* Blood Pressure Measurement */
        case 0x2A52: /* Record Access Control Point */
        case 0x2A55: /* SC Control Point */
        case 0x2A56: /* Digital */
        case 0x2A58: /* Analog */
        case 0x2A5A: /* Aggregate */
        case 0x2A66: /* Cycling Power Control Point */
        case 0x2A6B: /* LN Control Point */
        case 0x2A99: /* Database Change Increment */
        case 0x2A9C: /* Body Composition Measurement */
        case 0x2A9D: /* Weight Measurement */
        case 0x2A9F: /* User Control Point */
        case 0x2ABC: /* TDS Control Point */
        case 0x2AC5: /* Object Action Control Point */
        case 0x2AC6: /* Object List Control Point */
        case 0x2AC8: /* Object Changed */
        default:
            /* Supported */
            break;
        }

        if (value > 0x3)
            expert_add_info(pinfo, tree, &ei_btatt_bad_data);

        }

        break;
    case 0x2903: /* Server Characteristic Configuration */
        if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
            break;

        if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode))
            expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_characteristic_configuration_server, ett_btatt_value, hfx_btatt_characteristic_configuration_server, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2904: /* Characteristic Presentation Format */
        if (is_readable_request(att_data->opcode))
            break;

        if (!is_readable_response(att_data->opcode))
            expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_characteristic_presentation_format, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_characteristic_presentation_exponent, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_characteristic_presentation_unit, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_characteristic_presentation_namespace, tvb, offset, 1, ENC_NA);
        value = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (value == 0x01) /* Bluetooth SIG */
            proto_tree_add_item(tree, hf_btatt_characteristic_presentation_namespace_description_btsig, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        else
            proto_tree_add_item(tree, hf_btatt_characteristic_presentation_namespace_description, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2905: /* Characteristic Aggregate Format */
        if (is_readable_request(att_data->opcode))
            break;

        if (!is_readable_response(att_data->opcode))
            expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        sub_item = proto_tree_add_none_format(tree, hf_btatt_handles_info,
                tvb, offset, tvb_captured_length(tvb), "Handles (%i items)",
                tvb_captured_length(tvb) / 2);
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

        while (offset < (gint64) tvb_captured_length(tvb)) {
            offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL, HANDLE_TVB);
        }
        break;
    case 0x2906: /* Valid Range */ {
        bluetooth_uuid_t     characteristic_uuid;
        guint8              *characteristic_dissector_name;
        dissector_handle_t   characteristic_dissector;

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        characteristic_uuid = get_characteristic_uuid_from_handle(pinfo, handle, bluetooth_data);

        characteristic_dissector_name = wmem_strdup_printf(wmem_packet_scope(), "btgatt.uuid0x%s", print_numeric_uuid(&characteristic_uuid));
        characteristic_dissector = find_dissector(characteristic_dissector_name);

        sub_item = proto_tree_add_item(tree, hf_btatt_valid_range_lower_inclusive_value, tvb, offset, tvb_reported_length_remaining(tvb, offset) / 2, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

        if (characteristic_dissector)
            call_dissector_with_data(characteristic_dissector, tvb_new_subset(tvb, offset, tvb_reported_length_remaining(tvb, offset) / 2, tvb_reported_length_remaining(tvb, offset) / 2), pinfo, sub_tree, att_data);

        sub_item = proto_tree_add_item(tree, hf_btatt_valid_range_upper_inclusive_value, tvb, offset + tvb_reported_length_remaining(tvb, offset) / 2, tvb_reported_length_remaining(tvb, offset) / 2, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

        if (characteristic_dissector)
            call_dissector_with_data(characteristic_dissector, tvb_new_subset(tvb, offset + tvb_reported_length_remaining(tvb, offset) / 2, tvb_reported_length_remaining(tvb, offset) / 2, tvb_reported_length_remaining(tvb, offset) / 2), pinfo, sub_tree, att_data);

        offset += tvb_reported_length_remaining(tvb, offset);
        }
        break;
    case 0x2907: /* External Report Reference */
        if (service_uuid.bt_uuid == GATT_SERVICE_HUMAN_INTERFACE_DEVICE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        if (tvb_reported_length_remaining(tvb, offset) == 2) {
            proto_tree_add_item(tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        } else if (tvb_reported_length_remaining(tvb, offset) == 16) {
            proto_tree_add_item(tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
            offset += 16;
        } else {
            sub_item = proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_btatt_bad_data);
            offset = tvb_captured_length(tvb);
        }
        break;
    case 0x2908: /* GATT: Report Reference */
        if (service_uuid.bt_uuid == GATT_SERVICE_HUMAN_INTERFACE_DEVICE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_report_reference_report_id, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_report_reference_report_type, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2909: /* Number of Digitals */
        if (is_readable_request(att_data->opcode))
            break;

        if (!is_readable_response(att_data->opcode))
            expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_number_of_digitals, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x290A: /* Value Trigger Setting */
        if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
            break;

        if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode))
            expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_value_trigger_setting_condition, tvb, offset, 1, ENC_NA);
        value = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (value >= 1 && value <= 3) {
            proto_tree_add_item(tree, hf_btatt_value_trigger_setting_analog, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        } else if (value == 4) {
            call_dissector_with_data(find_dissector("btgatt.uuid0x2a56"), tvb_new_subset(tvb, offset, 1, 1), pinfo, tree, att_data);
            offset += 1;
        } else if (value == 5 || value == 6) {
            proto_tree_add_item(tree, hf_btatt_value_trigger_setting_analog_one, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_btatt_value_trigger_setting_analog_two, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x290B: /* Environmental Sensing Configuration */
        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_esp_trigger_logic, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x290C: /* Environmental Sensing Measurement */
        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_esp_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_esp_sampling_function, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_esp_measurement_period, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;

        proto_tree_add_item(tree, hf_btatt_esp_update_interval, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;

        proto_tree_add_item(tree, hf_btatt_esp_application, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_esp_measurement_uncertainty, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x290D: /* Environmental Sensing Trigger Setting */
        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_esp_condition, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_esp_operand, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
        offset += tvb_captured_length_remaining(tvb, offset);
        break;
    case 0x290E: /* Time Trigger Setting */
        if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
            break;

        if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode))
            expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_time_trigger_setting_condition, tvb, offset, 1, ENC_NA);
        value = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (value == 0) {
            proto_tree_add_item(tree, hf_btatt_time_trigger_setting_value, tvb, offset, 1, ENC_NA);
            offset += 1;
        } else if (value == 1 || value == 2) {
            proto_tree_add_item(tree, hf_btatt_time_trigger_setting_value_time_interval, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;
        } else if (value == 3) {
            proto_tree_add_item(tree, hf_btatt_time_trigger_setting_value_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2A00: /* Device Name */
        if (service_uuid.bt_uuid == GATT_SERVICE_GENERIC_ACCESS_PROFILE) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_device_name, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A01: /* Appearance */
        if (service_uuid.bt_uuid == GATT_SERVICE_GENERIC_ACCESS_PROFILE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        switch ((tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN) & 0xFFC0) >> 6) {
        case 0x003: /* Watch */
            hfs = hfx_btatt_appearance_watch;
            break;

        case 0x00C: /* Thermometer */
            hfs = hfx_btatt_appearance_thermometer;
            break;

        case 0x00D: /* Heart Rate Sensor */
            hfs = hfx_btatt_appearance_heart_rate;
            break;

        case 0x00E: /* Blood Pressure */
            hfs = hfx_btatt_appearance_blood_pressure;
            break;

        case 0x00F: /* HID */
            hfs = hfx_btatt_appearance_hid;
            break;

        case 0x011: /* Running Walking Sensor */
            hfs = hfx_btatt_appearance_running_walking_sensor;
            break;

        case 0x012: /* Cycling */
            hfs = hfx_btatt_appearance_cycling;
            break;

        case 0x031: /* Pulse Oximeter */
            hfs = hfx_btatt_appearance_pulse_oximeter;
            break;

        case 0x051: /* Outdoor Sports Activity */
            hfs = hfx_btatt_appearance_outdoor_sports_activity;
            break;

        default:
            hfs = hfx_btatt_appearance;
        }
        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_appearance, ett_btatt_value, hfs, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A02: /* Peripheral Privacy Flag */
        if (service_uuid.bt_uuid == GATT_SERVICE_GENERIC_ACCESS_PROFILE) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_peripheral_privacy_flag, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A03: /* Reconnection Address */
        if (service_uuid.bt_uuid == GATT_SERVICE_GENERIC_ACCESS_PROFILE) {
            if (is_writeable_response(att_data->opcode))
                break;

            if (!is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        offset = dissect_bd_addr(hf_btatt_reconnection_address, pinfo, tree, tvb, offset, FALSE, bluetooth_data->interface_id, bluetooth_data->adapter_id, NULL);

        break;
    case 0x2A04: /* Peripheral Preferred Connection Parameters */
        if (service_uuid.bt_uuid == GATT_SERVICE_GENERIC_ACCESS_PROFILE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_minimum_connection_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_maximum_connection_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_slave_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_connection_supervision_timeout_multiplier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A05: /* Service Changed */
        if (service_uuid.bt_uuid == GATT_SERVICE_GENERIC_ATTRIBUTE_PROFILE) {
            if (att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_starting_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_ending_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A06: /* Alert Level */
        if (service_uuid.bt_uuid == GATT_SERVICE_IMMEDIATE_ALERT) {
            if (att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        } else if (service_uuid.bt_uuid == GATT_SERVICE_LINK_LOSS) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_alert_level, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A07: /* Tx Power Level */
        if (service_uuid.bt_uuid == GATT_SERVICE_TX_POWER) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_tx_power_level, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A08: /* Date Time */
        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_month, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_day, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_hours, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_minutes, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_seconds, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A09: /* Day of Week */
        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_day_of_week, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A0A: /* Day Date Time */
    case 0x2A0C: /* Exact Time 256 */
    case 0x2A2B: /* Current Time */
        if (uuid.bt_uuid == 0x2A2B) {/* Current Time */
            if (service_uuid.bt_uuid == GATT_SERVICE_CURRENT_TIME_SERVICE) {
                if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                    break;

                if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) &&
                        att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                    expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
            }
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_month, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_day, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_hours, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_minutes, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_seconds, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_day_of_week, tvb, offset, 1, ENC_NA);
        offset += 1;

        if (uuid.bt_uuid == 0x2A0C || uuid.bt_uuid == 0x2A2B) {
            proto_tree_add_item(tree, hf_btatt_fractions256, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

         if (uuid.bt_uuid == 0x2A2B) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_time_adjust_reason, ett_btatt_value, hfx_btatt_time_adjust_reason, ENC_NA);
            offset += 1;
         }

        break;
    case 0x2A0D: /* DST Offset */
        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_dst_offset, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A0E: /* Time Zone */
        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_timezone, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A0F: /* Local Time Information */
        if (service_uuid.bt_uuid == GATT_SERVICE_CURRENT_TIME_SERVICE) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_timezone, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_dst_offset, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A11: /* Time with DST */
        if (service_uuid.bt_uuid == GATT_SERVICE_NEXT_DST_CHANGE_SERVICE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_month, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_day, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_hours, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_minutes, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_seconds, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_dst_offset, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A12: /* Time Accuracy */
        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_time_accuracy, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A13: /* Time Source */
        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_time_source, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A14: /* Reference Time Information */
        if (service_uuid.bt_uuid == GATT_SERVICE_CURRENT_TIME_SERVICE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_time_source, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_time_accuracy, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_time_days_since_update, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_time_hours_since_update, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A16: /* Time Update Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_REFERENCE_TIME_UPDATE_SERVICE) {
            if (att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_time_update_control_point, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A17: /* Time Update State */
        if (service_uuid.bt_uuid == GATT_SERVICE_REFERENCE_TIME_UPDATE_SERVICE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_time_current_state, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_time_result, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A18: /* Glucose Measurement */
        if (service_uuid.bt_uuid == GATT_SERVICE_GLUCOSE) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_glucose_measurement_flags, ett_btatt_value, hfx_btatt_glucose_measurement_flags, ENC_NA);
        flags = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_glucose_measurement_sequence_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        sub_item = proto_tree_add_item(tree, hf_btatt_glucose_measurement_base_time, tvb, offset, 7, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

        proto_tree_add_item(sub_tree, hf_btatt_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(sub_tree, hf_btatt_month, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(sub_tree, hf_btatt_day, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(sub_tree, hf_btatt_hours, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(sub_tree, hf_btatt_minutes, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(sub_tree, hf_btatt_seconds, tvb, offset, 1, ENC_NA);
        offset += 1;

        if (flags & 0x01) {
            proto_tree_add_item(tree, hf_btatt_glucose_measurement_time_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x02 && !(flags & 0x04)) {
            proto_tree_add_item(tree, hf_btatt_glucose_measurement_glucose_concentration_kg_per_l, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x02 && flags & 0x04) {
            proto_tree_add_item(tree, hf_btatt_glucose_measurement_glucose_concentration_mol_per_l, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x02) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_glucose_measurement_type_and_sample_location, ett_btatt_value, hfx_btatt_glucose_measurement_type_and_sample_location, ENC_NA);
            offset += 1;
        }

        if (flags & 0x08) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_glucose_measurement_sensor_status_annunciation, ett_btatt_value, hfx_btatt_glucose_measurement_sensor_status_annunciation, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2A19: /* Battery Level */
        if (service_uuid.bt_uuid == GATT_SERVICE_BATTERY_SERVICE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_battery_level, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A1C: /* Temperature Measurement */
    case 0x2A1E: /* Intermediate Temperature */
        if (uuid.bt_uuid == 0x2A1C) {/* Temperature Measurement */
            if (service_uuid.bt_uuid == GATT_SERVICE_HEALTH_THERMOMETER) {
                if (att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                    break;

                if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                    expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
            }
        } else if (uuid.bt_uuid == 0x2A1E) {/* Intermediate Temperature */
            if (service_uuid.bt_uuid == GATT_SERVICE_HEALTH_THERMOMETER) {
                if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                    expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
            }
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_temperature_measurement_flags, ett_btatt_value, hfx_btatt_temperature_measurement_flags, ENC_NA);
        flags = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (flags & 0x01) {
            proto_tree_add_item(tree, hf_btatt_temperature_measurement_value_celsius, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        } else {
            proto_tree_add_item(tree, hf_btatt_temperature_measurement_value_fahrenheit, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }

        if (flags & 0x02) {
            sub_item = proto_tree_add_item(tree, hf_btatt_temperature_measurement_timestamp, tvb, offset, 7, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

            proto_tree_add_item(sub_tree, hf_btatt_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(sub_tree, hf_btatt_month, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_day, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_hours, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_minutes, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_seconds, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x04) {
            proto_tree_add_item(tree, hf_btatt_temperature_type, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        break;
    case 0x2A1D: /* Temperature Type */
        if (service_uuid.bt_uuid == GATT_SERVICE_HEALTH_THERMOMETER) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_temperature_type, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A21: /* Measurement Interval */
        if (service_uuid.bt_uuid == GATT_SERVICE_HEALTH_THERMOMETER) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_measurement_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A22: /* Boot Keyboard Input Report */
        if (service_uuid.bt_uuid == GATT_SERVICE_HUMAN_INTERFACE_DEVICE) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        call_dissector_with_data(usb_hid_boot_keyboard_input_report_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree, NULL);
        offset += tvb_reported_length_remaining(tvb, offset);

        break;
    case 0x2A23: /* System ID */
        if (service_uuid.bt_uuid == GATT_SERVICE_DEVICE_INFORMATION) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_system_id_manufacturer_identifier, tvb, offset, 5, ENC_LITTLE_ENDIAN);
        offset += 5;

        proto_tree_add_item(tree, hf_btatt_system_id_organizationally_unique_identifier, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;
        break;
    case 0x2A24: /* Model Number String */
        if (service_uuid.bt_uuid == GATT_SERVICE_DEVICE_INFORMATION) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_model_number_string, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A25: /* Serial Number String */
        if (service_uuid.bt_uuid == GATT_SERVICE_DEVICE_INFORMATION) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_serial_number_string, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A26: /* Firmware Revision String */
        if (service_uuid.bt_uuid == GATT_SERVICE_DEVICE_INFORMATION) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_firmware_revision_string, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A27: /* Hardware Revision String */
        if (service_uuid.bt_uuid == GATT_SERVICE_DEVICE_INFORMATION) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_hardware_revision_string, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A28: /* Software Revision String */
        if (service_uuid.bt_uuid == GATT_SERVICE_DEVICE_INFORMATION) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_software_revision_string, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A29: /* Manufacturer Name String */
        if (service_uuid.bt_uuid == GATT_SERVICE_DEVICE_INFORMATION) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_manufacturer_string, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A2A: /* IEEE 11073-20601 Regulatory Certification Data List */
        if (service_uuid.bt_uuid == GATT_SERVICE_DEVICE_INFORMATION) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        sub_item = proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
        expert_add_info(pinfo, sub_item, &ei_btatt_undecoded);
        offset = tvb_captured_length(tvb);

        break;
    case 0x2A2C: /* Magnetic Declination */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_magnetic_declination, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A31: /* Scan Refresh */
        if (service_uuid.bt_uuid == GATT_SERVICE_SCAN_PARAMETERS) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_scan_refresh, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A32: /* Boot Keyboard Output Report */
        if (service_uuid.bt_uuid == GATT_SERVICE_HUMAN_INTERFACE_DEVICE) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        call_dissector_with_data(usb_hid_boot_keyboard_output_report_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree, NULL);
        offset += tvb_reported_length_remaining(tvb, offset);

        break;
    case 0x2A33: /* Boot Mouse Input Report */
        if (service_uuid.bt_uuid == GATT_SERVICE_HUMAN_INTERFACE_DEVICE) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        call_dissector_with_data(usb_hid_boot_mouse_input_report_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree, NULL);
        offset += tvb_reported_length_remaining(tvb, offset);

        break;
    case 0x2A34: /* Glucose Measurement Context */
        if (service_uuid.bt_uuid == GATT_SERVICE_GLUCOSE) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_glucose_measurement_context_flags, ett_btatt_value, hfx_btatt_glucose_measurement_context_flags, ENC_NA);
        flags = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_glucose_measurement_context_sequence_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (flags & 0x80) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_glucose_measurement_context_extended_flags, ett_btatt_value, hfx_btatt_glucose_measurement_context_extended_flags, ENC_NA);
            offset += 1;
        }

        if (flags & 0x01) {
            proto_tree_add_item(tree, hf_btatt_glucose_measurement_context_carbohydrate_id, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_btatt_glucose_measurement_context_carbohydrate_kg, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x02) {
            proto_tree_add_item(tree, hf_btatt_glucose_measurement_context_meal, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x04) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_glucose_measurement_context_tester_health, ett_btatt_value, hfx_btatt_glucose_measurement_context_tester_health, ENC_NA);
            offset += 1;
        }

        if (flags & 0x08) {
            proto_tree_add_item(tree, hf_btatt_glucose_measurement_context_exercise_duration, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_btatt_glucose_measurement_context_exercise_intensity, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x10) {
            proto_tree_add_item(tree, hf_btatt_glucose_measurement_context_medication_id, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (flags & 0x20) {
                proto_tree_add_item(tree, hf_btatt_glucose_measurement_context_medication_l, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            } else {
                proto_tree_add_item(tree, hf_btatt_glucose_measurement_context_medication_kg, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
        }

        if (flags & 0x40) {
            proto_tree_add_item(tree, hf_btatt_glucose_measurement_context_hba1c, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2A35: /* Blood Pressure Measurement */
    case 0x2A36: /* Intermediate Cuff Pressure */
        if (uuid.bt_uuid == 0x2A35) {/* Blood Pressure Measurement */
            if (service_uuid.bt_uuid == GATT_SERVICE_BLOOD_PRESSURE) {
                if (att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                    break;

                if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                    expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
            }
        } else if (uuid.bt_uuid == 0x2A36) {/* Intermediate Cuff Pressure */
            if (service_uuid.bt_uuid == GATT_SERVICE_BLOOD_PRESSURE) {
                if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                    expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
            }
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_blood_pressure_measurement_flags, ett_btatt_value, hfx_btatt_blood_pressure_measurement_flags, ENC_NA);
        flags = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (flags & 0x01) {
            proto_tree_add_item(tree, hf_btatt_blood_pressure_measurement_compound_value_systolic_kpa, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_btatt_blood_pressure_measurement_compound_value_diastolic_kpa, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_btatt_blood_pressure_measurement_compound_value_mean_arterial_pressure_kpa, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        } else {
            proto_tree_add_item(tree, hf_btatt_blood_pressure_measurement_compound_value_systolic_mmhg, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_btatt_blood_pressure_measurement_compound_value_diastolic_mmhg, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_btatt_blood_pressure_measurement_compound_value_mean_arterial_pressure_mmhg, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x02) {
            sub_item = proto_tree_add_item(tree, hf_btatt_blood_pressure_measurement_timestamp, tvb, offset, 7, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

            proto_tree_add_item(sub_tree, hf_btatt_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(sub_tree, hf_btatt_month, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_day, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_hours, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_minutes, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_seconds, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x04) {
            proto_tree_add_item(tree, hf_btatt_blood_pressure_measurement_pulse_rate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x08) {
            proto_tree_add_item(tree, hf_btatt_blood_pressure_measurement_user_id, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x10) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_blood_pressure_measurement_status, ett_btatt_value, hfx_btatt_blood_pressure_measurement_status, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2A37: /* Heart Rate Measurement */
        if (service_uuid.bt_uuid == GATT_SERVICE_HEART_RATE) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_heart_rate_measurement_flags, ett_btatt_value, hfx_btatt_heart_rate_measurement_flags, ENC_NA);
        flags = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (flags & 0x01) {
            proto_tree_add_item(tree, hf_btatt_heart_rate_measurement_value_16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        } else {
            proto_tree_add_item(tree, hf_btatt_heart_rate_measurement_value_8, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x08) {
            proto_tree_add_item(tree, hf_btatt_heart_rate_measurement_energy_expended, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x10) {
            guint interval_count = 0;

            sub_item = proto_tree_add_item(tree, hf_btatt_heart_rate_measurement_rr_intervals, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);
            while (tvb_reported_length_remaining(tvb, offset)) {
                proto_tree_add_item(sub_tree, hf_btatt_heart_rate_measurement_rr_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                interval_count += 1;
            }

            proto_item_append_text(sub_item, " [count = %2u]", interval_count);
        }

        break;
    case 0x2A38: /* Body Sensor Location */
        if (service_uuid.bt_uuid == GATT_SERVICE_HEART_RATE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_body_sensor_location, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A39: /* Heart Rate Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_HEART_RATE) {
            if (is_writeable_response(att_data->opcode))
                break;

            if (!is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_heart_rate_control_point, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A3F: /* Alert Status */
        if (service_uuid.bt_uuid == GATT_SERVICE_PHONE_ALERT_STATUS_SERVICE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_alert_status, ett_btatt_value, hfx_btatt_alert_status, ENC_NA);
        offset += 1;

        break;
    case 0x2A40: /* Ringer Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_PHONE_ALERT_STATUS_SERVICE) {
            if (att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_ringer_control_point, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A41: /* Ringer Setting */
        if (service_uuid.bt_uuid == GATT_SERVICE_PHONE_ALERT_STATUS_SERVICE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_ringer_setting, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A42: /* Alert Category ID Bit Mask */
    case 0x2A47: /* Supported New Alert Category */
    case 0x2A48: /* Supported Unread Alert Category */
        if (uuid.bt_uuid == 0x2A47 || uuid.bt_uuid == 0x2A48) {/* Supported New Alert Category || Supported Unread Alert Category*/
            if (service_uuid.bt_uuid == GATT_SERVICE_ALERT_NOTIFICATION_SERVICE) {
                if (is_readable_request(att_data->opcode))
                    break;

                if (!is_readable_response(att_data->opcode))
                    expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
            }
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_alert_category_id_bitmask_1, ett_btatt_value, hfx_btatt_alert_category_id_bitmask_1, ENC_NA);
        offset += 1;

        if (tvb_reported_length_remaining(tvb, offset) >= 1) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_alert_category_id_bitmask_2, ett_btatt_value, hfx_btatt_alert_category_id_bitmask_2, ENC_NA);
            offset += 1;
        }

        break;
    case 0x2A43: /* Alert Category ID */
        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_alert_category_id, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A44: /* Alert Notification Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_ALERT_NOTIFICATION_SERVICE) {
            if (is_writeable_response(att_data->opcode))
                break;

            if (!is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_alert_command_id, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_alert_category_id, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A45: /* Unread Alert Status */
        if (service_uuid.bt_uuid == GATT_SERVICE_ALERT_NOTIFICATION_SERVICE) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_alert_category_id, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_alert_unread_count, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A46: /* New Alert */
        if (service_uuid.bt_uuid == GATT_SERVICE_ALERT_NOTIFICATION_SERVICE) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_alert_category_id, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_alert_number_of_new_alert, tvb, offset, 1, ENC_NA);
        offset += 1;

        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(tree, hf_btatt_alert_text_string_information, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
            offset += tvb_captured_length_remaining(tvb, offset);
        }

        break;
    case 0x2A49: /* Blood Pressure Feature */
        if (service_uuid.bt_uuid == GATT_SERVICE_BLOOD_PRESSURE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_blood_pressure_feature, ett_btatt_value, hfx_btatt_blood_pressure_feature, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A4A: /* HOGP: HID Information */
        if (service_uuid.bt_uuid == GATT_SERVICE_HUMAN_INTERFACE_DEVICE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_hogp_bcd_hid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_hogp_b_country_code, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_hogp_flags, ett_btatt_value, hfx_btatt_hogp_flags, ENC_NA);
        offset += 1;

        break;
    case 0x2A4B: /* HOGP: Report Map */
        if (service_uuid.bt_uuid == GATT_SERVICE_HUMAN_INTERFACE_DEVICE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        offset = dissect_usb_hid_get_report_descriptor(pinfo, tree, tvb, offset, NULL);

        break;
    case 0x2A4C: /* HID Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_HUMAN_INTERFACE_DEVICE) {
            if (att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_hogp_hid_control_point_command, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A4D: /* Report */
        if (service_uuid.bt_uuid == GATT_SERVICE_HUMAN_INTERFACE_DEVICE) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_WRITE_COMMAND &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

/* TODO: Implement */
        sub_item = proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
        expert_add_info(pinfo, sub_item, &ei_btatt_undecoded);
        offset = tvb_captured_length(tvb);

        break;
    case 0x2A4E: /* HOGP: Protocol Mode */
        if (service_uuid.bt_uuid == GATT_SERVICE_HUMAN_INTERFACE_DEVICE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_hogp_protocol_mode, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A4F: /* Scan Interval Window */
        if (service_uuid.bt_uuid == GATT_SERVICE_SCAN_PARAMETERS) {
            if (att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_le_scan_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_le_scan_window, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A50: /* PnP ID */
        if (service_uuid.bt_uuid == GATT_SERVICE_DEVICE_INFORMATION) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_pnp_id_vendor_id_source, tvb, offset, 1, ENC_NA);
        value = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (value == 1)
            proto_tree_add_item(tree, hf_btatt_pnp_id_vendor_id_bluetooth_sig, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        else if (value == 2)
            proto_tree_add_item(tree, hf_btatt_pnp_id_vendor_id_usb_forum, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        else
            proto_tree_add_item(tree, hf_btatt_pnp_id_vendor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_pnp_id_product_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_pnp_id_product_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A51: /* Glucose Feature */
        if (service_uuid.bt_uuid == GATT_SERVICE_GLUCOSE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_glucose_feature, ett_btatt_value, hfx_btatt_glucose_feature, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A52: /* Record Access Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_GLUCOSE ||
                service_uuid.bt_uuid == GATT_SERVICE_CONTINUOUS_GLUCOSE_MONITORING ||
                service_uuid.bt_uuid == GATT_SERVICE_PULSE_OXIMETER) {
            if (is_writeable_response(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (!is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_record_access_control_point_opcode, tvb, offset, 1, ENC_NA);
        opcode = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_record_access_control_point_operator, tvb, offset, 1, ENC_NA);
        operator_value = tvb_get_guint8(tvb, offset);
        offset += 1;

        sub_item = proto_tree_add_item(tree, hf_btatt_record_access_control_point_operand, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);
        operand_offset = offset;

        switch (opcode) {
        case  1: /* Report Stored Records */
        case  2: /* Delete Stored Records */
        case  4: /* Report Number of Stored Records */
            switch (operator_value) {
            case 0: /* Null */
            case 1: /* All records */
            case 5: /* First record(i.e. oldest record) */
            case 6: /* Last record (i.e. most recent record) */
                /* N/A */

                break;
            case 2: /* Less than or equal to */
                proto_tree_add_item(sub_tree, hf_btatt_record_access_control_point_operand_filter_type, tvb, offset, 1, ENC_NA);
                value = tvb_get_guint8(tvb, offset);
                offset += 1;

                if (value == 0x01) /* Time offset */ {
                    proto_tree_add_item(sub_tree, hf_btatt_record_access_control_point_operand_max_time_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                } else {
                    proto_tree_add_item(sub_tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
                    offset = tvb_captured_length(tvb);
                }

                break;
            case 3: /* Greater than or equal to */
                proto_tree_add_item(sub_tree, hf_btatt_record_access_control_point_operand_filter_type, tvb, offset, 1, ENC_NA);
                value = tvb_get_guint8(tvb, offset);
                offset += 1;

                if (value == 0x01) /* Time offset */ {
                    proto_tree_add_item(sub_tree, hf_btatt_record_access_control_point_operand_min_time_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                } else {
                    proto_tree_add_item(sub_tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
                    offset = tvb_captured_length(tvb);
                }

                break;
            case 4: /* Within range of (inclusive) */
                proto_tree_add_item(sub_tree, hf_btatt_record_access_control_point_operand_filter_type, tvb, offset, 1, ENC_NA);
                value = tvb_get_guint8(tvb, offset);
                offset += 1;

                if (value == 0x01) /* Time offset */ {
                    proto_tree_add_item(sub_tree, hf_btatt_record_access_control_point_operand_min_time_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;

                    proto_tree_add_item(sub_tree, hf_btatt_record_access_control_point_operand_max_time_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                } else {
                    proto_tree_add_item(sub_tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
                    offset = tvb_captured_length(tvb);
                }

                break;
            }

            break;
        case  3: /* Abort Operation */
            /* N/A */

            break;

        case  5: /* Number of Stored Records Response */
            proto_tree_add_item(sub_tree, hf_btatt_record_access_control_point_operand_number_of_records, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case  6: /* Response Code */
            proto_tree_add_item(sub_tree, hf_btatt_record_access_control_point_request_opcode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_record_access_control_point_response_code, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        };

        proto_item_set_len(sub_item, offset - operand_offset);

        break;
    case 0x2A53: /* RSC Measurement */
        if (service_uuid.bt_uuid == GATT_SERVICE_RUNNING_SPEED_AND_CADENCE) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_rsc_measurement_flags, ett_btatt_value, hfx_btatt_rsc_measurement_flags, ENC_NA);
        flags = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_rsc_measurement_instantaneous_speed, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_rsc_measurement_instantaneous_cadence, tvb, offset, 1, ENC_NA);
        offset += 1;

        if (flags & 0x01) {
            proto_tree_add_item(tree, hf_btatt_rsc_measurement_instantaneous_stride_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x02) {
            proto_tree_add_item(tree, hf_btatt_rsc_measurement_total_distance, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }

        break;
    case 0x2A54: /* RSC Feature */
        if (service_uuid.bt_uuid == GATT_SERVICE_RUNNING_SPEED_AND_CADENCE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_rsc_feature, ett_btatt_value, hfx_btatt_rsc_feature, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A55: /* SC Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_RUNNING_SPEED_AND_CADENCE || service_uuid.bt_uuid == GATT_SERVICE_CYCLING_SPEED_AND_CADENCE) {
            if (is_writeable_response(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (!is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_sc_control_point_opcode, tvb, offset, 1, ENC_NA);
        opcode = tvb_get_guint8(tvb, offset);
        offset += 1;

        switch (opcode) {
        case  1: /* Set Cumulative Value */
            proto_tree_add_item(tree, hf_btatt_sc_control_point_cumulative_value, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            break;
        case  3: /* Update Sensor Location */
            proto_tree_add_item(tree, hf_btatt_sensor_location, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 16: /* Response Code */
            proto_tree_add_item(tree, hf_btatt_sc_control_point_request_opcode, tvb, offset, 1, ENC_NA);
            value = tvb_get_guint8(tvb, offset);
            offset += 1;

            proto_tree_add_item(tree, hf_btatt_sc_control_point_response_value, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (value == 0x04 && tvb_get_guint8(tvb, offset) == 0x01) { /* Request Supported Sensor Locations */
                while (tvb_captured_length_remaining(tvb, offset)) {
                    proto_tree_add_item(tree, hf_btatt_sensor_location, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }
            }

            break;
        case  2: /* Start Sensor Calibration */
        case  4: /* Request Supported Sensor Locations */
            /* N/A */
            break;
        }

        break;
    case 0x2A56: /* Digital */
        if (service_uuid.bt_uuid == GATT_SERVICE_AUTOMATION_IO) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_WRITE_COMMAND && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_digital, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A58: /* Analog */
        if (service_uuid.bt_uuid == GATT_SERVICE_AUTOMATION_IO) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_WRITE_COMMAND && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_analog, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A5A: /* Aggregate */
        if (service_uuid.bt_uuid == GATT_SERVICE_AUTOMATION_IO) {
            if (is_readable_request(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        call_dissector_with_data(find_dissector("btgatt.uuid0x2a56"), tvb_new_subset(tvb, offset, 1, 1), pinfo, tree, att_data);
        offset += 1;

        call_dissector_with_data(find_dissector("btgatt.uuid0x2a58"), tvb_new_subset(tvb, offset, 2, 2), pinfo, tree, att_data);
        offset += 2;

        break;
    case 0x2A5B: /* CSC Measurement */
        if (service_uuid.bt_uuid == GATT_SERVICE_CYCLING_SPEED_AND_CADENCE) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_csc_measurement_flags, ett_btatt_value, hfx_btatt_csc_measurement_flags, ENC_NA);
        flags = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (flags & 0x01) {
            proto_tree_add_item(tree, hf_btatt_csc_measurement_cumulative_wheel_revolutions, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_btatt_csc_measurement_last_event_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x02) {
            proto_tree_add_item(tree, hf_btatt_csc_measurement_cumulative_crank_revolutions, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_btatt_csc_measurement_last_event_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2A5C: /* CSC Feature */
        if (service_uuid.bt_uuid == GATT_SERVICE_CYCLING_SPEED_AND_CADENCE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_csc_feature, ett_btatt_value, hfx_btatt_csc_feature, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A5D: /* Sensor Location */
        if (service_uuid.bt_uuid == GATT_SERVICE_RUNNING_SPEED_AND_CADENCE ||
                service_uuid.bt_uuid == GATT_SERVICE_CYCLING_SPEED_AND_CADENCE ||
                service_uuid.bt_uuid == GATT_SERVICE_CYCLING_POWER) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_sensor_location, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A5E: /* PLX Spot-Check Measurement */
        if (service_uuid.bt_uuid == GATT_SERVICE_PULSE_OXIMETER) {
            if (att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_plx_spot_check_measurement_flags, ett_btatt_value, hfx_btatt_plx_spot_check_measurement_flags, ENC_NA);
        flags = tvb_get_guint8(tvb, offset);
        offset += 1;

        sub_item = proto_tree_add_item(tree, hf_btatt_plx_spo2pr_spot_check, tvb, offset, 4, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_value);

        proto_tree_add_item(sub_tree, hf_btatt_plx_spo2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(sub_tree, hf_btatt_plx_pulse_rate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (flags & 0x01) {
            sub_item = proto_tree_add_item(tree, hf_btatt_plx_spot_check_measurement_timestamp, tvb, offset, 7, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_btatt_value);

            call_dissector_with_data(find_dissector("btgatt.uuid0x2a08"), tvb_new_subset(tvb, offset, 7, 7), pinfo, sub_tree, att_data);
            offset += 7;
        }

        if (flags & 0x02) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_plx_measurement_status, ett_btatt_value, hfx_btatt_plx_measurement_status, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x04) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_plx_device_and_sensor_status, ett_btatt_value, hfx_btatt_plx_device_and_sensor_status, ENC_LITTLE_ENDIAN);
            offset += 3;
        }

        if (flags & 0x08) {
            proto_tree_add_item(tree, hf_btatt_plx_pulse_amplitude_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2A5F: /* PLX Continuous Measurement */
        if (service_uuid.bt_uuid == GATT_SERVICE_PULSE_OXIMETER) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_plx_continuous_measurement_flags, ett_btatt_value, hfx_btatt_plx_continuous_measurement_flags, ENC_NA);
        flags = tvb_get_guint8(tvb, offset);
        offset += 1;

        sub_item = proto_tree_add_item(tree, hf_btatt_plx_spo2pr_normal, tvb, offset, 4, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_value);

        proto_tree_add_item(sub_tree, hf_btatt_plx_spo2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(sub_tree, hf_btatt_plx_pulse_rate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (flags & 0x01) {
            sub_item = proto_tree_add_item(tree, hf_btatt_plx_spo2pr_fast, tvb, offset, 4, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_btatt_value);

            proto_tree_add_item(sub_tree, hf_btatt_plx_spo2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(sub_tree, hf_btatt_plx_pulse_rate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x02) {
            sub_item = proto_tree_add_item(tree, hf_btatt_plx_spo2pr_slow, tvb, offset, 4, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_btatt_value);

            proto_tree_add_item(sub_tree, hf_btatt_plx_spo2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(sub_tree, hf_btatt_plx_pulse_rate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x04) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_plx_measurement_status, ett_btatt_value, hfx_btatt_plx_measurement_status, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x08) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_plx_device_and_sensor_status, ett_btatt_value, hfx_btatt_plx_device_and_sensor_status, ENC_LITTLE_ENDIAN);
            offset += 3;
        }

        if (flags & 0x10) {
            proto_tree_add_item(tree, hf_btatt_plx_pulse_amplitude_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2A60: /* PLX Features */
        if (service_uuid.bt_uuid == GATT_SERVICE_PULSE_OXIMETER) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_plx_features_supported_features, ett_btatt_value, hfx_btatt_plx_features_supported_features, ENC_LITTLE_ENDIAN);
        flags = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (flags & 0x01) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_plx_measurement_status, ett_btatt_value, hfx_btatt_plx_measurement_status, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x02) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_plx_device_and_sensor_status, ett_btatt_value, hfx_btatt_plx_device_and_sensor_status, ENC_LITTLE_ENDIAN);
            offset += 3;
        }

        break;
    case 0x2A63: /* Cycling Power Measurement */
        if (service_uuid.bt_uuid == GATT_SERVICE_CYCLING_POWER) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_cycling_power_measurement_flags, ett_btatt_value, hfx_btatt_cycling_power_measurement_flags, ENC_LITTLE_ENDIAN);
        flags = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_cycling_power_measurement_instantaneous_power, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (flags & 0x01) {
            proto_tree_add_item(tree, hf_btatt_cycling_power_measurement_pedal_power_balance, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x04) {
            proto_tree_add_item(tree, hf_btatt_cycling_power_measurement_accumulated_torque, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x10) {
            proto_tree_add_item(tree, hf_btatt_cycling_power_measurement_wheel_revolution_data_cumulative_wheel_revolutions, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_btatt_cycling_power_measurement_wheel_revolution_data_last_wheel_event_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x20) {
            proto_tree_add_item(tree, hf_btatt_cycling_power_measurement_crank_revolution_data_cumulative_crank_revolutions, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_btatt_cycling_power_measurement_crank_revolution_data_last_crank_event_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x40) {
            proto_tree_add_item(tree, hf_btatt_cycling_power_measurement_extreme_force_magnitudes_maximum_force_magnitude, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_btatt_cycling_power_measurement_extreme_force_magnitudes_minimum_force_magnitude, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x80) {
            proto_tree_add_item(tree, hf_btatt_cycling_power_measurement_extreme_torque_magnitudes_maximum_torque_magnitude, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_btatt_cycling_power_measurement_extreme_torque_magnitudes_minimum_torque_magnitude, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x100) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_cycling_power_measurement_extreme_angles, ett_btatt_value, hfx_btatt_cycling_power_measurement_extreme_angles, ENC_NA);
            offset += 3;
        }

        if (flags & 0x200) {
            proto_tree_add_item(tree, hf_btatt_cycling_power_measurement_top_dead_spot_angle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x400) {
            proto_tree_add_item(tree, hf_btatt_cycling_power_measurement_bottom_dead_spot_angle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x800) {
            proto_tree_add_item(tree, hf_btatt_cycling_power_measurement_accumulated_energy, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2A64: /* Cycling Power Vector */
        if (service_uuid.bt_uuid == GATT_SERVICE_CYCLING_POWER) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_cycling_power_vector_flags, ett_btatt_value, hfx_btatt_cycling_power_vector_flags, ENC_NA);
        flags = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (flags & 0x01) {
            proto_tree_add_item(tree, hf_btatt_cycling_power_vector_crank_revolution_data_cumulative_crank_revolutions, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_btatt_cycling_power_vector_crank_revolution_data_last_crank_event_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x02) {
            proto_tree_add_item(tree, hf_btatt_cycling_power_vector_first_crank_measurement_angle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x04) {
            while (tvb_reported_length_remaining(tvb, offset) > 0) {
                proto_tree_add_item(tree, hf_btatt_cycling_power_vector_instantaneous_force_magnitude_array, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
        }

        if (flags & 0x08) {
            while (tvb_reported_length_remaining(tvb, offset) > 0) {
                proto_tree_add_item(tree, hf_btatt_cycling_power_vector_instantaneous_torque_magnitude_array, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
            }
        }

        break;
    case 0x2A65: /* Cycling Power Feature */
        if (service_uuid.bt_uuid == GATT_SERVICE_CYCLING_POWER) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_cycling_power_feature, ett_btatt_value, hfx_btatt_cycling_power_feature, ENC_LITTLE_ENDIAN);
        offset += 4;

        break;
    case 0x2A66: /* Cycling Power Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_CYCLING_POWER) {
            if (is_writeable_response(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (!is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_opcode, tvb, offset, 1, ENC_NA);
        opcode = tvb_get_guint8(tvb, offset);
        offset += 1;

        switch (opcode) {
        case  1: /* Set Cumulative Value */
            proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_cumulative_value, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            break;
        case  2: /* Update Sensor Location */
            proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_sensor_location, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case  4: /* Set Crank Length */
            proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_crank_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case  6: /* Set Chain Length */
            proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_chain_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case  8: /* Set Chain Weight */
            proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_chain_weight, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 10: /* Set Span Length */
            proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_span_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 13: /* Mask Cycling Power Measurement Characteristic Content */
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_cycling_power_control_point_content_mask, ett_btatt_value, hfx_btatt_cycling_power_control_point_content_mask, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case  3: /* Request Supported Sensor Locations */
        case  5: /* Request Crank Length */
        case  7: /* Request Chain Length */
        case  9: /* Request Chain Weight */
        case 11: /* Request Span Length */
        case 12: /* Start Offset Compensation */
        case 14: /* Request Sampling Rate */
        case 15: /* Request Factory Calibration Date */
            /* N/A */

            break;
        case 32: /* Response Code */
            proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_request_opcode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_response_value, tvb, offset, 1, ENC_NA);
            offset += 1;

            switch (tvb_get_guint8(tvb, offset - 2)) {
            case  1: /* Set Cumulative Value */
            case  2: /* Update Sensor Location */
            case  4: /* Set Crank Length */
            case  6: /* Set Chain Length */
            case  8: /* Set Chain Weight */
            case 10: /* Set Span Length */
            case 13: /* Mask Cycling Power Measurement Characteristic Content */
                /* N/A */

                break;
            case  3: /* Request Supported Sensor Locations */
                if (tvb_get_guint8(tvb, offset - 1) == 0x01) /* Success */ {
                    while (tvb_captured_length_remaining(tvb, offset)) {
                        proto_tree_add_item(tree, hf_btatt_sensor_location, tvb, offset, 1, ENC_NA);
                        offset += 1;
                    }
                }

                break;
            case  5: /* Request Crank Length */
                if (tvb_get_guint8(tvb, offset - 1) == 0x01) /* Success */ {
                    proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_crank_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }

                break;
            case  7: /* Request Chain Length */
                if (tvb_get_guint8(tvb, offset - 1) == 0x01) /* Success */ {
                    proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_chain_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }

                break;
            case  9: /* Request Chain Weight */
                if (tvb_get_guint8(tvb, offset - 1) == 0x01) /* Success */ {
                    proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_chain_weight, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }

                break;
            case 11: /* Request Span Length */
                if (tvb_get_guint8(tvb, offset - 1) == 0x01) /* Success */ {
                    proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_span_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }

                break;
            case 12: /* Start Offset Compensation */
                if (tvb_get_guint8(tvb, offset - 1) == 0x01) /* Success */ {
                    proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_start_offset_compensation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }

                break;
            case 14: /* Request Sampling Rate */
                if (tvb_get_guint8(tvb, offset - 1) == 0x01) /* Success */ {
                    proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_sampling_rate, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }

                break;
            case 15: /* Request Factory Calibration Date */
                if (tvb_get_guint8(tvb, offset - 1) == 0x01) /* Success */ {
                    sub_item = proto_tree_add_item(tree, hf_btatt_cycling_power_control_point_factory_calibration_date, tvb, offset, 7, ENC_NA);
                    sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

                    proto_tree_add_item(sub_tree, hf_btatt_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;

                    proto_tree_add_item(sub_tree, hf_btatt_month, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(sub_tree, hf_btatt_day, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(sub_tree, hf_btatt_hours, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(sub_tree, hf_btatt_minutes, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    proto_tree_add_item(sub_tree, hf_btatt_seconds, tvb, offset, 1, ENC_NA);
                    offset += 1;
                }

                break;
            }
            break;
        }

        break;
    case 0x2A67: /* Location and Speed */
        if (service_uuid.bt_uuid == GATT_SERVICE_LOCATION_AND_NAVIGATION) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_location_and_speed_flags, ett_btatt_value, hfx_btatt_location_and_speed_flags, ENC_LITTLE_ENDIAN);
        flags = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (flags & 0x01) {
            proto_tree_add_item(tree, hf_btatt_location_and_speed_instantaneous_speed, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x02) {
            proto_tree_add_item(tree, hf_btatt_location_and_speed_total_distance, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;
        }

        if (flags & 0x04) {
            proto_tree_add_item(tree, hf_btatt_location_and_speed_location_latitude, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_btatt_location_and_speed_location_longitude, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }

        if (flags & 0x08) {
            proto_tree_add_item(tree, hf_btatt_location_and_speed_elevation, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;
        }

        if (flags & 0x10) {
            proto_tree_add_item(tree, hf_btatt_location_and_speed_heading, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x20) {
            proto_tree_add_item(tree, hf_btatt_location_and_speed_rolling_time, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x40) {
            sub_item = proto_tree_add_item(tree, hf_btatt_location_and_speed_utc_time, tvb, offset, 7, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

            proto_tree_add_item(sub_tree, hf_btatt_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(sub_tree, hf_btatt_month, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_day, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_hours, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_minutes, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_seconds, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        break;
    case 0x2A68: /* Navigation */
        if (service_uuid.bt_uuid == GATT_SERVICE_LOCATION_AND_NAVIGATION) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_navigation_flags, ett_btatt_value, hfx_btatt_navigation_flags, ENC_LITTLE_ENDIAN);
        flags = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_navigation_bearing, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_navigation_heading, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (flags & 0x01) {
            proto_tree_add_item(tree, hf_btatt_navigation_remaining_distance, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;
        }

        if (flags & 0x02) {
            proto_tree_add_item(tree, hf_btatt_navigation_remaining_vertical_distance, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;
        }

        if (flags & 0x04) {
            sub_item = proto_tree_add_item(tree, hf_btatt_navigation_estimated_time_of_arrival, tvb, offset, 7, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

            proto_tree_add_item(sub_tree, hf_btatt_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(sub_tree, hf_btatt_month, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_day, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_hours, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_minutes, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_seconds, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        break;
    case 0x2A69: /* Position Quality */
        if (service_uuid.bt_uuid == GATT_SERVICE_LOCATION_AND_NAVIGATION) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_position_quality_flags, ett_btatt_value, hfx_btatt_position_quality_flags, ENC_LITTLE_ENDIAN);
        flags = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (flags & 0x01) {
            proto_tree_add_item(tree, hf_btatt_position_quality_number_of_beacons_in_solution, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x02) {
            proto_tree_add_item(tree, hf_btatt_position_quality_number_of_beacons_in_view, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x04) {
            proto_tree_add_item(tree, hf_btatt_position_quality_time_to_first_fix, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x08) {
            proto_tree_add_item(tree, hf_btatt_position_quality_ehpe, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }

        if (flags & 0x10) {
            proto_tree_add_item(tree, hf_btatt_position_quality_evpe, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }

        if (flags & 0x20) {
            proto_tree_add_item(tree, hf_btatt_position_quality_hdop, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x40) {
            proto_tree_add_item(tree, hf_btatt_position_quality_vdop, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        break;
    case 0x2A6A: /* LN Feature */
        if (service_uuid.bt_uuid == GATT_SERVICE_LOCATION_AND_NAVIGATION) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_ln_feature, ett_btatt_value, hfx_btatt_ln_feature, ENC_LITTLE_ENDIAN);
        offset += 4;

        break;
    case 0x2A6B: /* LN Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_LOCATION_AND_NAVIGATION) {
            if (is_writeable_response(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (!is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_ln_control_point_opcode, tvb, offset, 1, ENC_NA);
        opcode = tvb_get_guint8(tvb, offset);
        offset += 1;

        switch (opcode) {
        case  1: /* Set Cumulative Value */
            proto_tree_add_item(tree, hf_btatt_ln_control_point_cumulative_value, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;

            break;
        case  2: /* Mask Location and Speed Characteristic Content */
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_ln_control_point_content_mask, ett_btatt_value, hfx_btatt_ln_control_point_content_mask, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case  3: /* Navigation Control */
            proto_tree_add_item(tree, hf_btatt_ln_control_point_navigation_control, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case  4: /* Request Number of Routes */
            /* N/A */

            break;
        case  5: /* Request Name of Route */
        case  6: /* Select Route */
            proto_tree_add_item(tree, hf_btatt_ln_control_point_route_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case  7: /* Set Fix Rate */
            proto_tree_add_item(tree, hf_btatt_ln_control_point_fix_rate, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case  8: /* Set Elevation */
            proto_tree_add_item(tree, hf_btatt_ln_control_point_elevation, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;

            break;
        case 32: /* Response Code */
            proto_tree_add_item(tree, hf_btatt_ln_control_point_request_opcode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_btatt_ln_control_point_response_value, tvb, offset, 1, ENC_NA);
            offset += 1;

            switch (tvb_get_guint8(tvb, offset - 2)) {
            case  1: /* Set Cumulative Value */
            case  2: /* Mask Location and Speed Characteristic Content */
            case  3: /* Navigation Control */
            case  6: /* Select Route */
            case  7: /* Set Fix Rate */
            case  8: /* Set Elevation */
                /* N/A */

                break;
            case  4: /* Request Number of Routes */
                proto_tree_add_item(tree, hf_btatt_ln_control_point_response_value_number_of_routes, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                break;
            case  5: /* Request Name of Route */
                proto_tree_add_item(tree, hf_btatt_ln_control_point_response_value_name_of_route, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
                offset += tvb_captured_length_remaining(tvb, offset);

                break;
            }

            break;
        }

        break;
    case 0x2A6C: /* Elevation */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_elevation, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;

        break;
    case 0x2A6D: /* Pressure */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_pressure, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        break;
    case 0x2A6E: /* Temperature */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_temperature, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A6F: /* Humidity */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_humidity, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A70: /* True Wind Speed */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_true_wind_speed, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A71: /* True Wind Direction */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_true_wind_direction, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A72: /* Apparent Wind Speed */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_apparent_wind_speed, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A73: /* Apparent Wind Direction */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_apparent_wind_direction, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A74: /* Gust Factor */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_gust_factor, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A75: /* Pollen Concentration */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_pollen_concentration, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;

        break;
    case 0x2A76: /* UV Index */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_uv_index, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A77: /* Irradiance */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_irradiance, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A78: /* Rainfall */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_rainfall, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A79: /* Wind Chill */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_wind_chill, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A7A: /* Heat Index */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_heart_index, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A7B: /* Dew Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_dew_point, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A7D: /* Descriptor Value Changed */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_descriptor_value_changed_flags , ett_btatt_value, hfx_btatt_descriptor_value_changed_flags, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (tvb_reported_length_remaining(tvb, offset) == 2) {
            proto_tree_add_item(tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        } else if (tvb_reported_length_remaining(tvb, offset) == 16) {
            proto_tree_add_item(tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
            offset += 16;
        } else {
            sub_item = proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_btatt_bad_data);
            offset = tvb_captured_length(tvb);
        }

        break;
    case 0x2A7E: /* Aerobic Heart Rate Lower Limit */
        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_aerobic_heart_rate_lower_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A7F: /* Aerobic Threshold */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_aerobic_threshold, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A80: /* Age */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_age, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A81: /* Anaerobic Heart Rate Lower Limit */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_anaerobic_heart_rate_lower_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A82: /* Anaerobic Heart Rate Upper Limit */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_anaerobic_heart_rate_upper_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A83: /* Anaerobic Threshold */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_anaerobic_threshold, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A84: /* Aerobic Heart Rate Upper Limit */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_aerobic_heart_rate_upper_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A85: /* Date of Birth */
    case 0x2A86: /* Date of Threshold Assessment */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_month, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_day, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A87: /* Email Address */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_email_address, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A88: /* Fat Burn Heart Rate Lower Limit */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_fat_burn_heart_rate_lower_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A89: /* Fat Burn Heart Rate Upper Limit */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_fat_burn_heart_rate_upper_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A8A: /* First Name */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_first_name, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A8B: /* Five Zone Heart Rate Limits */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_five_zone_heart_rate_limits_very_light_light_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_five_zone_heart_rate_limits_light_moderate_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_five_zone_heart_rate_limits_moderate_hard_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_five_zone_heart_rate_limits_hard_maximum_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A8C: /* Gender */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_gender, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A8D: /* Heart Rate Max */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_heart_rate_max, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A8E: /* Height */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_height, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A8F: /* Hip Circumference */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_hip_circumference, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A90: /* Last Name */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_last_name, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A91: /* Maximum Recommended Heart Rate */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_maximum_recommended_heart_rate, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A92: /* Resting Heart Rate */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_resting_heart_rate, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A93: /* Sport Type for Aerobic and Anaerobic Thresholds */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_sport_type_for_aerobic_and_anaerobic_thresholds, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A94: /* Three Zone Heart Rate Limits */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_three_zone_heart_rate_limits_light_moderate, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_three_zone_heart_rate_limits_moderate_hard, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A95: /* Two Zone Heart Rate Limit */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_two_zone_heart_rate_limit_fat_burn_fitness, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A96: /* VO2 Max */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_vo2_max, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A97: /* Waist Circumference */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_waist_circumference, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A98: /* Weight */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_weight, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A99: /* Database Change Increment */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_database_change_increment, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        break;
    case 0x2A9A: /* User Index */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_user_index, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A9B: /* Body Composition Feature */
        if (service_uuid.bt_uuid == GATT_SERVICE_BODY_COMPOSITION) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_body_composition_feature, ett_btatt_value, hfx_btatt_body_composition_feature, ENC_LITTLE_ENDIAN);
        offset += 4;

        break;
    case 0x2A9C: /* Body Composition Measurement */
        if (service_uuid.bt_uuid == GATT_SERVICE_BODY_COMPOSITION) {
            if (att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_body_composition_measurement_flags, ett_btatt_value, hfx_btatt_body_composition_measurement_flags, ENC_LITTLE_ENDIAN);
        flags = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_body_composition_measurement_body_fat_percentage, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (flags & 0x02) {
            sub_item = proto_tree_add_item(tree, hf_btatt_body_composition_measurement_timestamp, tvb, offset, 7, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

            proto_tree_add_item(sub_tree, hf_btatt_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(sub_tree, hf_btatt_month, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_day, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_hours, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_minutes, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_seconds, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x04) {
            proto_tree_add_item(tree, hf_btatt_body_composition_measurement_user_id, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x08) {
            proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_basal_metabolism, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x10) {
            proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_muscle_percentage, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x20) {
            if (flags & 0x01)
                proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_muscle_mass_lb, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            else
                proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_muscle_mass_kg, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

        }

        if (flags & 0x40) {
            if (flags & 0x01)
                proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_fat_free_mass_lb, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            else
                proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_fat_free_mass_kg, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

        }

        if (flags & 0x80) {
            if (flags & 0x01)
                proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_soft_lean_mass_lb, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            else
                proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_soft_lean_mass_kg, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x100) {
            if (flags & 0x01)
                proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_body_water_mass_lb, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            else
                proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_body_water_mass_kg, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x200) {
            proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_impedance, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x400) {
            if (flags & 0x01)
                proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_weight_lb, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            else
                proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_weight_kg, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x800) {
            if (flags & 0x01)
                proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_height_inches, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            else
                proto_tree_add_item(sub_tree, hf_btatt_body_composition_measurement_height_meter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2A9D: /* Weight Measurement */
        if (service_uuid.bt_uuid == GATT_SERVICE_WEIGHT_SCALE) {
            if (is_writeable_response(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (!is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_weight_measurement_flags, ett_btatt_value, hfx_btatt_weight_measurement_flags, ENC_NA);
        flags = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (flags & 0x01)
            proto_tree_add_item(tree, hf_btatt_weight_measurement_weight_lb, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        else
            proto_tree_add_item(tree, hf_btatt_weight_measurement_weight_kg, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (flags & 0x02) {
            sub_item = proto_tree_add_item(tree, hf_btatt_weight_measurement_timestamp, tvb, offset, 7, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

            proto_tree_add_item(sub_tree, hf_btatt_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(sub_tree, hf_btatt_month, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_day, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_hours, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_minutes, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_seconds, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x04) {
            proto_tree_add_item(tree, hf_btatt_weight_measurement_user_id, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (flags & 0x08) {
            proto_tree_add_item(sub_tree, hf_btatt_weight_measurement_bmi, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            if (flags & 0x01)
                proto_tree_add_item(sub_tree, hf_btatt_weight_measurement_height_in, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            else
                proto_tree_add_item(sub_tree, hf_btatt_weight_measurement_height_m, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2A9E: /* Weight Scale Feature */
         if (service_uuid.bt_uuid == GATT_SERVICE_WEIGHT_SCALE) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_weight_scale_feature, ett_btatt_value, hfx_btatt_weight_scale_feature, ENC_LITTLE_ENDIAN);
        offset += 4;

        break;
    case 0x2A9F: /* User Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_writeable_response(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (!is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_user_control_point_opcode, tvb, offset, 1, ENC_NA);
        opcode = tvb_get_guint8(tvb, offset);
        offset += 1;

        switch (opcode) {
        case 0x01: /* Register New User */
            sub_item = proto_tree_add_item(tree, hf_btatt_user_control_point_consent_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            value =  tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
            if (value > 9999)
                expert_add_info(pinfo, sub_item, &ei_btatt_consent_out_of_bounds);
            offset += 2;

            break;
        case 0x02: /* Consent */
            proto_tree_add_item(tree, hf_btatt_user_index, tvb, offset, 1, ENC_NA);
            offset += 1;

            sub_item = proto_tree_add_item(tree, hf_btatt_user_control_point_consent_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            value =  tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
            if (value > 9999)
                expert_add_info(pinfo, sub_item, &ei_btatt_consent_out_of_bounds);
            offset += 2;

            break;
        case 0x03: /* Delete User Data */
            /* N/A */
            break;
        case 0x20: /* Response Code */
            proto_tree_add_item(tree, hf_btatt_user_control_point_request_opcode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_btatt_user_control_point_response_value, tvb, offset, 1, ENC_NA);
            offset += 1;

            if (tvb_get_guint8(tvb, offset - 2) == 0x01 && tvb_get_guint8(tvb, offset - 1) == 0x01) { /* Register New User && Success */
                proto_tree_add_item(tree, hf_btatt_user_index, tvb, offset, 1, ENC_NA);
                offset += 1;
            }

            break;
        }

        break;
    case 0x2AA0: /* Magnetic Flux Density - 2D */
    case 0x2AA1: /* Magnetic Flux Density - 3D */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_magnetic_flux_density_x, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_magnetic_flux_density_y, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (uuid.bt_uuid == 0x2AA1) {
            proto_tree_add_item(tree, hf_btatt_magnetic_flux_density_z, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2AA2: /* Language */
        if (service_uuid.bt_uuid == GATT_SERVICE_USER_DATA) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_language, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2AA3: /* Barometric Pressure Trend */
        if (service_uuid.bt_uuid == GATT_SERVICE_ENVIRONMENTAL_SENSING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_barometric_pressure_trend, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2AA4: /* Bond Management Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_BOND_MANAGEMENT) {
            if (is_writeable_response(att_data->opcode))
                break;

            if (!is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_bond_management_control_point_opcode, tvb, offset, 1, ENC_NA);
        offset += 1;

        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(tree, hf_btatt_bond_management_control_point_authorization_code, tvb, offset, length -1, ENC_NA | ENC_UTF_8);
            offset += tvb_reported_length_remaining(tvb, offset);
        }
        break;
    case 0x2AA5: /* Bond Management Feature */
        if (service_uuid.bt_uuid == GATT_SERVICE_BOND_MANAGEMENT) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_bond_management_feature, ett_btatt_value, hfx_btatt_bond_management_feature, ENC_LITTLE_ENDIAN);
        flags = tvb_get_guint24(tvb, offset, ENC_LITTLE_ENDIAN);
        offset += 3;

        if (flags & 0x800000) {
            do {
                proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_bond_management_feature_nth, ett_btatt_value, hfx_btatt_bond_management_feature_nth, ENC_LITTLE_ENDIAN);
                offset += 1;
            } while (tvb_get_guint8(tvb, offset - 1) & 0x80);
        }

        break;
    case 0x2AA6: /* Central Address Resolution */
        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_central_address_resolution, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2AA7: /* CGM Measurement */
        if (service_uuid.bt_uuid == GATT_SERVICE_CONTINUOUS_GLUCOSE_MONITORING) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        sub_item = proto_tree_add_item(tree, hf_btatt_cgm_measurement_size, tvb, offset, 1, ENC_NA);
        if (tvb_get_guint8(tvb, offset) >= 6)
            expert_add_info(pinfo, sub_item, &ei_btatt_cgm_size_too_small);
        offset += 1;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_cgm_measurement_flags, ett_btatt_value, hfx_btatt_cgm_measurement_flags, ENC_NA);
        flags = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_cgm_measurement_glucose_concentration, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_cgm_measurement_time_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (flags & 0xE0) {
            value = 0;
            if (flags & 0x80)
                value += 1;
            if (flags & 0x40)
                value += 1;
            if (flags & 0x20)
                value += 1;

            sub_item = proto_tree_add_item(tree, hf_btatt_cgm_sensor_status_annunciation, tvb, offset, value, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);
        }

        if (flags & 0x80) {
            proto_tree_add_bitmask(sub_tree, tvb, offset, hf_btatt_cgm_sensor_status_annunciation_status, ett_btatt_value, hfx_btatt_cgm_sensor_status_annunciation_status, ENC_NA);
            offset += 1;
        }

        if (flags & 0x40) {
            proto_tree_add_bitmask(sub_tree, tvb, offset, hf_btatt_cgm_sensor_status_annunciation_cal_temp, ett_btatt_value, hfx_btatt_cgm_sensor_status_annunciation_cal_temp, ENC_NA);
            offset += 1;
        }

        if (flags & 0x20) {
            proto_tree_add_bitmask(sub_tree, tvb, offset, hf_btatt_cgm_sensor_status_annunciation_warning, ett_btatt_value, hfx_btatt_cgm_sensor_status_annunciation_warning, ENC_NA);
            offset += 1;
        }

        if (flags & 0x01) {
            proto_tree_add_item(tree, hf_btatt_cgm_measurement_trend_information, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        if (flags & 0x02) {
            proto_tree_add_item(tree, hf_btatt_cgm_measurement_quality, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        /* NOTE: only add if "E2E-CRC Supported bit is set in CGM Feature", but for now simple heuristic should be enough */
        if (tvb_reported_length_remaining(tvb, offset) >= 2) {
            proto_tree_add_item(tree, hf_btatt_cgm_e2e_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2AA8: /* CGM Feature */
        if (service_uuid.bt_uuid == GATT_SERVICE_CONTINUOUS_GLUCOSE_MONITORING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_cgm_feature_feature, ett_btatt_value, hfx_btatt_cgm_feature_feature, ENC_LITTLE_ENDIAN);
        offset += 3;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_cgm_type_and_sample_location, ett_btatt_value, hfx_btatt_cgm_type_and_sample_location, ENC_NA);
        offset += 1;

        /* NOTE: This one is mandatory - if not supported then 0xFFFF */
        proto_tree_add_item(tree, hf_btatt_cgm_e2e_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2AA9: /* CGM Status */
        if (service_uuid.bt_uuid == GATT_SERVICE_CONTINUOUS_GLUCOSE_MONITORING) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_cgm_time_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        sub_item = proto_tree_add_item(tree, hf_btatt_cgm_status, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

        proto_tree_add_bitmask(sub_tree, tvb, offset, hf_btatt_cgm_sensor_status_annunciation_status, ett_btatt_value, hfx_btatt_cgm_sensor_status_annunciation_status, ENC_NA);
        offset += 1;

        proto_tree_add_bitmask(sub_tree, tvb, offset, hf_btatt_cgm_sensor_status_annunciation_cal_temp, ett_btatt_value, hfx_btatt_cgm_sensor_status_annunciation_cal_temp, ENC_NA);
        offset += 1;

        proto_tree_add_bitmask(sub_tree, tvb, offset, hf_btatt_cgm_sensor_status_annunciation_warning, ett_btatt_value, hfx_btatt_cgm_sensor_status_annunciation_warning, ENC_NA);
        offset += 1;


        /* NOTE: only add if "E2E-CRC Supported bit is set in CGM Feature", but for now simple heuristic should be enough */
        if (tvb_reported_length_remaining(tvb, offset) >= 2) {
            proto_tree_add_item(tree, hf_btatt_cgm_e2e_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2AAA: /* CGM Session Start Time */
        if (service_uuid.bt_uuid == GATT_SERVICE_CONTINUOUS_GLUCOSE_MONITORING) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        sub_item = proto_tree_add_item(tree, hf_btatt_cgm_session_start_time, tvb, offset, 7, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

        proto_tree_add_item(sub_tree, hf_btatt_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(sub_tree, hf_btatt_month, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(sub_tree, hf_btatt_day, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(sub_tree, hf_btatt_hours, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(sub_tree, hf_btatt_minutes, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(sub_tree, hf_btatt_seconds, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_timezone, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_dst_offset, tvb, offset, 1, ENC_NA);
        offset += 1;

        /* NOTE: only add if "E2E-CRC Supported bit is set in CGM Feature", but for now simple heuristic should be enough */
        if (tvb_reported_length_remaining(tvb, offset) >= 2) {
            proto_tree_add_item(tree, hf_btatt_cgm_e2e_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2AAB: /* CGM Session Run Time */
        if (service_uuid.bt_uuid == GATT_SERVICE_CONTINUOUS_GLUCOSE_MONITORING) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_cgm_session_run_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* NOTE: only add if "E2E-CRC Supported bit is set in CGM Feature", but for now simple heuristic should be enough */
        if (tvb_reported_length_remaining(tvb, offset) >= 2) {
            proto_tree_add_item(tree, hf_btatt_cgm_e2e_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2AAC: /* CGM Specific Ops Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_CONTINUOUS_GLUCOSE_MONITORING) {
            if (is_writeable_response(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (!is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_cgm_specific_ops_control_point_opcode, tvb, offset, 1, ENC_NA);
        opcode = tvb_get_guint8(tvb, offset);
        offset += 1;

        sub_item = proto_tree_add_item(tree, hf_btatt_cgm_specific_ops_control_point_operand, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);
        operand_offset = offset;

        switch (opcode) {
        case  1: /* Set CGM Communication Interval */
            proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_operand_communication_interval, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case  2: /* Get CGM Communication Interval */
        case  8: /* Get Patient High Alert Level */
        case 11: /* Get Patient Low Alert Level */
        case 14: /* Get Hypo Alert Level */
        case 17: /* Get Hyper Alert Level */
        case 20: /* Get Rate of Decrease Alert Level */
        case 23: /* Get Rate of Increase Alert Level */
        case 25: /* Reset Device Specific Alert */
        case 26: /* Start the Session */
        case 27: /* Stop the Session */
            /* N/A */

            break;
        case  4: /* Set Glucose Calibration Value */
            proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_calibration_glucose_concentration, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_calibration_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_bitmask(sub_tree, tvb, offset, hf_btatt_cgm_type_and_sample_location, ett_btatt_value, hfx_btatt_cgm_type_and_sample_location, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_next_calibration_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_calibration_data_record_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_bitmask(sub_tree, tvb, offset, hf_btatt_cgm_specific_ops_control_point_calibration_status, ett_btatt_value, hfx_btatt_cgm_specific_ops_control_point_calibration_status, ENC_NA);
            offset += 1;

            break;
        case  5: /* Get Glucose Calibration Value */
            proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_operand_calibration_data_record_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case  7: /* Set Patient High Alert Level */
        case 10: /* Set Patient Low Alert Level */
        case 13: /* Set Hypo Alert Level */
        case 16: /* Set Hyper Alert Level */
            proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_operand_alert_level, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 19: /* Set Rate of Decrease Alert Level */
        case 22: /* Set Rate of Increase Alert Level */
            proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_operand_alert_level_rate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case  3: /* CGM Communication Interval response */
        case  6: /* Glucose Calibration Value response */
        case  9: /* Patient High Alert Level Response */
        case 12: /* Patient Low Alert Level Response */
        case 15: /* Hypo Alert Level Response */
        case 18: /* Hyper Alert Level Response */
        case 21: /* Rate of Decrease Alert Level Response */
        case 24: /* Rate of Increase Alert Level Response */
            expert_add_info(pinfo, sub_item, &ei_btatt_opcode_invalid_request);
            break;

        case 28: /* Response Code */
            proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_request_opcode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_response_code, tvb, offset, 1, ENC_NA);
            offset += 1;

            switch (tvb_get_guint8(tvb, offset - 2)) {
            case  1: /* Set CGM Communication Interval */
            case  2: /* Get CGM Communication Interval */
            case  4: /* Set Glucose Calibration Value */
            case  5: /* Get Glucose Calibration Value */
            case  7: /* Set Patient High Alert Level */
            case  8: /* Get Patient High Alert Level */
            case 10: /* Set Patient Low Alert Level */
            case 11: /* Get Patient Low Alert Level */
            case 13: /* Set Hypo Alert Level */
            case 14: /* Get Hypo Alert Level */
            case 16: /* Set Hyper Alert Level */
            case 17: /* Get Hyper Alert Level */
            case 19: /* Set Rate of Decrease Alert Level */
            case 20: /* Get Rate of Decrease Alert Level */
            case 22: /* Set Rate of Increase Alert Level */
            case 23: /* Get Rate of Increase Alert Level */
            case 25: /* Reset Device Specific Alert */
            case 26: /* Start the Session */
            case 27: /* Stop the Session */
                expert_add_info(pinfo, sub_item, &ei_btatt_opcode_invalid_response);
                break;

            case  3: /* CGM Communication Interval response */
                proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_operand_communication_interval, tvb, offset, 1, ENC_NA);
                offset += 1;

                break;
            case  6: /* Glucose Calibration Value response */
                proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_calibration_glucose_concentration, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_calibration_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_bitmask(sub_tree, tvb, offset, hf_btatt_cgm_type_and_sample_location, ett_btatt_value, hfx_btatt_cgm_type_and_sample_location, ENC_NA);
                offset += 1;

                proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_next_calibration_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_calibration_data_record_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_bitmask(sub_tree, tvb, offset, hf_btatt_cgm_specific_ops_control_point_calibration_status, ett_btatt_value, hfx_btatt_cgm_specific_ops_control_point_calibration_status, ENC_NA);
                offset += 1;

                break;
            case  9: /* Patient High Alert Level Response */
            case 12: /* Patient Low Alert Level Response */
            case 15: /* Hypo Alert Level Response */
            case 18: /* Hyper Alert Level Response */
                proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_operand_alert_level, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                break;
            case 21: /* Rate of Decrease Alert Level Response */
            case 24: /* Rate of Increase Alert Level Response */
                proto_tree_add_item(sub_tree, hf_btatt_cgm_specific_ops_control_point_operand_alert_level_rate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                break;
            }

            break;
        };

        proto_item_set_len(sub_item, offset - operand_offset);

        /* NOTE: only add if "E2E-CRC Supported bit is set in CGM Feature", but for now simple heuristic should be enough */
        if (tvb_reported_length_remaining(tvb, offset) >= 2) {
            proto_tree_add_item(tree, hf_btatt_cgm_e2e_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }

        break;
    case 0x2AAD: /* Indoor Positioning Configuration */
        if (service_uuid.bt_uuid == GATT_SERVICE_INDOOR_POSITIONING) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_indoor_positioning_configuration, ett_btatt_value, hfx_btatt_indoor_positioning_configuration, ENC_NA);
        offset += 1;

        break;
    case 0x2AAE: /* Latitude */
        if (service_uuid.bt_uuid == GATT_SERVICE_INDOOR_POSITIONING) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_latitude, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        break;
    case 0x2AAF: /* Longitude */
        if (service_uuid.bt_uuid == GATT_SERVICE_INDOOR_POSITIONING) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_longitude, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        break;
    case 0x2AB0: /* Local North Coordinate */
        if (service_uuid.bt_uuid == GATT_SERVICE_INDOOR_POSITIONING) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_local_north_coordinate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2AB1: /* Local East Coordinate */
        if (service_uuid.bt_uuid == GATT_SERVICE_INDOOR_POSITIONING) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_local_east_coordinate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2AB2: /* Floor Number */
        if (service_uuid.bt_uuid == GATT_SERVICE_INDOOR_POSITIONING) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_floor_number, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2AB3: /* Altitude */
        if (service_uuid.bt_uuid == GATT_SERVICE_INDOOR_POSITIONING) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_altitude, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2AB4: /* Uncertainty */
        if (service_uuid.bt_uuid == GATT_SERVICE_INDOOR_POSITIONING) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_uncertainty, ett_btatt_value, hfx_btatt_uncertainty, ENC_NA);
        offset += 1;

        break;
    case 0x2AB5: /* Location Name */
        if (service_uuid.bt_uuid == GATT_SERVICE_INDOOR_POSITIONING) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_WRITE_COMMAND)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_location_name, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2AB6: /* URI */
        if (service_uuid.bt_uuid == GATT_SERVICE_HTTP_PROXY) {
            if (is_writeable_response(att_data->opcode))
                break;

            if (!is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_uri, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2AB7: /* HTTP Headers */
        if (service_uuid.bt_uuid == GATT_SERVICE_HTTP_PROXY) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        sub_item = proto_tree_add_item(tree, hf_btatt_http_headers, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_value);

        call_dissector(http_handle, tvb_new_subset_remaining(tvb, offset), pinfo, sub_tree);

        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2AB8: /* HTTP Status Code */
        if (service_uuid.bt_uuid == GATT_SERVICE_HTTP_PROXY) {
            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_NOTIFICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_http_status_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_http_data_status, ett_btatt_value, hfx_btatt_http_data_status, ENC_NA);
        offset += 1;

        break;
    case 0x2AB9: /* HTTP Entity Body */
        if (service_uuid.bt_uuid == GATT_SERVICE_HTTP_PROXY) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) &&
                    !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_http_entity_body, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2ABA: /* HTTP Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_HTTP_PROXY) {
            if (is_writeable_response(att_data->opcode))
                break;

            if (!is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_http_control_point_opcode, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2ABB: /* HTTPS Security */
        if (service_uuid.bt_uuid == GATT_SERVICE_HTTP_PROXY) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_https_security, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2ABC: /* TDS Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_TRANSPORT_DISCOVERY) {
            if (is_writeable_response(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (!is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_tds_opcode, tvb, offset, 1, ENC_NA);
        offset += 1;

        if (att_data->opcode == 0x1B || att_data->opcode == 0x1D) { /* Handle Value Notification || Handle Value Indication" */
            proto_tree_add_item(tree, hf_btatt_tds_result_code, tvb, offset, 1, ENC_NA);
            offset += 1;
        } else {
            proto_tree_add_item(tree, hf_btatt_tds_organization_id, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(tree, hf_btatt_tds_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
            offset += tvb_reported_length_remaining(tvb, offset);
        }

        break;
    case 0x2ABD: /* OTS Feature */
        if (service_uuid.bt_uuid == GATT_SERVICE_OBJECT_TRANSFER) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_ots_feature_oacp, ett_btatt_value, hfx_btatt_ots_feature_oacp, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_ots_feature_olcp, ett_btatt_value, hfx_btatt_ots_feature_olcp, ENC_LITTLE_ENDIAN);
        offset += 4;

        break;
    case 0x2ABE: /* Object Name */
        if (service_uuid.bt_uuid == GATT_SERVICE_OBJECT_TRANSFER) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_ots_object_name, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2ABF: /* Object Type */
        if (service_uuid.bt_uuid == GATT_SERVICE_OBJECT_TRANSFER) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        offset = dissect_gatt_uuid(tree, pinfo, tvb, offset);

        break;
    case 0x2AC0: /* Object Size */
        if (service_uuid.bt_uuid == GATT_SERVICE_OBJECT_TRANSFER) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_ots_current_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(tree, hf_btatt_ots_allocated_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        break;
    case 0x2AC1: /* Object First-Created */
        if (service_uuid.bt_uuid == GATT_SERVICE_OBJECT_TRANSFER) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        sub_item = proto_tree_add_item(tree, hf_btatt_ots_object_first_created, tvb, offset, 7, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_value);

        call_dissector_with_data(find_dissector("btgatt.uuid0x2a08"), tvb_new_subset(tvb, offset, 7, 7), pinfo, sub_tree, att_data);
        offset += 7;

        break;
    case 0x2AC2: /* Object Last-Modified */
        if (service_uuid.bt_uuid == GATT_SERVICE_OBJECT_TRANSFER) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        sub_item = proto_tree_add_item(tree, hf_btatt_ots_object_last_modified, tvb, offset, 7, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_value);

        call_dissector_with_data(find_dissector("btgatt.uuid0x2a08"), tvb_new_subset(tvb, offset, 7, 7), pinfo, sub_tree, att_data);
        offset += 7;

        break;
    case 0x2AC3: /* Object ID */
        if (service_uuid.bt_uuid == GATT_SERVICE_OBJECT_TRANSFER) {
            if (is_readable_request(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_ots_object_id, tvb, offset, 6, ENC_LITTLE_ENDIAN);
        offset += 6;

        break;
    case 0x2AC4: /* Object Properties */
        if (service_uuid.bt_uuid == GATT_SERVICE_OBJECT_TRANSFER) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_ots_properties, ett_btatt_value, hfx_btatt_ots_properties, ENC_LITTLE_ENDIAN);
        offset += 4;

        break;
    case 0x2AC5: /* Object Action Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_OBJECT_TRANSFER) {
            if (is_writeable_response(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (!is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_ots_action_opcode, tvb, offset, 1, ENC_NA);
        opcode = tvb_get_guint8(tvb, offset);
        offset += 1;

        switch (opcode) {
        case 0x01: /* Create  */
            proto_tree_add_item(tree, hf_btatt_ots_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            offset = dissect_gatt_uuid(tree, pinfo, tvb, offset);

            break;
        case 0x02: /* Delete  */
        case 0x07: /* Abort */
            /* none */

            break;
        case 0x03: /* Calculate Checksum */
        case 0x05: /* Read */
        case 0x06: /* Write */
            proto_tree_add_item(tree, hf_btatt_ots_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_btatt_ots_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            break;
        case 0x04: /* Execute */
            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                proto_tree_add_item(tree, hf_btatt_ots_execute_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
                offset += tvb_reported_length_remaining(tvb, offset);
            }

            break;
        case 0x60: /* Response Code */
            proto_tree_add_item(tree, hf_btatt_ots_action_response_opcode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_btatt_ots_action_result_code, tvb, offset, 1, ENC_NA);
            offset += 1;

            switch (tvb_get_guint8(tvb, offset)) {
            case 0x01: /* Create  */
            case 0x02: /* Delete  */
            case 0x05: /* Read */
            case 0x06: /* Write */
            case 0x07: /* Abort */
            case 0x60: /* Response Code */
                /* none */

                break;
            case 0x03: /* Calculate Checksum */
                proto_tree_add_checksum(tree, tvb, offset, hf_btatt_ots_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
                offset += 4;

                break;
            case 0x04: /* Execute */
                if (tvb_reported_length_remaining(tvb, offset) > 0) {
                    proto_tree_add_item(tree, hf_btatt_ots_execute_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
                    offset += tvb_reported_length_remaining(tvb, offset);
                }

                break;
            }
        }
        break;
    case 0x2AC6: /* Object List Control Point */
        if (service_uuid.bt_uuid == GATT_SERVICE_OBJECT_TRANSFER) {
            if (is_writeable_response(att_data->opcode) || att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (!is_writeable_request(att_data->opcode) && att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_ots_list_opcode, tvb, offset, 1, ENC_NA);
        opcode = tvb_get_guint8(tvb, offset);
        offset += 1;

        switch (opcode) {
        case 0x01: /* First */
        case 0x02: /* Last */
        case 0x03: /* Previous */
        case 0x04: /* Next */
        case 0x07: /* Request Number of Object */
        case 0x08: /* Clear Marking */
            /* none */
            break;
        case 0x05: /* Go To */
            proto_tree_add_item(tree, hf_btatt_ots_object_id, tvb, offset, 6, ENC_LITTLE_ENDIAN);
            offset += 6;

            break;
        case 0x06: /* Order */
            proto_tree_add_item(tree, hf_btatt_ots_list_order, tvb, offset, 1, ENC_NA);
            offset += 1;

            break;
        case 0x70: /* Response Code  */
            proto_tree_add_item(tree, hf_btatt_ots_list_response_opcode, tvb, offset, 1, ENC_NA);
            offset += 1;

            proto_tree_add_item(tree, hf_btatt_ots_list_result_code, tvb, offset, 1, ENC_NA);
            offset += 1;

            switch (tvb_get_guint8(tvb, offset - 2)) {
            case 0x01: /* First */
            case 0x02: /* Last */
            case 0x03: /* Previous */
            case 0x04: /* Next */
            case 0x05: /* Go To */
            case 0x06: /* Order */
            case 0x08: /* Clear Marking */
            case 0x70: /* Response Code  */
                /* none */
                break;
            case 0x07: /* Request Number of Object */
                proto_tree_add_item(tree, hf_btatt_ots_list_total_number_of_objects, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
            }
        }

        break;
    case 0x2AC7: /* Object List Filter */
        if (service_uuid.bt_uuid == GATT_SERVICE_OBJECT_TRANSFER) {
            if (is_readable_request(att_data->opcode) || is_writeable_response(att_data->opcode))
                break;

            if (!is_readable_response(att_data->opcode) && !is_writeable_request(att_data->opcode))
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_ots_filter, tvb, offset, 1, ENC_NA);
        offset += 1;
        switch (tvb_get_guint8(tvb, offset - 1)) {
        case 0x00: /* No Filter */
        case 0x0A: /* Marked Objects */
            /* none */
            break;
        case 0x01: /* Name Starts With */
        case 0x02: /* Name Ends With */
        case 0x03: /* Name Contains*/
        case 0x04: /* Name is Exactly */
            proto_tree_add_item(tree, hf_btatt_ots_name_string, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
            offset += tvb_reported_length_remaining(tvb, offset);

            break;
        case 0x05: /* Object Type */
            offset = dissect_gatt_uuid(tree, pinfo, tvb, offset);

            break;
        case 0x06: /* Created Between */
        case 0x07: /* Modified Between */
            call_dissector_with_data(find_dissector("btgatt.uuid0x2a08"), tvb_new_subset(tvb, offset, 7, 7), pinfo, tree, att_data);
            offset += 7;

            call_dissector_with_data(find_dissector("btgatt.uuid0x2a08"), tvb_new_subset(tvb, offset, 7, 7), pinfo, tree, att_data);
            offset += 7;

            break;
        case 0x08: /* Current Size Between */
        case 0x09: /* Allocated Size Between */
            proto_tree_add_item(tree, hf_btatt_ots_size_from, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(tree, hf_btatt_ots_size_to, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            break;
        }

        break;
    case 0x2AC8: /* Object Changed */
        if (service_uuid.bt_uuid == GATT_SERVICE_OBJECT_TRANSFER) {
            if (att_data->opcode == ATT_OPCODE_HANDLE_VALUE_CONFIRMATION)
                break;

            if (att_data->opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
                expert_add_info(pinfo, tree, &ei_btatt_invalid_usage);
        }

        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_ots_flags, ett_btatt_value, hfx_btatt_ots_flags, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_ots_object_id, tvb, offset, 6, ENC_LITTLE_ENDIAN);
        offset += 6;

        break;
    default:
        if (bluetooth_gatt_has_no_parameter(att_data->opcode))
            break;

        proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
        offset = tvb_captured_length(tvb);
    }

    return old_offset + offset;
}

static int
dissect_btgatt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item  *main_item;
    proto_tree  *main_tree;
    proto_item  *patron_item = NULL;
    bluetooth_uuid_t uuid;

    main_item = proto_tree_add_item(tree, (gint) GPOINTER_TO_UINT(wmem_list_frame_data(wmem_list_tail(pinfo->layers))), tvb, 0, tvb_captured_length(tvb), ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btgatt);

    if (strlen(pinfo->current_proto) > 7) {
        uuid.size = 2;
        uuid.bt_uuid = (guint16) g_ascii_strtoull(pinfo->current_proto + strlen(pinfo->current_proto) - 7, NULL, 16);
        uuid.data[1] = uuid.bt_uuid & 0xFF;
        uuid.data[0] = (uuid.bt_uuid >> 8) & 0xFF;
    } else {
        uuid.size = 2;
        uuid.bt_uuid = 0;
    }

    return dissect_attribute_value(main_tree, patron_item, pinfo, tvb,
            0, tvb_captured_length(tvb), 0, uuid, (btatt_data_t *) data);

}

static gboolean
is_long_attribute_value(bluetooth_uuid_t uuid)
{
    switch (uuid.bt_uuid) {
    case 0x2901: /* Characteristic User Description */
    case 0x2A00: /* Device Name */
    case 0x2A24: /* Model Number String */
    case 0x2A25: /* Serial Number String */
    case 0x2A26: /* Firmware Revision String */
    case 0x2A27: /* Hardware Revision String */
    case 0x2A28: /* Software Revision String */
    case 0x2A29: /* Manufacturer Name String */
    case 0x2A4B: /* Report Map */
    case 0x2A87: /* Email Address */
    case 0x2A90: /* Last Name */
    case 0x2AA4: /* Bond Management Control Point */
    case 0x2AB5: /* Location Name */
    case 0x2AB6: /* URI */
    case 0x2AB7: /* HTTP Headers */
    case 0x2AB9: /* HTTP Entity Body */
    case 0x2ABE: /* Object Name */
        return TRUE;
    }

    return FALSE;
}

static guint
get_mtu(packet_info *pinfo, bluetooth_data_t *bluetooth_data)
{
    wmem_tree_key_t  key[3];
    guint32          frame_number;
    mtu_data_t      *mtu_data;
    wmem_tree_t     *sub_wmemtree;
    guint            mtu = 23;

    frame_number = pinfo->num;

    key[0].length = 1;
    key[0].key    = &bluetooth_data->interface_id;
    key[1].length = 1;
    key[1].key    = &bluetooth_data->adapter_id;
    key[2].length = 0;
    key[2].key    = NULL;

    sub_wmemtree = (wmem_tree_t *) wmem_tree_lookup32_array(mtus, key);
    mtu_data = (sub_wmemtree) ? (mtu_data_t *) wmem_tree_lookup32_le(sub_wmemtree, frame_number) : NULL;

    if (mtu_data)
        mtu = mtu_data->mtu;

    return mtu;
}

static void
save_mtu(packet_info *pinfo, bluetooth_data_t *bluetooth_data, guint mtu)
{
    wmem_tree_key_t  key[4];
    guint32          frame_number;
    mtu_data_t      *mtu_data;

    frame_number = pinfo->num;

    key[0].length = 1;
    key[0].key    = &bluetooth_data->interface_id;
    key[1].length = 1;
    key[1].key    = &bluetooth_data->adapter_id;
    key[2].length = 1;
    key[2].key    = &frame_number;
    key[3].length = 0;
    key[3].key    = NULL;

    mtu_data = wmem_new(wmem_file_scope(), mtu_data_t);
    mtu_data->mtu = mtu;

    wmem_tree_insert32_array(mtus, key, mtu_data);
}

static void
save_value_fragment(packet_info *pinfo, tvbuff_t *tvb, gint offset,
        guint32 handle, guint data_offset, bluetooth_data_t *bluetooth_data)
{
    wmem_tree_key_t   key[5];
    guint32           frame_number;
    fragment_data_t  *fragment_data;

    frame_number = pinfo->num;

    key[0].length = 1;
    key[0].key    = &bluetooth_data->interface_id;
    key[1].length = 1;
    key[1].key    = &bluetooth_data->adapter_id;
    key[2].length = 1;
    key[2].key    = &handle;
    key[3].length = 1;
    key[3].key    = &frame_number;
    key[4].length = 0;
    key[4].key    = NULL;

    fragment_data = wmem_new(wmem_file_scope(), fragment_data_t);
    fragment_data->length = tvb_captured_length_remaining(tvb, offset);
    fragment_data->offset = data_offset;
    fragment_data->data_in_frame = frame_number;
    fragment_data->data = (guint8 *) tvb_memdup(wmem_file_scope(), tvb, offset, fragment_data->length);

    wmem_tree_insert32_array(fragments, key, fragment_data);
}

static guint8 *
get_value(packet_info *pinfo, guint32 handle, bluetooth_data_t *bluetooth_data, guint *length)
{
    wmem_tree_key_t   key[4];
    guint32           frame_number;
    fragment_data_t  *fragment_data;
    wmem_tree_t      *sub_wmemtree;
    guint             last_offset = G_MAXUINT;
    guint             size;
    gboolean          first = TRUE;
    guint8           *data = NULL;


    frame_number = pinfo->num;

    key[0].length = 1;
    key[0].key    = &bluetooth_data->interface_id;
    key[1].length = 1;
    key[1].key    = &bluetooth_data->adapter_id;
    key[2].length = 1;
    key[2].key    = &handle;
    key[3].length = 0;
    key[3].key    = NULL;

    sub_wmemtree = (wmem_tree_t *) wmem_tree_lookup32_array(fragments, key);
    while (1) {
        fragment_data = (sub_wmemtree) ? (fragment_data_t *) wmem_tree_lookup32_le(sub_wmemtree, frame_number) : NULL;
        if (!fragment_data || (fragment_data && fragment_data->offset >= last_offset))
            break;

        if (first) {
            size = fragment_data->offset + fragment_data->length;
            data = (guint8 *) wmem_alloc(pinfo->pool, size);

            if (length)
                *length = size;

            first = FALSE;
        } else if (fragment_data->offset + fragment_data->length != last_offset) {
            break;
        }

        memcpy(data + fragment_data->offset, fragment_data->data, fragment_data->length);

        if (fragment_data->offset == 0)
            return data;
        frame_number = fragment_data->data_in_frame - 1;
        last_offset = fragment_data->offset;
    }

    if (length)
        *length = 0;
    return NULL;
}

static int
dissect_btatt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item        *main_item;
    proto_tree        *main_tree;
    proto_item        *sub_item;
    proto_tree        *sub_tree;
    int                offset = 0;
    guint8             opcode;
    guint8             request_opcode;
    bluetooth_data_t  *bluetooth_data;
    btatt_data_t       att_data;
    request_data_t    *request_data;
    guint16            handle;
    bluetooth_uuid_t   uuid;
    guint              mtu;

    memset(&uuid, 0, sizeof uuid);

    bluetooth_data = (bluetooth_data_t *) data;

    if (tvb_reported_length_remaining(tvb, 0) < 1)
        return 0;

    att_data.bluetooth_data   = bluetooth_data;

    main_item = proto_tree_add_item(tree, proto_btatt, tvb, 0, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btatt);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATT");

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
            break;
    }

    mtu = get_mtu(pinfo, bluetooth_data);
    if (tvb_reported_length(tvb) > mtu)
        expert_add_info(pinfo, main_item, &ei_btatt_mtu_exceeded);

    proto_tree_add_bitmask_with_flags(main_tree, tvb, offset, hf_btatt_opcode, ett_btatt_opcode,  hfx_btatt_opcode, ENC_NA, BMT_NO_APPEND);
    opcode = tvb_get_guint8(tvb, 0);
    att_data.opcode = opcode;
    offset++;

    request_data = get_request(tvb, offset, pinfo, opcode, bluetooth_data);

    col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(opcode, opcode_vals, "<unknown>"));

    switch (opcode) {
    case 0x01: /* Error Response */
        {
        guint8               error_code;
        bluetooth_uuid_t     service_uuid;
        const value_string  *error_vals = error_code_vals;
        gint                 hfx_btatt_error_code = hf_btatt_error_code;

        proto_tree_add_bitmask_with_flags(main_tree, tvb, offset, hf_btatt_req_opcode_in_error, ett_btatt_opcode,  hfx_btatt_opcode, ENC_NA, BMT_NO_APPEND);
        request_opcode = tvb_get_guint8(tvb, offset);
        offset += 1;

        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle_in_error, tvb, offset, bluetooth_data, NULL, HANDLE_TVB);
        handle = tvb_get_letohs(tvb, offset - 2);

        error_code = tvb_get_guint8(tvb, offset);

        if (error_code >= 0x80 && error_code <= 0x9F) {
            service_uuid = get_service_uuid_from_handle(pinfo, handle, bluetooth_data);

            switch (service_uuid.bt_uuid) {
            case GATT_SERVICE_AUTOMATION_IO:
                error_vals = error_code_aios_vals;
                hfx_btatt_error_code = hf_btatt_error_code_aios;

                break;
            case GATT_SERVICE_ALERT_NOTIFICATION_SERVICE:
                error_vals = error_code_ans_vals;
                hfx_btatt_error_code = hf_btatt_error_code_ans;

                break;
            case GATT_SERVICE_BOND_MANAGEMENT:
                error_vals = error_code_bms_vals;
                hfx_btatt_error_code = hf_btatt_error_code_bms;

                break;
            case GATT_SERVICE_CONTINUOUS_GLUCOSE_MONITORING:
                error_vals = error_code_cgms_vals;
                hfx_btatt_error_code = hf_btatt_error_code_cgms;

                break;
            case GATT_SERVICE_CYCLING_POWER:
                error_vals = error_code_cps_vals;
                hfx_btatt_error_code = hf_btatt_error_code_cps;

                break;
            case GATT_SERVICE_CYCLING_SPEED_AND_CADENCE:
                error_vals = error_code_cscs_vals;
                hfx_btatt_error_code = hf_btatt_error_code_cscs;

                break;
            case GATT_SERVICE_CURRENT_TIME_SERVICE:
                error_vals = error_code_cts_vals;
                hfx_btatt_error_code = hf_btatt_error_code_cts;

                break;
            case GATT_SERVICE_ENVIRONMENTAL_SENSING:
                error_vals = error_code_ess_vals;
                hfx_btatt_error_code = hf_btatt_error_code_ess;

                break;
            case GATT_SERVICE_GLUCOSE:
                error_vals = error_code_gls_vals;
                hfx_btatt_error_code = hf_btatt_error_code_gls;

                break;
            case GATT_SERVICE_HTTP_PROXY:
                error_vals = error_code_hps_vals;
                hfx_btatt_error_code = hf_btatt_error_code_hps;

                break;
            case GATT_SERVICE_HEART_RATE:
                error_vals = error_code_hrs_vals;
                hfx_btatt_error_code = hf_btatt_error_code_hrs;

                break;
            case GATT_SERVICE_HEALTH_THERMOMETER:
                error_vals = error_code_hts_vals;
                hfx_btatt_error_code = hf_btatt_error_code_hts;

                break;
            case GATT_SERVICE_INDOOR_POSITIONING:
                error_vals = error_code_ips_vals;
                hfx_btatt_error_code = hf_btatt_error_code_ips;

                break;
            case GATT_SERVICE_OBJECT_TRANSFER:
                error_vals = error_code_ots_vals;
                hfx_btatt_error_code = hf_btatt_error_code_ots;

                break;
            case GATT_SERVICE_RUNNING_SPEED_AND_CADENCE:
                error_vals = error_code_rscs_vals;
                hfx_btatt_error_code = hf_btatt_error_code_rscs;

                break;
            case GATT_SERVICE_USER_DATA:
                error_vals = error_code_uds_vals;
                hfx_btatt_error_code = hf_btatt_error_code_uds;

                break;
            default:
                error_vals = error_code_vals;
                hfx_btatt_error_code = hf_btatt_error_code;
            }
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, " - %s, Handle: 0x%04x",
                        val_to_str_const(error_code, error_vals, "<unknown>"),
                        handle);

        col_append_info_by_handle(pinfo, handle, bluetooth_data);

        proto_tree_add_item(main_tree, hfx_btatt_error_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        if (request_data && (request_opcode == 0x08 || request_opcode == 0x10)) {
            sub_item = proto_tree_add_uint(main_tree, hf_btatt_uuid16, tvb, 0, 0, request_data->parameters.read_by_type.uuid.bt_uuid);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }
        }
        break;

    case 0x02: /* Exchange MTU Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Client Rx MTU: %u", tvb_get_letohs(tvb, offset));
        proto_tree_add_item(main_tree, hf_btatt_client_rx_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.mtu.mtu = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }

        break;

    case 0x03: /* Exchange MTU Response */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Server Rx MTU: %u", tvb_get_letohs(tvb, offset));
        proto_tree_add_item(main_tree, hf_btatt_server_rx_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        if (!pinfo->fd->flags.visited && request_data && bluetooth_data) {
            guint new_mtu;

            new_mtu = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
            if (new_mtu > request_data->parameters.mtu.mtu)
                new_mtu = request_data->parameters.mtu.mtu;
            save_mtu(pinfo, bluetooth_data, new_mtu);
        }
        offset += 2;
        break;

    case 0x04: /* Find Information Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handles: 0x%04x..0x%04x",
                            tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));
        proto_tree_add_item(main_tree, hf_btatt_starting_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(main_tree, hf_btatt_ending_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.find_information.starting_handle = tvb_get_guint16(tvb, offset - 4, ENC_LITTLE_ENDIAN);
            request_parameters.find_information.ending_handle   = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }

        break;

    case 0x05: /* Find Information Response */
        {
            guint8  format;

            sub_item = proto_tree_add_item(main_tree, hf_btatt_uuid_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            format = tvb_get_guint8(tvb, offset);
            offset += 1;

            if (format == 1) {
                while( tvb_reported_length_remaining(tvb, offset) > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_btatt_information_data, tvb, offset, 4, ENC_NA),
                    sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

                    offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL, HANDLE_TVB);
                    handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

                    proto_tree_add_item(sub_tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    uuid = get_uuid(tvb, offset, 2);
                    offset += 2;

                    proto_item_append_text(sub_item, ", Handle: 0x%04x, UUID: %s",
                            tvb_get_letohs(tvb, offset - 4),
                            print_uuid(&uuid));

                    save_handle(pinfo, uuid, handle, ATTRIBUTE_TYPE_OTHER, bluetooth_data);

                    col_append_info_by_handle(pinfo, handle, bluetooth_data);
                }
            }
            else if (format == 2) {
                while( tvb_reported_length_remaining(tvb, offset) > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_btatt_information_data, tvb, offset, 4, ENC_NA),
                    sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

                    offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL, HANDLE_TVB);
                    handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

                    proto_tree_add_item(sub_tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
                    uuid = get_uuid(tvb, offset, 16);
                    offset += 16;

                    proto_item_append_text(sub_item, ", Handle: 0x%04x, UUID: %s",
                            tvb_get_letohs(tvb, offset - 4),
                            print_uuid(&uuid));

                    save_handle(pinfo, uuid, handle, ATTRIBUTE_TYPE_OTHER, bluetooth_data);

                    col_append_info_by_handle(pinfo, handle, bluetooth_data);
                }
            }
            else {
                expert_add_info(pinfo, sub_item, &ei_btatt_uuid_format_unknown);
            }
        }
        break;

    case 0x06: /* Find By Type Value Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s, Handles: 0x%04x..0x%04x",
                            val_to_str_ext_const(tvb_get_letohs(tvb, offset+4), &bluetooth_uuid_vals_ext, "<unknown>"),
                            tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

        proto_tree_add_item(main_tree, hf_btatt_starting_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(main_tree, hf_btatt_ending_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(main_tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        uuid = get_uuid(tvb, offset - 2, 2);
        offset += 2;

        dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset), 0, uuid, &att_data);

        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.read_by_type.starting_handle = tvb_get_guint16(tvb, offset - 6, ENC_LITTLE_ENDIAN);
            request_parameters.read_by_type.ending_handle   = tvb_get_guint16(tvb, offset - 4, ENC_LITTLE_ENDIAN);
            request_parameters.read_by_type.uuid = uuid;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }

        offset = tvb_reported_length(tvb);

        break;

    case 0x07: /* Find By Type Value Response */
        while( tvb_reported_length_remaining(tvb, offset) > 0 ) {
            sub_item = proto_tree_add_none_format(main_tree, hf_btatt_handles_info, tvb, offset, 4,
                                            "Handles Info, Handle: 0x%04x, Group End Handle: 0x%04x",
                                            tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

            sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

            offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL, HANDLE_TVB);

            proto_tree_add_item(sub_tree, hf_btatt_group_end_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            if (request_data)
                save_handle(pinfo, request_data->parameters.read_by_type.uuid,
                        tvb_get_guint16(tvb, offset - 4, ENC_LITTLE_ENDIAN),
                        ATTRIBUTE_TYPE_OTHER, bluetooth_data);

        }
        break;

    case 0x08: /* Read By Type Request */
    case 0x10: /* Read By Group Type Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s, Handles: 0x%04x..0x%04x",
                            val_to_str_ext_const(tvb_get_letohs(tvb, offset+4), &bluetooth_uuid_vals_ext, "<unknown>"),
                            tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

        proto_tree_add_item(main_tree, hf_btatt_starting_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(main_tree, hf_btatt_ending_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (tvb_reported_length_remaining(tvb, offset) == 2) {
            proto_tree_add_item(main_tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            if (!pinfo->fd->flags.visited && bluetooth_data) {
                union request_parameters_union  request_parameters;

                request_parameters.read_by_type.starting_handle = tvb_get_guint16(tvb, offset - 6, ENC_LITTLE_ENDIAN);
                request_parameters.read_by_type.ending_handle   = tvb_get_guint16(tvb, offset - 4, ENC_LITTLE_ENDIAN);
                request_parameters.read_by_type.uuid = get_uuid(tvb, offset - 2, 2);

                save_request(pinfo, opcode, request_parameters, bluetooth_data);
            }
        } else if (tvb_reported_length_remaining(tvb, offset) == 16) {
            sub_item = proto_tree_add_item(main_tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
            proto_item_append_text(sub_item, " (%s)", val_to_str_ext_const(tvb_get_letohs(tvb, offset),
                                            &bluetooth_uuid_vals_ext, "<unknown>"));
            offset += 16;

            if (!pinfo->fd->flags.visited && bluetooth_data) {
                union request_parameters_union  request_parameters;

                request_parameters.read_by_type.starting_handle = tvb_get_guint16(tvb, offset - 20, ENC_LITTLE_ENDIAN);
                request_parameters.read_by_type.ending_handle   = tvb_get_guint16(tvb, offset - 18, ENC_LITTLE_ENDIAN);
                request_parameters.read_by_type.uuid = get_uuid(tvb, offset - 16, 16);

                save_request(pinfo, opcode, request_parameters, bluetooth_data);
            }
        } else {
            sub_item = proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
            expert_add_info(pinfo, sub_item, &ei_btatt_bad_data);
            offset = tvb_captured_length(tvb);
        }

        break;

    case 0x09: /* Read By Type Response */
        {
            guint8  length = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(main_tree, hf_btatt_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            if(length > 0) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Attribute List Length: %u",
                                        tvb_reported_length_remaining(tvb, offset)/length);

                while (tvb_reported_length_remaining(tvb, offset) >= length)
                {
                    sub_item = proto_tree_add_none_format(main_tree, hf_btatt_attribute_data, tvb,
                                                    offset, length, "Attribute Data, Handle: 0x%04x",
                                                    tvb_get_letohs(tvb, offset));

                    sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

                    if (request_data) {
                        save_handle(pinfo, request_data->parameters.read_by_type.uuid,
                                tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN),
                                ATTRIBUTE_TYPE_OTHER, bluetooth_data);
                    }

                    offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL, HANDLE_TVB);

                    if (request_data) {
                        offset = dissect_attribute_value(sub_tree, sub_item, pinfo, tvb, offset, length - 2, tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN), request_data->parameters.read_by_type.uuid, &att_data);
                    } else {
                        proto_tree_add_item(sub_tree, hf_btatt_value, tvb, offset, length - 2, ENC_NA);
                        offset += length - 2;
                    }
                }
            }

            if (request_data) {
                sub_item = proto_tree_add_uint(main_tree, hf_btatt_uuid16, tvb, 0, 0, request_data->parameters.read_by_type.uuid.bt_uuid);
                PROTO_ITEM_SET_GENERATED(sub_item);
            }
        }
        break;

    case 0x0a: /* Read Request */
        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid, HANDLE_TVB);
        handle = tvb_get_letohs(tvb, offset - 2);

        col_append_info_by_handle(pinfo, handle, bluetooth_data);

        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.read_write.handle = handle;
            request_parameters.read_write.offset = 0;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }

        offset = dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset), handle, uuid, &att_data);

        break;

    case 0x0b: /* Read Response */
        if (request_data) {
            dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid, request_data->parameters.read_write.handle);

            col_append_info_by_handle(pinfo, request_data->parameters.read_write.handle, bluetooth_data);
        }

        if (is_long_attribute_value(uuid) && tvb_captured_length(tvb) >= mtu) {
            sub_item = proto_tree_add_item(main_tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
            if (!pinfo->fd->flags.visited && request_data && bluetooth_data)
                save_value_fragment(pinfo, tvb, offset, request_data->parameters.read_write.handle, 0, bluetooth_data);
            offset = tvb_captured_length(tvb);

            expert_add_info(pinfo, sub_item, &ei_btatt_mtu_full);
        } else {
            if (request_data)
                handle = request_data->parameters.read_write.handle;
            else
                handle = 0;

            offset = dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset), handle, uuid, &att_data);
        }
        break;

    case 0x0c: /* Read Blob Request */
        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid, HANDLE_TVB);
        handle = tvb_get_letohs(tvb, offset - 2);

        col_append_info_by_handle(pinfo, handle, bluetooth_data);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Offset: %u", tvb_get_letohs(tvb, offset));

        proto_tree_add_item(main_tree, hf_btatt_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, 0, handle, uuid, &att_data);


        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.read_write.handle = handle;
            request_parameters.read_write.offset = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        break;

    case 0x0d: /* Read Blob Response */
        if (request_data) {
            dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid, request_data->parameters.read_write.handle);

            col_append_info_by_handle(pinfo, request_data->parameters.read_write.handle, bluetooth_data);

            if (request_data->parameters.read_write.offset == 0 && !is_long_attribute_value(uuid)) {
                offset = dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset), request_data->parameters.read_write.handle, uuid, &att_data);
            } else {
                if (!pinfo->fd->flags.visited && bluetooth_data)
                    save_value_fragment(pinfo, tvb, offset, request_data->parameters.read_write.handle, request_data->parameters.read_write.offset, bluetooth_data);

                if (tvb_captured_length(tvb) < mtu) {
                    tvbuff_t  *next_tvb;
                    guint      reassembled_length;
                    guint8    *reassembled_data;

                    sub_item = proto_tree_add_item(main_tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
                    offset = tvb_captured_length(tvb);

                    reassembled_data = get_value(pinfo, request_data->parameters.read_write.handle, bluetooth_data, &reassembled_length);
                    if (reassembled_data) {
                        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_value);
                        next_tvb = tvb_new_child_real_data(tvb, reassembled_data, reassembled_length, reassembled_length);
                        add_new_data_source(pinfo, next_tvb, "Reassembled ATT");
                        dissect_attribute_value(sub_tree, NULL, pinfo, next_tvb, 0, tvb_captured_length(next_tvb), request_data->parameters.read_write.handle, uuid, &att_data);
                    }
                } else {
                    sub_item = proto_tree_add_item(main_tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
                    offset = tvb_captured_length(tvb);

                    expert_add_info(pinfo, sub_item, &ei_btatt_mtu_full);
                }
            }
        } else {
            proto_tree_add_item(main_tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
            offset = tvb_captured_length(tvb);
        }

        break;

    case 0x0e: /* Multiple Read Request */
        if(tvb_reported_length_remaining(tvb, offset) < 4) {
            expert_add_info(pinfo, main_item, &ei_btatt_handle_too_few);
            break;
        }

        col_append_str(pinfo->cinfo, COL_INFO, ", Handles: ");
        while (tvb_reported_length_remaining(tvb, offset) >= 2) {
            offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid, HANDLE_TVB);
            handle = tvb_get_letohs(tvb, offset - 2);
            col_append_fstr(pinfo->cinfo, COL_INFO, "0x%04x ", handle);

            dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, 0, handle, uuid, &att_data);
        }

        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.read_multiple.number_of_handles = (tvb_captured_length(tvb) - 1) / 2;
            request_parameters.read_multiple.handle = (guint16 *) tvb_memdup(wmem_file_scope(),
                    tvb, 1, request_parameters.read_multiple.number_of_handles * 2);

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        break;

    case 0x0f: /* Multiple Read Response */
        if (request_data) {
            guint  i_handle;

            for (i_handle = 0; i_handle < request_data->parameters.read_multiple.number_of_handles; i_handle += 1) {
                dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid, request_data->parameters.read_multiple.handle[i_handle]);
                offset = dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset), request_data->parameters.read_multiple.handle[i_handle], uuid, &att_data);
            }
        } else {
            proto_tree_add_item(main_tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
            offset = tvb_reported_length(tvb);
        }
        break;

    case 0x11: /* Read By Group Type Response */
        {
            guint8  length = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(main_tree, hf_btatt_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            if (length > 0) {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Attribute List Length: %u", tvb_reported_length_remaining(tvb, offset)/length);

                while (tvb_reported_length_remaining(tvb, offset) >= length) {
                    sub_item = proto_tree_add_none_format(main_tree, hf_btatt_attribute_data, tvb, offset, length,
                                                    "Attribute Data, Handle: 0x%04x, Group End Handle: 0x%04x",
                                                    tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

                    sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

                    offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL, HANDLE_TVB);
                    handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

                    proto_tree_add_item(sub_tree, hf_btatt_group_end_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;

                    if (request_data) {
                        offset = dissect_attribute_value(sub_tree, sub_item, pinfo, tvb, offset, length - 4, handle, request_data->parameters.read_by_type.uuid, &att_data);
                    } else {
                        proto_tree_add_item(sub_tree, hf_btatt_value, tvb, offset, length - 4, ENC_NA);
                        offset += length - 4;
                    }
                }
            }

            if (request_data) {
                sub_item = proto_tree_add_uint(main_tree, hf_btatt_uuid16, tvb, 0, 0, request_data->parameters.read_by_type.uuid.bt_uuid);
                PROTO_ITEM_SET_GENERATED(sub_item);
            }
        }
        break;

    case 0x12: /* Write Request */
    case 0x1d: /* Handle Value Indication */
    case 0x52: /* Write Command */
    case 0x1b: /* Handle Value Notification */
        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid, HANDLE_TVB);
        handle = tvb_get_letohs(tvb, offset - 2);

        col_append_info_by_handle(pinfo, handle, bluetooth_data);

        offset = dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset), tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN), uuid, &att_data);

        if (!pinfo->fd->flags.visited && bluetooth_data && (opcode == 0x12 || opcode == 0x1d)) {
            union request_parameters_union  request_parameters;

            request_parameters.read_write.handle = handle;
            request_parameters.read_write.offset = 0;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        break;

    case 0x13: /* Write Response */
        /* No parameters */

        if (request_data) {
            dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid, request_data->parameters.read_write.handle);

            dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, 0, request_data->parameters.read_write.handle, uuid, &att_data);

            col_append_info_by_handle(pinfo, request_data->parameters.read_write.handle, bluetooth_data);
        }

        break;

    case 0x16: /* Prepare Write Request */
    case 0x17: /* Prepare Write Response */
        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid, HANDLE_TVB);
        handle = tvb_get_letohs(tvb, offset - 2);

        col_append_info_by_handle(pinfo, handle, bluetooth_data);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Offset: %u", tvb_get_letohs(tvb, offset));

        proto_tree_add_item(main_tree, hf_btatt_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (!pinfo->fd->flags.visited && bluetooth_data && opcode == 0x16) {
            union request_parameters_union  request_parameters;

            request_parameters.data = NULL;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        if (!pinfo->fd->flags.visited && request_data && bluetooth_data && opcode == 0x16)
            save_value_fragment(pinfo, tvb, offset,
                    tvb_get_guint16(tvb, offset - 4, ENC_LITTLE_ENDIAN),
                    tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN),
                    bluetooth_data);

/* XXX: How to detect there is max data in frame and it is last fragment?
        (Execute Write Request/Response is good candidate, but there is no one handle) */
        if (request_data && tvb_captured_length(tvb) < mtu) {
            tvbuff_t  *next_tvb;
            guint      reassembled_length;
            guint8    *reassembled_data;

            sub_item = proto_tree_add_item(main_tree, hf_btatt_value, tvb, offset, -1, ENC_NA);

            reassembled_data = get_value(pinfo, request_data->parameters.read_write.handle, bluetooth_data, &reassembled_length);
            if (reassembled_data) {
                sub_tree = proto_item_add_subtree(sub_item, ett_btatt_value);
                next_tvb = tvb_new_child_real_data(tvb, reassembled_data, reassembled_length, reassembled_length);
                add_new_data_source(pinfo, next_tvb, "Reassembled ATT");
                dissect_attribute_value(sub_tree, NULL, pinfo, next_tvb, 0, tvb_captured_length(next_tvb), request_data->parameters.read_write.handle, uuid, &att_data);
            }
        } else {
            proto_tree_add_item(main_tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
        }

        offset = tvb_reported_length(tvb);

        break;

    case 0x18: /* Execute Write Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                        val_to_str_const(tvb_get_guint8(tvb, offset), flags_vals, "<unknown>"));
        proto_tree_add_item(main_tree, hf_btatt_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            /* NOTE: Enable request-response tracking using empty data*/
            request_parameters.data = NULL;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        break;

    case 0x19: /* Execute Write Response */
        /* No parameters */
        break;

    case 0x1E: /* Handle Value Confirmation */
        if (request_data) {
            dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid, request_data->parameters.read_write.handle);

            col_append_info_by_handle(pinfo, request_data->parameters.read_write.handle, bluetooth_data);

            dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, 0, request_data->parameters.read_write.handle, uuid, &att_data);
        }
        break;

    case 0xd2: /* Signed Write Command */
        {
            guint8 length;

            offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid, HANDLE_TVB);
            handle = tvb_get_letohs(tvb, offset - 2);

            col_append_info_by_handle(pinfo, handle, bluetooth_data);

            length = tvb_reported_length_remaining(tvb, offset);
            dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, (length > 12) ? length - 12 : 0, handle, uuid, &att_data);
            if (length > 12) {
                offset += length - 12;
            }

            proto_tree_add_item(main_tree, hf_btatt_sign_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(main_tree, hf_btatt_signature, tvb, offset, 8, ENC_NA);
            offset+=8;
        break;
        }
    default:
        break;
    }

    if (request_data) {
        if (request_data->request_in_frame > 0  && request_data->request_in_frame != pinfo->num) {
            sub_item = proto_tree_add_uint(main_tree, hf_request_in_frame, tvb, 0, 0, request_data->request_in_frame);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }

        if (!pinfo->fd->flags.visited && request_data->response_in_frame == 0 &&
                pinfo->num > request_data->request_in_frame)
            request_data->response_in_frame = pinfo->num;

        if (request_data->response_in_frame > 0 && request_data->response_in_frame != pinfo->num) {
            sub_item = proto_tree_add_uint(main_tree, hf_response_in_frame, tvb, 0, 0, request_data->response_in_frame);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }
    }

    return offset;
}

static int
dissect_btgatt_nordic_uart_tx(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    btatt_data_t *att_data = (btatt_data_t *) data;

    if (bluetooth_gatt_has_no_parameter(att_data->opcode))
        return -1;

    proto_tree_add_item(tree, hf_gatt_nordic_uart_tx, tvb, 0, tvb_captured_length(tvb), ENC_ASCII | ENC_NA);

    return tvb_captured_length(tvb);
}

static int
dissect_btgatt_nordic_uart_rx(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    btatt_data_t *att_data = (btatt_data_t *) data;

    if (bluetooth_gatt_has_no_parameter(att_data->opcode))
        return -1;

    proto_tree_add_item(tree, hf_gatt_nordic_uart_rx, tvb, 0, tvb_captured_length(tvb), ENC_ASCII | ENC_NA);

    return tvb_captured_length(tvb);
}

static int
dissect_btgatt_nordic_dfu_control_point(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gint    offset = 0;
    guint8  opcode;
    guint8  request_opcode;
    guint8  status;
    btatt_data_t *att_data = (btatt_data_t *) data;

    if (bluetooth_gatt_has_no_parameter(att_data->opcode))
        return -1;

    proto_tree_add_item(tree, hf_gatt_nordic_dfu_control_point_opcode, tvb, offset, 1, ENC_NA);
    opcode = tvb_get_guint8(tvb, offset);
    offset += 1;

    switch (opcode) {
    case 0x01: /* Start DFU */
        proto_tree_add_item(tree, hf_gatt_nordic_dfu_control_point_image_type, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x02: /* Initialize DFU Parameters */
        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(tree, hf_gatt_nordic_dfu_control_point_init_packet, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        break;
    case 0x03: /* Receive Firmware Image */
    case 0x04: /* Validate Firmware */
    case 0x05: /* Activate Image and Reset */
    case 0x06: /* Reset System */
    case 0x07: /* Report Received Image Size */
        /* nop */

        break;
    case 0x08: /* Packet Receipt Notification Request */
        proto_tree_add_item(tree, hf_gatt_nordic_dfu_control_point_number_of_packets, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x10: /* Response Code */
        proto_tree_add_item(tree, hf_gatt_nordic_dfu_control_point_request_opcode, tvb, offset, 1, ENC_NA);
        request_opcode = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(tree, hf_gatt_nordic_dfu_control_point_response_value, tvb, offset, 1, ENC_NA);
        status = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (request_opcode == 0x07 && status == 0x01) { /* Report Received Image Size && Success */
            proto_tree_add_item(tree, hf_gatt_nordic_dfu_control_point_number_of_bytes, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }

        break;
    case 0x11: /* Packet Receipt Notification */
        proto_tree_add_item(tree, hf_gatt_nordic_dfu_control_point_number_of_bytes, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;
    }

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert(tree, pinfo, &ei_btatt_unexpected_data, tvb, offset, -1);
        offset = tvb_captured_length(tvb);
    }

    return offset;
}


static int
dissect_btgatt_nordic_dfu_packet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    btatt_data_t *att_data = (btatt_data_t *) data;

    if (bluetooth_gatt_has_no_parameter(att_data->opcode))
        return -1;

    proto_tree_add_item(tree, hf_gatt_nordic_dfu_packet, tvb, 0, tvb_captured_length(tvb), ENC_NA);

    return tvb_captured_length(tvb);
}

void
proto_register_btatt(void)
{
    module_t         *module;
    expert_module_t  *expert_btatt;


    static hf_register_info hf[] = {
        {&hf_btatt_opcode,
            {"Opcode", "btatt.opcode",
            FT_UINT8, BASE_HEX, VALS(opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_opcode_authentication_signature,
            {"Authentication Signature", "btatt.opcode.authentication_signature",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL}
        },
        {&hf_btatt_opcode_command,
            {"Command", "btatt.opcode.command",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL}
        },
        {&hf_btatt_opcode_method,
            {"Method", "btatt.opcode.method",
            FT_UINT8, BASE_HEX, VALS(opcode_vals), 0x3F,
            NULL, HFILL}
        },
        {&hf_btatt_handles_info,
            {"Handles Info", "btatt.handles_info",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_attribute_data,
            {"Attribute Data", "btatt.attribute_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_handle,
            {"Handle", "btatt.handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_starting_handle,
            {"Starting Handle", "btatt.starting_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ending_handle,
            {"Ending Handle", "btatt.ending_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_group_end_handle,
            {"Group End Handle", "btatt.group_end_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_value,
            {"Value", "btatt.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_req_opcode_in_error,
            {"Request Opcode in Error", "btatt.req_opcode_in_error",
            FT_UINT8, BASE_HEX, VALS(opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_handle_in_error,
            {"Handle in Error", "btatt.handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_aios,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_aios_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_ans,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_ans_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_bms,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_bms_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_cgms,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_cgms_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_cps,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_cps_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_cscs,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_cscs_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_cts,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_cts_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_ess,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_ess_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_gls,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_gls_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_hps,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_hps_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_hrs,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_hrs_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_hts,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_hts_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_ips,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_ips_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_ots,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_ots_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_rscs,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_rscs_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_error_code_uds,
            {"Error Code", "btatt.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_uds_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_service_uuid16,
            {"Service UUID", "btatt.service_uuid16",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_uuid_vals_ext, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_service_uuid128,
            {"Service UUID", "btatt.service_uuid128",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_uuid16,
            {"Characteristic UUID", "btatt.characteristic_uuid16",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_uuid_vals_ext, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_uuid128,
            {"Characteristic UUID", "btatt.characteristic_uuid128",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_uuid16,
            {"UUID", "btatt.uuid16",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_uuid_vals_ext, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_uuid128,
            {"UUID", "btatt.uuid128",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_client_rx_mtu,
            {"Client Rx MTU", "btatt.client_rx_mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_server_rx_mtu,
            {"Server Rx MTU", "btatt.server_rx_mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_uuid_format,
            {"UUID Format", "btatt.uuid_format",
            FT_UINT8, BASE_HEX, VALS(uuid_format_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_length,
            {"Length", "btatt.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Length of Handle/Value Pair", HFILL}
        },
        {&hf_btatt_offset,
            {"Offset", "btatt.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_flags,
            {"Flags", "btatt.flags",
            FT_UINT8, BASE_HEX, VALS(flags_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_sign_counter,
            {"Sign Counter", "btatt.sign_counter",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_signature,
            {"Signature", "btatt.signature",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties,
            {"Characteristic Properties", "btatt.characteristic_properties",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_extended_properties,
            {"Extended Properties", "btatt.characteristic_properties.extended_properties",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_authenticated_signed_writes,
            {"Authenticated Signed Writes", "btatt.characteristic_properties.authenticated_signed_writes",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_indicate,
            {"Indicate", "btatt.characteristic_properties.indicate",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_notify,
            {"Notify", "btatt.characteristic_properties.notify",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_write,
            {"Write", "btatt.characteristic_properties.write",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_write_without_response,
            {"Write without Response", "btatt.characteristic_properties.write_without_response",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_read,
            {"Read", "btatt.characteristic_properties.read",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_properties_broadcast,
            {"Broadcast", "btatt.characteristic_properties.broadcast",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_value_handle,
            {"Characteristic Value Handle", "btatt.handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_included_service_handle,
            {"Included Service Handle", "btatt.handle",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_information_data,
            {"Information Data", "btatt.information_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_configuration_client,
            {"Characteristic Configuration Client", "btatt.characteristic_configuration_client",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_configuration_client_reserved,
            {"Reseved", "btatt.characteristic_configuration_client.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFFC,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_configuration_client_indication,
            {"Indication", "btatt.characteristic_configuration_client.indication",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_configuration_client_notification,
            {"Notification", "btatt.characteristic_configuration_client.notification",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_configuration_server,
            {"Characteristic Configuration Server", "btatt.characteristic_configuration_server",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_configuration_server_reserved,
            {"Reseved", "btatt.characteristic_configuration_server.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFFE,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_configuration_server_broadcast,
            {"Broadcast", "btatt.characteristic_configuration_server.broadcast",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_hogp_protocol_mode,
            {"Protocol Mode", "btatt.hogp.protocol_mode",
            FT_UINT8, BASE_HEX, VALS(hogp_protocol_mode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_report_reference_report_id,
            {"Report ID", "btatt.report_reference.report_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_report_reference_report_type,
            {"Report Type", "btatt.report_reference.report_id",
            FT_UINT8, BASE_HEX, VALS(report_reference_report_type_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_hogp_bcd_hid,
            {"bcdHID", "btatt.hogp.bcd_hid",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_hogp_b_country_code,
            {"bCountryCode", "btatt.hogp.b_country_code",
            FT_UINT8, BASE_HEX, VALS(hid_country_code_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_hogp_flags,
            {"Flags", "btatt.hogp.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_hogp_flags_reserved,
            {"Reserved", "btatt.hogp.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL}
        },
        {&hf_btatt_hogp_flags_normally_connectable,
            {"Normally Connectable", "btatt.hogp.flags.normally_connectable",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_hogp_flags_remote_wake,
            {"Remote Wake", "btatt.hogp.flags.remote_wake",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_user_description,
            {"Characteristic User Description", "btatt.characteristic_user_description",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_extended_properties,
            {"Characteristic Extended Properties", "btatt.characteristic_extended_properties",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_extended_properties_reserved,
            {"Reserved", "btatt.characteristic_extended_properties.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFFC,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_extended_properties_writable_auxiliaries,
            {"Writable Auxiliaries", "btatt.characteristic_extended_properties.writable_auxiliaries",
            FT_UINT16, BASE_HEX, NULL, 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_extended_properties_reliable_write,
            {"Reliable Write", "btatt.characteristic_extended_properties.reliable_write",
            FT_UINT16, BASE_HEX, NULL, 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_presentation_format,
            {"Format", "btatt.characteristic_presentation.format",
            FT_UINT8, BASE_HEX, VALS(characteristic_presentation_format_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_presentation_exponent,
            {"Exponent", "btatt.characteristic_presentation.exponent",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_presentation_unit,
            {"Unit", "btatt.characteristic_presentation.unit",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_uuid_vals_ext, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_presentation_namespace,
            {"Namespace", "btatt.characteristic_presentation.namespace",
            FT_UINT8, BASE_HEX, VALS(characteristic_presentation_namespace_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_presentation_namespace_description,
            {"Namespace Descrition", "btatt.characteristic_presentation.namespace_description",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_characteristic_presentation_namespace_description_btsig,
            {"Namespace Descrition", "btatt.characteristic_presentation.namespace_description",
            FT_UINT16, BASE_HEX, VALS(characteristic_presentation_namespace_description_btsig_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_esp_trigger_logic,
            {"Trigger Logic", "btatt.esp.trigger_logic",
            FT_UINT8, BASE_HEX, VALS(esp_trigger_logic_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_esp_condition,
            {"Trigger Logic", "btatt.esp.condition",
            FT_UINT8, BASE_HEX, VALS(esp_condition_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_esp_operand,
            {"Operand", "btatt.esp.operand",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_esp_flags,
            {"Flags", "btatt.esp.flags",
            FT_UINT16, BASE_HEX, NULL, 0xFFFF,
            NULL, HFILL}
        },
        {&hf_btatt_esp_sampling_function,
            {"Sampling Function", "btatt.esp.sampling_function",
            FT_UINT8, BASE_HEX, VALS(esp_sampling_function_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_esp_measurement_period,
            {"Measurement Period", "btatt.esp.measurement_period",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_esp_update_interval,
            {"Update Interval", "btatt.esp.update_interval",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_esp_application,
            {"Application", "btatt.esp.application",
            FT_UINT8, BASE_HEX, VALS(esp_application_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_esp_measurement_uncertainty,
            {"Measurement Uncertainty", "btatt.esp.measurement_uncertainty",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_device_name,
            {"Device Name", "btatt.device_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_appearance,
            {"Appearance", "btatt.appearance",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_appearance_category,
            {"Category", "btatt.appearance.category",
            FT_UINT16, BASE_DEC_HEX, VALS(appearance_category_vals), 0xFFC0,
            NULL, HFILL}
        },
        {&hf_btatt_appearance_subcategory,
            {"Subcategory", "btatt.appearance.subcategory",
            FT_UINT16, BASE_DEC_HEX, VALS(appearance_subcategory_generic_vals), 0x003F,
            NULL, HFILL}
        },
        {&hf_btatt_appearance_subcategory_watch,
            {"Subcategory", "btatt.appearance.subcategory.watch",
            FT_UINT16, BASE_DEC_HEX, VALS(appearance_subcategory_watch_vals), 0x003F,
            NULL, HFILL}
        },
        {&hf_btatt_appearance_subcategory_thermometer,
            {"Subcategory", "btatt.appearance.subcategory.thermometer",
            FT_UINT16, BASE_DEC_HEX, VALS(appearance_subcategory_thermometer_vals), 0x003F,
            NULL, HFILL}
        },
        {&hf_btatt_appearance_subcategory_heart_rate,
            {"Subcategory", "btatt.appearance.subcategory.heart_rate",
            FT_UINT16, BASE_DEC_HEX, VALS(appearance_subcategory_heart_rate_vals), 0x003F,
            NULL, HFILL}
        },
        {&hf_btatt_appearance_subcategory_blood_pressure,
            {"Subcategory", "btatt.appearance.subcategory.blood_pressure",
            FT_UINT16, BASE_DEC_HEX, VALS(appearance_subcategory_blood_pressure_vals), 0x003F,
            NULL, HFILL}
        },
        {&hf_btatt_appearance_subcategory_hid,
            {"Subcategory", "btatt.appearance.subcategory.hid",
            FT_UINT16, BASE_DEC_HEX, VALS(appearance_subcategory_hid_vals), 0x003F,
            NULL, HFILL}
        },
        {&hf_btatt_appearance_subcategory_running_walking_sensor,
            {"Subcategory", "btatt.appearance.subcategory.running_walking_sensor",
            FT_UINT16, BASE_DEC_HEX, VALS(appearance_subcategory_running_walking_sensor_vals), 0x003F,
            NULL, HFILL}
        },
        {&hf_btatt_appearance_subcategory_cycling,
            {"Subcategory", "btatt.appearance.subcategory.cycling",
            FT_UINT16, BASE_DEC_HEX, VALS(appearance_subcategory_cycling_vals), 0x003F,
            NULL, HFILL}
        },
        {&hf_btatt_appearance_subcategory_pulse_oximeter,
            {"Subcategory", "btatt.appearance.subcategory.pulse_oximeter",
            FT_UINT16, BASE_DEC_HEX, VALS(appearance_subcategory_pulse_oximeter_vals), 0x003F,
            NULL, HFILL}
        },
        {&hf_btatt_appearance_subcategory_outdoor_sports_activity,
            {"Subcategory", "btatt.appearance.subcategory.outdoor_sports_activity",
            FT_UINT16, BASE_DEC_HEX, VALS(appearance_subcategory_outdoor_sports_activity_vals), 0x003F,
            NULL, HFILL}
        },
        {&hf_btatt_peripheral_privacy_flag,
            {"Peripheral Privacy", "btatt.peripheral_privacy_flag",
            FT_BOOLEAN, 8, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_btatt_reconnection_address,
            { "Reconnection Address", "btatt.reconnection_address",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        {&hf_btatt_minimum_connection_interval,
            {"Minimum Connection Interval", "btatt.minimum_connection_interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_maximum_connection_interval,
            {"Maximum Connection Interval", "btatt.maximum_connection_interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_slave_latency,
            {"Slave Latency", "btatt.slave_latency",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_connection_supervision_timeout_multiplier,
            {"Connection Supervision Timeout Multiplier", "btatt.connection_supervision_timeout_multiplier",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_alert_level,
            {"Alert Level", "btatt.alert_level",
            FT_UINT8, BASE_HEX, VALS(alert_level_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_tx_power_level,
            {"Tx Power Level", "btatt.tx_power_level",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_year,
            {"Year", "btatt.year",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_month,
            {"Month", "btatt.month",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_day,
            {"Day", "btatt.day",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_hours,
            {"Hours", "btatt.hours",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_minutes,
            {"Minutes", "btatt.minutes",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_seconds,
            {"Seconds", "btatt.seconds",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_day_of_week,
            {"Day of Week", "btatt.day_of_week",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_fractions256,
            {"Fractions256", "btatt.fractions256",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "1/256th of a second", HFILL}
        },
        {&hf_btatt_dst_offset,
            {"Daylight Saving Time Offset", "btatt.dst_offset",
            FT_UINT8, BASE_HEX, VALS(dst_offset_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_model_number_string,
            {"Model Number String", "btatt.model_number_string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_serial_number_string,
            {"Serial Number String", "btatt.serial_number_string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_firmware_revision_string,
            {"Firmware Revision String", "btatt.firmware_revision_string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_hardware_revision_string,
            {"Hardware Revision String", "btatt.hardware_revision_string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_software_revision_string,
            {"Software Revision String", "btatt.software_revision_string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_manufacturer_string,
            {"Manufacturer String", "btatt.manufacturer_string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_system_id_manufacturer_identifier,
            {"Manufacturer Identifier", "btatt.system_id.manufacturer_identifier",
            FT_UINT40, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_system_id_organizationally_unique_identifier,
            {"Organizationally Unique Identifier", "btatt.system_id.organizationally_unique_identifier",
            FT_UINT24, BASE_HEX, VALS(oui_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_timezone,
            {"Timezone", "btatt.timezone",
            FT_INT8, BASE_DEC, VALS(timezone_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_time_accuracy,
            {"Time Accuracy", "btatt.time_accuracy",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_time_source,
            {"Time Source", "btatt.time_source",
            FT_UINT8, BASE_DEC, VALS(time_source_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_time_days_since_update,
            {"Days Since Update", "btatt.days_since_update",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_time_hours_since_update,
            {"Hours Since Update", "btatt.hours_since_update",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_time_update_control_point,
            {"Update Control Point", "btatt.update_control_point",
            FT_UINT8, BASE_HEX, VALS(time_update_control_point_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_time_current_state,
            {"Current State", "btatt.time_current_state",
            FT_UINT8, BASE_HEX, VALS(time_current_state_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_time_result,
            {"Result", "btatt.time_result",
            FT_UINT8, BASE_HEX, VALS(time_result_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_battery_level,
            {"Battery Level", "btatt.battery_level",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_temperature_type,
            {"Temperature Type", "btatt.temperature_type",
            FT_UINT8, BASE_HEX, VALS(temperature_type_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_measurement_interval,
            {"Measurement Interval", "btatt.measurement_interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_time_adjust_reason,
            {"Adjust Reason", "btatt.adjust_reason",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_time_adjust_reason_reserved,
            {"Reserved", "btatt.adjust_reason.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL}
        },
        {&hf_btatt_time_adjust_reason_change_of_dst,
            {"Change of DST", "btatt.adjust_reason.change_of_dst",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_time_adjust_reason_change_of_timezone,
            {"Change of Timezone", "btatt.adjust_reason.change_of_timezone",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_time_adjust_reason_external_reference_time_update,
            {"External Reference Time Update", "btatt.adjust_reason.external_reference_time_update",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_time_adjust_reason_manual_time_update,
            {"Manual Time Update", "btatt.adjust_reason.manual_time_update",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_magnetic_declination,
            {"Magnetic Declination", "btatt.magnetic_declination",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_scan_refresh,
            {"Scan Refresh", "btatt.scan_refresh",
            FT_UINT8, BASE_HEX, VALS(scan_refresh_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_sensor_location,
            {"Body Sensor Location", "btatt.body_sensor_location",
            FT_UINT8, BASE_HEX, VALS(body_sensor_location_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_heart_rate_control_point,
            {"Heart Rate Control Point", "btatt.heart_rate_control_point",
            FT_UINT8, BASE_HEX, VALS(heart_rate_control_point_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_alert_status,
            {"Alert Status", "btatt.alert.status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_alert_status_reserved,
            {"Reserved", "btatt.alert.status.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF8,
            NULL, HFILL}
        },
        {&hf_btatt_alert_status_display_alert_status,
            {"Display Alert Status", "btatt.alert.status.display_alert_status",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_alert_status_vibrate_state,
            {"Vibrate State", "btatt.alert.status.vibrate_state",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_alert_status_ringer_state,
            {"Ringer State", "btatt.alert_status.ringer_state",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_ringer_control_point,
            {"Ringer Control Point", "btatt.ringer_control_point",
            FT_UINT8, BASE_HEX, VALS(ringer_control_point_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ringer_setting,
            {"Ringer Setting", "btatt.ringer_setting",
            FT_UINT8, BASE_HEX, VALS(ringer_setting_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_alert_category_id_bitmask_1,
            {"Alert Category ID Bitmask 1", "btatt.alert.category_id_bitmask_1",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_alert_category_id_bitmask_1_schedule,
            {"Schedule", "btatt.alert.category_id_bitmask_1.schedule",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL}
        },
        {&hf_btatt_alert_category_id_bitmask_1_voice_mail,
            {"Voice Mail", "btatt.alert.category_id_bitmask_1.voice_mail",
            FT_UINT8, BASE_HEX, NULL, 0x40,
            NULL, HFILL}
        },
        {&hf_btatt_alert_category_id_bitmask_1_sms_mms,
            {"SMS/MMS", "btatt.alert.category_id_bitmask_1.sms_mms",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL}
        },
        {&hf_btatt_alert_category_id_bitmask_1_missed_call,
            {"Missed Call", "btatt.alert.category_id_bitmask_1.missed_call",
            FT_UINT8, BASE_HEX, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_alert_category_id_bitmask_1_call,
            {"Call", "btatt.alert.category_id_bitmask_1.call",
            FT_UINT8, BASE_HEX, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_alert_category_id_bitmask_1_news,
            {"News", "btatt.alert.category_id_bitmask_1.news",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_alert_category_id_bitmask_1_email,
            {"Email", "btatt.alert.category_id_bitmask_1.email",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_alert_category_id_bitmask_1_simple_alert,
            {"Simple Alert", "btatt.alert.category_id_bitmask_1.simple_alert",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_alert_category_id_bitmask_2,
            {"Alert Category ID Bitmask 2", "btatt.alert.category_id_bitmask_2",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_alert_category_id_bitmask_2_reserved,
            {"Reserved", "btatt.alert.category_id_bitmask_2.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL}
        },
        {&hf_btatt_alert_category_id_bitmask_2_instant_message,
            {"Instant Message", "btatt.alert.category_id_bitmask_2.instant_message",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_alert_category_id_bitmask_2_high_prioritized_alert,
            {"High Prioritized Alert", "btatt.alert.category_id_bitmask_2.high_prioritized_alert",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_alert_category_id,
            {"Alert Category ID", "btatt.alert.category_id",
            FT_UINT8, BASE_HEX, VALS(alert_category_id_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_alert_command_id,
            {"Alert Command ID", "btatt.alert.command_id",
            FT_UINT8, BASE_HEX, VALS(alert_command_id_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_alert_unread_count,
            {"Unread Count", "btatt.alert.unread_count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_alert_number_of_new_alert,
            {"Number of New Alert", "btatt.alert.number_of_new_alert",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_alert_text_string_information,
            {"Text String Information", "btatt.text_string_information",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_feature,
            {"Blood Pressure Feature", "btatt.blood_pressure.feature",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_feature_reserved,
            {"Reserved", "btatt.blood_pressure.feature.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFC0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_feature_multiple_bond,
            {"Multiple Bond", "btatt.blood_pressure.feature.multiple_bond",
            FT_BOOLEAN, 16, NULL, 0x20,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_feature_measurement_position_detection,
            {"Measurement Position Detection", "btatt.blood_pressure.feature.measurement_position_detection",
            FT_BOOLEAN, 16, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_feature_puls_rate_range,
            {"Puls Rate Range", "btatt.blood_pressure.feature.puls_rate_range",
            FT_BOOLEAN, 16, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_feature_irregular_pulse_detection,
            {"Irregular Pulse Detection", "btatt.blood_pressure.feature.irregular_pulse_detection",
            FT_BOOLEAN, 16, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_feature_cuff_fit_detection,
            {"Cuff Fit Detection", "btatt.blood_pressure.feature.cuff_fit_detection",
            FT_BOOLEAN, 16, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_feature_body_movement_detection,
            {"Body Movement Detection", "btatt.blood_pressure.feature.body_movement_detection",
            FT_BOOLEAN, 16, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_hogp_hid_control_point_command,
            {"HID Control Point Command", "btatt.hogp.hid_control_point_command",
            FT_UINT8, BASE_HEX, VALS(hid_control_point_command_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_le_scan_interval,
            {"LE Scan Interval", "btatt.le_scan_interval",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_le_scan_window,
            {"LE Scan Window", "btatt.le_scan_window",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_btatt_pnp_id_vendor_id_source,
            { "Vendor ID Source",                "btatt.pnp_id.vendor_id_source",
            FT_UINT16, BASE_HEX, VALS(pnp_id_vendor_id_source_vals), 0,
            NULL, HFILL }
        },
        { &hf_btatt_pnp_id_vendor_id,
            { "Vendor ID",                       "btatt.pnp_id.vendor_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_btatt_pnp_id_vendor_id_bluetooth_sig,
            { "Vendor ID",                       "btatt.pnp_id.vendor_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0,
            NULL, HFILL }
        },
        { &hf_btatt_pnp_id_vendor_id_usb_forum,
            { "Vendor ID",                       "btatt.pnp_id.vendor_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &ext_usb_vendors_vals, 0,
            NULL, HFILL }
        },
        { &hf_btatt_pnp_id_product_id,
            { "Product ID",                      "btatt.pnp_id.product_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_btatt_pnp_id_product_version,
            { "Version",                         "btatt.pnp_id.product_version",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        {&hf_btatt_glucose_feature,
            {"Glucose Feature", "btatt.glucose.feature",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_feature_reserved,
            {"Reserved", "btatt.glucose.feature.reserved",
            FT_BOOLEAN, 16, NULL, 0xF800,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_feature_multiple_bond,
            {"Multiple Bond", "btatt.glucose.feature.multiple_bond",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_feature_time_fault,
            {"Time Fault", "btatt.glucose.feature.time_fault",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_feature_general_device_fault,
            {"General Device Fault", "btatt.glucose.feature.general_device_fault",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_feature_sensor_read_interrupt_detection,
            {"Sensor Read Interrupt Detection", "btatt.glucose.feature.sensor_read_interrupt_detection",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_feature_sensor_temperature_high_low_detection,
            {"Sensor Temperature High-Low Detection", "btatt.glucose.feature.sensor_temperature_high_low_detection",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_feature_sensor_result_high_low_detection,
            {"Sensor Result High-Low Detection", "btatt.glucose.feature.sensor_result_high_low_detection",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_feature_sensor_strip_type_error_detection,
            {"Sensor Strip Type Error Detection", "btatt.glucose.feature.sensor_strip_type_error_detection",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_feature_sensor_strip_insertion_error_detection,
            {"Sensor Strip Insertion Error Detection", "btatt.glucose.feature.sensor_strip_insertion_error_detection",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_feature_sensor_sample_size,
            {"Sensor Sample Size", "btatt.glucose.feature.sensor_sample_size",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_feature_sensor_malfunction_detection,
            {"Sensor Malfunction Detection", "btatt.glucose.feature.sensor_malfunction_detection",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_feature_low_battery_detection_during_measurement,
            {"Low Battery Detection During Measurement", "btatt.glucose.feature.low_battery_detection_during_measurement",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_feature,
            {"RSC Feature", "btatt.rsc.feature",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_feature_reserved,
            {"Reserved", "btatt.rsc.feature.reserved",
            FT_BOOLEAN, 16, NULL, 0xFF80,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_feature_multiple_sensor_locations,
            {"Multiple Sensor Locations", "btatt.rsc.feature.multiple_sensor_locations",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_feature_calibration_procedure,
            {"Calibration Procedure", "btatt.rsc.feature.calibration_procedure",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_feature_walking_or_running_status,
            {"Walking_or Running Status", "btatt.rsc.feature.walking_or_running_status",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_feature_total_distance_measurement,
            {"Total Distance Measurement", "btatt.rsc.feature.total_distance_measurement",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_feature_instantaneous_stride_length_measurement,
            {"Instantaneous Stride Length Measurement", "btatt.rsc.feature.instantaneous_stride_length_measurement",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_csc_feature,
            {"CSC Feature", "btatt.csc.feature",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_csc_feature_reserved,
            {"Reserved", "btatt.csc.feature.reserved",
            FT_BOOLEAN, 16, NULL, 0xFFF8,
            NULL, HFILL}
        },
        {&hf_btatt_csc_feature_multiple_sensor_locations,
            {"Multiple Sensor Locations", "btatt.csc.feature.multiple_sensor_locations",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL}
        },
        {&hf_btatt_csc_feature_crank_revolution_data,
            {"Crank Revolution Data", "btatt.csc.feature.crank_revolution_data",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_csc_feature_wheel_revolution_data,
            {"Wheel Revolution Data", "btatt.csc.feature.wheel_revolution_data",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_sensor_location,
            {"Sensor Location", "btatt.sensor_location",
            FT_UINT8, BASE_HEX, VALS(sensor_location_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_elevation,
            {"Elevation", "btatt.elevation",
            FT_INT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_pressure,
            {"Pressure", "btatt.pressure",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_temperature,
            {"Temperature", "btatt.temperature",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_humidity,
            {"Humidity", "btatt.humidity",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_true_wind_speed,
            {"True Wind Speed", "btatt.true_wind_speed",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_true_wind_direction,
            {"True Wind Direction", "btatt.true_wind_direction",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_apparent_wind_speed,
            {"Apparent Wind Speed", "btatt.apparent_wind_speed",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_apparent_wind_direction,
            {"Apparent Wind Direction", "btatt.apparent_wind_direction",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_gust_factor,
            {"Gust Factor", "btatt.gust_factor",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_pollen_concentration,
            {"Pollen Concentration", "btatt.pollen_concentration",
            FT_INT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_uv_index,
            {"UV Index", "btatt.uv_index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_irradiance,
            {"Irradiance", "btatt.irradiance",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_rainfall,
            {"Rainfall", "btatt.rainfall",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_wind_chill,
            {"Wind Chill", "btatt.wind_chill",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_heart_index,
            {"Heart Index", "btatt.heart_index",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_dew_point,
            {"Dew Point", "btatt.dew_point",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_descriptor_value_changed_flags,
            {"Flags", "btatt.descriptor_value_changed.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_descriptor_value_changed_flags_reserved,
            {"Reserved", "btatt.descriptor_value_changed.flags.reserved",
            FT_BOOLEAN, 16, NULL, 0xF800,
            NULL, HFILL}
        },
        {&hf_btatt_descriptor_value_changed_flags_change_to_characteristic_user_description_descriptor,
            {"Change to Characteristic User Description Descriptor", "btatt.descriptor_value_changed.flags.change_to_characteristic_user_description_descriptor",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL}
        },
        {&hf_btatt_descriptor_value_changed_flags_change_to_es_measurement_descriptor,
            {"Change to ES Measurement Descriptor", "btatt.descriptor_value_changed.flags.change_to_es_measurement_descriptor",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL}
        },
        {&hf_btatt_descriptor_value_changed_flags_change_to_es_configuration_descriptor,
            {"Change to ES Configuration Descriptor", "btatt.descriptor_value_changed.flags.change_to_es_configuration_descriptor",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL}
        },
        {&hf_btatt_descriptor_value_changed_flags_change_to_one_or_more_es_trigger_setting_descriptors,
            {"Change to One or More ES Trigger Setting Descriptors", "btatt.descriptor_value_changed.flags.change_to_one_or_more_es_trigger_setting_descriptors",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_descriptor_value_changed_flags_source_of_change,
            {"Source of Change", "btatt.descriptor_value_changed.flags.source_of_change",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_aerobic_heart_rate_lower_limit,
            {"Aerobic Heart Rate Lower Limit", "btatt.aerobic_heart_rate_lower_limit",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_aerobic_threshold,
            {"Aerobic Threshold", "btatt.aerobic_threshold",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_age,
            {"Age", "btatt.age",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_anaerobic_heart_rate_lower_limit,
            {"Anaerobic Heart Rate Lower Limit", "btatt.anaerobic_heart_rate_lower_limit",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_anaerobic_heart_rate_upper_limit,
            {"Anaerobic Heart Rate Upper Limit", "btatt.anaerobic_heart_rate_upper_limit",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_anaerobic_threshold,
            {"Anaerobic Threshold", "btatt.anaerobic_threshold",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_aerobic_heart_rate_upper_limit,
            {"Aerobic Heart Rate Upper Limit", "btatt.aerobic_heart_rate_upper_limit",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_email_address,
            {"Email Address", "btatt.email_address",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_fat_burn_heart_rate_lower_limit,
            {"Fat Burn Heart Rate Lower Limit", "btatt.fat_burn_heart_rate_lower_limit",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_fat_burn_heart_rate_upper_limit,
            {"Fat Burn Heart Rate Upper Limit", "btatt.fat_burn_heart_rate_upper_limit",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_first_name,
            {"First Name", "btatt.first_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_five_zone_heart_rate_limits_very_light_light_limit,
            {"Very Light/Light Limit", "btatt.five_zone_heart_rate_limits.very_light_light_limit",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_five_zone_heart_rate_limits_light_moderate_limit,
            {"Light/Moderate Limit,", "btatt.five_zone_heart_rate_limits.light_moderate_limit",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_five_zone_heart_rate_limits_moderate_hard_limit,
            {"Moderate/Hard Limit", "btatt.five_zone_heart_rate_limits.moderate_hard_limit",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_five_zone_heart_rate_limits_hard_maximum_limit,
            {"Hard/Maximum Limit", "btatt.five_zone_heart_rate_limits.hard_maximum_limit",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_gender,
            {"Gender", "btatt.gender",
            FT_UINT8, BASE_HEX, VALS(gender_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_heart_rate_max,
            {"Heart Rate Max", "btatt.heart_rate_max",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_height,
            {"Height", "btatt.height",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_hip_circumference,
            {"Hip Circumference", "btatt.hip_circumference",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_last_name,
            {"Last Name", "btatt.last_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_maximum_recommended_heart_rate,
            {"Maximum Recommended Heart Rate", "btatt.maximum_recommended_heart_rate",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_resting_heart_rate,
            {"Resting Heart Rate", "btatt.resting_heart_rate",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_sport_type_for_aerobic_and_anaerobic_thresholds,
            {"Sport Type for Aerobic and Anaerobic Thresholds", "btatt.sport_type_for_aerobic_and_anaerobic_thresholds",
            FT_UINT8, BASE_DEC, VALS(sport_type_for_aerobic_and_anaerobic_thresholds_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_three_zone_heart_rate_limits_light_moderate,
            {"Three zone Heart Rate Limits - Light (Fat burn) / Moderate (Aerobic) Limit", "btatt.three_zone_heart_rate_limits.light_moderate",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_three_zone_heart_rate_limits_moderate_hard,
            {"Three zone Heart Rate Limits - Moderate (Aerobic) / Hard (Anaerobic) Limit", "btatt.three_zone_heart_rate_limits.moderate_hard",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_two_zone_heart_rate_limit_fat_burn_fitness,
            {"Two zone Heart Rate Limit - Fat burn / Fitness Limit", "btatt.two_zone_heart_rate_limit.fat_burn_fitness",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_vo2_max,
            {"VO2 Max", "btatt.vo2_max",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_waist_circumference,
            {"Waist Circumference", "btatt.waist_circumference",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_weight,
            {"Weight", "btatt.weight",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_database_change_increment,
            {"Database Change Increment", "btatt.database_change_increment",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_user_index,
            {"User Index", "btatt.user_index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_magnetic_flux_density_x,
            {"X", "btatt.hf_btatt_magnetic_flux_density.x",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_magnetic_flux_density_y,
            {"Y", "btatt.hf_btatt_magnetic_flux_density.y",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_magnetic_flux_density_z,
            {"Z", "btatt.hf_btatt_magnetic_flux_density.z",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_language,
            {"Language", "btatt.language",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_barometric_pressure_trend,
            {"Barometric Pressure Trend", "btatt.barometric_pressure_trend",
            FT_UINT8, BASE_DEC, VALS(barometric_pressure_trend_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_central_address_resolution,
            {"Central Address Resolution", "btatt.central_address_resolution",
            FT_UINT8, BASE_DEC, VALS(central_address_resolution_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature,
            {"Cycling Power Feature", "btatt.cycling_power_feature",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_reserved,
            {"Reserved", "btatt.cycling_power_feature.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFF80000,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_factory_calibration_date,
            {"Factory Calibration Date", "btatt.cycling_power_feature.factory_calibration_date",
            FT_BOOLEAN, 32, NULL, 0x00040000,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_instantaneous_measurement_direction,
            {"Instantaneous Measurement Direction", "btatt.cycling_power_feature.instantaneous_measurement_direction",
            FT_BOOLEAN, 32, NULL, 0x00020000,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_sensor_measurement_context,
            {"Sensor Measurement Context", "btatt.cycling_power_feature.sensor_measurement_context",
            FT_UINT32, BASE_HEX, VALS(cycling_power_feature_sensor_measurement_context_vals), 0x00010000,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_span_length_adjustment,
            {"Span Length Adjustment", "btatt.cycling_power_feature.span_length_adjustment",
            FT_BOOLEAN, 32, NULL, 0x00008000,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_chain_weight_adjustment,
            {"Chain Weight Adjustment", "btatt.cycling_power_feature.chain_weight_adjustment",
            FT_BOOLEAN, 32, NULL, 0x00004000,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_chain_length_adjustment,
            {"Chain Length Adjustment", "btatt.cycling_power_feature.chain_length_adjustment",
            FT_BOOLEAN, 32, NULL, 0x00002000,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_crank_length_adjustment,
            {"Crank Length Adjustment", "btatt.cycling_power_feature.crank_length_adjustment",
            FT_BOOLEAN, 32, NULL, 0x00001000,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_multiple_sensor_locations,
            {"Multiple Sensor Locations", "btatt.cycling_power_feature.multiple_sensor_locations",
            FT_BOOLEAN, 32, NULL, 0x00000800,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_cycling_power_measurement_characteristic_content_masking,
            {"Cycling Power Measurement Characteristic Content Masking", "btatt.cycling_power_feature.cycling_power_measurement_characteristic_content_masking",
            FT_BOOLEAN, 32, NULL, 0x00000400,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_offset_compensation,
            {"Offset Compensation", "btatt.cycling_power_feature.offset_compensation",
            FT_BOOLEAN, 32, NULL, 0x00000200,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_offset_compensation_indicator,
            {"Offset Compensation Indicator", "btatt.cycling_power_feature.offset_compensation_indicator",
            FT_BOOLEAN, 32, NULL, 0x00000100,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_accumulated_energy,
            {"Accumulated Energy", "btatt.cycling_power_feature.accumulated_energy",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_top_and_bottom_dead_spot_angles,
            {"Top and Bottom Dead Spot Angles", "btatt.cycling_power_feature.top_and_bottom_dead_spot_angles",
            FT_BOOLEAN, 32, NULL, 0x00000040,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_extreme_angles,
            {"Extreme Angles", "btatt.cycling_power_feature.extreme_angles",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_extreme_magnitudes,
            {"Extreme Magnitudes", "btatt.cycling_power_feature.extreme_magnitudes",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_crank_revolution_data,
            {"Crank Revolution Data", "btatt.cycling_power_feature.crank_revolution_data",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_wheel_revolution_data,
            {"Wheel Revolution Data", "btatt.cycling_power_feature.wheel_revolution_data",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_accumulated_torque,
            {"Accumulated Torque", "btatt.cycling_power_feature.accumulated_torque",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_feature_pedal_power_balance,
            {"Pedal Power Balance", "btatt.cycling_power_feature.pedal_power_balance",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature,
            {"LN Feature", "btatt.ln_feature",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_reserved,
            {"Reserved", "btatt.ln_feature.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFE00000,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_position_status,
            {"Position Status", "btatt.ln_feature.position_status",
            FT_BOOLEAN, 32, NULL, 0x00100000,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_elevation_setting,
            {"Elevation Setting,", "btatt.ln_feature.elevation_setting",
            FT_BOOLEAN, 32, NULL, 0x00080000,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_fix_rate_setting,
            {"Fix Rate Setting", "btatt.ln_feature.fix_rate_setting",
            FT_BOOLEAN, 32, NULL, 0x00040000,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_location_and_speed_characteristic_content_masking,
            {"Location and Speed Characteristic Content Masking", "btatt.ln_feature.location_and_speed_characteristic_content_masking",
            FT_BOOLEAN, 32, NULL, 0x00020000,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_vertical_dilution_of_precision,
            {"Vertical Dilution of Precision", "btatt.ln_feature.vertical_dilution_of_precision",
            FT_BOOLEAN, 32, NULL, 0x00010000,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_horizontal_dilution_of_precision,
            {"Horizontal Dilution of Precision", "btatt.ln_feature.horizontal_dilution_of_precision",
            FT_BOOLEAN, 32, NULL, 0x00008000,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_estimated_vertical_position_error,
            {"Estimated Vertical Position Error", "btatt.ln_feature.estimated_vertical_position_error",
            FT_BOOLEAN, 32, NULL, 0x00004000,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_estimated_horizontal_position_error,
            {"Estimated Horizontal Position Error", "btatt.ln_feature.estimated_horizontal_position_error",
            FT_BOOLEAN, 32, NULL, 0x00002000,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_time_to_first_fix,
            {"Time to First Fix", "btatt.ln_feature.time_to_first_fix",
            FT_BOOLEAN, 32, NULL, 0x00001000,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_number_of_beacons_in_view,
            {"Number of Beacons in View", "btatt.ln_feature.number_of_beacons_in_view",
            FT_BOOLEAN, 32, NULL, 0x00000800,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_number_of_beacons_in_solution,
            {"Number of Beacons in Solution", "btatt.ln_feature.number_of_beacons_in_solution",
            FT_BOOLEAN, 32, NULL, 0x00000400,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_estimated_time_of_arrival,
            {"Estimated Time of Arrival", "btatt.ln_feature.estimated_time_of_arrival",
            FT_BOOLEAN, 32, NULL, 0x00000200,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_remaining_vertical_distance,
            {"Remaining Vertical Distance", "btatt.ln_feature.remaining_vertical_distance",
            FT_BOOLEAN, 32, NULL, 0x00000100,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_remaining_distance,
            {"Remaining Distance", "btatt.ln_feature.remaining_distance",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_utc_time,
            {"UTC Time", "btatt.ln_feature.utc_time",
            FT_BOOLEAN, 32, NULL, 0x00000040,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_rolling_time,
            {"Rolling Time", "btatt.ln_feature.rolling_time",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_heading,
            {"Heading", "btatt.ln_feature.heading",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_elevation,
            {"Elevation", "btatt.ln_feature.elevation",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_location,
            {"Location", "btatt.ln_feature.location",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_total_distance,
            {"Total Distance", "btatt.ln_feature.total_distance",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL}
        },
        {&hf_btatt_ln_feature_instantaneous_speed,
            {"Instantaneous Speed", "btatt.ln_feature.instantaneous_speed",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature,
            {"Body Composition Feature", "btatt.body_composition_feature",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature_reserved,
            {"Reserved", "btatt.body_composition_feature.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFC0000,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature_height_measurement_resolution,
            {"Height Measurement Resolution", "btatt.body_composition_feature.height_measurement_resolution",
            FT_UINT32, BASE_HEX, VALS(body_composition_feature_height_measurement_resolution_vals), 0x00038000,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature_mass_measurement_resolution,
            {"Mass Measurement Resolution", "btatt.body_composition_feature.mass_measurement_resolution",
            FT_UINT32, BASE_HEX, VALS(body_composition_feature_mass_measurement_resolution_vals), 0x00007800,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature_height,
            {"Height", "btatt.body_composition_feature.height",
            FT_BOOLEAN, 32, NULL, 0x00000400,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature_weight,
            {"Weight", "btatt.body_composition_feature.weight",
            FT_BOOLEAN, 32, NULL, 0x00000200,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature_impedance,
            {"Impedance", "btatt.body_composition_feature.impedance",
            FT_BOOLEAN, 32, NULL, 0x00000100,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature_body_water_mass,
            {"Body Water Mass", "btatt.body_composition_feature.body_water_mass",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature_soft_lean_mass,
            {"Soft Lean Mass", "btatt.body_composition_feature.soft_lean_mass",
            FT_BOOLEAN, 32, NULL, 0x00000040,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature_fat_free_mass,
            {"Fat Free Mass", "btatt.body_composition_feature.fat_free_mass",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature_muscle_mass,
            {"Muscle Mass", "btatt.body_composition_feature.muscle_mass",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature_muscle_percentage,
            {"Muscle Percentage", "btatt.body_composition_feature.muscle_percentage",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature_basal_metabolism,
            {"Basal Metabolism", "btatt.body_composition_feature.basal_metabolism",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature_multiple_users,
            {"Multiple Users", "btatt.body_composition_feature.multiple_users",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_feature_timestamp,
            {"Timestamp", "btatt.body_composition_feature.timestamp",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL}
        },
        {&hf_btatt_weight_scale_feature,
            {"Body Composition Feature", "btatt.weight_scale_feature",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_weight_scale_feature_reserved,
            {"Reserved", "btatt.weight_scale_feature.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFFFC00,
            NULL, HFILL}
        },
        {&hf_btatt_weight_scale_feature_height_measurement_resolution,
            {"Height Measurement Resolution", "btatt.weight_scale_feature.height_measurement_resolution",
            FT_UINT32, BASE_HEX, VALS(weight_scale_feature_height_measurement_resolution_vals), 0x00000380,
            NULL, HFILL}
        },
        {&hf_btatt_weight_scale_feature_weight_measurement_resolution,
            {"Mass Measurement Resolution", "btatt.weight_scale_feature.weight_measurement_resolution",
            FT_UINT32, BASE_HEX, VALS(weight_scale_feature_weight_measurement_resolution_vals), 0x000000078,
            NULL, HFILL}
        },
        {&hf_btatt_weight_scale_feature_bmi,
            {"BMI", "btatt.weight_scale_feature.bmi",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL}
        },
        {&hf_btatt_weight_scale_feature_multiple_users,
            {"Multiple Users", "btatt.weight_scale_feature.multiple_users",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL}
        },
        {&hf_btatt_weight_scale_feature_timestamp,
            {"Timestamp", "btatt.weight_scale_feature.timestamp",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_flags,
            {"Flags", "btatt.glucose_measurement.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_flags_reserved,
            {"Reserved", "btatt.glucose_measurement.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xE0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_flags_context_information_follows,
            {"Context Information Follows", "btatt.glucose_measurement.flags.context_information_follows",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_flags_sensor_status_annunciation_present,
            {"Sensor Status Annunciation Present", "btatt.glucose_measurement.flags.sensor_status_annunciation_present",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_flags_glucose_concentration_units,
            {"Glucose Concentration Units", "btatt.glucose_measurement.flags.glucose_concentration_units",
            FT_UINT8, BASE_HEX, VALS(glucose_measurement_flags_glucose_concentration_units_vals), 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_flags_glucose_concentration_type_and_sample_location_present,
            {"Glucose Concentration, Type and Sample Location Present", "btatt.glucose_measurement.flags.glucose_concentration_type_and_sample_location_present",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_flags_time_offset_present,
            {"Time Offset Present", "btatt.glucose_measurement.flags.time_offset_present",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sequence_number,
            {"Body Composition Feature", "btatt.glucose_measurement.sequence_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_base_time,
            {"Base Time", "btatt.glucose_measurement.base_time",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_time_offset,
            {"Time Offset", "btatt.glucose_measurement.time_offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_glucose_concentration_kg_per_l,
            {"Glucose Concentration [kg/l]", "btatt.glucose_measurement.glucose_concentration.kg_per_l",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_glucose_concentration_mol_per_l,
            {"Glucose Concentration [mol/l]", "btatt.glucose_measurement.glucose_concentration.mol_per_l",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_type_and_sample_location,
            {"Glucose Concentration [mol/l]", "btatt.glucose_measurement.type_and_sample_location",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_type_and_sample_location_type,
            {"Type", "btatt.glucose_measurement.type_and_sample_location.type",
            FT_UINT8, BASE_HEX, VALS(glucose_measurement_type_and_sample_location_type_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_type_and_sample_location_sample_location,
            {"Sample Location", "btatt.glucose_measurement.type_and_sample_location.sample_location",
            FT_UINT8, BASE_HEX, VALS(glucose_measurement_type_and_sample_location_sample_location_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sensor_status_annunciation,
            {"Sensor Status Annunciation", "btatt.glucose_measurement.sensor_status_annunciation",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sensor_status_annunciation_reserved,
            {"Reserved", "btatt.glucose_measurement.sensor_status_annunciation.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xF000,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sensor_status_annunciation_time_fault,
            {"Time fault has occurred in the sensor and time may be inaccurate", "btatt.glucose_measurement.sensor_status_annunciation.time_fault",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sensor_status_annunciation_general_fault,
            {"General device fault has occurred in the sensor", "btatt.glucose_measurement.sensor_status_annunciation.general_fault",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sensor_status_annunciation_read_interrupted,
            {"Sensor read interrupted because strip was pulled too soon at time of measurement", "btatt.glucose_measurement.sensor_status_annunciation.read_interrupted",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sensor_status_annunciation_temperature_too_low,
            {"Sensor temperature too low for valid test/result at time of measurement", "btatt.glucose_measurement.sensor_status_annunciation.temperature_too_low",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sensor_status_annunciation_temperature_too_high,
            {"Sensor temperature too high for valid test/result at time of measurement", "btatt.glucose_measurement.sensor_status_annunciation.temperature_too_high",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sensor_status_annunciation_result_too_lower,
            {"Sensor result lower than the device can process", "btatt.glucose_measurement.sensor_status_annunciation.result_too_lower",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sensor_status_annunciation_result_too_high,
            {"Sensor result higher than the device can process", "btatt.glucose_measurement.sensor_status_annunciation.result_too_high",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sensor_status_annunciation_strip_type_incorrect,
            {"Strip type incorrect for device", "btatt.glucose_measurement.sensor_status_annunciation.strip_type_incorrect",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sensor_status_annunciation_strip_insertion_error,
            {"Strip insertion error", "btatt.glucose_measurement.sensor_status_annunciation.strip_insertion_error",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sensor_status_annunciation_size_insufficient,
            {"Sample size for blood or control solution insufficient at time of measurement", "btatt.glucose_measurement.sensor_status_annunciation.size_insufficient",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sensor_status_annunciation_fault,
            {"Sensor malfunction or faulting at time of measurement", "btatt.glucose_measurement.sensor_status_annunciation.fault",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_sensor_status_annunciation_battery_low,
            {"Device battery low at time of measurement", "btatt.glucose_measurement.sensor_status_annunciation.battery_low",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature,
            {"Sensor Status Annunciation", "btatt.bond_management_feature",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_feature_extension,
            {"Feature Extension", "btatt.bond_management_feature.feature_extension",
            FT_BOOLEAN, 24, NULL, 0x800000,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_reserved,
            {"Reserved", "btatt.bond_management_feature.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x780000,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_identify_yourself,
            {"Identify Yourself", "btatt.bond_management_feature.identify_yourself",
            FT_BOOLEAN, 24, NULL, 0x040000,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_9,
            {"Authorization Code Required for Feature Above", "btatt.bond_management_feature.authorization_code_required_for_feature_above.9",
            FT_BOOLEAN, 24, NULL, 0x020000,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_remove_all_but_the_active_bond_on_le_transport_only_server,
            {"Remove all but the active bond on server (LE transport only)", "btatt.bond_management_feature.remove_all_but_the_active_bond_on_le_transport_only_server",
            FT_BOOLEAN, 24, NULL, 0x010000,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_8,
            {"Authorization Code Required for Feature Above", "btatt.bond_management_feature.authorization_code_required_for_feature_above.8",
            FT_BOOLEAN, 24, NULL, 0x008000,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_remove_all_but_the_active_bond_on_br_edr_transport_only_server,
            {"Remove all but the active bond on server (BR/EDR transport only)", "btatt.bond_management_feature.remove_all_but_the_active_bond_on_br_edr_transport_only_server",
            FT_BOOLEAN, 24, NULL, 0x004000,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_7,
            {"Authorization Code Required for Feature Above", "btatt.bond_management_feature.authorization_code_required_for_feature_above.7",
            FT_BOOLEAN, 24, NULL, 0x002000,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_remove_all_but_the_active_bond_on_br_edr_and_le_server,
            {"Remove all but the active bond on server (BR/EDR and LE)", "btatt.bond_management_feature.remove_all_but_the_active_bond_on_br_edr_and_le_server",
            FT_BOOLEAN, 24, NULL, 0x001000,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_6,
            {"Authorization Code Required for Feature Above", "btatt.bond_management_feature.authorization_code_required_for_feature_above.6",
            FT_BOOLEAN, 24, NULL, 0x000800,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_remove_all_bonds_on_le_transport_only_server,
            {"Remove all bonds on server (LE transport only)", "btatt.bond_management_feature.remove_all_bonds_on_le_transport_only_server",
            FT_BOOLEAN, 24, NULL, 0x000400,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_5,
            {"Authorization Code Required for Feature Above", "btatt.bond_management_feature.authorization_code_required_for_feature_above.5",
            FT_BOOLEAN, 24, NULL, 0x000200,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_remove_all_bonds_on_br_edr_transport_only_server,
            {"Remove all bonds on server (BR/EDR transport only)", "btatt.bond_management_feature.remove_all_bonds_on_br_edr_transport_only_server",
            FT_BOOLEAN, 24, NULL, 0x000100,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_4,
            {"Authorization Code Required for Feature Above", "btatt.bond_management_feature.authorization_code_required_for_feature_above.4",
            FT_BOOLEAN, 24, NULL, 0x000080,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_remove_all_bonds_on_br_edr_and_le_server,
            {"Remove all bonds on server (BR/EDR and LE)", "btatt.bond_management_feature.remove_all_bonds_on_br_edr_and_le_server",
            FT_BOOLEAN, 24, NULL, 0x000040,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_3,
            {"Authorization Code Required for Feature Above", "btatt.bond_management_feature.authorization_code_required_for_feature_above.3",
            FT_BOOLEAN, 24, NULL, 0x000020,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_delete_bond_of_current_le_transport_only_connection,
            {"Delete bond of current connection (LE transport only)", "btatt.bond_management_feature.delete_bond_of_current_le_transport_only_connection",
            FT_BOOLEAN, 24, NULL, 0x000010,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_2,
            {"Authorization Code Required for Feature Above", "btatt.bond_management_feature.authorization_code_required_for_feature_above.2",
            FT_BOOLEAN, 24, NULL, 0x000008,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_delete_bond_of_current_br_edr_transport_only_connection,
            {"Delete bond of current connection (BR/EDR transport only)", "btatt.bond_management_feature.delete_bond_of_current_br_edr_transport_only_connection",
            FT_BOOLEAN, 24, NULL, 0x000004,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_authorization_code_required_for_feature_above_1,
            {"Authorization Code Required for Feature Above", "btatt.bond_management_feature.authorization_code_required_for_feature_above.1",
            FT_BOOLEAN, 24, NULL, 0x000002,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_delete_bond_of_current_br_edr_and_le_connection,
            {"Delete Bond of current connection (BR/EDR and LE)", "btatt.bond_management_feature.delete_bond_of_current_br_edr_and_le_connection",
            FT_BOOLEAN, 24, NULL, 0x000001,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_nth,
            {"Extended Features", "btatt.bond_management_feature.nth",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_nth_feature_extension,
            {"Feature Extension", "btatt.bond_management_feature.nth.feature_extension",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_feature_nth_reserved,
            {"Reserved", "btatt.bond_management_feature.nth.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x7F,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_control_point_opcode,
            {"Opcode", "btatt.bond_management_control_point.opcode",
            FT_UINT8, BASE_HEX, VALS(bond_management_control_point_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_bond_management_control_point_authorization_code,
            {"Authorization Code", "btatt.bond_management_control_point.authorization_code",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_temperature_measurement_flags,
            {"Sensor Status Annunciation", "btatt.temperature_measurement.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_temperature_measurement_flags_reserved,
            {"Reserved", "btatt.temperature_measurement.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF8,
            NULL, HFILL}
        },
        {&hf_btatt_temperature_measurement_flags_temperature_type,
            {"Temperature Type", "btatt.temperature_measurement.flags.temperature_type",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_temperature_measurement_flags_timestamp,
            {"Timestamp", "btatt.temperature_measurement.flags.timestamp",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_temperature_measurement_flags_temperature_unit,
            {"Temperature Unit", "btatt.temperature_measurement.flags.temperature_unit",
            FT_UINT8, BASE_HEX, VALS(temperature_measurement_flags_temperature_unit_vals), 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_temperature_measurement_value_celsius,
            {"Value [Celsius]", "btatt.temperature_measurement.value.celsius",
            FT_IEEE_11073_FLOAT, BASE_FLOAT, NULL, 0x00,
            NULL, HFILL}
        },
        {&hf_btatt_temperature_measurement_value_fahrenheit,
            {"Value [Fahrenheit]", "btatt.temperature_measurement.value.fahrenheit",
            FT_IEEE_11073_FLOAT, BASE_FLOAT, NULL, 0x00,
            NULL, HFILL}
        },
        {&hf_btatt_temperature_measurement_timestamp,
            {"Timestamp", "btatt.temperature_measurement.timestamp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_flags,
            {"Glucose Measurement Context", "btatt.glucose_measurement_context.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_flags_extended_flags,
            {"Extended Flags", "btatt.glucose_measurement_context.flags.extended_flags",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_flags_hba1c,
            {"HbA1c", "btatt.glucose_measurement_context.flags.hba1c",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_flags_medication_value_units,
            {"Medication Value Units", "btatt.glucose_measurement_context.flags.medication_value_units",
            FT_UINT8, BASE_HEX, VALS(glucose_measurement_context_flags_medication_value_units_vals), 0x20,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_flags_medication_id_and_medication,
            {"Medication ID And Medication", "btatt.glucose_measurement_context.flags.",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_flags_exercise_duration_and_exercise_intensity,
            {"Exercise Duration And Exercise Intensity", "btatt.glucose_measurement_context.flags.",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_flags_tester_health,
            {"Tester Health", "btatt.glucose_measurement_context.flags.",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_flags_meal,
            {"Meal", "btatt.glucose_measurement_context.flags.",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_flags_carbohydrate_id_and_carbohydrate,
            {"Carbohydrate ID And Carbohydrate", "btatt.glucose_measurement_context.flags.",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_sequence_number,
            {"Sequence Number", "btatt.glucose_measurement_context.sequence_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_extended_flags,
            {"Extended Flags", "btatt.glucose_measurement_context.extended_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_extended_flags_reserved,
            {"Reserved", "btatt.glucose_measurement_context.extended_flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFF,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_carbohydrate_id,
            {"Carbohydrate ID", "btatt.glucose_measurement_context.carbohydrate_id",
            FT_UINT8, BASE_HEX, VALS(glucose_measurement_context_carbohydrate_id_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_carbohydrate_kg,
            {"Carbohydrate [kg]", "btatt.glucose_measurement_context.carbohydrate.kg",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_meal,
            {"Meal", "btatt.glucose_measurement_context.meal",
            FT_UINT8, BASE_HEX, VALS(glucose_measurement_context_meal_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_tester_health,
            {"Tester and Health", "btatt.glucose_measurement_context.tester_and_health",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_tester,
            {"Tester", "btatt.glucose_measurement_context.tester_and_health.tester",
            FT_UINT8, BASE_HEX, VALS(glucose_measurement_context_tester_vals), 0xF0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_health,
            {"Health", "btatt.glucose_measurement_context.tester_and_health.health",
            FT_UINT8, BASE_HEX, VALS(glucose_measurement_context_health_vals), 0x0F,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_exercise_duration,
            {"Exercise Duration", "btatt.glucose_measurement_context.exercise_duration",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_exercise_intensity,
            {"Exercise Intensity", "btatt.glucose_measurement_context.exercise_intensity",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_medication_id,
            {"Medication ID", "btatt.glucose_measurement_context.medication_id",
            FT_UINT8, BASE_HEX, VALS(glucose_measurement_context_medication_id_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_medication_l,
            {"Medication [l]", "btatt.glucose_measurement_context.medication.l",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_medication_kg,
            {"Medication [kg]", "btatt.glucose_measurement_context.medication.kg",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_glucose_measurement_context_hba1c,
            {"HbA1c", "btatt.glucose_measurement_context.hba1c",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_flags,
            {"Flags", "btatt.blood_pressure_measurement.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_flags_reserved,
            {"Reserved", "btatt.blood_pressure_measurement.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xE0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_flags_measurement_status,
            {"Measurement Status", "btatt.blood_pressure_measurement.flags.measurement_status",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_flags_user_id,
            {"User ID", "btatt.blood_pressure_measurement.flags.user_id",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_flags_pulse_rate,
            {"Pulse Rate", "btatt.blood_pressure_measurement.flags.pulse_rate",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_flags_timestamp,
            {"Timestamp", "btatt.blood_pressure_measurement.flags.timestamp",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_flags_unit,
            {"Unit", "btatt.blood_pressure_measurement.flags.unit",
            FT_UINT8, BASE_HEX, VALS(blood_pressure_measurement_unit_vals), 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_compound_value_systolic_kpa,
            {"Systolic [kPa]", "btatt.blood_pressure_measurement.compound_value.systolic.kpa",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_compound_value_diastolic_kpa,
            {"Diastolic [kPa]", "btatt.blood_pressure_measurement.compound_value.diastolic.kpa",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_compound_value_mean_arterial_pressure_kpa,
            {"Arterial Pressure [kPa]", "btatt.blood_pressure_measurement.compound_value.arterial_pressure.kpa",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_compound_value_systolic_mmhg,
            {"Systolic [mmHg]", "btatt.blood_pressure_measurement.compound_value.systolic.mmhg",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_compound_value_diastolic_mmhg,
            {"Diastolic [mmHg]", "btatt.blood_pressure_measurement.compound_value.diastolic.mmhg",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_compound_value_mean_arterial_pressure_mmhg,
            {"Arterial Pressure [mmHg]", "btatt.blood_pressure_measurement.compound_value.arterial_pressure.mmhg",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_timestamp,
            {"Timestamp", "btatt.blood_pressure_measurement.compound_value.timestamp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_pulse_rate,
            {"Pulse Rate", "btatt.blood_pressure_measurement.pulse_rate",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_user_id,
            {"User ID", "btatt.blood_pressure_measurement.user_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_status,
            {"Flags", "btatt.blood_pressure_measurement.status",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_status_reserved,
            {"Reserved", "btatt.blood_pressure_measurement.status.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFC0,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_status_improper_measurement_position,
            {"Improper Measurement Position", "btatt.blood_pressure_measurement.status.improper_measurement_position",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_status_pulse_rate_range_detection,
            {"Pulse_Rate Range Detection", "btatt.blood_pressure_measurement.status.pulse_rate_range_detection",
            FT_UINT16, BASE_HEX, VALS(blood_pressure_measurement_status_pulse_rate_range_detection_vals), 0x0018,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_status_irregular_pulse,
            {"Irregular Pulse", "btatt.blood_pressure_measurement.status.irregular_pulse",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_status_cuff_fit_too_loose,
            {"Cuff Fit too Loose", "btatt.blood_pressure_measurement.status.cuff_fit_too_loose",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_blood_pressure_measurement_status_body_movement,
            {"Body Movement", "btatt.blood_pressure_measurement.status.body_movement",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_heart_rate_measurement_flags,
            {"Flags", "btatt.heart_rate_measurement.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_heart_rate_measurement_flags_reserved,
            {"Reserved", "btatt.heart_rate_measurement.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xE0,
            NULL, HFILL}
        },
        {&hf_btatt_heart_rate_measurement_flags_rr_interval,
            {"RR Interval", "btatt.heart_rate_measurement.flags.rr_interval",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_heart_rate_measurement_flags_energy_expended,
            {"Energy Expended", "btatt.heart_rate_measurement.flags.energy_expended",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_heart_rate_measurement_flags_sensor_contact_status_support,
            {"Sensor Support", "btatt.heart_rate_measurement.flags.sensor_contact_status.support",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_heart_rate_measurement_flags_sensor_contact_status_contact,
            {"Sensor Contact", "btatt.heart_rate_measurement.flags.sensor_contact_status.contact",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_heart_rate_measurement_flags_value_16,
            {"Value is UINT16", "btatt.heart_rate_measurement.flags.value_16",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_heart_rate_measurement_value_8,
            {"Value", "btatt.heart_rate_measurement.value.8",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_heart_rate_measurement_value_16,
            {"Value", "btatt.heart_rate_measurement.value.16",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_heart_rate_measurement_energy_expended,
            {"Energy Expended", "btatt.heart_rate_measurement.energy_expended",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_heart_rate_measurement_rr_intervals,
            {"RR Intervals", "btatt.heart_rate_measurement.rr_intervals",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_heart_rate_measurement_rr_interval,
            {"RR Interval", "btatt.heart_rate_measurement.rr_interval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_record_access_control_point_opcode,
            {"Opcode", "btatt.record_access_control_point.opcode",
            FT_UINT8, BASE_DEC, VALS(record_access_control_point_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_record_access_control_point_operator,
            {"Operator", "btatt.record_access_control_point.operator",
            FT_UINT8, BASE_DEC, VALS(record_access_control_point_operator_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_record_access_control_point_operand,
            {"Operand", "btatt.record_access_control_point.operand",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_record_access_control_point_operand_filter_type,
            {"Filter Type", "btatt.record_access_control_point.operand.filter_type",
            FT_UINT8, BASE_DEC, VALS(record_access_control_point_operand_filter_type_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_record_access_control_point_operand_min_time_offset,
            {"Min Time Offset", "btatt.record_access_control_point_operand.min_time_offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_record_access_control_point_operand_max_time_offset,
            {"Max Time Offset", "btatt.record_access_control_point_operand.max_time_offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_record_access_control_point_operand_number_of_records,
            {"Number of Records", "btatt.record_access_control_point_operand.number_of_records",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_record_access_control_point_request_opcode,
            {"Request Opcode", "btatt.record_access_control_point.request_opcode",
            FT_UINT8, BASE_DEC, VALS(record_access_control_point_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_record_access_control_point_response_code,
            {"Request Opcode", "btatt.record_access_control_point.response_code",
            FT_UINT8, BASE_DEC, VALS(record_access_control_point_response_code_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_value_trigger_setting_condition,
            {"Condition", "btatt.value_trigger_setting.condition",
            FT_UINT8, BASE_DEC, VALS(value_trigger_setting_condition_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_value_trigger_setting_analog,
            {"Analog", "btatt.value_trigger_setting.analog",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_value_trigger_setting_analog_one,
            {"Analog One", "btatt.value_trigger_setting.analog_one",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_value_trigger_setting_analog_two,
            {"Analog Two", "btatt.value_trigger_setting.analog_two",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_digital,
            {"Digital", "btatt.digital",
            FT_UINT8, BASE_DEC, VALS(digital_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_analog,
            {"Analog", "btatt.analog",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_location_name,
            {"Location Name", "btatt.location_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_uncertainty,
            {"Uncertainty", "btatt.uncertainty",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_uncertainty_reserved,
            {"Reserved", "btatt.uncertainty.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL}
        },
        {&hf_btatt_uncertainty_precision,
            {"Precision", "btatt.uncertainty.precision",
            FT_UINT8, BASE_HEX, VALS(btatt_ips_uncertainty_precision_vals), 0x70,
            NULL, HFILL}
        },
        {&hf_btatt_uncertainty_update_time,
            {"Update Time", "btatt.uncertainty.update_time",
            FT_UINT8, BASE_HEX, VALS(btatt_ips_uncertainty_update_time_vals), 0x0E,
            NULL, HFILL}
        },
        {&hf_btatt_uncertainty_stationary,
            {"Stationary", "btatt.uncertainty.stationary",
            FT_UINT8, BASE_HEX, VALS(btatt_ips_uncertainty_stationary_vals), 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_latitude,
            {"Latitude", "btatt.latitude",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_longitude,
            {"Longitude", "btatt.longitude",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_local_north_coordinate,
            {"Local North Coordinate", "btatt.local_north_coordinate",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_local_east_coordinate,
            {"Local East Coordinate", "btatt.local_east_coordinate",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_floor_number,
            {"Floor Number", "btatt.floor_number",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_altitude,
            {"Altitude", "btatt.altitude",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_indoor_positioning_configuration,
            {"Indoor Positioning Configuration", "btatt.indoor_positioning_configuration",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_indoor_positioning_configuration_reserved,
            {"Reserved", "btatt.indoor_positioning_configuration.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xC0,
            NULL, HFILL}
        },
        {&hf_btatt_indoor_positioning_configuration_location_name,
            {"Location Name", "btatt.indoor_positioning_configuration.location_name",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL}
        },
        {&hf_btatt_indoor_positioning_configuration_uncertainty,
            {"Uncertainty", "btatt.indoor_positioning_configuration.uncertainty",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL}
        },
        {&hf_btatt_indoor_positioning_configuration_floor_number,
            {"Floor Number", "btatt.indoor_positioning_configuration.floor_number",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_indoor_positioning_configuration_altitude,
            {"Altitude", "btatt.indoor_positioning_configuration.altitude",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_indoor_positioning_configuration_tx_power,
            {"Tx Power", "btatt.indoor_positioning_configuration.tx_power",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_indoor_positioning_configuration_coordinate_system,
            {"Coordinate System", "btatt.indoor_positioning_configuration.coordinate_system",
            FT_UINT8, BASE_HEX, VALS(btatt_ips_coordinate_system), 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_indoor_positioning_configuration_coordinates,
            {"Coordinates", "btatt.indoor_positioning_configuration.coordinates",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_number_of_digitals,
            {"Number of Digitals", "btatt.number_of_digitals",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_time_trigger_setting_condition,
            {"Condition", "btatt.time_trigger_setting.condition",
            FT_UINT8, BASE_HEX, VALS(time_trigger_setting_condition_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_time_trigger_setting_value,
            {"Value", "btatt.time_trigger_setting.value",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_time_trigger_setting_value_count,
            {"Count", "btatt.time_trigger_setting.count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_time_trigger_setting_value_time_interval,
            {"Time Interval", "btatt.time_trigger_setting.time_interval",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_measurement_flags,
            {"Flags", "btatt.rsc_measurement.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_measurement_flags_reserved,
            {"Reserved", "btatt.rsc_measurement.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF8,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_measurement_flags_type_of_movement,
            {"Type of Movement", "btatt.rsc_measurement.flags.type_of_movement",
            FT_UINT8, BASE_HEX, VALS(rsc_measurement_flags_type_of_movement_vals), 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_measurement_flags_total_distance_present,
            {"Total Distance Present", "btatt.rsc_measurement.flags.total_distance_present",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_measurement_flags_instantaneous_stride_length_present,
            {"Instantaneous Stride Length Present", "btatt.rsc_measurement.flags.instantaneous_stride_length_present",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_measurement_instantaneous_speed,
            {"Instantaneous Speed", "btatt.rsc_measurement.instantaneous_speed",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_measurement_instantaneous_cadence,
            {"Instantaneous Cadence", "btatt.rsc_measurement.instantaneous_cadence",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_measurement_instantaneous_stride_length,
            {"Instantaneous Stride Length", "btatt.rsc_measurement.instantaneous_stride_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_rsc_measurement_total_distance,
            {"Total Distance", "btatt.rsc_measurement.total_distance",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_sc_control_point_opcode,
            {"Opcode", "btatt.sc_control_point.opcode",
            FT_UINT8, BASE_HEX, VALS(sc_control_point_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_sc_control_point_request_opcode,
            {"Request Opcode", "btatt.sc_control_point.request_opcode",
            FT_UINT8, BASE_HEX, VALS(sc_control_point_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_sc_control_point_cumulative_value,
            {"Cumulative Value", "btatt.sc_control_point.cumulative_value",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_sc_control_point_response_value,
            {"Response Value", "btatt.sc_control_point.response_value",
            FT_UINT8, BASE_HEX, VALS(sc_control_point_response_value_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags,
            {"Flags", "btatt.cycling_power_measurement.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags_reserved,
            {"Reserved", "btatt.cycling_power_measurement.flags.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xE000,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags_offset_compensation_indicator,
            {"Offset Compensation Indicator", "btatt.cycling_power_measurement.flags.offset_compensation_indicator",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags_accumulated_energy,
            {"Accumulated Energy", "btatt.cycling_power_measurement.flags.accumulated_energy",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags_bottom_dead_spot_angle,
            {"Bottom Dead Spot Angle", "btatt.cycling_power_measurement.flags.bottom_dead_spot_angle",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags_top_dead_spot_angle,
            {"Top Dead Spot Angle", "btatt.cycling_power_measurement.flags.top_dead_spot_angle",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags_extreme_angles,
            {"Extreme_angles", "btatt.cycling_power_measurement.flags.extreme_angles",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags_extreme_torque_magnitudes,
            {"Extreme Torque Magnitudes", "btatt.cycling_power_measurement.flags.extreme_torque_magnitudes",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags_extreme_force_magnitudes,
            {"Extreme Force Magnitudes", "btatt.cycling_power_measurement.flags.extreme_force_magnitudes",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags_crank_revolution_data,
            {"Crank Revolution Data", "btatt.cycling_power_measurement.flags.crank_revolution_data",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags_wheel_revolution_data,
            {"Wheel Revolution Data", "btatt.cycling_power_measurement.flags.wheel_revolution_data",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags_accumulated_torque_source,
            {"accumulated_torque_source", "btatt.cycling_power_measurement.flags.accumulated_torque_source",
            FT_UINT16, BASE_HEX, VALS(cycling_power_measurement_flags_accumulated_torque_source_vals), 0x0008,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags_accumulated_torque,
            {"Accumulated Torque", "btatt.cycling_power_measurement.flags.accumulated_torque",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags_pedal_power_balance_reference,
            {"Pedal Power Balance Reference", "btatt.cycling_power_measurement.flags.pedal_power_balance_reference",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_flags_pedal_power_balance,
            {"Pedal Power Balance", "btatt.cycling_power_measurement.flags.pedal_power_balance",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_instantaneous_power,
            {"Instantaneous Power", "btatt.cycling_power_measurement.instantaneous_power",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_pedal_power_balance,
            {"Pedal Power Balance", "btatt.cycling_power_measurement.pedal_power_balance",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_accumulated_torque,
            {"Accumulated Torque", "btatt.cycling_power_measurement.accumulated_torque",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_wheel_revolution_data_cumulative_wheel_revolutions,
            {"Wheel Revolution Data Cumulative Wheel Revolutions", "btatt.cycling_power_measurement.wheel_revolution_data_cumulative_wheel_revolutions",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_wheel_revolution_data_last_wheel_event_time,
            {"Wheel Revolution Data Last Wheel Event Time", "btatt.cycling_power_measurement.wheel_revolution_data_last_wheel_event_time",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_crank_revolution_data_cumulative_crank_revolutions,
            {"Crank Revolution Data Cumulative Crank Revolutions", "btatt.cycling_power_measurement.crank_revolution_data_cumulative_crank_revolutions",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_crank_revolution_data_last_crank_event_time,
            {"Crank Revolution Data Last Crank Event Time", "btatt.cycling_power_measurement.crank_revolution_data_last_crank_event_time",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_extreme_force_magnitudes_maximum_force_magnitude,
            {"Extreme Force Magnitudes Maximum Force Magnitude", "btatt.cycling_power_measurement.extreme_force_magnitudes_maximum_force_magnitude",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_extreme_force_magnitudes_minimum_force_magnitude,
            {"Extreme Force Magnitudes Minimum Force Magnitude", "btatt.cycling_power_measurement.extreme_force_magnitudes_minimum_force_magnitude",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_extreme_torque_magnitudes_maximum_torque_magnitude,
            {"Extreme Torque Magnitudes Maximum Torque Magnitude", "btatt.cycling_power_measurement.extreme_torque_magnitudes_maximum_torque_magnitude",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_extreme_torque_magnitudes_minimum_torque_magnitude,
            {"Extreme Torque Magnitudes Minimum Torque Magnitude", "btatt.cycling_power_measurement.extreme_torque_magnitudes_minimum_torque_magnitude",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_extreme_angles,
            {"Extreme Angles", "btatt.cycling_power_measurement.extreme_angles",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_extreme_angles_maximum,
            {"Minimum", "btatt.cycling_power_measurement.extreme_angles.maximum",
            FT_UINT24, BASE_DEC, NULL, 0xFFF000,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_extreme_angles_minimum,
            {"Maximum", "btatt.cycling_power_measurement.extreme_angles.minimum",
            FT_UINT24, BASE_DEC, NULL, 0x000FFF,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_top_dead_spot_angle,
            {"Top Dead Spot Angle", "btatt.cycling_power_measurement.top_dead_spot_angle",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_bottom_dead_spot_angle,
            {"Bottom Dead Spot Angle", "btatt.cycling_power_measurement.bottom_dead_spot_angle",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_measurement_accumulated_energy,
            {"Accumulated Energy", "btatt.cycling_power_measurement.accumulated_energy",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_csc_measurement_flags,
            {"Flags", "btatt.csc_measurement.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_csc_measurement_flags_reserved,
            {"Reserved", "btatt.csc_measurement.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL}
        },
        {&hf_btatt_csc_measurement_flags_crank_revolution_data,
            {"Crank Revolution Data", "btatt.csc_measurement.flags.crank_revolution_data",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_csc_measurement_flags_wheel_revolution_data,
            {"Wheel Revolution Data", "btatt.csc_measurement.flags.wheel_revolution_data",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_csc_measurement_cumulative_wheel_revolutions,
            {"Cumulative Wheel Revolutions", "btatt.csc_measurement.cumulative_wheel_revolutions",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_csc_measurement_cumulative_crank_revolutions,
            {"Cumulative Crank Revolutions", "btatt.csc_measurement.cumulative_crank_revolutions",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_csc_measurement_last_event_time,
            {"Last Event Time", "btatt.csc_measurement.last_event_time",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_vector_flags,
            {"Flags", "btatt.csc_measurement.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_vector_flags_reserved,
            {"Reserved", "btatt.csc_measurement.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xC0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_vector_flags_instantaneous_measurement_direction,
            {"Instantaneous Measurement Direction", "btatt.cycling_power_vector.flags.instantaneous_measurement_direction",
            FT_UINT8, BASE_HEX, VALS(cycling_power_vector_flags_instantaneous_measurement_direction_vals), 0x30,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_vector_flags_instantaneous_torque_magnitude_array,
            {"Instantaneous Torque Magnitude Array", "btatt.cycling_power_vector.flags.instantaneous_torque_magnitude_array",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_vector_flags_instantaneous_force_magnitude_array,
            {"Instantaneous Force Magnitude Array", "btatt.cycling_power_vector.flags.instantaneous_force_magnitude_array",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_vector_flags_first_crank_measurement_angle,
            {"First Crank Measurement Angle", "btatt.cycling_power_vector.flags.first_crank_measurement_angle",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_vector_flags_crank_revolution_data,
            {"Crank Revolution Data", "btatt.cycling_power_vector.flags.crank_revolution_data",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },

        {&hf_btatt_cycling_power_vector_crank_revolution_data_cumulative_crank_revolutions,
            {"cumulative_crank_revolutions", "btatt.csc_measurement.cumulative_crank_revolutions",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_vector_crank_revolution_data_last_crank_event_time,
            {"Last Crank Event Time", "btatt.csc_measurement.last_crank_event_time",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_vector_first_crank_measurement_angle,
            {"First Crank Measurement Angle", "btatt.csc_measurement.first_crank_measurement_angle",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },

        {&hf_btatt_cycling_power_vector_instantaneous_force_magnitude_array,
            {"Instantaneous Force Magnitude Array", "btatt.csc_measurement.instantaneous_force_magnitude_array",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_vector_instantaneous_torque_magnitude_array,
            {"Instantaneous Torque Magnitude Array", "btatt.csc_measurement.instantaneous_torque_magnitude_array",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_opcode,
            {"Opcode", "btatt.cycling_power_control_point.opcode",
            FT_UINT8, BASE_HEX, VALS(cycling_power_control_point_opcode), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_cumulative_value,
            {"Cumulative Value", "btatt.cycling_power_control_point.cumulative_value",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_sensor_location,
            {"Sensor Location", "btatt.cycling_power_control_point.sensor_location",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_crank_length,
            {"Crank Length", "btatt.cycling_power_control_point.crank_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_chain_length,
            {"Chain Length", "btatt.cycling_power_control_point.chain_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_chain_weight,
            {"Chain Weight", "btatt.cycling_power_control_point.chain_weight",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_span_length,
            {"Span Length", "btatt.cycling_power_control_point.span_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_content_mask,
            {"Content Mask", "btatt.cycling_power_control_point.content_mask",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_content_mask_reserved,
            {"Reserved", "btatt.cycling_power_control_point.content_mask.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFE0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_content_mask_accumulated_energy,
            {"Accumulated Energy", "btatt.cycling_power_control_point.content_mask.accumulated_energy",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x100,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_content_mask_bottom_dead_spot_angle,
            {"Bottom Dead Spot Angle", "btatt.cycling_power_control_point.content_mask.bottom_dead_spot_angle",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x080,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_content_mask_top_dead_spot_angle,
            {"Top Dead Spot Angle", "btatt.cycling_power_control_point.content_mask.top_dead_spot_angle",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x040,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_content_mask_extreme_angles,
            {"Extreme Angles", "btatt.cycling_power_control_point.content_mask.extreme_angles",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x020,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_content_mask_extreme_magnitudes,
            {"Extreme Magnitudes", "btatt.cycling_power_control_point.content_mask.extreme_magnitudes",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x010,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_content_mask_crank_revolution_data,
            {"Crank Revolution Data", "btatt.cycling_power_control_point.content_mask.crank_revolution_data",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x008,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_content_mask_wheel_revolution_data,
            {"Wheel Revolution Data", "btatt.cycling_power_control_point.content_mask.wheel_revolution_data",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x004,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_content_mask_accumulated_torque,
            {"Accumulated Torque", "btatt.cycling_power_control_point.content_mask.accumulated_torque",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x002,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_content_mask_pedal_power_balance,
            {"Pedal Power Balance", "btatt.cycling_power_control_point.content_mask.pedal_power_balance",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x001,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_request_opcode,
            {"Request Opcode", "btatt.cycling_power_control_point.request_opcode",
            FT_UINT8, BASE_HEX, VALS(cycling_power_control_point_opcode), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_response_value,
            {"Response Value", "btatt.cycling_power_control_point.response_value",
            FT_UINT8, BASE_HEX, VALS(cycling_power_control_point_response_value), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_start_offset_compensation,
            {"Start Offset Compensation", "btatt.cycling_power_control_point.start_offset_compensation",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_sampling_rate,
            {"Sampling Rate", "btatt.cycling_power_control_point.sampling_rate",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cycling_power_control_point_factory_calibration_date,
            {"Factory Calibration Date", "btatt.cycling_power_control_point.factory_calibration_date",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_flags,
            {"Flags", "btatt.location_and_speed.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_flags_reserved,
            {"Reserved", "btatt.location_and_speed.flags.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xC000,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_flags_heading_source,
            {"Heading Source", "btatt.location_and_speed.flags.heading_source",
            FT_BOOLEAN, 16, TFS(&flags_heading_source_tfs), 0x3000,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_flags_elevation_source,
            {"Elevation Source", "btatt.location_and_speed.flags.elevation_source",
            FT_UINT16, BASE_HEX, VALS(location_and_speed_flags_elevation_source_vals), 0x0C00,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_flags_speed_and_distance_format,
            {"Speed_and Distance Format", "btatt.location_and_speed.flags.speed_and_distance_format",
            FT_BOOLEAN, 16, TFS(&location_and_speed_flags_speed_and_distance_format_tfs), 0x0200,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_flags_position_status,
            {"Position Status", "btatt.location_and_speed.flags.position_status",
            FT_UINT16, BASE_HEX, VALS(flags_position_status_vals), 0x0180,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_flags_utc_time,
            {"UTC Time Present", "btatt.location_and_speed.flags.utc_time",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_flags_rolling_time,
            {"Rolling Time", "btatt.location_and_speed.flags.rolling_time",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_flags_heading,
            {"Heading", "btatt.location_and_speed.flags.heading",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_flags_elevation,
            {"Elevation", "btatt.location_and_speed.flags.elevation",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_flags_location,
            {"Location", "btatt.location_and_speed.flags.location",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_flags_total_distance,
            {"Total Distance Present", "btatt.location_and_speed.flags.total_distance",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_flags_instantaneous_speed,
            {"Instantaneous Speed", "btatt.location_and_speed.flags.instantaneous_speed",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_instantaneous_speed,
            {"Instantaneous Speed", "btatt.location_and_speed.instantaneous_speed",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_total_distance,
            {"Total Distance", "btatt.location_and_speed.total_distance",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_location_longitude,
            {"Location Longitude", "btatt.location_and_speed.location.longitude",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_location_latitude,
            {"Location Latitude", "btatt.location_and_speed.location.latitude",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_elevation,
            {"Elevation", "btatt.location_and_speed.elevation",
            FT_INT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_heading,
            {"Heading", "btatt.location_and_speed.heading",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_rolling_time,
            {"Rolling Time", "btatt.location_and_speed.rolling_time",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_location_and_speed_utc_time,
            {"UTC Time", "btatt.location_and_speed.utc_time",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_flags,
            {"Flags", "btatt.navigation.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_flags_reserved,
            {"Reserved", "btatt.navigation.flags.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFE00,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_flags_destination_reached,
            {"Destination Reached", "btatt.navigation.flags.destination_reached",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_flags_waypoint_reached,
            {"Waypoint Reached", "btatt.navigation.flags.waypoint_reached",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_flags_navigation_indicator_type,
            {"Navigation Indicator Type", "btatt.navigation.flags.navigation_indicator_type",
            FT_BOOLEAN, 16, TFS(&navigation_indicator_type_tfs), 0x0040,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_flags_heading_source,
            {"Heading Source", "btatt.navigation.flags.heading_source",
            FT_BOOLEAN, 16, TFS(&flags_heading_source_tfs), 0x0020,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_flags_position_status,
            {"Position Status", "btatt.navigation.flags.position_status",
            FT_UINT16, BASE_HEX, VALS(flags_position_status_vals), 0x0018,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_flags_estimated_time_of_arrival,
            {"Estimated Time of Arrival", "btatt.navigation.flags.estimated_time_of_arrival",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_flags_remaining_vertical_distance,
            {"Remaining Vertical Distance", "btatt.navigation.flags.remaining_vertical_distance",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_flags_remaining_distance,
            {"Remaining Distance", "btatt.navigation.flags.remaining_distance",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_bearing,
            {"Bearing", "btatt.navigation.bearing",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_heading,
            {"Heading", "btatt.navigation.heading",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_remaining_distance,
            {"Remaining Distance", "btatt.navigation.remaining_distance",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_remaining_vertical_distance,
            {"Remaining Vertical Distance", "btatt.navigation.remaining_vertical_distance",
            FT_INT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_navigation_estimated_time_of_arrival,
            {"Estimated Time of Arrival", "btatt.navigation.estimated_time_of_arrival",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_flags,
            {"Flags", "btatt.position_quality.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_flags_reserved,
            {"Reserved", "btatt.position_quality.flags.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFE00,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_flags_position_status,
            {"Position Status", "btatt.position_quality.flags.position_status",
            FT_UINT16, BASE_HEX, VALS(flags_position_status_vals), 0x0180,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_flags_vdop,
            {"VDOP", "btatt.position_quality.flags.vdop",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_flags_hdop,
            {"HDOP", "btatt.position_quality.flags.hdop",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_flags_evpe,
            {"EVPE", "btatt.position_quality.flags.evpe",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_flags_ehpe,
            {"EHPE", "btatt.position_quality.flags.ehpe",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_flags_time_to_first_fix,
            {"Time to First Fix", "btatt.position_quality.flags.time_to_first_fix",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_flags_number_of_beacons_in_view,
            {"Number of Beacons in View", "btatt.position_quality.flags.number_of_beacons_in_view",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_flags_number_of_beacons_in_solution,
            {"Number of Beacons_in Solution", "btatt.position_quality.flags.number_of_beacons_in_solution",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_number_of_beacons_in_solution,
            {"number_of_beacons_in_solution", "btatt.position_quality.number_of_beacons_in_solution",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_number_of_beacons_in_view,
            {"number_of_beacons_in_view", "btatt.position_quality.number_of_beacons_in_view",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_time_to_first_fix,
            {"time_to_first_fix", "btatt.position_quality.time_to_first_fix",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_ehpe,
            {"EHPE", "btatt.position_quality.ehpe",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_evpe,
            {"EVPE", "btatt.position_quality.evpe",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_hdop,
            {"HDOP", "btatt.position_quality.hdop",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_position_quality_vdop,
            {"VDOP", "btatt.position_quality.vdop",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_opcode,
            {"Opcode", "btatt.ln_control_point.opcode",
            FT_UINT8, BASE_HEX, VALS(ln_control_point_opcode), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_cumulative_value,
            {"Cumulative Value", "btatt.ln_control_point.cumulative_value",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_content_mask,
            {"Content Mask", "btatt.ln_control_point.content_mask",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_content_mask_reserved,
            {"Reserved", "btatt.ln_control_point.content_mask.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFF80,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_content_mask_utc_time,
            {"UTC Time", "btatt.ln_control_point.content_mask.utc_time",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x0040,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_content_mask_rolling_time,
            {"Rolling Time", "btatt.ln_control_point.content_mask.rolling_time",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x0020,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_content_mask_heading,
            {"Heading", "btatt.ln_control_point.content_mask.heading",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x0010,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_content_mask_elevation,
            {"Elevation", "btatt.ln_control_point.content_mask.elevation",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x0008,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_content_mask_location,
            {"Location", "btatt.ln_control_point.content_mask.location",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x0004,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_content_mask_total_distance,
            {"Total Distance", "btatt.ln_control_point.content_mask.total_distance",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_content_mask_instantaneous_speed,
            {"Instantaneous Speed", "btatt.ln_control_point.content_mask.instantaneous_speed",
            FT_BOOLEAN, 16, TFS(&control_point_mask_value_tfs), 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_navigation_control,
            {"Navigation Control", "btatt.ln_control_point.navigation_control",
            FT_UINT8, BASE_HEX, VALS(ln_control_point_navigation_control_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_route_number,
            {"Route Number", "btatt.ln_control_point.route_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_fix_rate,
            {"Fix Rate", "btatt.ln_control_point.fix_rate",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_elevation,
            {"Elevation", "btatt.ln_control_point.elevation",
            FT_INT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_request_opcode,
            {"Request Opcode", "btatt.ln_control_point.request_opcode",
            FT_UINT8, BASE_HEX, VALS(ln_control_point_opcode), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_response_value,
            {"Response Value", "btatt.ln_control_point.response_value",
            FT_UINT8, BASE_HEX, VALS(ln_control_point_response_value), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_response_value_number_of_routes,
            {"Number of Routes", "btatt.ln_control_point.number_of_routes",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ln_control_point_response_value_name_of_route,
            {"Name_of Route", "btatt.ln_control_point.name_of_route",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags,
            {"Flags", "btatt.body_composition_measurement.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags_reserved,
            {"Reserved", "btatt.body_composition_measurement.flags.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xE000,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags_multiple_packet_measurement,
            {"Multiple Packet Measurement", "btatt.body_composition_measurement.flags.multiple_packet_measurement",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags_height,
            {"Height", "btatt.body_composition_measurement.flags.height",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags_weight,
            {"Weight", "btatt.body_composition_measurement.flags.weight",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags_impedance,
            {"Impedance", "btatt.body_composition_measurement.flags.impedance",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags_body_water_mass,
            {"Body Water Mass", "btatt.body_composition_measurement.flags.body_water_mass",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags_soft_lean_mass,
            {"Soft Lean Mass", "btatt.body_composition_measurement.flags.soft_lean_mass",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags_fat_free_mass,
            {"Fat Free Mass", "btatt.body_composition_measurement.flags.fat_free_mass",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags_muscle_mass,
            {"Muscle Mass", "btatt.body_composition_measurement.flags.muscle_mass",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags_muscle_percentage,
            {"Muscle Percentage", "btatt.body_composition_measurement.flags.muscle_percentage",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags_basal_metabolism,
            {"Basal Metabolism", "btatt.body_composition_measurement.flags.basal_metabolism",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags_user_id,
            {"User ID", "btatt.body_composition_measurement.flags.user_id",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags_timestamp,
            {"Timestamp", "btatt.body_composition_measurement.flags.timestamp",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_flags_measurement_units,
            {"Measurement Units", "btatt.body_composition_measurement.flags.measurement_units",
            FT_UINT16, BASE_HEX, VALS(body_composition_measurement_flags_measurement_units_vals), 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_body_fat_percentage,
            {"Body Fat Percentage", "btatt.body_composition_measurement.body_fat_percentage",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_timestamp,
            {"Timestamp", "btatt.body_composition_measurement.timestamp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_user_id,
            {"User ID", "btatt.body_composition_measurement.user_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_basal_metabolism,
            {"Basal Metabolism", "btatt.body_composition_measurement.basal_metabolism",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_muscle_percentage,
            {"Muscle Percentage", "btatt.body_composition_measurement.muscle_percentage",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_muscle_mass_lb,
            {"Muscle Mass [lb]", "btatt.body_composition_measurement.muscle_mass.lb",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_muscle_mass_kg,
            {"Muscle Mass [kg]", "btatt.body_composition_measurement.muscle_mass.kg",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_fat_free_mass_lb,
            {"Fat Free Mass [lb]", "btatt.body_composition_measurement.fat_free_mass.lb",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_fat_free_mass_kg,
            {"Fat Free Mass [kg]", "btatt.body_composition_measurement.fat_free_mass.kg",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_soft_lean_mass_lb,
            {"Soft Lean Mass [lb]", "btatt.body_composition_measurement.soft_lean_mass.lb",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_soft_lean_mass_kg,
            {"Soft Lean Mass [kg]", "btatt.body_composition_measurement.soft_lean_mass.kg",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_body_water_mass_lb,
            {"Body Water Mass [lb]", "btatt.body_composition_measurement.body_water_mass.lb",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_body_water_mass_kg,
            {"Body Water Mass [kg]", "btatt.body_composition_measurement.body_water_mass.kg",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_impedance,
            {"Impedance", "btatt.body_composition_measurement.impedance",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_weight_lb,
            {"Weight [lb]", "btatt.body_composition_measurement.weight.lb",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_weight_kg,
            {"Weight [kg]", "btatt.body_composition_measurement.weight.kg",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_height_inches,
            {"Height [inches]", "btatt.body_composition_measurement.height.inches",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_body_composition_measurement_height_meter,
            {"Height [meter]", "btatt.body_composition_measurement.height.meter",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_weight_measurement_flags,
            {"Flags", "btatt.weight_measurement.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_weight_measurement_flags_reserved,
            {"Reserved", "btatt.weight_measurement.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL}
        },
        {&hf_btatt_weight_measurement_flags_bmi_and_height,
            {"BMI and Height", "btatt.weight_measurement.flags.bmi_and_height",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_weight_measurement_flags_user_id,
            {"User ID", "btatt.weight_measurement.flags.user_id",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_weight_measurement_flags_timestamp,
            {"Timestamp", "btatt.weight_measurement.flags.timestamp",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_weight_measurement_flags_measurement_units,
            {"Measurement Units", "btatt.weight_measurement.flags.measurement_units",
            FT_BOOLEAN, 8, TFS(&weight_measurement_flags_measurement_units_tfs), 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_weight_measurement_weight_lb,
            {"Weight [lb]", "btatt.weight_measurement.weight.lb",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_weight_measurement_weight_kg,
            {"Weight [kg]", "btatt.weight_measurement.weight.kg",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_weight_measurement_timestamp,
            {"Timestamp", "btatt.weight_measurement.timestamp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_weight_measurement_user_id,
            {"User ID", "btatt.weight_measurement.user_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_weight_measurement_bmi,
            {"BMI", "btatt.weight_measurement.bmi",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_weight_measurement_height_in,
            {"Height [in]", "btatt.weight_measurement.height.in",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_weight_measurement_height_m,
            {"Height [m]", "btatt.weight_measurement.height.m",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_user_control_point_opcode,
            {"Opcode", "btatt.user_control_point.opcode",
            FT_UINT8, BASE_HEX, VALS(user_control_point_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_user_control_point_request_opcode,
            {"Request Opcode", "btatt.user_control_point.request_opcode",
            FT_UINT8, BASE_HEX, VALS(user_control_point_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_user_control_point_response_value,
            {"Response Value", "btatt.user_control_point.response_value",
            FT_UINT8, BASE_HEX, VALS(user_control_point_response_value_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_user_control_point_consent_code,
            {"Consent Code", "btatt.user_control_point.consent_code",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_measurement_size,
            {"Size", "btatt.cgm_measurement.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_measurement_flags,
            {"Flags", "btatt.cgm_measurement.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_measurement_flags_cgm_trend_information,
            {"CGM Trend Information", "btatt.cgm_measurement.flags.cgm_trend_information",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_measurement_flags_cgm_quality,
            {"CGM Quality", "btatt.cgm_measurement.flags.cgm_quality",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_measurement_flags_reserved,
            {"Reserved", "btatt.cgm_measurement.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x38,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_measurement_flags_sensor_status_annunciation_warning,
            {"Sensor Status Annunciation - Warning", "btatt.cgm_measurement.flags.sensor_status_annunciation.warning",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_measurement_flags_sensor_status_annunciation_cal_temp,
            {"Sensor Status Annunciation - Cal/Temp", "btatt.cgm_measurement.flags.sensor_status_annunciation.cal_temp",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_measurement_flags_sensor_status_annunciation_status,
            {"Sensor Status Annunciation - Status", "btatt.cgm_measurement.flags.sensor_status_annunciation.status",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_measurement_glucose_concentration,
            {"Glucose Concentration", "btatt.cgm_measurement.glucose_concentration",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_measurement_time_offset,
            {"Time Offset", "btatt.cgm_measurement.time_offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation,
            {"Sensor Status Annunciation", "btatt.cgm.sensor_status_annunciation",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_status,
            {"Status", "btatt.cgm.sensor_status_annunciation.status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_status_reserved,
            {"Reserved", "btatt.cgm.sensor_status_annunciation.status.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xC0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_status_general_device_fault_has_occurred_in_the_sensor,
            {"General Device Fault has Occurred in the Sensor", "btatt.cgm.sensor_status_annunciation.status.general_device_fault_has_occurred_in_the_sensor",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_status_device_specific_alert,
            {"Device Specific Alert", "btatt.cgm.sensor_status_annunciation.status.device_specific_alert",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_status_sensor_malfunction,
            {"Sensor Malfunction", "btatt.cgm.sensor_status_annunciation.status.sensor_malfunction",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_status_sensor_type_incorrect_for_device,
            {"Sensor Type Incorrect for Device", "btatt.cgm.sensor_status_annunciation.status.sensor_type_incorrect_for_device",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_status_device_battery_low,
            {"Device Battery Low", "btatt.cgm.sensor_status_annunciation.status.device_battery_low",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_status_session_stopped,
            {"Session Stopped", "btatt.cgm.sensor_status_annunciation.status.session_stopped",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_cal_temp,
            {"Cal/Temp", "btatt.cgm.sensor_status_annunciation.cal_temp",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_cal_temp_reserved,
            {"Reserved", "btatt.cgm.sensor_status_annunciation.cal_temp.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xC0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_cal_temp_sensor_temperature_too_low_for_valid_test_result_at_time_of_measurement,
            {"Sensor Temperature too Low for Valid Test Result at Time of Measurement", "btatt.cgm.sensor_status_annunciation.cal_temp.sensor_temperature_too_low_for_valid_test_result_at_time_of_measurement",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_cal_temp_sensor_temperature_too_high_for_valid_test_result_at_time_of_measurement,
            {"Sensor Temperature too High for Valid Test Result at Time of Measurement", "btatt.cgm_measurement.sensor_cal_temp_annunciation.cal_temp.sensor_temperature_too_high_for_valid_test_result_at_time_of_measurement",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_cal_temp_calibration_required,
            {"Calibration Required", "btatt.cgm_measurement.sensor_cal_temp_annunciation.cal_temp.calibration_required",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_cal_temp_calibration_recommended,
            {"Calibration Recommended", "btatt.cgm_measurement.sensor_cal_temp_annunciation.cal_temp.calibration_recommended",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_cal_temp_calibration_not_allowed,
            {"Calibration not Allowed", "btatt.cgm_measurement.sensor_cal_temp_annunciation.cal_temp.calibration_not_allowed",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_cal_temp_time_synchronization_between_sensor_and_collector_required,
            {"Time Synchronization between Sensor and Collector Required", "btatt.cgm_measurement.sensor_cal_temp_annunciation.cal_temp.time_synchronization_between_sensor_and_collector_required",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_warning,
            {"Warning", "btatt.cgm.sensor_status_annunciation.warning",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_higher_than_the_device_can_process,
            {"Sensor Result Higher than the Device Can Process", "btatt.cgm.sensor_status_annunciation.warning.sensor_result_higher_than_the_device_can_process",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_lower_than_the_device_can_process,
            {"Sensor Result Lower than the Device Can Process", "btatt.cgm_measurement.sensor_warning_annunciation.warning.sensor_result_lower_than_the_device_can_process",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_warning_sensor_rate_of_increase_exceeded,
            {"Sensor Rate of Increase Exceeded", "btatt.cgm_measurement.sensor_warning_annunciation.warning.sensor_rate_of_increase_exceeded",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_warning_sensor_rate_of_decrease_exceeded,
            {"Sensor Rate of Decrease Exceeded", "btatt.cgm_measurement.sensor_warning_annunciation.warning.sensor_rate_of_decrease_exceeded",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_higher_than_the_hyper_level,
            {"Sensor Result Higher than the Hyper Level", "btatt.cgm_measurement.sensor_warning_annunciation.warning.sensor_result_higher_than_the_hyper_level",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_lower_than_the_hypo_level,
            {"Sensor Result Lower than the Hypo Level", "btatt.cgm_measurement.sensor_warning_annunciation.warning.sensor_result_lower_than_the_hypo_level",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_higher_than_the_patient_high_level,
            {"Sensor Result Higher than the Patient High Level", "btatt.cgm_measurement.sensor_warning_annunciation.warning.sensor_result_higher_than_the_patient_high_level",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sensor_status_annunciation_warning_sensor_result_lower_than_the_patient_low_level,
            {"Sensor Result Lower than the Patient Low Level", "btatt.cgm_measurement.sensor_warning_annunciation.warning.sensor_result_lower_than_the_patient_low_level",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_measurement_trend_information,
            {"Trend Information", "btatt.cgm_measurement.trend_information",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_measurement_quality,
            {"Quality", "btatt.cgm_measurement.quality",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_e2e_crc,
            {"E2E-CRC", "btatt.cgm.e2e_crc.",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature,
            {"Feature", "btatt.cgm_feature.feature",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_reserved,
            {"Reserved", "btatt.cgm_feature.feature.reserved",
            FT_UINT24, BASE_HEX, NULL, 0xFE0000,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_quality,
            {"Quality", "btatt.cgm_feature.feature.quality",
            FT_BOOLEAN, 24, NULL, 0x010000,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_trend_information,
            {"Trend Information", "btatt.cgm_feature.feature.trend_information",
            FT_BOOLEAN, 24, NULL, 0x008000,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_multiple_sessions,
            {"Multiple Sessions", "btatt.cgm_feature.feature.multiple_sessions",
            FT_BOOLEAN, 24, NULL, 0x004000,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_multiple_bond,
            {"Multiple Bond", "btatt.cgm_feature.feature.multiple_bond",
            FT_BOOLEAN, 24, NULL, 0x002000,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_e2e_crc,
            {"E2E-CRC", "btatt.cgm_feature.feature.e2e_crc",
            FT_BOOLEAN, 24, NULL, 0x001000,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_general_device_fault,
            {"General Device Fault", "btatt.cgm_feature.feature.general_device_fault",
            FT_BOOLEAN, 24, NULL, 0x000800,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_sensor_type_error_detection,
            {"Sensor Type Error Detection", "btatt.cgm_feature.feature.sensor_type_error_detection",
            FT_BOOLEAN, 24, NULL, 0x000400,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_low_battery_detection,
            {"Low Battery Detection", "btatt.cgm_feature.feature.low_battery_detection",
            FT_BOOLEAN, 24, NULL, 0x000200,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_sensor_result_high_low_detection,
            {"Sensor Result High-Low Detection", "btatt.cgm_feature.feature.sensor_result_high_low_detection",
            FT_BOOLEAN, 24, NULL, 0x000100,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_sensor_temperature_high_low_detection,
            {"Sensor Temperature High-Low Detection", "btatt.cgm_feature.feature.sensor_temperature_high_low_detection",
            FT_BOOLEAN, 24, NULL, 0x000080,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_sensor_malfunction_detection,
            {"Sensor Malfunction Detection", "btatt.cgm_feature.feature.sensor_malfunction_detection",
            FT_BOOLEAN, 24, NULL, 0x000040,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_device_specific_alert,
            {"Device Specific Alert", "btatt.cgm_feature.feature.device_specific_alert",
            FT_BOOLEAN, 24, NULL, 0x000020,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_rate_of_increase_decrease_alerts,
            {"Rate of Increase Decrease Alerts", "btatt.cgm_feature.feature.rate_of_increase_decrease_alerts",
            FT_BOOLEAN, 24, NULL, 0x000010,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_hyper_alerts,
            {"Hyper Alerts", "btatt.cgm_feature.feature.hyper_alerts",
            FT_BOOLEAN, 24, NULL, 0x000008,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_hypo_alerts,
            {"Hypo Alerts", "btatt.cgm_feature.feature.hypo_alerts",
            FT_BOOLEAN, 24, NULL, 0x000004,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_patient_high_low_alerts,
            {"Patient High-Low Alerts", "btatt.cgm_feature.feature.patient_high_low_alerts",
            FT_BOOLEAN, 24, NULL, 0x000002,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_feature_feature_calibration,
            {"Calibration", "btatt.cgm_feature.feature.calibration",
            FT_BOOLEAN, 24, NULL, 0x000001,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_type_and_sample_location,
            {"Type and Sample Location", "btatt.cgm.type_and_sample_location",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_type,
            {"Type and Sample Location", "btatt.cgm.type_and_sample_location.type",
            FT_UINT8, BASE_HEX, VALS(cgm_feature_type_vals), 0xF0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_sample_location,
            {"Sample Location", "btatt.cgm.type_and_sample_location.sample_location",
            FT_UINT8, BASE_HEX, VALS(cgm_feature_sample_location_vals), 0x0F,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_time_offset,
            {"Time Offset", "btatt.cgm.time_offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_status,
            {"Status", "btatt.cgm.status",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_session_start_time,
            {"Session Start Time", "btatt.cgm.session_start_time",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_session_run_time,
            {"Session Run Time", "btatt.cgm.session_run_time",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_opcode,
            {"Opcode", "btatt.cgm_specific_ops_control_point.opcode",
            FT_UINT8, BASE_HEX, VALS(cgm_specific_ops_control_point_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_operand,
            {"Operand", "btatt.cgm_specific_ops_control_point.operand",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_operand_communication_interval,
            {"Communication Interval", "btatt.cgm_specific_ops_control_point.operand.communication_interval",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_calibration_glucose_concentration,
            {"Calibration Glucose Concentration", "btatt.cgm_specific_ops_control_point.operand.calibration_glucose_concentration",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_calibration_time,
            {"Calibration Time", "btatt.cgm_specific_ops_control_point.operand.calibration_time",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_next_calibration_time,
            {"Next Calibration Time", "btatt.cgm_specific_ops_control_point.operand.next_calibration_time",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_calibration_data_record_number,
            {"Calibration Data Record Number", "btatt.cgm_specific_ops_control_point.operand.calibration_data_record_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_calibration_status,
            {"Calibration Status", "btatt.cgm_specific_ops_control_point.operand.calibration_status",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_calibration_status_reserved,
            {"Reserved", "btatt.cgm_specific_ops_control_point.operand.calibration_status.reserved",
            FT_UINT8, BASE_DEC, NULL, 0xF8,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_calibration_status_pending,
            {"Pending", "btatt.cgm_specific_ops_control_point.operand.calibration_status.pending",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_calibration_status_out_of_range,
            {"Out of Range", "btatt.cgm_specific_ops_control_point.operand.calibration_status.out_of_range",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_calibration_status_rejected,
            {"Rejected", "btatt.cgm_specific_ops_control_point.operand.calibration_status.rejected",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_operand_calibration_data_record_number,
            {"Calibration Data Record Number", "btatt.cgm_specific_ops_control_point.operand.calibration_data_record_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_operand_alert_level,
            {"Alert Level [mg/dL]", "btatt.cgm_specific_ops_control_point.operand.alert_level",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_operand_alert_level_rate,
            {"Alert Level Rate [mg/dL/min]", "btatt.cgm_specific_ops_control_point.operand.alert_level_rate",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_request_opcode,
            {"Request Opcode", "btatt.cgm_specific_ops_control_point.request_opcode",
            FT_UINT8, BASE_HEX, VALS(cgm_specific_ops_control_point_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_cgm_specific_ops_control_point_response_code,
            {"Response Code", "btatt.cgm_specific_ops_control_point.response_code",
            FT_UINT8, BASE_HEX, VALS(cgm_specific_ops_control_point_response_code_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_uri,
            {"URI", "btatt.uri",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_http_headers,
            {"HTTP Headers", "btatt.http_headers",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_http_status_code,
            {"HTTP Status Code", "btatt.http_status_code",
            FT_UINT16, BASE_DEC, VALS(vals_http_status_code), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_http_data_status,
            {"HTTP Data Status", "btatt.http_data_status",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_http_data_status_headers_received,
            {"Headers Received", "btatt.http_data_status.headers_received",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_http_data_status_headers_truncated,
            {"Headers Truncated", "btatt.http_data_status.headers_truncated",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_http_data_status_body_received,
            {"Body Received", "btatt.http_data_status.body_received",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_http_data_status_body_truncated,
            {"Body Truncated", "btatt.http_data_status.body_truncated",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_http_data_status_reserved,
            {"Reserved", "btatt.http_data_status.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL}
        },
        {&hf_btatt_http_entity_body,
            {"HTTP Entity Body", "btatt.http_entity_body",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_http_control_point_opcode,
            {"Opcode", "btatt.control_point.opcode",
            FT_UINT8, BASE_HEX, VALS(http_control_point_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_https_security,
            {"HTTPS Security", "btatt.https_security",
            FT_UINT8, BASE_HEX, VALS(https_security_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_tds_opcode,
            {"Opcode", "btatt.tds.opcode",
            FT_UINT8, BASE_HEX, VALS(tds_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_tds_organization_id,
            {"Organization ID", "btatt.tds.organization_id",
            FT_UINT8, BASE_HEX, VALS(tds_organization_id_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_tds_result_code,
            {"Result Code", "btatt.tds.result_code",
            FT_UINT8, BASE_HEX, VALS(tds_result_code_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_tds_data,
            {"Data", "btatt.tds.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_oacp,
            {"OACP Features", "btatt.ots.oacp",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_oacp_reserved,
            {"Reserved", "btatt.ots.oacp.reserved",
            FT_BOOLEAN, 32, NULL, 0xFFFFFC00,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_oacp_abort,
            {"Abort", "btatt.ots.oacp.abort",
            FT_BOOLEAN, 32, NULL, 0x00000200,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_oacp_patching_of_object,
            {"Patching of Object", "btatt.ots.oacp.patching_of_object",
            FT_BOOLEAN, 32, NULL, 0x00000100,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_oacp_truncation_of_objects,
            {"Truncation of Objects", "btatt.ots.oacp.truncation_of_objects",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_oacp_appending_additional_data_to_object,
            {"Appending Additional Data to Object", "btatt.ots.oacp.appending_additional_data_to_object",
            FT_BOOLEAN, 32, NULL, 0x00000040,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_oacp_write,
            {"Write", "btatt.ots.oacp.write",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_oacp_read,
            {"Read", "btatt.ots.oacp.read",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_oacp_execute,
            {"Execute", "btatt.ots.oacp.execute",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_oacp_calculate_checksum,
            {"Calculate Checksum", "btatt.ots.oacp.calculate_checksum",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_oacp_delete,
            {"Delete", "btatt.ots.oacp.delete",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_oacp_create,
            {"Create", "btatt.ots.oacp.create",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_olcp,
            {"OLCP Features", "btatt.ots.olcp",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_olcp_reserved,
            {"Reserved", "btatt.ots.olcp.reserved",
            FT_BOOLEAN, 32, NULL, 0xFFFFFFF0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_olcp_clear_marking,
            {"Clear Marking", "btatt.ots.olcp.clear_marking",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_olcp_request_number_of_objects,
            {"Request Number of Objects", "btatt.ots.olcp.request_number_of_objects",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_olcp_order,
            {"Order", "btatt.ots.olcp.order",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL}
        },
        {&hf_btatt_ots_feature_olcp_go_to,
            {"Go To", "btatt.ots.olcp.go_to",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL}
        },
        {&hf_btatt_ots_object_name,
            {"Object Name", "btatt.ots.object_name",
            FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_current_size,
            {"Current Size", "btatt.ots.current_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_allocated_size,
            {"Allocated Size", "btatt.ots.allocated_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_object_id,
            {"Object ID", "btatt.ots.object_id",
            FT_UINT48, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_properties,
            {"Properties", "btatt.ots.properties",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_properties_reserved,
            {"Reserved", "btatt.ots.properties.reserved",
            FT_BOOLEAN, 32, NULL, 0xFFFFFF00,
            NULL, HFILL}
        },
        {&hf_btatt_ots_properties_mark,
            {"Mark", "btatt.ots.properties.mark",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL}
        },
        {&hf_btatt_ots_properties_patch,
            {"Patch", "btatt.ots.properties.patch",
            FT_BOOLEAN, 32, NULL, 0x00000040,
            NULL, HFILL}
        },
        {&hf_btatt_ots_properties_truncate,
            {"Truncate", "btatt.ots.properties.truncate",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL}
        },
        {&hf_btatt_ots_properties_append,
            {"Append", "btatt.ots.properties.append",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL}
        },
        {&hf_btatt_ots_properties_write,
            {"Write", "btatt.ots.properties.write",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL}
        },
        {&hf_btatt_ots_properties_read,
            {"Read", "btatt.ots.properties.read",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL}
        },
        {&hf_btatt_ots_properties_execute,
            {"Execute", "btatt.ots.properties.execute",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL}
        },
        {&hf_btatt_ots_properties_delete,
            {"Delete", "btatt.ots.properties.delete",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL}
        },
        {&hf_btatt_ots_flags,
            {"Properties", "btatt.ots.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_flags_reserved,
            {"Reserved", "btatt.ots.flags.reserved",
            FT_BOOLEAN, 8, NULL, 0xE0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_flags_object_deletion,
            {"Object Deletion", "btatt.ots.flags.object_deletion",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_ots_flags_object_creation,
            {"Object Creation", "btatt.ots.flags.object_creation",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_ots_flags_change_occured_to_the_object_metadata,
            {"Change Occured to the Object Metadata", "btatt.ots.flags.change_occured_to_the_object_metadata",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_ots_flags_change_occured_to_the_object_contents,
            {"Change Occured to the Object Contents", "btatt.ots.flags.change_occured_to_the_object_contents",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_ots_flags_source_of_change,
            {"Source of Change", "btatt.ots.flags.source_of_change",
            FT_BOOLEAN, 8, TFS(&tfs_client_server), 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_ots_action_opcode,
            {"Opcode", "btatt.ots.action.opcode",
            FT_UINT8, BASE_HEX, VALS(ots_action_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_size,
            {"Size", "btatt.ots.size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_offset,
            {"Offset", "btatt.ots.offset",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_length,
            {"Length", "btatt.ots.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_execute_data,
            {"Execute Data", "btatt.ots.execute_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_action_response_opcode,
            {"Response Opcode", "btatt.ots.action.response_opcode",
            FT_UINT8, BASE_HEX, VALS(ots_action_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_action_result_code,
            {"Result Code", "btatt.ots.action.result_code",
            FT_UINT8, BASE_HEX, VALS(ots_action_result_code_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_checksum,
            {"Checksum", "btatt.ots.checksum",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_list_opcode,
            {"Opcode", "btatt.ots.list.opcode",
            FT_UINT8, BASE_HEX, VALS(ots_list_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_list_order,
            {"Order", "btatt.ots.list.order",
            FT_UINT8, BASE_HEX, VALS(ots_list_order_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_list_response_opcode,
            {"Response Opcode", "btatt.ots.list.response_opcode",
            FT_UINT8, BASE_HEX, VALS(ots_list_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_list_result_code,
            {"Result Code", "btatt.ots.list.result_code",
            FT_UINT8, BASE_HEX, VALS(ots_list_result_code_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_list_total_number_of_objects,
            {"Total Number of Objects", "btatt.ots.list.total_number_of_objects",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_filter,
            {"Filter", "btatt.ots.filter",
            FT_UINT8, BASE_HEX, VALS(ots_filter_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_size_from,
            {"Size From", "btatt.ots.size_from",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_size_to,
            {"Size To", "btatt.ots.size_to",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_name_string,
            {"Name String", "btatt.ots.name_string",
            FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_object_first_created,
            {"First Created", "btatt.ots.first_created",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_ots_object_last_modified,
            {"Last Modified", "btatt.ots.last_modified",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_spot_check_measurement_flags,
            {"Flags", "btatt.plxs.spot_check_measurement.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_spot_check_measurement_flags_reserved,
            {"Reserved", "btatt.plxs.spot_check_measurement.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xE0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_spot_check_measurement_flags_device_clock_is_not_set,
            {"Device Clock is not Set", "btatt.plxs.spot_check_measurement.flags.device_clock_is_not_set",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_plx_spot_check_measurement_flags_pulse_amplitude_index,
            {"Pulse Amplitude Index", "btatt.plxs.spot_check_measurement.flags.pulse_amplitude_index",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_plx_spot_check_measurement_flags_device_and_sensor_status,
            {"Device and Sensor Status", "btatt.plxs.spot_check_measurement.flags.device_and_sensor_status",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_plx_spot_check_measurement_flags_measurement_status,
            {"Measurement Status", "btatt.plxs.spot_check_measurement.flags.measurement_status",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_plx_spot_check_measurement_flags_timestamp,
            {"Timestamp", "btatt.plxs.spot_check_measurement.flags.timestamp",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btatt_plx_spo2,
            {"SpO2", "btatt.plxs.spot_check_measurement.spo2",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_pulse_rate,
            {"Pulse Rate", "btatt.plxs.spot_check_measurement.pulse_rate",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_spot_check_measurement_timestamp,
            {"Timestamp", "btatt.plxs.spot_check_measurement.timestamp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_measurement_status,
            {"Timestamp", "btatt.plxs.spot_check_measurement.measurement_status",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_measurement_status_invalid_measurement_detected,
            {"Invalid Measurement Detected", "btatt.plxs.spot_check_measurement.measurement_status.invalid_measurement_detected",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL}
        },
        {&hf_btatt_plx_measurement_status_questionable_measurement_detected,
            {"Questionable Measurement Detected", "btatt.plxs.spot_check_measurement.measurement_status.questionable_measurement_detected",
            FT_BOOLEAN, 16, NULL, 0x4000,
            NULL, HFILL}
        },
        {&hf_btatt_plx_measurement_status_measurement_unavailable,
            {"Measurement Unavailable", "btatt.plxs.spot_check_measurement.measurement_status.measurement_unavailable",
            FT_BOOLEAN, 16, NULL, 0x2000,
            NULL, HFILL}
        },
        {&hf_btatt_plx_measurement_status_calibration_ongoing,
            {"Calibration Ongoing", "btatt.plxs.spot_check_measurement.measurement_status.calibration_ongoing",
            FT_BOOLEAN, 16, NULL, 0x1000,
            NULL, HFILL}
        },
        {&hf_btatt_plx_measurement_status_data_for_testing,
            {"Data for Testing", "btatt.plxs.spot_check_measurement.measurement_status.data_for_testing",
            FT_BOOLEAN, 16, NULL, 0x0800,
            NULL, HFILL}
        },
        {&hf_btatt_plx_measurement_status_data_for_demonstration,
            {"Data for Demonstration", "btatt.plxs.spot_check_measurement.measurement_status.data_for_demonstration",
            FT_BOOLEAN, 16, NULL, 0x0400,
            NULL, HFILL}
        },
        {&hf_btatt_plx_measurement_status_data_from_measurement_storage,
            {"Data from Measurement Storage", "btatt.plxs.spot_check_measurement.measurement_status.data_from_measurement_storage",
            FT_BOOLEAN, 16, NULL, 0x0200,
            NULL, HFILL}
        },
        {&hf_btatt_plx_measurement_status_fully_qualified_data,
            {"Fully Qualified Data", "btatt.plxs.spot_check_measurement.measurement_status.fully_qualified_data",
            FT_BOOLEAN, 16, NULL, 0x0100,
            NULL, HFILL}
        },
        {&hf_btatt_plx_measurement_status_validated_data,
            {"Validated Data", "btatt.plxs.spot_check_measurement.measurement_status.validated_data",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL}
        },
        {&hf_btatt_plx_measurement_status_early_estimated_data,
            {"Early Estimated Data", "btatt.plxs.spot_check_measurement.measurement_status.early_estimated_data",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL}
        },
        {&hf_btatt_plx_measurement_status_measurement_ongoing,
            {"Measurement Ongoing", "btatt.plxs.spot_check_measurement.measurement_status.measurement_ongoing",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL}
        },
        {&hf_btatt_plx_measurement_status_reserved,
            {"Reserved", "btatt.plxs.spot_check_measurement.measurement_status.reserved",
            FT_BOOLEAN, 16, NULL, 0x001F,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status,
            {"Device and Sensor Status", "btatt.plxs.spot_check_measurement.device_and_sensor_status",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_reserved,
            {"Reserved", "btatt.plxs.spot_check_measurement.device_and_sensor_status.reserved",
            FT_UINT24, BASE_HEX, NULL, 0xFF0000,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_sensor_disconnected,
            {"Sensor Disconnected", "btatt.plxs.spot_check_measurement.device_and_sensor_status.sensor_disconnected",
            FT_BOOLEAN, 24, NULL, 0x008000,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_sensor_malfunctioning,
            {"Sensor Malfunctioning", "btatt.plxs.spot_check_measurement.device_and_sensor_status.sensor_malfunctioning",
            FT_BOOLEAN, 24, NULL, 0x004000,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_sensor_displaced,
            {"Sensor Displaced", "btatt.plxs.spot_check_measurement.device_and_sensor_status.sensor_displaced",
            FT_BOOLEAN, 24, NULL, 0x002000,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_unknown_sensor_connected,
            {"Unknown Sensor Connected", "btatt.plxs.spot_check_measurement.device_and_sensor_status.unknown_sensor_connected",
            FT_BOOLEAN, 24, NULL, 0x001000,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_sensor_unconnected_to_user,
            {"Unconnected to User", "btatt.plxs.spot_check_measurement.device_and_sensor_status.unconnected_to_user",
            FT_BOOLEAN, 24, NULL, 0x000800,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_sensor_interference_detected,
            {"Interference Detected", "btatt.plxs.spot_check_measurement.device_and_sensor_status.interference_detected",
            FT_BOOLEAN, 24, NULL, 0x000400,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_signal_analysis_ongoing,
            {"Signal Analysis Ongoing", "btatt.plxs.spot_check_measurement.device_and_sensor_status.signal_analysis_ongoing",
            FT_BOOLEAN, 24, NULL, 0x000200,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_questionable_pulse_detected,
            {"Questionable Pulse Detected", "btatt.plxs.spot_check_measurement.device_and_sensor_status.questionable_pulse_detected",
            FT_BOOLEAN, 24, NULL, 0x000100,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_non_pulsatile_signal_detected,
            {"Non Pulsatile Signal Detected", "btatt.plxs.spot_check_measurement.device_and_sensor_status.non_pulsatile_signal_detected",
            FT_BOOLEAN, 24, NULL, 0x000080,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_erratic_signal_detected,
            {"Erratic Signal Detected", "btatt.plxs.spot_check_measurement.device_and_sensor_status.erratic_signal_detected",
            FT_BOOLEAN, 24, NULL, 0x000040,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_low_perfusion_detected,
            {"Low Perfusion Detected", "btatt.plxs.spot_check_measurement.device_and_sensor_status.low_perfusion_detected",
            FT_BOOLEAN, 24, NULL, 0x000020,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_poor_signal_detected,
            {"Poor Signal Detected", "btatt.plxs.spot_check_measurement.device_and_sensor_status.poor_signal_detected",
            FT_BOOLEAN, 24, NULL, 0x000010,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_inadequate_signal_detected,
            {"Inadequate Signal Detected", "btatt.plxs.spot_check_measurement.device_and_sensor_status.inadequate_signal_detected",
            FT_BOOLEAN, 24, NULL, 0x000008,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_signal_processing_irregularity_detected,
            {"Signal Processing Irregularity Detected", "btatt.plxs.spot_check_measurement.device_and_sensor_status.signal_processing_irregularity_detected",
            FT_BOOLEAN, 24, NULL, 0x000004,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_equipment_malfunction_detected,
            {"Equipment Malfunction Detected", "btatt.plxs.spot_check_measurement.device_and_sensor_status.equipment_malfunction_detected",
            FT_BOOLEAN, 24, NULL, 0x000002,
            NULL, HFILL}
        },
        {&hf_btatt_plx_device_and_sensor_status_extended_display_update_ongoing,
            {"Extended Display Update Ongoing", "btatt.plxs.spot_check_measurement.device_and_sensor_status.extended_display_update_ongoing",
            FT_BOOLEAN, 24, NULL, 0x000001,
            NULL, HFILL}
        },
        {&hf_btatt_plx_pulse_amplitude_index,
            {"Pulse Amplitude Index", "btatt.plxs.spot_check_measurement.pulse_amplitude_index",
            FT_IEEE_11073_SFLOAT, BASE_FLOAT, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_spo2pr_spot_check,
            {"SpO2PR Spot Check", "btatt.plxs.spo2pr_spot_check",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_spo2pr_normal,
            {"SpO2PR Normal", "btatt.plxs.spo2pr_normal",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_spo2pr_fast,
            {"SpO2PR Fast", "btatt.plxs.spo2pr_fast",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_spo2pr_slow,
            {"SpO2PR Slow", "btatt.plxs.spo2pr_slow",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_continuous_measurement_flags,
            {"Flags", "btatt.plxs.continuous_measurement.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_continuous_measurement_flags_reserved,
            {"Reserved", "btatt.plxs.continuous_measurement.flags.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xE0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_continuous_measurement_flags_pulse_amplitude_index,
            {"Pulse Amplitude Index", "btatt.plxs.continuous_measurement.flags.pulse_amplitude_index",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btatt_plx_continuous_measurement_flags_device_and_sensor_status,
            {"Device and Sensor Status", "btatt.plxs.continuous_measurement.flags.device_and_sensor_status",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btatt_plx_continuous_measurement_flags_measurement_status,
            {"Measurement Status", "btatt.plxs.continuous_measurement.flags.measurement_status",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btatt_plx_continuous_measurement_flags_spo2pr_slow,
            {"SpO2PR-Slow", "btatt.plxs.continuous_measurement.flags.spo2pr_slow",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btatt_plx_continuous_measurement_flags_spo2pr_fast,
            {"SpO2PR-Fast", "btatt.plxs.continuous_measurement.flags.spo2pr_fast",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },

        {&hf_btatt_plx_features_supported_features,
            {"Supported Features", "btatt.plxs.features.supported_features",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_plx_features_supported_features_reserved,
            {"Reserved", "btatt.plxs.features.supported_features.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFF00,
            NULL, HFILL}
        },
        {&hf_btatt_plx_features_supported_features_multiple_bonds,
            {"Multiple Bonds", "btatt.plxs.features.supported_features.multiple_bonds",
            FT_BOOLEAN, 16, NULL, 0x0080,
            NULL, HFILL}
        },
        {&hf_btatt_plx_features_supported_features_pulse_amplitude_index,
            {"Pulse Amplitude Index", "btatt.plxs.features.supported_features.pulse_amplitude_index",
            FT_BOOLEAN, 16, NULL, 0x0040,
            NULL, HFILL}
        },
        {&hf_btatt_plx_features_supported_features_spo2pr_slow,
            {"SpO2PR-Slow", "btatt.plxs.features.supported_features.spo2pr_slow",
            FT_BOOLEAN, 16, NULL, 0x0020,
            NULL, HFILL}
        },
        {&hf_btatt_plx_features_supported_features_spo2pr_fast,
            {"SpO2PR-Fast", "btatt.plxs.features.supported_features.spo2pr_fast",
            FT_BOOLEAN, 16, NULL, 0x0010,
            NULL, HFILL}
        },
        {&hf_btatt_plx_features_supported_features_timestamp_storage_for_spot_check,
            {"Timestamp Storage for Spot-Check", "btatt.plxs.features.supported_features.timestamp_storage_for_spot_check",
            FT_BOOLEAN, 16, NULL, 0x0008,
            NULL, HFILL}
        },
        {&hf_btatt_plx_features_supported_features_measurement_storage_for_spot_check,
            {"Measurement Storage for Spot-Check", "btatt.plxs.features.supported_features.measurement_storage_for_spot_check",
            FT_BOOLEAN, 16, NULL, 0x0004,
            NULL, HFILL}
        },
        {&hf_btatt_plx_features_supported_features_device_and_sensor_status,
            {"Device and Sensor Status", "btatt.plxs.features.supported_features.device_and_sensor_status",
            FT_BOOLEAN, 16, NULL, 0x0002,
            NULL, HFILL}
        },
        {&hf_btatt_plx_features_supported_features_measurement_status,
            {"Measurement Status", "btatt.plxs.features.supported_features.measurement_status",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL}
        },
        {&hf_btatt_valid_range_lower_inclusive_value,
            {"Lower Inclusive Value", "btatt.valid_range.lower_inclusive_value",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_valid_range_upper_inclusive_value,
            {"Upper Inclusive Value", "btatt.valid_range.upper_inclusive_value",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_request_in_frame,
            {"Request in Frame", "btatt.request_in_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            NULL, HFILL}
        },
        {&hf_response_in_frame,
            {"Response in Frame", "btatt.response_in_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            NULL, HFILL}
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_btatt,
        &ett_btatt_list,
        &ett_btatt_value,
        &ett_btatt_opcode,
        &ett_btatt_handle,
        &ett_btatt_characteristic_properties
    };

    static ei_register_info ei[] = {
        { &ei_btatt_uuid_format_unknown,    { "btatt.uuid_format.unknown",            PI_PROTOCOL,  PI_WARN, "Unknown format", EXPFILL }},
        { &ei_btatt_handle_too_few,         { "btatt.handle.too_few",                 PI_PROTOCOL,  PI_WARN, "Too few handles, should be 2 or more", EXPFILL }},
        { &ei_btatt_mtu_exceeded,           { "btatt.mtu.exceeded",                   PI_PROTOCOL,  PI_WARN, "Packet size exceed current ATT_MTU", EXPFILL }},
        { &ei_btatt_mtu_full,               { "btatt.mtu.full",                       PI_PROTOCOL,  PI_NOTE, "Reached ATT_MTU. Attribute value may be longer.", EXPFILL }},
        { &ei_btatt_consent_out_of_bounds,  { "btatt.consent.out_of_bounds",          PI_PROTOCOL,  PI_WARN, "Consent Code is out of bounds (0 to 9999)", EXPFILL }},
        { &ei_btatt_cgm_size_too_small,     { "btatt.cgm_measurement.size.too_small", PI_PROTOCOL,  PI_WARN, "Size too small (6 or geater)", EXPFILL }},
        { &ei_btatt_opcode_invalid_request, { "btatt.opcode.invalid_request" ,        PI_PROTOCOL,  PI_WARN, "Invalid request", EXPFILL }},
        { &ei_btatt_opcode_invalid_response,{ "btatt.opcode.invalid_response",        PI_PROTOCOL,  PI_WARN, "Invalid response", EXPFILL }},
        { &ei_btatt_invalid_usage,          { "btatt.invalid_usage",                  PI_PROTOCOL,  PI_WARN, "Invalid usage of this characteristic with this opcode", EXPFILL }},
        { &ei_btatt_bad_data,               { "btatt.bad_data",                       PI_PROTOCOL,  PI_WARN, "Bad Data", EXPFILL }},
        { &ei_btatt_unexpected_data,        { "btatt.unexpected_data",                PI_PROTOCOL,  PI_WARN, "Unexpected Data", EXPFILL }},
        { &ei_btatt_undecoded,              { "btatt.undecoded",                      PI_UNDECODED, PI_NOTE, "Undecoded", EXPFILL }},
    };

    static build_valid_func btatt_handle_da_build_value[1] = {btatt_handle_value};
    static decode_as_value_t btatt_handle_da_values = {btatt_handle_prompt, 1, btatt_handle_da_build_value};
    static decode_as_t btatt_handle_da = {"btatt", "ATT Handle", "btatt.handle",
            1, 0, &btatt_handle_da_values, NULL, NULL,
            decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    /* Register the protocol name and description */
    proto_btatt = proto_register_protocol("Bluetooth Attribute Protocol", "BT ATT", "btatt");

    btatt_handle = register_dissector("btatt", dissect_btatt, proto_btatt);

    att_handle_dissector_table = register_dissector_table("btatt.handle", "BT ATT Handle", proto_btatt, FT_UINT16, BASE_HEX);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_btatt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_btatt = expert_register_protocol(proto_btatt);
    expert_register_field_array(expert_btatt, ei, array_length(ei));

    mtus = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    requests = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    fragments = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    handle_to_uuid = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    module = prefs_register_protocol(proto_btatt, NULL);
    prefs_register_static_text_preference(module, "att.version",
            "Bluetooth Protocol ATT version from Core 4.0",
            "Version of protocol supported by this dissector.");

    register_decode_as(&btatt_handle_da);
}

void
proto_reg_handoff_btatt(void)
{
    gint                i_array;
    GString            *uuid_str = g_string_new("");

    http_handle = find_dissector_add_dependency("http", proto_btatt);
    usb_hid_boot_keyboard_input_report_handle  = find_dissector_add_dependency("usbhid.boot_report.keyboard.input", proto_btatt);
    usb_hid_boot_keyboard_output_report_handle = find_dissector_add_dependency("usbhid.boot_report.keyboard.output", proto_btatt);
    usb_hid_boot_mouse_input_report_handle     = find_dissector_add_dependency("usbhid.boot_report.mouse.input", proto_btatt);

    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_ATT, btatt_handle);
    dissector_add_uint("btl2cap.cid", BTL2CAP_FIXED_CID_ATT, btatt_handle);

    btatt_tap_handles = register_tap("btatt.handles");

    for (i_array = 0; bluetooth_uuid_vals[i_array].strptr != NULL; i_array += 1) {
        gchar *name;
        gchar *short_name;
        gchar *abbrev;
        dissector_handle_t  handle_tmp;
        gint                proto_tmp;

        if (bluetooth_uuid_vals[i_array].value < 0x1800) {
            continue;
        }

        if ((bluetooth_uuid_vals[i_array].value & 0xFF00) == 0x2700) {
            continue;
        }

        g_string_printf(uuid_str, "0x%04x", bluetooth_uuid_vals[i_array].value);
        name       = wmem_strconcat(wmem_epan_scope(), "Bluetooth GATT Attribute ",
                bluetooth_uuid_vals[i_array].strptr, " (UUID ", uuid_str->str, ")", NULL);
        short_name = wmem_strconcat(wmem_epan_scope(), "BT GATT ",
                bluetooth_uuid_vals[i_array].strptr, " (UUID ", uuid_str->str, ")", NULL);
        abbrev     = wmem_strconcat(wmem_epan_scope(), "btgatt.uuid", uuid_str->str, NULL);

        proto_tmp = proto_register_protocol(name, short_name, abbrev);
        handle_tmp = register_dissector(abbrev, dissect_btgatt, proto_tmp);

        dissector_add_for_decode_as("btatt.handle", handle_tmp);
    }
    g_string_free(uuid_str, TRUE);
}

void
proto_register_btgatt(void)
{
    static hf_register_info hf[] = {
        {&hf_gatt_nordic_uart_tx,
            {"UART Tx", "btgatt.nordic.uart_tx.text",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_gatt_nordic_uart_rx,
            {"UART Rx", "btgatt.nordic.uart_rx.text",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_gatt_nordic_dfu_packet,
            {"Packet", "btgatt.nordic.dfu.packet.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_gatt_nordic_dfu_control_point_opcode,
            {"Opcode", "btgatt.nordic.dfu.control_point.opcode",
            FT_UINT8, BASE_DEC, VALS(nordic_dfu_control_point_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_gatt_nordic_dfu_control_point_init_packet,
            {"Init Packet", "btgatt.nordic.dfu.control_point.init_packet",
            FT_UINT8, BASE_HEX, VALS(nordic_dfu_control_point_init_packet_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_gatt_nordic_dfu_control_point_image_type,
            {"Image Type", "btgatt.nordic.dfu.control_point.image_type",
            FT_UINT8, BASE_HEX, VALS(nordic_dfu_control_point_image_type_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_gatt_nordic_dfu_control_point_number_of_bytes,
            {"Number of Bytes of Firmware Image Received", "btgatt.nordic.dfu.control_point.number_of_bytes",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_gatt_nordic_dfu_control_point_number_of_packets,
            {"Number of Packets", "btgatt.nordic.dfu.control_point.number_of_packets",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_gatt_nordic_dfu_control_point_request_opcode,
            {"Request Opcode", "btgatt.nordic.dfu.control_point.request_opcode",
            FT_UINT8, BASE_DEC, VALS(nordic_dfu_control_point_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_gatt_nordic_dfu_control_point_response_value,
            {"Response Value", "btgatt.nordic.dfu.control_point.response_value",
            FT_UINT8, BASE_DEC, VALS(nordic_dfu_control_point_response_value_vals), 0x0,
            NULL, HFILL}
        }
    };


    static gint *ett[] = {
        &ett_btgatt
    };

    proto_btgatt = proto_register_protocol("Bluetooth GATT Attribute Protocol", "BT GATT", "btgatt");

    btgatt_handle = register_dissector("btgatt", dissect_btgatt, proto_btgatt);

    proto_register_field_array(proto_btgatt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_btgatt(void)
{
    gint                i_array;
    struct uuid_dissectors_t {
        const gchar *uuid;

        const gchar *name;
        const gchar *short_name;
        const gchar *abbrev_name;

        int (*dissect_func)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
    } uuid_dissectors[] = {
        { "6e400001-b5a3-f393-e0a9-e50e24dcca9e", "Bluetooth GATT Nordic UART Service",      "Nordic UART Service",      "btgatt.nordic.uart",               NULL},
        { "6e400002-b5a3-f393-e0a9-e50e24dcca9e", "Bluetooth GATT Nordic UART Tx",           "Nordic UART Tx",           "btgatt.nordic.uart_tx",            dissect_btgatt_nordic_uart_tx},
        { "6e400003-b5a3-f393-e0a9-e50e24dcca9e", "Bluetooth GATT Nordic UART Rx",           "Nordic UART Rx",           "btgatt.nordic.uart_rx",            dissect_btgatt_nordic_uart_rx},
        { "00001530-1212-efde-1523-785feabcd123", "Bluetooth GATT Nordic DFU Service",       "Nordic DFU Service",       "btgatt.nordic.dfu",                NULL},
        { "00001531-1212-efde-1523-785feabcd123", "Bluetooth GATT Nordic DFU Control Point", "Nordic DFU Control Point", "btgatt.nordic.dfu.control_point",  dissect_btgatt_nordic_dfu_control_point},
        { "00001532-1212-efde-1523-785feabcd123", "Bluetooth GATT Nordic DFU Packet",        "Nordic DFU Packet",        "btgatt.nordic.dfu.packet",         dissect_btgatt_nordic_dfu_packet},

        { NULL, NULL, NULL, NULL, NULL},
    };

    i_array = 0;

    while (uuid_dissectors[i_array].uuid) {
        dissector_handle_t  handle_tmp;
        gint                proto_tmp;

        wmem_tree_insert_string(bluetooth_uuids, uuid_dissectors[i_array].uuid, (gchar *) uuid_dissectors[i_array].short_name, 0);

        if (!uuid_dissectors[i_array].dissect_func) {
            i_array += 1;
            continue;
        }

        proto_tmp  = proto_register_protocol(uuid_dissectors[i_array].name, uuid_dissectors[i_array].short_name, uuid_dissectors[i_array].abbrev_name);
        handle_tmp = register_dissector(uuid_dissectors[i_array].abbrev_name, uuid_dissectors[i_array].dissect_func, proto_tmp);

        dissector_add_string("bluetooth.uuid", uuid_dissectors[i_array].uuid, handle_tmp);
        dissector_add_for_decode_as("btatt.handle", handle_tmp);
        i_array += 1;
    }
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
