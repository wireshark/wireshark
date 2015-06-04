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
#include <epan/expert.h>
#include <epan/oui.h>
#include <epan/decode_as.h>
#include <epan/tap.h>

#include "packet-bluetooth.h"
#include "packet-btatt.h"
#include "packet-btl2cap.h"
#include "packet-btsdp.h"
#include "packet-usb-hid.h"

/* Initialize the protocol and registered fields */
static int proto_btatt = -1;

static int hf_btatt_opcode = -1;
static int hf_btatt_handle = -1;
static int hf_btatt_starting_handle = -1;
static int hf_btatt_ending_handle = -1;
static int hf_btatt_group_end_handle = -1;
static int hf_btatt_value = -1;
static int hf_btatt_req_opcode_in_error = -1;
static int hf_btatt_handle_in_error = -1;
static int hf_btatt_error_code = -1;
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

static wmem_tree_t *mtus = NULL;
static wmem_tree_t *requests = NULL;
static wmem_tree_t *fragments = NULL;
static wmem_tree_t *handle_to_uuid = NULL;

static dissector_handle_t btatt_handle;
static dissector_handle_t usb_hid_boot_keyboard_input_report_handle;
static dissector_handle_t usb_hid_boot_keyboard_output_report_handle;
static dissector_handle_t usb_hid_boot_mouse_input_report_handle;

static dissector_table_t att_handle_dissector_table;
static dissector_table_t att_uuid16_dissector_table;
static dissector_table_t att_uuid128_dissector_table;

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

/* Error codes */
static const value_string error_vals[] = {
    {0x01, "Invalid Handle"},
    {0x02, "Read Not Permitted"},
    {0x03, "Write Not Permitted"},
    {0x04, "Invalid PDU"},
    {0x05, "Insufficient Authentication"},
    {0x06, "Request Not Supported"},
    {0x07, "Invalid Offset"},
    {0x08, "Insufficient Authorization"},
    {0x09, "Prepare Queue Full"},
    {0x0a, "Attribute Not Found"},
    {0x0b, "Attribute Not Long"},
    {0x0c, "Insufficient Encryption Key Size"},
    {0x0d, "Invalid Attribute Value Length"},
    {0x0e, "Unlikely Error"},
    {0x0f, "Insufficient Encryption"},
    {0x10, "Unsupported Group Type"},
    {0x11, "Insufficient Resources"},
    {0x80, "Application Error"},
    {0xfd, "Improper Client Characteristic Configuration Descriptor"},
    {0xfe, "Procedure Already In Progress"},
    {0xff, "Out of Range"},
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

static const value_string appearance_subcategory_watch_vals[] = {
    {0x01, "Sports Watch"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_thermometer_vals[] = {
    {0x01, "Ear"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_heart_rate_vals[] = {
    {0x01, "Heart Rate Belt"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_blood_pressure_vals[] = {
    {0x01, "Arm"},
    {0x02, "Wrist"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_hid_vals[] = {
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
    {0x01, "In-Shoe"},
    {0x02, "On-Shoe"},
    {0x03, "On-Hip"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_cycling_vals[] = {
    {0x01, "Cycling Computer"},
    {0x02, "Speed Sensor"},
    {0x03, "Cadence Sensor"},
    {0x04, "Power Sensor"},
    {0x05, "Speed and Cadence Sensor"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_pulse_oximeter_vals[] = {
    {0x01, "Fingertip"},
    {0x02, "Wrist Worn"},
    {0x0, NULL}
};

static const value_string appearance_subcategory_outdoor_sports_activity_vals[] = {
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
    {0x00,   "Not supported"},
    {0x01,   "Supported"},
    {0x02,   ""},
    {0x0, NULL}
};



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

typedef struct _handle_data_t {
    bluetooth_uuid_t uuid;
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

#define PROTO_DATA_BTATT_HANDLE   0x00
#define PROTO_DATA_BTATT_UUID16   0x01
#define PROTO_DATA_BTATT_UUID128  0x02

static void btatt_handle_prompt(packet_info *pinfo, gchar* result)
{
    gulong *value_data;

    value_data = (gulong *) p_get_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_HANDLE);
    if (value_data)
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "ATT Handle 0x%04x as", (guint) *value_data);
    else
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown ATT Handle");
}

static gpointer btatt_handle_value(packet_info *pinfo)
{

    return (gpointer) p_get_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_HANDLE);

}

static void btatt_uuid16_prompt(packet_info *pinfo, gchar* result)
{
    gulong *value_data;

    value_data = (gulong *) p_get_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_UUID16);
    if (value_data)
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "ATT UUID16 0x%04x as", (guint) *value_data);
    else
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown ATT UUID16");
}

static gpointer btatt_uuid16_value(packet_info *pinfo)
{

    return (gpointer) p_get_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_UUID16);

}

static void btatt_uuid128_prompt(packet_info *pinfo, gchar* result)
{
    gchar *value_data;

    value_data = (gchar *) p_get_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_UUID128);
    if (value_data)
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "ATT UUID128 %s as", (gchar *) value_data);
    else
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown ATT UUID128");
}

static gpointer btatt_uuid128_value(packet_info *pinfo)
{
    gchar *value_data;

    value_data = (gchar *) p_get_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_UUID128);

    if (value_data)
        return (gpointer) value_data;

    return NULL;
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

    frame_number = pinfo->fd->num;

    sub_wmemtree = (wmem_tree_t *) wmem_tree_lookup32_array(requests, key);
    request_data = (sub_wmemtree) ? (request_data_t *) wmem_tree_lookup32_le(sub_wmemtree, frame_number) : NULL;

    if (!request_data)
        return NULL;

    if (request_data->request_in_frame == pinfo->fd->num)
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

    frame_number = pinfo->fd->num;

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
        bluetooth_data_t *bluetooth_data)
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

        frame_number = pinfo->fd->num;

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

    frame_number = pinfo->fd->num;

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

static int
dissect_handle_uint(proto_tree *tree, packet_info *pinfo, gint hf,
        tvbuff_t *tvb, gint offset, bluetooth_data_t *bluetooth_data,
        bluetooth_uuid_t *uuid, guint16 handle)
{
    proto_item        *sub_item;
    proto_tree        *sub_tree;
    bluetooth_uuid_t   local_uuid;

    sub_item = proto_tree_add_uint(tree, hf, tvb, 0, 0, handle);
    PROTO_ITEM_SET_GENERATED(sub_item);
    local_uuid = get_uuid_from_handle(pinfo, handle, bluetooth_data);
    if (local_uuid.size == 2 || local_uuid.size == 16) {
        proto_item_append_text(sub_item, " (%s)", print_uuid(&local_uuid));
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_handle);

        if (local_uuid.size == 2)
            sub_item = proto_tree_add_uint(sub_tree, hf_btatt_uuid16, tvb, 0, 0, local_uuid.bt_uuid);
        else
            sub_item = proto_tree_add_bytes_with_length(sub_tree, hf_btatt_uuid128, tvb, 0, 0, local_uuid.data, 16);


        PROTO_ITEM_SET_GENERATED(sub_item);

        if (uuid)
            *uuid = local_uuid;
    } else {
        if (uuid) {
            local_uuid.size = 0;
            local_uuid.bt_uuid = 0;
            *uuid = local_uuid;
        }
    }

    return offset + 2;
}

static int
dissect_handle(proto_tree *tree, packet_info *pinfo, gint hf,
        tvbuff_t *tvb, gint offset, bluetooth_data_t *bluetooth_data,
        bluetooth_uuid_t *uuid)
{
    proto_item        *sub_item;
    proto_tree        *sub_tree;
    guint16            handle;
    bluetooth_uuid_t   local_uuid;

    sub_item = proto_tree_add_item(tree, hf, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    handle = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    local_uuid = get_uuid_from_handle(pinfo, handle, bluetooth_data);
    if (local_uuid.size == 2 || local_uuid.size == 16) {
        proto_item_append_text(sub_item, " (%s)", print_uuid(&local_uuid));
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_handle);

        if (local_uuid.size == 2)
            sub_item = proto_tree_add_uint(sub_tree, hf_btatt_uuid16, tvb, 0, 0, local_uuid.bt_uuid);
        else
            sub_item = proto_tree_add_bytes_with_length(sub_tree, hf_btatt_uuid128, tvb, 0, 0, local_uuid.data, 16);

        PROTO_ITEM_SET_GENERATED(sub_item);

        if (uuid)
            *uuid = local_uuid;
    } else {
        if (uuid) {
            local_uuid.size = 0;
            local_uuid.bt_uuid = 0;
            *uuid = local_uuid;
        }
    }

    return offset + 2;
}

static gint
dissect_attribute_value(proto_tree *tree, proto_item *patron_item, packet_info *pinfo, tvbuff_t *old_tvb,
        gint old_offset, gint length, guint16 handle, bluetooth_uuid_t uuid, bluetooth_data_t *bluetooth_data)
{
    proto_item  *sub_item;
    proto_tree  *sub_tree;
    tvbuff_t    *tvb;
    gint         offset = 0;
    bluetooth_uuid_t sub_uuid;
    guint16      sub_handle;
    guint32      value;
    const gint  **hfs;

    tvb = tvb_new_subset(old_tvb, old_offset, length, length);

    if (p_get_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_HANDLE) == NULL) {
        guint16 *value_data;

        value_data = wmem_new(wmem_file_scope(), guint16);
        *value_data = handle;

        p_add_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_HANDLE, value_data);
    }

    if (dissector_try_uint_new(att_handle_dissector_table, handle, tvb, pinfo, tree, TRUE, bluetooth_data))
        return old_offset + length;

    if (uuid.size == 2) {
        if (p_get_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_UUID16) == NULL) {
            guint16 *value_data;

            value_data = wmem_new(wmem_file_scope(), guint16);
            *value_data = uuid.bt_uuid;

            p_add_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_UUID16, value_data);
        }
    } else if (uuid.size == 16) {
        if (p_get_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_UUID128) == NULL) {
            guint8 *value_data;

            value_data = wmem_strdup(wmem_file_scope(), print_numeric_uuid(&uuid));

            p_add_proto_data(pinfo->pool, pinfo, proto_btatt, PROTO_DATA_BTATT_UUID128, value_data);
        }
    }

    if (!uuid.bt_uuid) {
        proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);

        return old_offset + tvb_captured_length(tvb);
    }

    if (dissector_try_string(att_uuid128_dissector_table, print_uuid(&uuid), tvb, pinfo, tree, bluetooth_data))
        return old_offset + length;

    if (dissector_try_uint_new(att_uuid16_dissector_table, uuid.bt_uuid, tvb, pinfo, tree, TRUE, bluetooth_data))
        return old_offset + length;


    switch (uuid.bt_uuid) {
    case 0x2800: /* GATT Primary Service Declaration */
    case 0x2801: /* GATT Secondary Service Declaration */
        if (tvb_reported_length_remaining(tvb, offset) == 2) {
            proto_tree_add_item(tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            sub_uuid = get_uuid(tvb, offset, 2);
            proto_item_append_text(patron_item, ", UUID: %s", print_uuid(&sub_uuid));
            offset += 2;

            save_handle(pinfo, sub_uuid, handle, bluetooth_data);
        } else if (tvb_reported_length_remaining(tvb, offset) == 16) {
            proto_tree_add_item(tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
            sub_uuid = get_uuid(tvb, offset, 16);
            proto_item_append_text(patron_item, ", UUID128: %s", print_uuid(&sub_uuid));
            offset += 16;

            save_handle(pinfo, sub_uuid, handle, bluetooth_data);
        } else {
            proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
            offset = tvb_captured_length(tvb);
        }

        break;
    case 0x2802: /* GATT Include Declaration */
        offset = dissect_handle(tree, pinfo, hf_btatt_included_service_handle, tvb, offset, bluetooth_data, NULL);
        sub_handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(tree, hf_btatt_ending_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        sub_uuid = get_uuid(tvb, offset, 2);
        proto_item_append_text(patron_item, ", Included Handle: 0x%04x, UUID: %s", sub_handle, print_uuid(&sub_uuid));
        offset += 2;

        save_handle(pinfo, sub_uuid, sub_handle, bluetooth_data);

        break;
    case 0x2803: /* GATT Characteristic Declaration*/
        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_characteristic_properties, ett_btatt_characteristic_properties,  hfx_btatt_characteristic_properties, ENC_NA);
        offset += 1;

        offset = dissect_handle(tree, pinfo, hf_btatt_characteristic_value_handle, tvb, offset, bluetooth_data, NULL);
        sub_handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

        if (tvb_reported_length_remaining(tvb, offset) == 16) {
            proto_tree_add_item(tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
            sub_uuid = get_uuid(tvb, offset, 16);
            proto_item_append_text(patron_item, ", Characteristic Handle: 0x%04x, UUID128: %s", tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN), print_uuid(&sub_uuid));
            offset += 16;

            save_handle(pinfo, sub_uuid, sub_handle, bluetooth_data);
        } else if (tvb_reported_length_remaining(tvb, offset) == 2) {
            proto_tree_add_item(tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            sub_uuid = get_uuid(tvb, offset, 2);
            proto_item_append_text(patron_item, ", Characteristic Handle: 0x%04x, UUID: %s", sub_handle, print_uuid(&sub_uuid));
            offset += 2;

            save_handle(pinfo, sub_uuid, sub_handle, bluetooth_data);
        } else {
            proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
            offset = tvb_captured_length(tvb);
        }

        break;
    case 0x2900: /* Characteristic Extended Properties */
        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_characteristic_extended_properties, ett_btatt_value, hfx_btatt_characteristic_extended_properties, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2901: /* Characteristic User Description */
        proto_tree_add_item(tree, hf_btatt_characteristic_user_description, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2902: /* GATT: Client Characteristic Configuration */
        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_characteristic_configuration_client, ett_btatt_value, hfx_btatt_characteristic_configuration_client, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2903: /* Server Characteristic Configuration */
        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_characteristic_configuration_server, ett_btatt_value, hfx_btatt_characteristic_configuration_server, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2904: /* Characteristic Presentation Format */
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
        sub_item = proto_tree_add_none_format(tree, hf_btatt_handles_info,
                tvb, offset, tvb_captured_length(tvb), "Handles (%i items)",
                tvb_captured_length(tvb) / 2);
        sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

        while (offset < (gint64) tvb_captured_length(tvb)) {
            offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL);
        }
        break;
    case 0x2907: /* External Report Reference */
        if (tvb_reported_length_remaining(tvb, offset) == 2) {
            proto_tree_add_item(tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        } else if (tvb_reported_length_remaining(tvb, offset) == 16) {
            proto_tree_add_item(tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
            offset += 16;
        } else {
            proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
            offset = tvb_captured_length(tvb);
        }
        break;
    case 0x2908: /* GATT: Report Reference */
        proto_tree_add_item(tree, hf_btatt_report_reference_report_id, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_report_reference_report_type, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x290B: /* Environmental Sensing Configuration */
        proto_tree_add_item(tree, hf_btatt_esp_trigger_logic, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x290C: /* Environmental Sensing Measurement */
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
        proto_tree_add_item(tree, hf_btatt_esp_condition, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_esp_operand, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
        offset += tvb_captured_length_remaining(tvb, offset);
        break;
    case 0x2A4A: /* HOGP: HID Information */
        proto_tree_add_item(tree, hf_btatt_hogp_bcd_hid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_hogp_b_country_code, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_hogp_flags, ett_btatt_value, hfx_btatt_hogp_flags, ENC_NA);
        offset += 1;

        break;
    case 0x2A4B: /* HOGP: Report Map */
        offset = dissect_usb_hid_get_report_descriptor(pinfo, tree, tvb, offset, NULL);

        break;
    case 0x2A4E: /* HOGP: Protocol Mode */
        proto_tree_add_item(tree, hf_btatt_hogp_protocol_mode, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;

    case 0x2A00: /* Device Name */
        proto_tree_add_item(tree, hf_btatt_device_name, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A01: /* Appearance */
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
        proto_tree_add_item(tree, hf_btatt_peripheral_privacy_flag, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A03: /* Reconnection Address */
        offset = dissect_bd_addr(hf_btatt_reconnection_address, tree, tvb, offset, NULL);

        break;
    case 0x2A04: /* Peripheral Preferred Connection Parameters */
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
        proto_tree_add_item(tree, hf_btatt_starting_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_ending_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A06: /* Alert Level */
        proto_tree_add_item(tree, hf_btatt_alert_level, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A07: /* Tx Power Level */
        proto_tree_add_item(tree, hf_btatt_tx_power_level, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A08: /* Date Time */
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
        proto_tree_add_item(tree, hf_btatt_day_of_week, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A0A: /* Day Date Time */
    case 0x2A0C: /* Exact Time 256 */
    case 0x2A2B: /* Current Time */
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
        proto_tree_add_item(tree, hf_btatt_dst_offset, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A0E: /* Time Zone */
        proto_tree_add_item(tree, hf_btatt_timezone, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A0F: /* Local Time Information */
        proto_tree_add_item(tree, hf_btatt_timezone, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_dst_offset, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A11: /* Time with DST */
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
        proto_tree_add_item(tree, hf_btatt_time_accuracy, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A13: /* Time Source */
        proto_tree_add_item(tree, hf_btatt_time_source, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A14: /* Reference Time Information */
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
        proto_tree_add_item(tree, hf_btatt_time_update_control_point, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A17: /* Time Update State */
        proto_tree_add_item(tree, hf_btatt_time_current_state, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_time_result, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A19: /* Battery Level */
        proto_tree_add_item(tree, hf_btatt_battery_level, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A1D: /* Temperature Type */
        proto_tree_add_item(tree, hf_btatt_temperature_type, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A21: /* Measurement Interval */
        proto_tree_add_item(tree, hf_btatt_measurement_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A22: /* Boot Keyboard Input Report */
        call_dissector_with_data(usb_hid_boot_keyboard_input_report_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree, NULL);
        offset += length;

        break;
    case 0x2A23: /* System ID */
        proto_tree_add_item(tree, hf_btatt_system_id_manufacturer_identifier, tvb, offset, 5, ENC_LITTLE_ENDIAN);
        offset += 5;

        proto_tree_add_item(tree, hf_btatt_system_id_organizationally_unique_identifier, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;
        break;
    case 0x2A24: /* Model Number String */
        proto_tree_add_item(tree, hf_btatt_model_number_string, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A25: /* Serial Number String */
        proto_tree_add_item(tree, hf_btatt_serial_number_string, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A26: /* Firmware Revision String */
        proto_tree_add_item(tree, hf_btatt_firmware_revision_string, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A27: /* Hardware Revision String */
        proto_tree_add_item(tree, hf_btatt_hardware_revision_string, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A28: /* Software Revision String */
        proto_tree_add_item(tree, hf_btatt_software_revision_string, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A29: /* Manufacturer Name String */
        proto_tree_add_item(tree, hf_btatt_manufacturer_string, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A2C: /* Magnetic Declination */
        proto_tree_add_item(tree, hf_btatt_magnetic_declination, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A31: /* Scan Refresh */
        proto_tree_add_item(tree, hf_btatt_scan_refresh, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A32: /* Boot Keyboard Output Report */
        call_dissector_with_data(usb_hid_boot_keyboard_output_report_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree, NULL);
        offset += length;

        break;
    case 0x2A33: /* Boot Mouse Input Report */
        call_dissector_with_data(usb_hid_boot_mouse_input_report_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree, NULL);
        offset += length;

        break;
    case 0x2A38: /* Body Sensor Location */
        proto_tree_add_item(tree, hf_btatt_body_sensor_location, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A39: /* Heart Rate Control Point */
        proto_tree_add_item(tree, hf_btatt_heart_rate_control_point, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A3F: /* Alert Status */
        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_alert_status, ett_btatt_value, hfx_btatt_alert_status, ENC_NA);
        offset += 1;

        break;
    case 0x2A40: /* Ringer Control Point */
        proto_tree_add_item(tree, hf_btatt_ringer_control_point, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A41: /* Ringer Setting */
        proto_tree_add_item(tree, hf_btatt_ringer_setting, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A42: /* Alert Category ID Bit Mask */
    case 0x2A47: /* Supported New Alert Category */
    case 0x2A48: /* Supported Unread Alert Category */
        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_alert_category_id_bitmask_1, ett_btatt_value, hfx_btatt_alert_category_id_bitmask_1, ENC_NA);
        offset += 1;

        if (tvb_reported_length_remaining(tvb, offset) >= 1) {
            proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_alert_category_id_bitmask_2, ett_btatt_value, hfx_btatt_alert_category_id_bitmask_2, ENC_NA);
            offset += 1;
        }

        break;
    case 0x2A43: /* Alert Category ID */
        proto_tree_add_item(tree, hf_btatt_alert_category_id, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A44: /* Alert Notification Control Point */
        proto_tree_add_item(tree, hf_btatt_alert_command_id, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_alert_category_id, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A45: /* Unread Alert Status */
        proto_tree_add_item(tree, hf_btatt_alert_category_id, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_alert_unread_count, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A46: /* New Alert */
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
        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_blood_pressure_feature, ett_btatt_value, hfx_btatt_blood_pressure_feature, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A4C: /* HID Control Point */
        proto_tree_add_item(tree, hf_btatt_hogp_hid_control_point_command, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A4F: /* Scan Interval Window */
        proto_tree_add_item(tree, hf_btatt_le_scan_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_le_scan_window, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A50: /* PnP ID */
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
        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_glucose_feature, ett_btatt_value, hfx_btatt_glucose_feature, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A54: /* RSC Feature */
        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_rsc_feature, ett_btatt_value, hfx_btatt_rsc_feature, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A5C: /* CSC Feature */
        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_csc_feature, ett_btatt_value, hfx_btatt_csc_feature, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A5D: /* Sensor Location */
        proto_tree_add_item(tree, hf_btatt_sensor_location, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A6C: /* Elevation */
        proto_tree_add_item(tree, hf_btatt_elevation, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;

        break;
    case 0x2A6D: /* Pressure */
        proto_tree_add_item(tree, hf_btatt_pressure, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        break;
    case 0x2A6E: /* Temperature */
        proto_tree_add_item(tree, hf_btatt_temperature, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A6F: /* Humidity */
        proto_tree_add_item(tree, hf_btatt_humidity, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A70: /* True Wind Speed */
        proto_tree_add_item(tree, hf_btatt_true_wind_speed, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A71: /* True Wind Direction */
        proto_tree_add_item(tree, hf_btatt_true_wind_direction, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A72: /* Apparent Wind Speed */
        proto_tree_add_item(tree, hf_btatt_apparent_wind_speed, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A73: /* Apparent Wind Direction */
        proto_tree_add_item(tree, hf_btatt_apparent_wind_direction, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A74: /* Gust Factor */
        proto_tree_add_item(tree, hf_btatt_gust_factor, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A75: /* Pollen Concentration */
        proto_tree_add_item(tree, hf_btatt_pollen_concentration, tvb, offset, 3, ENC_LITTLE_ENDIAN);
        offset += 3;

        break;
    case 0x2A76: /* UV Index */
        proto_tree_add_item(tree, hf_btatt_uv_index, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A77: /* Irradiance */
        proto_tree_add_item(tree, hf_btatt_irradiance, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A78: /* Rainfall */
        proto_tree_add_item(tree, hf_btatt_rainfall, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A79: /* Wind Chill */
        proto_tree_add_item(tree, hf_btatt_wind_chill, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A7A: /* Heat Index */
        proto_tree_add_item(tree, hf_btatt_heart_index, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A7B: /* Dew Point */
        proto_tree_add_item(tree, hf_btatt_dew_point, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A7D: /* Descriptor Value Changed */
        proto_tree_add_bitmask(tree, tvb, offset, hf_btatt_descriptor_value_changed_flags , ett_btatt_value, hfx_btatt_descriptor_value_changed_flags, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (tvb_reported_length_remaining(tvb, offset) == 2) {
            proto_tree_add_item(tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        } else if (tvb_reported_length_remaining(tvb, offset) == 16) {
            proto_tree_add_item(tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
            offset += 16;
        } else {
            proto_tree_add_item(tree, hf_btatt_value, tvb, offset, -1, ENC_NA);
            offset = tvb_captured_length(tvb);
        }

        break;
    case 0x2A7E: /* Aerobic Heart Rate Lower Limit */
        proto_tree_add_item(tree, hf_btatt_aerobic_heart_rate_lower_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A7F: /* Aerobic Threshold */
        proto_tree_add_item(tree, hf_btatt_aerobic_threshold, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A80: /* Age */
        proto_tree_add_item(tree, hf_btatt_age, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A81: /* Anaerobic Heart Rate Lower Limit */
        proto_tree_add_item(tree, hf_btatt_anaerobic_heart_rate_lower_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A82: /* Anaerobic Heart Rate Upper Limit */
        proto_tree_add_item(tree, hf_btatt_anaerobic_heart_rate_upper_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A83: /* Anaerobic Threshold */
        proto_tree_add_item(tree, hf_btatt_anaerobic_threshold, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A84: /* Aerobic Heart Rate Upper Limit */
        proto_tree_add_item(tree, hf_btatt_aerobic_heart_rate_upper_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A85: /* Date of Birth */
    case 0x2A86: /* Date of Threshold Assessment */
        proto_tree_add_item(tree, hf_btatt_year, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btatt_month, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_day, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A87: /* Email Address */
        proto_tree_add_item(tree, hf_btatt_email_address, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A88: /* Fat Burn Heart Rate Lower Limit */
        proto_tree_add_item(tree, hf_btatt_fat_burn_heart_rate_lower_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A89: /* Fat Burn Heart Rate Upper Limit */
        proto_tree_add_item(tree, hf_btatt_fat_burn_heart_rate_upper_limit, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A8A: /* First Name */
        proto_tree_add_item(tree, hf_btatt_first_name, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A8B: /* Five Zone Heart Rate Limits */
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
        proto_tree_add_item(tree, hf_btatt_gender, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A8D: /* Heart Rate Max */
        proto_tree_add_item(tree, hf_btatt_heart_rate_max, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A8E: /* Height */
        proto_tree_add_item(tree, hf_btatt_height, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A8F: /* Hip Circumference */
        proto_tree_add_item(tree, hf_btatt_hip_circumference, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A90: /* Last Name */
        proto_tree_add_item(tree, hf_btatt_last_name, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2A91: /* Maximum Recommended Heart Rate */
        proto_tree_add_item(tree, hf_btatt_maximum_recommended_heart_rate, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A92: /* Resting Heart Rate */
        proto_tree_add_item(tree, hf_btatt_resting_heart_rate, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A93: /* Sport Type for Aerobic and Anaerobic Thresholds */
        proto_tree_add_item(tree, hf_btatt_sport_type_for_aerobic_and_anaerobic_thresholds, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A94: /* Three Zone Heart Rate Limits */
        proto_tree_add_item(tree, hf_btatt_three_zone_heart_rate_limits_light_moderate, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_btatt_three_zone_heart_rate_limits_moderate_hard, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A95: /* Two Zone Heart Rate Limit */
        proto_tree_add_item(tree, hf_btatt_two_zone_heart_rate_limit_fat_burn_fitness, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A96: /* VO2 Max */
        proto_tree_add_item(tree, hf_btatt_vo2_max, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2A97: /* Waist Circumference */
        proto_tree_add_item(tree, hf_btatt_waist_circumference, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A98: /* Weight */
        proto_tree_add_item(tree, hf_btatt_weight, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;
    case 0x2A99: /* Database Change Increment */
        proto_tree_add_item(tree, hf_btatt_database_change_increment, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        break;
    case 0x2A9A: /* User Index */
        proto_tree_add_item(tree, hf_btatt_user_index, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2AA0: /* Magnetic Flux Density - 2D */
    case 0x2AA1: /* Magnetic Flux Density - 3D */
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
        proto_tree_add_item(tree, hf_btatt_language, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA | ENC_UTF_8);
        offset += tvb_captured_length_remaining(tvb, offset);

        break;
    case 0x2AA3: /* Barometric Pressure Trend */
        proto_tree_add_item(tree, hf_btatt_barometric_pressure_trend, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;
    case 0x2AA6: /* Central Address Resolution */
        proto_tree_add_item(tree, hf_btatt_central_address_resolution, tvb, offset, 1, ENC_NA);
        offset += 1;

        break;

    case 0x2906: /* Valid Range */
    case 0x2A18: /* Glucose Measurement */
    case 0x2A1C: /* Temperature Measurement */
    case 0x2A1E: /* Intermediate Temperature */
    case 0x2A2A: /* IEEE 11073-20601 Regulatory Certification Data List */
    case 0x2A34: /* Glucose Measurement Context */
    case 0x2A35: /* Blood Pressure Measurement */
    case 0x2A36: /* Intermediate Cuff Pressure */
    case 0x2A37: /* Heart Rate Measurement */
    case 0x2A4D: /* Report */
    case 0x2A52: /* Record Access Control Point */
    case 0x2A53: /* RSC Measurement */
    case 0x2A55: /* SC Control Point */
    case 0x2A5B: /* CSC Measurement */
    case 0x2A63: /* Cycling Power Measurement */
    case 0x2A64: /* Cycling Power Vector */
    case 0x2A65: /* Cycling Power Feature */
    case 0x2A66: /* Cycling Power Control Point */
    case 0x2A67: /* Location and Speed */
    case 0x2A68: /* Navigation */
    case 0x2A69: /* Position Quality */
    case 0x2A6A: /* LN Feature */
    case 0x2A6B: /* LN Control Point */
    case 0x2A9B: /* Body Composition Feature */
    case 0x2A9C: /* Body Composition Measurement */
    case 0x2A9D: /* Weight Measurement */
    case 0x2A9E: /* Weight Scale Feature */
    case 0x2A9F: /* User Control Point */
    case 0x2AA4: /* Bond Management Control Point */
    case 0x2AA5: /* Bond Management Feature */
    case 0x2AA7: /* CGM Measurement */
    case 0x2AA8: /* CGM Feature */
    case 0x2AA9: /* CGM Status */
    case 0x2AAA: /* CGM Session Start Time */
    case 0x2AAB: /* CGM Session Run Time */
    case 0x2AAC: /* CGM Specific Ops Control Point */
/* TODO: Implement */
    default:
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

    main_item = proto_tree_add_item(tree, (gint) GPOINTER_TO_UINT(wmem_list_frame_data(wmem_list_tail(pinfo->layers))), tvb, 0, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btgatt);

    uuid.size = 2;
    uuid.bt_uuid = (guint16) g_ascii_strtoull(pinfo->current_proto + strlen(pinfo->current_proto) - 7, NULL, 16);
    uuid.data[0] = uuid.bt_uuid & 0xFF;
    uuid.data[1] = (uuid.bt_uuid >> 8) & 0xFF;

    return dissect_attribute_value(main_tree, patron_item, pinfo, tvb,
            0, tvb_captured_length(tvb), 0, uuid, (bluetooth_data_t *) data);

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

    frame_number = pinfo->fd->num;

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

    frame_number = pinfo->fd->num;

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

    frame_number = pinfo->fd->num;

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
    guint16           last_offset = 0xFFFF;
    guint16           size;
    gboolean          first = TRUE;
    guint8           *data = NULL;


    frame_number = pinfo->fd->num;

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
        if (!fragment_data || (fragment_data && fragment_data->offset >= last_offset)) {
            if (length)
                *length = 0;
            return NULL;
        }

        last_offset = fragment_data->offset;
        if (first) {
            size = fragment_data->offset + fragment_data->length;
            data = (guint8 *) wmem_alloc(pinfo->pool, size);

            if (length)
                *length = size;

            first = FALSE;
        }

        memcpy(data + fragment_data->offset, fragment_data->data, fragment_data->length);

        if (fragment_data->offset == 0)
            return data;
        frame_number = fragment_data->data_in_frame - 1;
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
    request_data_t    *request_data;
    guint16            handle;
    bluetooth_uuid_t   uuid;
    guint              mtu;

    uuid.size = 0;
    uuid.bt_uuid = 0;

    bluetooth_data = (bluetooth_data_t *) data;

    if (tvb_reported_length_remaining(tvb, 0) < 1)
        return 0;

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
    offset++;

    request_data = get_request(tvb, offset, pinfo, opcode, bluetooth_data);

    col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(opcode, opcode_vals, "<unknown>"));

    switch (opcode) {
    case 0x01: /* Error Response */
        proto_tree_add_bitmask_with_flags(main_tree, tvb, offset, hf_btatt_req_opcode_in_error, ett_btatt_opcode,  hfx_btatt_opcode, ENC_NA, BMT_NO_APPEND);
        request_opcode = tvb_get_guint8(tvb, offset);
        offset += 1;

        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle_in_error, tvb, offset, bluetooth_data, NULL);

        col_append_fstr(pinfo->cinfo, COL_INFO, " - %s, Handle: 0x%04x",
                        val_to_str_const(tvb_get_guint8(tvb, offset), error_vals, "<unknown>"),
                        tvb_get_letohs(tvb, offset - 2));

        proto_tree_add_item(main_tree, hf_btatt_error_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        if (request_data && (request_opcode == 0x08 || request_opcode == 0x10)) {
            sub_item = proto_tree_add_uint(main_tree, hf_btatt_uuid16, tvb, 0, 0, request_data->parameters.read_by_type.uuid.bt_uuid);
            PROTO_ITEM_SET_GENERATED(sub_item);
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
            guint8  format = tvb_get_guint8(tvb, offset);

            sub_item = proto_tree_add_item(main_tree, hf_btatt_uuid_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;

            if (format == 1) {
                while( tvb_reported_length_remaining(tvb, offset) > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_btatt_information_data, tvb, offset, 4, ENC_NA),
                    sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

                    offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL);
                    handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

                    proto_tree_add_item(sub_tree, hf_btatt_uuid16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    uuid = get_uuid(tvb, offset, 2);
                    offset += 2;

                    proto_item_append_text(sub_item, ", Handle: 0x%04x, UUID: %s",
                            tvb_get_letohs(tvb, offset - 4),
                            print_uuid(&uuid));

                    save_handle(pinfo, uuid, handle, bluetooth_data);
                }
            }
            else if (format == 2) {
                while( tvb_reported_length_remaining(tvb, offset) > 0) {
                    sub_item = proto_tree_add_item(main_tree, hf_btatt_information_data, tvb, offset, 4, ENC_NA),
                    sub_tree = proto_item_add_subtree(sub_item, ett_btatt_list);

                    offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL);
                    handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

                    proto_tree_add_item(sub_tree, hf_btatt_uuid128, tvb, offset, 16, ENC_NA);
                    uuid = get_uuid(tvb, offset, 16);
                    offset += 16;

                    proto_item_append_text(sub_item, ", Handle: 0x%04x, UUID: %s",
                            tvb_get_letohs(tvb, offset - 4),
                            print_uuid(&uuid));

                    save_handle(pinfo, uuid, handle, bluetooth_data);
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

        dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset), 0, uuid, bluetooth_data);

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

            offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL);

            proto_tree_add_item(sub_tree, hf_btatt_group_end_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            if (request_data)
                save_handle(pinfo, request_data->parameters.read_by_type.uuid,
                        tvb_get_guint16(tvb, offset - 4, ENC_LITTLE_ENDIAN),
                        bluetooth_data);

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
        }
        else if (tvb_reported_length_remaining(tvb, offset) == 16) {
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
                        save_handle(pinfo, request_data->parameters.read_by_type.uuid, tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN), bluetooth_data);
                    }

                    offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL);

                    if (request_data) {
                        offset = dissect_attribute_value(sub_tree, sub_item, pinfo, tvb, offset, length - 2, tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN), request_data->parameters.read_by_type.uuid, bluetooth_data);
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
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x", tvb_get_letohs(tvb, offset));

        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL);

        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.read_write.handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);
            request_parameters.read_write.offset = 0;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        break;

    case 0x0b: /* Read Response */
        if (request_data) {
            dissect_handle_uint(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid, request_data->parameters.read_write.handle);
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

            offset = dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset), handle, uuid, bluetooth_data);
        }
        break;

    case 0x0c: /* Read Blob Request */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x, Offset: %u",
                        tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL);

        proto_tree_add_item(main_tree, hf_btatt_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;


        if (!pinfo->fd->flags.visited && bluetooth_data) {
            union request_parameters_union  request_parameters;

            request_parameters.read_write.handle = tvb_get_guint16(tvb, offset - 4, ENC_LITTLE_ENDIAN);
            request_parameters.read_write.offset = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        break;

    case 0x0d: /* Read Blob Response */
        if (request_data) {
            dissect_handle_uint(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid, request_data->parameters.read_write.handle);

            if (request_data->parameters.read_write.offset == 0 && !is_long_attribute_value(uuid)) {
                offset = dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset), request_data->parameters.read_write.handle, uuid, bluetooth_data);
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
                        dissect_attribute_value(sub_tree, NULL, pinfo, next_tvb, 0, tvb_captured_length(next_tvb), request_data->parameters.read_write.handle, uuid, bluetooth_data);
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
            offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL);
            col_append_fstr(pinfo->cinfo, COL_INFO, "0x%04x ", tvb_get_letohs(tvb, offset - 2));
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
                dissect_handle_uint(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid, request_data->parameters.read_multiple.handle[i_handle]);
                offset = dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset), request_data->parameters.read_multiple.handle[i_handle], uuid, bluetooth_data);
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

                    offset = dissect_handle(sub_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL);
                    handle = tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN);

                    proto_tree_add_item(sub_tree, hf_btatt_group_end_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;

                    if (request_data) {
                        offset = dissect_attribute_value(sub_tree, sub_item, pinfo, tvb, offset, length - 4, handle, request_data->parameters.read_by_type.uuid, bluetooth_data);
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
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x", tvb_get_letohs(tvb, offset));

        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid);

        offset = dissect_attribute_value(main_tree, NULL, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset), tvb_get_guint16(tvb, offset - 2, ENC_LITTLE_ENDIAN), uuid, bluetooth_data);

        if (!pinfo->fd->flags.visited && bluetooth_data && (opcode == 0x12 || opcode == 0x1d)) {
            union request_parameters_union  request_parameters;

            request_parameters.data = NULL;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        break;

    case 0x13: /* Write Response */
        /* No parameters */
        break;

    case 0x16: /* Prepare Write Request */
    case 0x17: /* Prepare Write Response */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x, Offset: %u",
                        tvb_get_letohs(tvb, offset), tvb_get_letohs(tvb, offset+2));

        offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, &uuid);

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
                dissect_attribute_value(sub_tree, NULL, pinfo, next_tvb, 0, tvb_captured_length(next_tvb), request_data->parameters.read_write.handle, uuid, bluetooth_data);
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

            request_parameters.data = NULL;

            save_request(pinfo, opcode, request_parameters, bluetooth_data);
        }
        break;

    case 0x19: /* Execute Write Response */
        /* No parameters */
        break;

    case 0xd2: /* Signed Write Command */
        {
            guint8 length;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", Handle: 0x%04x", tvb_get_letohs(tvb, offset));

            offset = dissect_handle(main_tree, pinfo, hf_btatt_handle, tvb, offset, bluetooth_data, NULL);

            length = tvb_reported_length_remaining(tvb, offset);
            if (length > 12) {
                proto_tree_add_item(main_tree, hf_btatt_value, tvb, offset, length-12, ENC_NA);
                offset+=length-12;
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
        if (request_data->request_in_frame > 0  && request_data->request_in_frame != pinfo->fd->num) {
            sub_item = proto_tree_add_uint(main_tree, hf_request_in_frame, tvb, 0, 0, request_data->request_in_frame);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }

        if (!pinfo->fd->flags.visited && request_data->response_in_frame == 0 &&
                pinfo->fd->num > request_data->request_in_frame)
            request_data->response_in_frame = pinfo->fd->num;

        if (request_data->response_in_frame > 0 && request_data->response_in_frame != pinfo->fd->num) {
            sub_item = proto_tree_add_uint(main_tree, hf_response_in_frame, tvb, 0, 0, request_data->response_in_frame);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }
    }

    return offset;
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
            FT_UINT8, BASE_HEX, VALS(error_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btatt_uuid16,
            {"UUID", "btatt.uuid16",
            FT_UINT16, BASE_HEX |BASE_EXT_STRING, &bluetooth_uuid_vals_ext, 0x0,
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
            FT_UINT16, BASE_DEC_HEX, NULL, 0x003F,
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
/* TODO: FT_UINT40 */
        {&hf_btatt_system_id_manufacturer_identifier,
            {"Manufacturer Identifier", "btatt.system_id.manufacturer_identifier",
            FT_UINT64, BASE_HEX, NULL, 0x0,
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
        &ett_btatt_characteristic_properties,
        &ett_btgatt
    };

    static ei_register_info ei[] = {
        { &ei_btatt_uuid_format_unknown, { "btatt.uuid_format.unknown", PI_PROTOCOL, PI_WARN, "Unknown format", EXPFILL }},
        { &ei_btatt_handle_too_few,      { "btatt.handle.too_few",      PI_PROTOCOL, PI_WARN, "Too few handles, should be 2 or more", EXPFILL }},
        { &ei_btatt_mtu_exceeded,        { "btatt.mtu.exceeded",        PI_PROTOCOL, PI_WARN, "Packet size exceed current ATT_MTU", EXPFILL }},
        { &ei_btatt_mtu_full,            { "btatt.mtu.full",            PI_PROTOCOL, PI_NOTE, "Reached ATT_MTU. Attribute value may be longer.", EXPFILL }},
    };

    static build_valid_func btatt_handle_da_build_value[1] = {btatt_handle_value};
    static decode_as_value_t btatt_handle_da_values = {btatt_handle_prompt, 1, btatt_handle_da_build_value};
    static decode_as_t btatt_handle_da = {"btatt", "ATT Handle", "btatt.handle",
            1, 0, &btatt_handle_da_values, NULL, NULL,
            decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    static build_valid_func btatt_uuid16_da_build_value[1] = {btatt_uuid16_value};
    static decode_as_value_t btatt_uuid16_da_values = {btatt_uuid16_prompt, 1, btatt_uuid16_da_build_value};
    static decode_as_t btatt_uuid16_da = {"btatt", "ATT UUID16", "btatt.uuid16",
            1, 0, &btatt_uuid16_da_values, NULL, NULL,
            decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    static build_valid_func btatt_uuid128_da_build_value[1] = {btatt_uuid128_value};
    static decode_as_value_t btatt_uuid128_da_values = {btatt_uuid128_prompt, 1, btatt_uuid128_da_build_value};
    static decode_as_t btatt_uuid128_da = {"btatt", "ATT UUID128", "btatt.uuid128",
            1, 0, &btatt_uuid128_da_values, NULL, NULL,
            decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    /* Register the protocol name and description */
    proto_btatt = proto_register_protocol("Bluetooth Attribute Protocol", "BT ATT", "btatt");

    btatt_handle = new_register_dissector("btatt", dissect_btatt, proto_btatt);

    att_handle_dissector_table  = register_dissector_table("btatt.handle",  "BT ATT Handle",  FT_UINT16, BASE_HEX);
    att_uuid16_dissector_table  = register_dissector_table("btatt.uuid16",  "BT ATT UUID16",  FT_UINT16, BASE_HEX);
    att_uuid128_dissector_table = register_dissector_table("btatt.uuid128", "BT ATT UUID128", FT_STRING,  BASE_NONE);

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
  register_decode_as(&btatt_uuid16_da);
  register_decode_as(&btatt_uuid128_da);
}

void
proto_reg_handoff_btatt(void)
{
    gint i_array;

    usb_hid_boot_keyboard_input_report_handle  = find_dissector("usbhid.boot_report.keyboard.input");
    usb_hid_boot_keyboard_output_report_handle = find_dissector("usbhid.boot_report.keyboard.output");
    usb_hid_boot_mouse_input_report_handle     = find_dissector("usbhid.boot_report.mouse.input");

    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_ATT, btatt_handle);
    dissector_add_uint("btl2cap.cid", BTL2CAP_FIXED_CID_ATT, btatt_handle);

    btatt_tap_handles = register_tap("btatt.handles");

    for (i_array = 0; bluetooth_uuid_vals[i_array].strptr != NULL; i_array += 1) {
        gchar *name;
        gchar *short_name;
        gchar *abbrev;
        dissector_handle_t  handle_tmp;
        gint proto_tmp = -1;

        if (bluetooth_uuid_vals[i_array].value < 0x1800) {
            continue;
        }

        if ((bluetooth_uuid_vals[i_array].value & 0xFF00) == 0x2700) {
            continue;
        }

        name       = wmem_strdup_printf(wmem_epan_scope(), "Bluetooth GATT Attribute %s (UUID 0x%04x)",
                bluetooth_uuid_vals[i_array].strptr, bluetooth_uuid_vals[i_array].value);
        short_name = wmem_strdup_printf(wmem_epan_scope(), "BT GATT %s (UUID 0x%04x)",
                bluetooth_uuid_vals[i_array].strptr, bluetooth_uuid_vals[i_array].value);
        abbrev     = wmem_strdup_printf(wmem_epan_scope(), "btgatt.uuid0x%04x",
                bluetooth_uuid_vals[i_array].value);

        proto_tmp = proto_register_protocol(name, short_name, abbrev);
        handle_tmp = new_register_dissector(short_name, dissect_btgatt, proto_tmp);

        dissector_add_for_decode_as("btatt.handle", handle_tmp);
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
