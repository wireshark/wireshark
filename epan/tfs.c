/* tfs.c
 * true_false strings
 * Copyright 2007, Jaap Keuter <jaap.keuter@xs4all.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "tfs.h"

/** Returns the string representing the true or false value. */
const char *tfs_get_string(gboolean value, const true_false_string *tfs)
{
    return value ? tfs->true_string : tfs->false_string;
}

/*
 * A default set of true/false strings that dissectors can use for
 * FT_BOOLEAN header fields.
 */
const true_false_string tfs_true_false = { "True", "False" };
const true_false_string tfs_yes_no = { "Yes", "No" };
const true_false_string tfs_no_yes = { "No", "Yes" };
const true_false_string tfs_set_notset = { "Set", "Not set" };
const true_false_string tfs_enabled_disabled = { "Enabled", "Disabled" };
const true_false_string tfs_disabled_enabled = { "Disabled", "Enabled" };
const true_false_string tfs_ok_error = { "Ok", "Error" };
const true_false_string tfs_error_ok = { "Error", "Ok" };
const true_false_string tfs_success_fail = { "Success", "Fail" };
const true_false_string tfs_fail_success = { "Fail", "Success" };
const true_false_string tfs_on_off = { "On", "Off" };
const true_false_string tfs_ack_nack = { "Ack", "Nack" };
const true_false_string tfs_odd_even = { "Odd", "Even" };
const true_false_string tfs_allow_block = { "Allow", "Block" };
const true_false_string tfs_restricted_allowed = { "Restricted", "Allowed" };
const true_false_string tfs_restricted_not_restricted = { "Restricted", "Not restricted" };
const true_false_string tfs_accept_reject = { "Accept", "Reject" };
const true_false_string tfs_more_nomore = { "More", "No more" };
const true_false_string tfs_present_absent = { "Present", "Absent" };
const true_false_string tfs_present_not_present = { "Present", "Not Present" };
const true_false_string tfs_active_inactive = { "Active", "Inactive" };
const true_false_string tfs_activated_deactivated = { "Activated", "Deactivated" };
const true_false_string tfs_found_not_found = { "Found", "Not found" };
const true_false_string tfs_command_response = { "Command", "Response" };
const true_false_string tfs_response_command = { "Response", "Command" };
const true_false_string tfs_capable_not_capable = { "Capable", "Not capable" };
const true_false_string tfs_supported_not_supported = { "Supported", "Not supported" };
const true_false_string tfs_not_supported_supported = { "Not Supported", "Supported" };
const true_false_string tfs_used_notused = { "Used", "Not used" };
const true_false_string tfs_high_low = { "High", "Low" };
const true_false_string tfs_high_normal = { "High", "Normal" };
const true_false_string tfs_low_normal = { "Low", "Normal" };
const true_false_string tfs_pressed_not_pressed = { "Pressed", "Not pressed" };
const true_false_string tfs_implemented_not_implemented = { "Implemented", "Not Implemented" };
const true_false_string tfs_requested_not_requested = { "Requested", "Not Requested" };
const true_false_string tfs_reliable_not_reliable = { "Reliable", "Not Reliable" };
const true_false_string tfs_allowed_not_allowed = { "Allowed", "Not Allowed" };
const true_false_string tfs_not_allowed_allowed = { "Not Allowed", "Allowed" };
const true_false_string tfs_accepted_not_accepted = { "Accepted", "Not Accepted" };
const true_false_string tfs_detected_not_detected = { "Detected", "Not Detected" };
const true_false_string tfs_available_not_available = { "Available", "Not available" };
const true_false_string tfs_shared_independent = { "Shared", "Independent" };
const true_false_string tfs_valid_invalid = { "Valid", "Invalid" };
const true_false_string tfs_invalid_valid = { "Invalid", "Valid" };
const true_false_string tfs_group_unique_name = { "Group name", "Unique name" };
const true_false_string tfs_inuse_not_inuse = { "In use", "Not in use" };
const true_false_string tfs_critical_not_critical = { "Critical", "Not critical" };
const true_false_string tfs_complete_incomplete = { "Complete", "Incomplete" };
const true_false_string tfs_valid_not_valid = { "Valid", "Not Valid" };
const true_false_string tfs_do_not_clear_clear = { "Do not clear", "Clear" };
const true_false_string tfs_confirmed_unconfirmed = { "Confirmed", "Unconfirmed" };
const true_false_string tfs_enforced_not_enforced = { "Enforced", "Not enforced" };
const true_false_string tfs_possible_not_possible = { "Possible", "Not possible" };
const true_false_string tfs_required_not_required = { "Required", "Not required" };
const true_false_string tfs_registered_not_registered = { "Registered", "Not registered" };
const true_false_string tfs_provisioned_not_provisioned = { "Provisioned", "Not provisioned" };
const true_false_string tfs_included_not_included = { "Included", "Not included" };
const true_false_string tfs_allocated_by_receiver_sender = {"allocated by receiver", "allocated by sender"};
const true_false_string tfs_asynchronous_synchronous = { "Asynchronous", "Synchronous" };
const true_false_string tfs_protocol_sensative_bit_transparent = { "Protocol sensitive", "Bit transparent" };
const true_false_string tfs_full_half = { "Full", "Half" };
const true_false_string tfs_acknowledged_not_acknowledged = { "Acknowledged", "Not Acknowledged" };
const true_false_string tfs_segmentation_no_segmentation = { "Segmentation", "No segmentation" };
const true_false_string tfs_response_request = { "Response", "Request" };
const true_false_string tfs_defined_not_defined = { "Defined", "Not defined" };
const true_false_string tfs_constructed_primitive = { "Constructed", "Primitive" };
const true_false_string tfs_client_server = { "Client", "Server" };
const true_false_string tfs_server_client = { "Server", "Client" };
const true_false_string tfs_preferred_no_preference = { "Preferred", "No preference" };
const true_false_string tfs_encrypt_do_not_encrypt = { "Encrypt", "Do Not Encrypt" };
const true_false_string tfs_down_up = { "Down", "Up" };
const true_false_string tfs_up_down = { "Up", "Down" };
const true_false_string tfs_downlink_uplink = { "Downlink", "Uplink" };
const true_false_string tfs_uplink_downlink = { "Uplink", "Downlink" };
const true_false_string tfs_s2c_c2s = { "Server to Client", "Client to Server" };
const true_false_string tfs_c2s_s2c = { "Client to Server", "Server to Client" };
const true_false_string tfs_open_closed = { "Open", "Closed" };
const true_false_string tfs_external_internal = { "External", "Internal" };
const true_false_string tfs_changed_not_changed = { "Changed", "Not Changed" };
const true_false_string tfs_needed_not_needed = { "Needed", "Not Needed" };
const true_false_string tfs_selected_not_selected = { "Selected", "Not Selected" };
const true_false_string tfs_add_drop = { "Add", "Drop" };
const true_false_string tfs_no_extension_extension = { "No Extension", "Extension" };
const true_false_string tfs_user_provider = { "User", "Provider" };

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
