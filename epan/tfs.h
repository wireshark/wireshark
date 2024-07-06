/* tfs.h
 * true_false strings
 * Copyright 2007, Jaap Keuter <jaap.keuter@xs4all.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TFS_H__
#define __TFS_H__

#include <stdbool.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * true_false strings
 */

/** Struct for boolean representation */
typedef struct true_false_string {
    const char *true_string;   /**< The string presented when true  */
    const char *false_string;  /**< The string presented when false */
} true_false_string;

/** Returns the string representing the true or false value.
 *
 * From the given true_false_string return the appropriate string pointer
 * @param[in] value The boolean value for which the string representation is sought
 * @param[in] tfs   The true_false_string containing the relevant strings
 * @return          Pointer to the appropriate string
 */
WS_DLL_PUBLIC const char *tfs_get_string(bool value, const true_false_string *tfs);

#define tfs_get_true_false(value)   tfs_get_string(value, NULL)

/*
 * A default set of true/false strings that dissectors can use for
 * FT_BOOLEAN header fields. By default { "True", "False" } is used.
 */
WS_DLL_PUBLIC const true_false_string tfs_yes_no;
WS_DLL_PUBLIC const true_false_string tfs_no_yes;
WS_DLL_PUBLIC const true_false_string tfs_set_notset;
WS_DLL_PUBLIC const true_false_string tfs_enabled_disabled;
WS_DLL_PUBLIC const true_false_string tfs_disabled_enabled;
WS_DLL_PUBLIC const true_false_string tfs_ok_error;
WS_DLL_PUBLIC const true_false_string tfs_error_ok;
WS_DLL_PUBLIC const true_false_string tfs_success_fail;
WS_DLL_PUBLIC const true_false_string tfs_fail_success;
WS_DLL_PUBLIC const true_false_string tfs_on_off;
WS_DLL_PUBLIC const true_false_string tfs_off_on;
WS_DLL_PUBLIC const true_false_string tfs_ack_nack;
WS_DLL_PUBLIC const true_false_string tfs_odd_even;
WS_DLL_PUBLIC const true_false_string tfs_allow_block;
WS_DLL_PUBLIC const true_false_string tfs_restricted_not_restricted;
WS_DLL_PUBLIC const true_false_string tfs_not_restricted_restricted;
WS_DLL_PUBLIC const true_false_string tfs_accept_reject;
WS_DLL_PUBLIC const true_false_string tfs_more_nomore;
WS_DLL_PUBLIC const true_false_string tfs_present_absent;
WS_DLL_PUBLIC const true_false_string tfs_present_not_present;
WS_DLL_PUBLIC const true_false_string tfs_active_inactive;
WS_DLL_PUBLIC const true_false_string tfs_activated_deactivated;
WS_DLL_PUBLIC const true_false_string tfs_found_not_found;
WS_DLL_PUBLIC const true_false_string tfs_command_response;
WS_DLL_PUBLIC const true_false_string tfs_response_command;
WS_DLL_PUBLIC const true_false_string tfs_capable_not_capable;
WS_DLL_PUBLIC const true_false_string tfs_supported_not_supported;
WS_DLL_PUBLIC const true_false_string tfs_not_supported_supported;
WS_DLL_PUBLIC const true_false_string tfs_used_notused;
WS_DLL_PUBLIC const true_false_string tfs_high_low;
WS_DLL_PUBLIC const true_false_string tfs_high_normal;
WS_DLL_PUBLIC const true_false_string tfs_low_normal;
WS_DLL_PUBLIC const true_false_string tfs_pressed_not_pressed;
WS_DLL_PUBLIC const true_false_string tfs_implemented_not_implemented;
WS_DLL_PUBLIC const true_false_string tfs_requested_not_requested;
WS_DLL_PUBLIC const true_false_string tfs_reliable_not_reliable;
WS_DLL_PUBLIC const true_false_string tfs_allowed_not_allowed;
WS_DLL_PUBLIC const true_false_string tfs_not_allowed_allowed;
WS_DLL_PUBLIC const true_false_string tfs_accepted_not_accepted;
WS_DLL_PUBLIC const true_false_string tfs_detected_not_detected;
WS_DLL_PUBLIC const true_false_string tfs_available_not_available;
WS_DLL_PUBLIC const true_false_string tfs_shared_independent;
WS_DLL_PUBLIC const true_false_string tfs_valid_invalid;
WS_DLL_PUBLIC const true_false_string tfs_invalid_valid;
WS_DLL_PUBLIC const true_false_string tfs_group_unique_name;
WS_DLL_PUBLIC const true_false_string tfs_inuse_not_inuse;
WS_DLL_PUBLIC const true_false_string tfs_critical_not_critical;
WS_DLL_PUBLIC const true_false_string tfs_complete_incomplete;
WS_DLL_PUBLIC const true_false_string tfs_valid_not_valid;
WS_DLL_PUBLIC const true_false_string tfs_do_not_clear_clear;
WS_DLL_PUBLIC const true_false_string tfs_confirmed_unconfirmed;
WS_DLL_PUBLIC const true_false_string tfs_enforced_not_enforced;
WS_DLL_PUBLIC const true_false_string tfs_possible_not_possible;
WS_DLL_PUBLIC const true_false_string tfs_required_not_required;
WS_DLL_PUBLIC const true_false_string tfs_registered_not_registered;
WS_DLL_PUBLIC const true_false_string tfs_provisioned_not_provisioned;
WS_DLL_PUBLIC const true_false_string tfs_included_not_included;
WS_DLL_PUBLIC const true_false_string tfs_allocated_by_receiver_sender;
WS_DLL_PUBLIC const true_false_string tfs_asynchronous_synchronous;
WS_DLL_PUBLIC const true_false_string tfs_protocol_sensative_bit_transparent;
WS_DLL_PUBLIC const true_false_string tfs_full_half;
WS_DLL_PUBLIC const true_false_string tfs_acknowledged_not_acknowledged;
WS_DLL_PUBLIC const true_false_string tfs_segmentation_no_segmentation;
WS_DLL_PUBLIC const true_false_string tfs_response_request;
WS_DLL_PUBLIC const true_false_string tfs_defined_not_defined;
WS_DLL_PUBLIC const true_false_string tfs_constructed_primitive;
WS_DLL_PUBLIC const true_false_string tfs_client_server;
WS_DLL_PUBLIC const true_false_string tfs_server_client;
WS_DLL_PUBLIC const true_false_string tfs_preferred_no_preference;
WS_DLL_PUBLIC const true_false_string tfs_encrypt_do_not_encrypt;
WS_DLL_PUBLIC const true_false_string tfs_down_up;
WS_DLL_PUBLIC const true_false_string tfs_up_down;
WS_DLL_PUBLIC const true_false_string tfs_uplink_downlink;
WS_DLL_PUBLIC const true_false_string tfs_s2c_c2s;
WS_DLL_PUBLIC const true_false_string tfs_open_closed;
WS_DLL_PUBLIC const true_false_string tfs_external_internal;
WS_DLL_PUBLIC const true_false_string tfs_changed_not_changed;
WS_DLL_PUBLIC const true_false_string tfs_needed_not_needed;
WS_DLL_PUBLIC const true_false_string tfs_selected_not_selected;
WS_DLL_PUBLIC const true_false_string tfs_add_drop;
WS_DLL_PUBLIC const true_false_string tfs_no_extension_extension;
WS_DLL_PUBLIC const true_false_string tfs_user_provider;
WS_DLL_PUBLIC const true_false_string tfs_applicable_not_applicable;
WS_DLL_PUBLIC const true_false_string tfs_current_not_yet;
WS_DLL_PUBLIC const true_false_string tfs_should_be_traced_should_not_be_traced;
WS_DLL_PUBLIC const true_false_string tfs_activate_do_not_activate;
WS_DLL_PUBLIC const true_false_string tfs_data_pdu_control_pdu;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TFS_H__ */

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
