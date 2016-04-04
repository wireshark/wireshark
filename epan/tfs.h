/* tfs.h
 * true_false strings
 * Copyright 2007, Jaap Keuter <jaap.keuter@xs4all.nl>
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

#ifndef __TFS_H__
#define __TFS_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * true_false strings
 */

/** Struct for boolean enumerations */
typedef struct true_false_string {
        const char      *true_string;   /**< The string presented when true  */
        const char      *false_string;  /**< The string presented when false */
} true_false_string;

/*
 * A default set of true/false strings that dissectors can use for
 * FT_BOOLEAN header fields.
 */
WS_DLL_PUBLIC const true_false_string tfs_true_false;
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
WS_DLL_PUBLIC const true_false_string tfs_ack_nack;
WS_DLL_PUBLIC const true_false_string tfs_odd_even;
WS_DLL_PUBLIC const true_false_string tfs_allow_block;
WS_DLL_PUBLIC const true_false_string tfs_restricted_allowed;
WS_DLL_PUBLIC const true_false_string tfs_accept_reject;
WS_DLL_PUBLIC const true_false_string tfs_more_nomore;
WS_DLL_PUBLIC const true_false_string tfs_present_absent;
WS_DLL_PUBLIC const true_false_string tfs_present_not_present;
WS_DLL_PUBLIC const true_false_string tfs_active_inactive;
WS_DLL_PUBLIC const true_false_string tfs_found_not_found;
WS_DLL_PUBLIC const true_false_string tfs_command_response;
WS_DLL_PUBLIC const true_false_string tfs_response_command;
WS_DLL_PUBLIC const true_false_string tfs_capable_not_capable;
WS_DLL_PUBLIC const true_false_string tfs_supported_not_supported;
WS_DLL_PUBLIC const true_false_string tfs_used_notused;
WS_DLL_PUBLIC const true_false_string tfs_high_low;
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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TFS_H__ */
