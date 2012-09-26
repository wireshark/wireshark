/* tfs.h
 * true_false strings
 * Copyright 2007, Jaap Keuter <jaap.keuter@xs4all.nl>
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

#ifndef __TFS_H__
#define __TFS_H__

/** @file
 * true_false strings
 */

/** Struct for boolean enumerations */
typedef struct true_false_string {
        const char      *true_string;	/**< The string presented when true  */
        const char      *false_string;	/**< The string presented when false */
} true_false_string;

/*
 * A default set of true/false strings that dissectors can use for
 * FT_BOOLEAN header fields.
 */
WS_VAR_IMPORT const true_false_string tfs_true_false;
WS_VAR_IMPORT const true_false_string tfs_yes_no;
WS_VAR_IMPORT const true_false_string tfs_no_yes;
WS_VAR_IMPORT const true_false_string tfs_set_notset;
WS_VAR_IMPORT const true_false_string tfs_enabled_disabled;
WS_VAR_IMPORT const true_false_string tfs_disabled_enabled;
WS_VAR_IMPORT const true_false_string tfs_ok_error;
WS_VAR_IMPORT const true_false_string tfs_error_ok;
WS_VAR_IMPORT const true_false_string tfs_success_fail;
WS_VAR_IMPORT const true_false_string tfs_fail_success;
WS_VAR_IMPORT const true_false_string tfs_on_off;
WS_VAR_IMPORT const true_false_string tfs_ack_nack;
WS_VAR_IMPORT const true_false_string tfs_odd_even;
WS_VAR_IMPORT const true_false_string tfs_allow_block;
WS_VAR_IMPORT const true_false_string tfs_restricted_allowed;
WS_VAR_IMPORT const true_false_string tfs_accept_reject;
WS_VAR_IMPORT const true_false_string tfs_more_nomore;
WS_VAR_IMPORT const true_false_string tfs_present_absent;
WS_VAR_IMPORT const true_false_string tfs_present_not_present;
WS_VAR_IMPORT const true_false_string tfs_active_inactive;
WS_VAR_IMPORT const true_false_string tfs_found_not_found;
WS_VAR_IMPORT const true_false_string tfs_command_response;
WS_VAR_IMPORT const true_false_string tfs_capable_not_capable;
WS_VAR_IMPORT const true_false_string tfs_supported_not_supported;
WS_VAR_IMPORT const true_false_string tfs_used_notused;
WS_VAR_IMPORT const true_false_string tfs_high_low;
WS_VAR_IMPORT const true_false_string tfs_pressed_not_pressed;
WS_VAR_IMPORT const true_false_string tfs_implemented_not_implemented;
WS_VAR_IMPORT const true_false_string tfs_requested_not_requested;
WS_VAR_IMPORT const true_false_string tfs_reliable_not_reliable;
WS_VAR_IMPORT const true_false_string tfs_allowed_not_allowed;
WS_VAR_IMPORT const true_false_string tfs_not_allowed_allowed;
WS_VAR_IMPORT const true_false_string tfs_accepted_not_accepted;
WS_VAR_IMPORT const true_false_string tfs_detected_not_detected;
WS_VAR_IMPORT const true_false_string tfs_available_not_available;
WS_VAR_IMPORT const true_false_string tfs_shared_independent;
WS_VAR_IMPORT const true_false_string tfs_valid_invalid;
WS_VAR_IMPORT const true_false_string tfs_group_unique_name;
#endif
