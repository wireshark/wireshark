/* packet-diameter_3gpp.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

static const value_string diameter_3gpp_IKEv2_error_type_vals[] = {
    { 1, "UNSUPPORTED_CRITICAL_PAYLOAD" },
    { 4, "INVALID_IKE_SPI" },
    { 5, "INVALID_MAJOR_VERSION" },
    { 7, "INVALID_SYNTAX" },
    { 9, "INVALID_MESSAGE_ID" },
    { 11, "INVALID_SPI" },
    { 14, "NO_PROPOSAL_CHOSEN" },
    { 17, "INVALID_IKE_PAYLOAD" },
    { 24, "AUTHENTICATION_FAILED" },
    { 34, "SINGLE_PAIR_REQUIRED" },
    { 35, "NO_ADDITIONAL_SAS" },
    { 36, "INTERNAL_ADDRESS_FAILURE" },
    { 37, "FAILED_CP_REQUIRED" },
    { 38, "TS_UNACCEPTABLE" },
    { 39, "INVALID_SELECTORS" },
    { 40, "UNACCEPTABLE_ADDRESSES" },
    { 41, "UNEXPECTED_NAT_DETECTED" },
    { 42, "USE_ASSIGNED_HoA" },
    { 43, "TEMPORARY_FAILURE" },
    { 44, "CHILD_SA_NOT_FOUND" },
    { 45, "INVALID_GROUP_ID" },
    { 46, "AUTHORIZATION_FAILED" },
    { 0, NULL }
};

static const value_string diameter_3gpp_termination_cause_vals[] = {
    { 1, "DIAMETER_LOGOUT" },
    { 2, "DIAMETER_SERVICE_NOT_PROVIDED" },
    { 3, "DIAMETER_BAD_ANSWER" },
    { 4, "DIAMETER_ADMINISTRATIVE" },
    { 5, "DIAMETER_LINK_BROKEN" },
    { 6, "DIAMETER_AUTH_EXPIRED" },
    { 7, "DIAMETER_USER_MOVED" },
    { 8, "DIAMETER_SESSION_TIMEOUT" },
    { 9, "Unassigned" },
    { 10, "Unassigned" },
    { 11, "User Request" },
    { 12, "Lost Carrier" },
    { 13, "Lost Service" },
    { 14, "Idle Timeout" },
    { 15, "Session Timeout" },
    { 16, "Admin Reset" },
    { 17, "Admin Reboot" },
    { 18, "Port Error" },
    { 19, "NAS Error" },
    { 20, "NAS Request" },
    { 21, "NAS Reboot" },
    { 22, "Port Unneeded" },
    { 23, "Port Preempted" },
    { 24, "Port Suspended" },
    { 25, "Service Unavailable" },
    { 26, "Callback" },
    { 27, "User Error" },
    { 28, "Host Request" },
    { 29, "Supplicant Restart" },
    { 30, "Reauthentication Failure" },
    { 31, "Port Reinitialized" },
    { 32, "Port Administratively Disabled" },
    { 0, NULL }
};

int dissect_diameter_3gpp_core_network_restrictions(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, void* data);

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
