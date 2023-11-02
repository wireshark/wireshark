/* wtap_opttypes.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include "secrets-types.h"

const char* secrets_type_description(uint32_t type)
{
#if 0
    /* value_string from file-pcapng.c
     * XXX: value_string is defined in epan. Perhaps some of the
     * functions (not the ones that allocate in wmem_packet_scope())
     * should be moved to wsutil so that other libraries can use them
     * (capinfos, etc. don't link with libwireshark).
     */
    static const value_string secrets_types_vals[] = {
        { SECRETS_TYPE_TLS,             "TLS Key Log" },
        { SECRETS_TYPE_SSH,             "SSH Key Log" },
        { SECRETS_TYPE_WIREGUARD,       "WireGuard Key Log" },
        { SECRETS_TYPE_ZIGBEE_NWK_KEY,  "Zigbee NWK Key" },
        { SECRETS_TYPE_ZIGBEE_APS_KEY,  "Zigbee APS Key" },
        { SECRETS_TYPE_OPCUA,           "OPC UA Key Log" },
        { 0, NULL }
    };
    return val_to_str_const(type, secrets_types_vals, "Unknown");
#endif
    switch (type) {
        case SECRETS_TYPE_TLS:
            return "TLS Key Log";
        case SECRETS_TYPE_SSH:
            return "SSH Key Log";
        case SECRETS_TYPE_WIREGUARD:
            return "WireGuard Key Log";
        case SECRETS_TYPE_ZIGBEE_NWK_KEY:
            return "Zigbee NWK Key";
        case SECRETS_TYPE_ZIGBEE_APS_KEY:
            return "Zigbee APS Key";
        case SECRETS_TYPE_OPCUA:
            return "OPC UA Key Log";
        default:
            return "Unknown";
    }
}
