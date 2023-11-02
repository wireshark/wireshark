/** @file
 *
 * Identifiers used by Decryption Secrets Blocks (DSB).
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SECRETS_TYPES_H__
#define __SECRETS_TYPES_H__

#include "ws_symbol_export.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Type describing the format of the opaque secrets value in a pcapng DSB.
 */
#define SECRETS_TYPE_TLS            0x544c534b /* TLS Key Log */
#define SECRETS_TYPE_SSH            0x5353484b /* SSH Key Log */
#define SECRETS_TYPE_WIREGUARD      0x57474b4c /* WireGuard Key Log */
#define SECRETS_TYPE_ZIGBEE_NWK_KEY 0x5a4e574b /* Zigbee NWK Key */
#define SECRETS_TYPE_ZIGBEE_APS_KEY 0x5a415053 /* Zigbee APS Key */
#define SECRETS_TYPE_OPCUA          0x55414b4c /* OPC UA Key Log */

WS_DLL_PUBLIC
const char* secrets_type_description(uint32_t type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SECRETS_TYPES_H__ */
