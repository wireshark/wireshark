/** @file
 * Definitions for GUID handling
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __GUID_UTILS_H__
#define __GUID_UTILS_H__

#include <stdint.h>
#include "ws_symbol_export.h"
#include <epan/wmem_scopes.h>

#define GUID_LEN	16

/* Note: this might be larger than GUID_LEN, so don't overlay data in packets
   with this. */
typedef struct _e_guid_t {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
} e_guid_t;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Initialize the GUID handling component
 *
 * Called during epan initialization, this sets up the GUID table for
 * looked via the UUID type API
 */
WS_DLL_PUBLIC void guids_init(void);

/**
 * @brief Add a GUID
 *
 * Adds the GUID to name mapping item
 *
 * @param guid GUID value
 * @param name Friendly name associated with the GUID
 */
WS_DLL_PUBLIC void guids_add_guid(const e_guid_t *guid, const char *name);

/**
 * @brief Remove a GUID to name mapping
 *
 * Remove the GUID to name mapping item from the current table
 *
 * @param guid GUID value
 */
WS_DLL_PUBLIC void guids_delete_guid(const e_guid_t *guid);

/**
 * @brief Retrieve name for GUID value
 *
 * Retrieve the registered name for this GUID; uses the scope for the fallback case only
 *
 * @param guid GUID value
 * @param scope memory scope the name should be returned in
 * @return GUID name if found, NULL otherwise
 */
WS_DLL_PUBLIC const char *guids_get_guid_name(const e_guid_t *guid, wmem_allocator_t *scope);

/**
 * @brief Retrieve name for GUID value
 *
 * Tries to match a guid against its name, returns the associated string ptr on a match.
 * Formats uuid number and returns the resulting string via wmem scope, if name is unknown.
 *
 * (if you need hex string only, use guid_to_str instead)
 *
 * @param guid GUID value
 * @param scope memory scope the name should be returned in
 * @return GUID name if found, hex string otherwise
 */
WS_DLL_PUBLIC const char* guids_resolve_guid_to_str(const e_guid_t *guid, wmem_allocator_t *scope);

/**
 * @brief Compare two GUID values
 *
 * Compare two GUID values for sorting purposes
 *
 * @param g1 First GUID value
 * @param g2 Second GUID value
 * @return 1 if g1 > g2, -1 if g1 < g2, 0 if g1 == g2
 */
WS_DLL_PUBLIC int guid_cmp(const e_guid_t *g1, const e_guid_t *g2);

/**
 * @brief Created 32-bit hash value for GUID
 *
 * Take the first 8 bytes of the GUID and create hash value from it
 *
 * @param guid GUID value to hash
 * @return Hash value for GUID
 */
WS_DLL_PUBLIC unsigned guid_hash(const e_guid_t *guid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __GUID_UTILS_H__ */
