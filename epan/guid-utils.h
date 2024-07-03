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

#include "ws_symbol_export.h"
#include <wsutil/wmem/wmem.h>

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

WS_DLL_PUBLIC void guids_init(void);

/* add a GUID */
WS_DLL_PUBLIC void guids_add_guid(const e_guid_t *guid, const char *name);

/* remove a guid to name mapping */
WS_DLL_PUBLIC void guids_delete_guid(const e_guid_t *guid);

/* try to get registered name for this GUID */
WS_DLL_PUBLIC const char *guids_get_guid_name(const e_guid_t *guid, wmem_allocator_t *scope);

/* resolve GUID to name (or if unknown to hex string) */
/* (if you need hex string only, use guid_to_str instead) */
WS_DLL_PUBLIC const char* guids_resolve_guid_to_str(const e_guid_t *guid, wmem_allocator_t *scope);

/* add a UUID (dcerpc_init_uuid() will call this too) */
#define guids_add_uuid(uuid, name) guids_add_guid((const e_guid_t *) (uuid), (name))

/* try to get registered name for this UUID */
#define guids_get_uuid_name(uuid, scope) guids_get_guid_name((e_guid_t *) (uuid), scope)

/* resolve UUID to name (or if unknown to hex string) */
/* (if you need hex string only, use guid_to_str instead) */
#define guids_resolve_uuid_to_str(uuid) guids_resolve_guid_to_str((e_guid_t *) (uuid))

WS_DLL_PUBLIC int guid_cmp(const e_guid_t *g1, const e_guid_t *g2);

WS_DLL_PUBLIC unsigned guid_hash(const e_guid_t *guid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __GUID_UTILS_H__ */
