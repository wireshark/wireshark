/* guid-utils.h
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

#define GUID_LEN	16

/* Note: this might be larger than GUID_LEN, so don't overlay data in packets
   with this. */
typedef struct _e_guid_t {
    guint32 data1;
    guint16 data2;
    guint16 data3;
    guint8  data4[8];
} e_guid_t;


WS_DLL_PUBLIC void guids_init(void);

/* add a GUID */
WS_DLL_PUBLIC void guids_add_guid(const e_guid_t *guid, const gchar *name);

/* try to get registered name for this GUID */
WS_DLL_PUBLIC const gchar *guids_get_guid_name(const e_guid_t *guid);

/* resolve GUID to name (or if unknown to hex string) */
/* (if you need hex string only, use guid_to_str instead) */
WS_DLL_PUBLIC const gchar* guids_resolve_guid_to_str(const e_guid_t *guid);

/* add a UUID (dcerpc_init_uuid() will call this too) */
#define guids_add_uuid(uuid, name) guids_add_guid((const e_guid_t *) (uuid), (name))

/* try to get registered name for this UUID */
#define guids_get_uuid_name(uuid) guids_get_guid_name((e_guid_t *) (uuid))

/* resolve UUID to name (or if unknown to hex string) */
/* (if you need hex string only, use guid_to_str instead) */
#define guids_resolve_uuid_to_str(uuid) guids_resolve_guid_to_str((e_guid_t *) (uuid))

WS_DLL_PUBLIC int guid_cmp(const e_guid_t *g1, const e_guid_t *g2);

#endif /* __GUID_UTILS_H__ */
