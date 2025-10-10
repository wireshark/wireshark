/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __APP_MEM_USAGE_H__
#define __APP_MEM_USAGE_H__

#include "ws_symbol_export.h"

typedef struct {
	const char *name;
	size_t (*fetch)(void);
	void (*gc)(void);

} ws_mem_usage_t;

WS_DLL_PUBLIC void memory_usage_component_register(const ws_mem_usage_t *component);

WS_DLL_PUBLIC void memory_usage_gc(void);

WS_DLL_PUBLIC const char *memory_usage_get(unsigned idx, size_t *value);

#endif /* APP_MEM_USAGE_H */
