/*
 * app_mem_usage.h
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
	gsize (*fetch)(void);
	void (*gc)(void);

} ws_mem_usage_t;

WS_DLL_PUBLIC void memory_usage_component_register(const ws_mem_usage_t *component);

WS_DLL_PUBLIC void memory_usage_gc(void);

WS_DLL_PUBLIC const char *memory_usage_get(guint idx, gsize *value);

#endif /* APP_MEM_USAGE_H */
