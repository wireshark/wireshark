/*
 * app_mem_usage.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
