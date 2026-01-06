/* init.c
 * Initialization of UI "helper" components
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "init.h"

#include "ui/ui_prefs.h"
#include "ui/language.h"
#include <wsutil/ws_assert.h>

static wmem_allocator_t* ui_scope;

void ui_init(void)
{
    ui_scope = wmem_allocator_new(WMEM_ALLOCATOR_BLOCK);

    ui_prefs_init();
    language_init();
}

void ui_cleanup(void)
{
    language_cleanup();
    ui_prefs_cleanup();

    ws_assert(ui_scope);
    wmem_destroy_allocator(ui_scope);
    ui_scope = NULL;
}


wmem_allocator_t* wmem_ui_scope(void)
{
    ws_assert(ui_scope);
    return ui_scope;
}
