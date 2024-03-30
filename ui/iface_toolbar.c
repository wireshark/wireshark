/* iface_toolbar.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "iface_toolbar.h"


static iface_toolbar_add_cb_t iface_toolbar_add_cb;
static iface_toolbar_remove_cb_t iface_toolbar_remove_cb;

void iface_toolbar_add(const iface_toolbar *toolbar)
{
    if (iface_toolbar_add_cb) {
        iface_toolbar_add_cb(toolbar);
    }
}

void iface_toolbar_remove(const char *menu_title)
{
    if (iface_toolbar_remove_cb) {
        iface_toolbar_remove_cb(menu_title);
    }
}

bool iface_toolbar_use(void)
{
    return iface_toolbar_add_cb ? true : false;
}

void iface_toolbar_register_cb(iface_toolbar_add_cb_t add_cb, iface_toolbar_remove_cb_t remove_cb)
{
    iface_toolbar_add_cb = add_cb;
    iface_toolbar_remove_cb = remove_cb;
}
