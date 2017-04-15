/* iface_toolbar.cpp
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

void iface_toolbar_remove(const gchar *menu_title)
{
    if (iface_toolbar_remove_cb) {
        iface_toolbar_remove_cb(menu_title);
    }
}

gboolean iface_toolbar_use(void)
{
    return iface_toolbar_add_cb ? TRUE : FALSE;
}

void iface_toolbar_register_cb(iface_toolbar_add_cb_t add_cb, iface_toolbar_remove_cb_t remove_cb)
{
    iface_toolbar_add_cb = add_cb;
    iface_toolbar_remove_cb = remove_cb;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
