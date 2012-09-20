/* gtk_iface_monitor.c
 * interface monitor by Pontus Fuchs <pontus.fuchs@gmail.com>
 *
 * $Id$
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

#ifdef HAVE_LIBPCAP

#include <string.h>

#include <glib.h>

#include "../../iface_monitor.h"

#include "capture_opts.h"

#include "ui/capture_globals.h"
#include "ui/iface_lists.h"

#include "ui/gtk/capture_dlg.h"

GIOChannel *iface_mon_channel;

static void
gtk_iface_mon_event_cb(const char *iface, int up)
{
    int present = 0;
    guint ifs;
    interface_t device;

    for (ifs = 0; ifs < global_capture_opts.all_ifaces->len; ifs++) {
      device = g_array_index(global_capture_opts.all_ifaces, interface_t, ifs);
      if (!strcmp(device.name, iface))
          present = 1;
    }

    if (present == up)
        return;

    refresh_local_interface_lists();
}

static gboolean
gtk_iface_mon_event(GIOChannel *source _U_, GIOCondition condition _U_, gpointer data _U_)
{
    iface_mon_event();
    return TRUE;
}

int
gtk_iface_mon_start(void)
{
    int sock, err;
    err = iface_mon_start(&gtk_iface_mon_event_cb);
    if (err)
        return err;
    sock = iface_mon_get_sock();

    iface_mon_channel = g_io_channel_unix_new(sock);
    g_io_channel_set_encoding(iface_mon_channel, NULL, NULL);
    g_io_add_watch(iface_mon_channel,
                             G_IO_IN|G_IO_ERR|G_IO_HUP,
                             &gtk_iface_mon_event,
                             NULL);
    return 0;
}

int
gtk_iface_mon_stop(void)
{
    iface_mon_stop();
    return 0;
}

#endif /* HAVE_LIBPCAP */
