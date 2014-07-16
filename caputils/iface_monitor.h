/* iface_monitor.h
 * interface monitor by Pontus Fuchs <pontus.fuchs@gmail.com>
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
#ifndef IFACE_MONITOR_H
#define IFACE_MONITOR_H

#ifdef HAVE_LIBPCAP

/*
 * Callback for interface changes.
 *
 * iface is a pointer to the name of the interface.
 *
 * up is 1 if the interface is up, 0 if it's down.
 *
 * XXX - we really want "gone", not "down", where "gone" may include
 * "down" if the OS requires an interface to be up in order to start
 * a capture on it (as is the case in Linux and in OS X prior to
 * Lion), but should also include *gone*, as in "there is no longer
 * an interface with this name, so it's neither down nor up".
 *
 * We also may want other events, such as address changes, so what
 * we might want is "add", "remove", and "modify" as the events.
 */
typedef void (*iface_mon_cb)(const char *iface, int up);

/*
 * Start watching for interface changes.
 */
int
iface_mon_start(iface_mon_cb cb);

/*
 * Stop watching for interface changes.
 */
void
iface_mon_stop(void);

/*
 * Get the socket on which interface changes are delivered, so that
 * we can add it to the event loop.
 *
 * XXX - what if it's not a socket or other file descriptor?
 */
int
iface_mon_get_sock(void);

/*
 * Call this if something is readable from the interface change socket.
 * It will call the callback as appropriate.
 */
void
iface_mon_event(void);

#endif /* HAVE_LIBPCAP */

#endif /* IFACE_MONITOR_H */
