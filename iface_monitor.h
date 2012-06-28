/* iface_monitor.h
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#ifndef IFACE_MONITOR_H
#define IFACE_MONITOR_H

#ifdef HAVE_LIBPCAP

typedef void (*iface_mon_cb)(const char *iface, int up);
int
iface_mon_start(iface_mon_cb cb);

void
iface_mon_stop(void);

int
iface_mon_get_sock(void);

void
iface_mon_event(void);

#endif /* HAVE_LIBPCAP */

#endif /* IFACE_MONITOR_H */
