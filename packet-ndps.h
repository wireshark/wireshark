/* packet-ipx.h
 * Routines for NetWare's NDPS
 * Greg Morris <gmorris@novell.com>
 *
 * $Id: packet-ndps.h,v 1.1 2002/09/23 17:14:54 jmayer Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@etheeal.com>
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
#define NDPS_HEADER_LEN 16

#define TCP_PORT_PA                     0x0d44 /* NDPS Printer Agent */
#define TCP_PORT_BROKER                 0x0bc6 /* NDPS Broker */
#define TCP_PORT_SRS                    0x0bca /* NDPS Service Registry Service */
#define TCP_PORT_ENS                    0x0bc8 /* NDPS Event Notification Service */
#define TCP_PORT_RMS                    0x0bcb /* NDPS Remote Management Service */
#define TCP_PORT_NOTIFY_LISTENER        0x0bc9 /* NDPS Notify Listener */
