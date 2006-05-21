/* capture_wpcap_packet.h
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2001 Gerald Combs
 *
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

#ifndef CAPTURE_WPCAP_PACKET_H
#define CAPTURE_WPCAP_PACKET_H


extern void wpcap_packet_load(void);

/* get the packet.dll version info */
extern char *wpcap_packet_get_version(void);

/* open the interface */
extern void * wpcap_packet_open(char *if_name);

/* close the interface */
extern void wpcap_packet_close(void * adapter);

extern int wpcap_packet_request(void *a, ULONG Oid, int set, char *value, unsigned int *length);

extern int wpcap_packet_request_uint(void *a, ULONG Oid, UINT *value);

extern int wpcap_packet_request_ulong(void *a, ULONG Oid, ULONG *value);


#endif  /* CAPTURE_WPCAP_PACKET_H */
