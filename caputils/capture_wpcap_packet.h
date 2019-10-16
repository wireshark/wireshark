/* capture_wpcap_packet.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_WPCAP_PACKET_H
#define CAPTURE_WPCAP_PACKET_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* CAPTURE_WPCAP_PACKET_H */
