/* chdlctypes.h
 * Defines Cisco HDLC packet types that aren't just Ethernet types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CHDLCTYPES_H__
#define __CHDLCTYPES_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CHDLCTYPE_FRARP		0x0808	/* Frame Relay ARP */
#define CHDLCTYPE_BPDU		0x4242	/* IEEE spanning tree protocol */
#define CHDLCTYPE_OSI 	        0xfefe  /* ISO network-layer protocols */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* chdlctypes.h */
