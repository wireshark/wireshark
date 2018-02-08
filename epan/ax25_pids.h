/* ax25_pids.h
 *
 * Protocol IDs for Amateur Packet Radio protocol dissection
 * Copyright 2005,2006,2007,2008,2009,2010,2012 R.W. Stearn <richard@rns-stearn.demon.co.uk>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __AX25_PIDS_H__
#define __AX25_PIDS_H__

/* AX.25 Layer 3 Protocol ID's (pid) */
#define AX25_P_ROSE	0x01	/* ISO 8208 / CCITT X.25 PLP */
#define AX25_P_RFC1144C	0x06	/* Compressed TCP/IP packet. Van Jacobson RFC1144 */
#define AX25_P_RFC1144	0x07	/* Uncompressed TCP/IP packet. Van Jacobson RFC1144 */
#define AX25_P_SEGMENT	0x08	/* segmentation fragment */
#define AX25_P_TEXNET	0xC3	/* TEXNET datagram */
#define AX25_P_LCP	0xC4	/* Link Quality Protocol */
#define AX25_P_ATALK	0xCA	/* AppleTalk */
#define AX25_P_ATALKARP	0xCB	/* AppleTalk ARP */
#define AX25_P_IP	0xCC	/* ARPA Internet Protocol */
#define AX25_P_ARP	0xCD	/* ARPA Address Resolution Protocol */
#define AX25_P_FLEXNET 	0xCE	/* FlexNet */
#define AX25_P_NETROM 	0xCF	/* NET/ROM */
#define AX25_P_NO_L3 	0xF0	/* No layer 3 protocol */
#define AX25_P_L3_ESC 	0xFF	/* Escape character. Next octet contains more layer 3 protocol info */

#endif /* __AX25_PIDS_H__ */
