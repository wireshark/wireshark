/** @file
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

#ifndef __PACKET_AX25_H__
#define __PACKET_AX25_H__

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

/*
 * Key for p_add_proto_data(pinfo->pool, pinfo, proto_ax25, ...).
 *
 * An encapsulating dissector that knows which radio port a frame came
 * from (KISS) stores GUINT_TO_POINTER(port + 1) under this key just
 * before calling the AX.25 dissector. The AX.25 dissector consumes and
 * removes it, and uses the port as part of the link (conversation) key.
 *
 * The data pointer isn't used for this because the AX.25 dissector is
 * also reached through wtap_encap and ip.proto, whose callers pass data
 * pointers of their own.
 */
#define AX25_PROTO_DATA_PORT	0x80000001U

/*
 * Same mechanism: GUINT_TO_POINTER(n) when the last n octets handed to
 * the AX.25 dissector aren't part of the AX.25 frame (a KISS checksum).
 * They are still dissected as before; AX.25 only leaves them out where
 * the length of the frame matters.
 */
#define AX25_PROTO_DATA_TRAILER	0x80000003U

#endif /* __PACKET_AX25_H__ */
