/* packet-idp.h
 * Declarations for XNS IDP
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_IDP_H__
#define __PACKET_IDP_H__

#define IDP_PACKET_TYPE_RIP	  1
#define IDP_PACKET_TYPE_ECHO	  2
#define IDP_PACKET_TYPE_ERROR	  3
#define IDP_PACKET_TYPE_PEP	  4
#define IDP_PACKET_TYPE_SPP	  5
#define IDP_PACKET_TYPE_PUPLOOKUP 6

#define IDP_SOCKET_RIP            1
#define IDP_SOCKET_ECHO           2
#define IDP_SOCKET_ERROR          3
#define IDP_SOCKET_COURIER        5
#define IDP_SOCKET_TIME           8
#define IDP_SOCKET_PUPLOOKUP      9

/*
 * 3Com SMB-over-XNS?
 */
#define IDP_SOCKET_SMB		0x0bbc

#endif
