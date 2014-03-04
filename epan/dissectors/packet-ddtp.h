/* packet-ddtp.h
 * Routines for DDTP (Dynamic DNS Tools Protocol) packet disassembly
 * see http://ddt.sourceforge.net/
 * Olivier Abad <oabad@noos.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *
 */

#ifndef __PACKET_DDTP_H__
#define __PACKET_DDTP_H__

#define DDTP_VERSION_ERROR	0
#define DDTP_VERSION_4		1
#define DDTP_VERSION_5		2

#define DDTP_ENCRYPT_ERROR	0
#define DDTP_ENCRYPT_PLAINTEXT	1
#define DDTP_ENCRYPT_BLOWFISH	2

#define DDTP_MESSAGE_ERROR	0
#define DDTP_UPDATE_QUERY	1
#define DDTP_UPDATE_REPLY	2
#define DDTP_ALIVE_QUERY	3
#define DDTP_ALIVE_REPLY	4

#define DDTP_MARK_ONLINE	0
#define DDTP_MARK_OFFLINE	1

#define DDTP_UPDATE_SUCCEEDED	0
#define DDTP_UPDATE_FAILED	1
#define DDTP_INVALID_PASSWORD	2
#define DDTP_INVALID_ACCOUNT	3
#define DDTP_INVALID_OPCODE	4

#endif
