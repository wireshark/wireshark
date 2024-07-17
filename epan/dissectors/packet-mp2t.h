/* packet-mp2t.h
 *
 * Routines for RFC 2250 MPEG2 (ISO/IEC 13818-1) Transport Stream dissection
 *
 * Copyright 2006, Erwin Rol <erwin@erwinrol.com>
 * Copyright 2012-2014, Guy Martin <gmsoft@tuxicoman.be>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_MP2T_H__
#define __PACKET_MP2T_H__

/* The MPEG2 TS packet size */
#define MP2T_PACKET_SIZE 188
#define MP2T_SYNC_BYTE   0x47

extern void
mp2t_add_stream_type(packet_info *pinfo, uint32_t pid, uint32_t stream_type);

#endif /* __PACKET_MP2T_H__ */
