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

WS_DLL_PUBLIC uint32_t
mp2t_get_stream_count(void);

WS_DLL_PUBLIC bool
mp2t_get_sub_stream_id(unsigned stream, unsigned sub_stream, bool le, unsigned *sub_stream_out);

extern char *mp2t_follow_conv_filter(epan_dissect_t *edt, packet_info *pinfo, unsigned *stream, unsigned *sub_stream);
extern char *mp2t_follow_index_filter(unsigned stream, unsigned sub_stream);

#endif /* __PACKET_MP2T_H__ */
