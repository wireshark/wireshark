/** @file
 *
 * RTP stream id functions for Wireshark
 *
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RTP_STREAM_ID_H__
#define __RTP_STREAM_ID_H__

/** @file
 *  "RTP Streams" dialog box common routines.
 *  @ingroup main_ui_group
 */

#include <epan/address.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* forward */
struct _rtp_info;

/** Defines an rtp stream identification */
typedef struct _rtpstream_id {
    address         src_addr;
    uint16_t        src_port;
    address         dst_addr;
    uint16_t        dst_port;
    uint32_t        ssrc;
} rtpstream_id_t;

/**
 * Get hash of rtpstream_id
 */
unsigned rtpstream_id_to_hash(const rtpstream_id_t *id);

/**
 * Copy rtpstream_id_t structure
 */
void rtpstream_id_copy(const rtpstream_id_t *src, rtpstream_id_t *dest);

/**
 * Deep copy addresses and ports from pinfo
 */
void rtpstream_id_copy_pinfo(const packet_info *pinfo, rtpstream_id_t *dest, bool swap_src_dst);

/**
 * Shallow copy addresses and ports from pinfo
 * Do not call rtpstream_id_free if you use this function.
 */
void rtpstream_id_copy_pinfo_shallow(const packet_info *pinfo, rtpstream_id_t *dest, bool swap_src_dst);

/**
 * Free memory allocated for id
 * it releases address items only, do not release whole structure!
 */
void rtpstream_id_free(rtpstream_id_t *id);

/**
 * Check if two rtpstream_id_t are equal
 * - compare src_addr, dest_addr, src_port, dest_port
 * - compare other items when requested
 * Note: ssrc is the only other item now, but it is expected it will be extended later
 */
#define RTPSTREAM_ID_EQUAL_NONE		0x0000
#define RTPSTREAM_ID_EQUAL_SSRC		0x0001
bool rtpstream_id_equal(const rtpstream_id_t *id1, const rtpstream_id_t *id2, unsigned flags);

/**
 * Check if rtpstream_id_t is equal to pinfo
 * - compare src_addr, dest_addr, src_port, dest_port with pinfo
 * - if swap_src_dst is true, compare src to dst and vice versa
 */
bool rtpstream_id_equal_pinfo(const rtpstream_id_t *id, const packet_info *pinfo, bool swap_src_dst);

/**
 * Check if rtpstream_id_t is equal to pinfo and rtp_info
 * - compare src_addr, dest_addr, src_port, dest_port with pinfo
 * - compare ssrc with rtp_info
 */
bool rtpstream_id_equal_pinfo_rtp_info(const rtpstream_id_t *id, const packet_info *pinfo, const struct _rtp_info *rtp_info);

/**
 * Get hash of rtpstream_id extracted from packet_info and _rtp_info
 */
unsigned pinfo_rtp_info_to_hash(const packet_info *pinfo, const struct _rtp_info *rtp_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __RTP_STREAM_ID_H__ */
