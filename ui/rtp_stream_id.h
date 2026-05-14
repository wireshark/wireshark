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
 * @brief Get hash of rtpstream_id
 * @param id The RTP stream ID for which to calculate the hash.
 * @return The hash value of the RTP stream ID.
 */
unsigned rtpstream_id_to_hash(const rtpstream_id_t *id);

/**
 * @brief Copy rtpstream_id_t structure
 * @param src The source RTP stream ID.
 * @param dest The destination RTP stream ID.
 */
void rtpstream_id_copy(const rtpstream_id_t *src, rtpstream_id_t *dest);

/**
 * @brief Deep copy addresses and ports from pinfo
 * @param pinfo The packet information containing source and destination addresses and ports.
 * @param dest The destination RTP stream ID.
 * @param swap_src_dst Whether to swap source and destination for copying.
 */
void rtpstream_id_copy_pinfo(const packet_info *pinfo, rtpstream_id_t *dest, bool swap_src_dst);

/**
 * @brief Shallow copy addresses and ports from pinfo
 *
 * Do not call rtpstream_id_free if you use this function.
 *
 * @param pinfo The packet information containing source and destination addresses and ports.
 * @param dest The destination RTP stream ID.
 * @param swap_src_dst Whether to swap source and destination for copying.
 */
void rtpstream_id_copy_pinfo_shallow(const packet_info *pinfo, rtpstream_id_t *dest, bool swap_src_dst);

/**
 * @brief Free memory allocated for id
 * it releases address items only, do not release whole structure!
 *
 * @param id The RTP stream ID to free.
 */
void rtpstream_id_free(rtpstream_id_t *id);

#define RTPSTREAM_ID_EQUAL_NONE		0x0000
#define RTPSTREAM_ID_EQUAL_SSRC		0x0001

/**
 * @brief Compare two RTP stream IDs for equality.
 *
 *  * Check if two rtpstream_id_t are equal
 * - compare src_addr, dest_addr, src_port, dest_port
 * - compare other items when requested
 * Note: ssrc is the only other item now, but it is expected it will be extended later
 *
 * Compares two RTP stream IDs based on their source and destination addresses, ports, and optionally SSRC.
 *
 * @param id1 Pointer to the first RTP stream ID.
 * @param id2 Pointer to the second RTP stream ID.
 * @param flags Flags indicating which fields to compare (e.g., RTPSTREAM_ID_EQUAL_SSRC).
 * @return true if the IDs are equal according to the specified criteria, false otherwise.
 */
bool rtpstream_id_equal(const rtpstream_id_t *id1, const rtpstream_id_t *id2, unsigned flags);

/**
 * @brief Check if rtpstream_id_t is equal to pinfo
 * - compare src_addr, dest_addr, src_port, dest_port with pinfo
 * - if swap_src_dst is true, compare src to dst and vice versa
 *
 * @param id The RTP stream ID to compare.
 * @param pinfo The packet information containing source and destination addresses and ports.
 * @param swap_src_dst Whether to swap source and destination for comparison.
 * @return true if the RTP stream ID matches the packet information according to the specified criteria, false otherwise.
 */
bool rtpstream_id_equal_pinfo(const rtpstream_id_t *id, const packet_info *pinfo, bool swap_src_dst);

/**
 * @brief Check if rtpstream_id_t is equal to pinfo and rtp_info
 * - compare src_addr, dest_addr, src_port, dest_port with pinfo
 * - compare ssrc with rtp_info
 *
 * @param id The RTP stream ID to compare.
 * @param pinfo The packet information containing source and destination addresses and ports.
 * @param rtp_info The RTP information containing the SSRC.
 * @return true if the RTP stream ID matches the packet information and RTP information according to the specified criteria, false otherwise.
 */
bool rtpstream_id_equal_pinfo_rtp_info(const rtpstream_id_t *id, const packet_info *pinfo, const struct _rtp_info *rtp_info);

/**
 * @brief Get hash of rtpstream_id extracted from packet_info and _rtp_info
 * @param pinfo The packet information containing source and destination addresses and ports.
 * @param rtp_info The RTP information containing the SSRC.
 * @return The hash value of the RTP stream ID.
 */
unsigned pinfo_rtp_info_to_hash(const packet_info *pinfo, const struct _rtp_info *rtp_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __RTP_STREAM_ID_H__ */
