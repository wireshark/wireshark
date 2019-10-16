/* rtp_stream_id.h
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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <epan/address.h>

/* forward */
struct _rtp_info;

/** Defines an rtp stream identification */
typedef struct _rtpstream_id {
    address         src_addr;
    guint16         src_port;
    address         dst_addr;
    guint16         dst_port;
    guint32         ssrc;
} rtpstream_id_t;

/**
 * Copy rtpstream_id_t structure
 */
void rtpstream_id_copy(const rtpstream_id_t *src, rtpstream_id_t *dest);

/**
 * Copy addresses and ports from pinfo
 */
void rtpstream_id_copy_pinfo(const packet_info *pinfo, rtpstream_id_t *dest, gboolean swap_src_dst);

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
gboolean rtpstream_id_equal(const rtpstream_id_t *id1, const rtpstream_id_t *id2, guint flags);

/**
 * Check if rtpstream_id_t is equal to pinfo
 * - compare src_addr, dest_addr, src_port, dest_port with pinfo
 * - compare ssrc with rtp_info
 */
gboolean rtpstream_id_equal_pinfo_rtp_info(const rtpstream_id_t *id, const packet_info *pinfo, const struct _rtp_info *rtp_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __RTP_STREAM_ID_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
