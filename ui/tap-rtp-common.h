/** @file
 *
 * RTP streams handler functions used by tshark and wireshark
 *
 * Copyright 2008, Ericsson AB
 * By Balint Reczey <balint.reczey@ericsson.com>
 *
 * most functions are copied from ui/gtk/rtp_stream.c and ui/gtk/rtp_analisys.c
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_RTP_COMMON_H__
#define __TAP_RTP_COMMON_H__

#include "ui/rtp_stream.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* type of error when saving voice in a file didn't succeed */
typedef enum {
    TAP_RTP_NO_ERROR,
    TAP_RTP_WRONG_CODEC,
    TAP_RTP_WRONG_LENGTH,
    TAP_RTP_PADDING_ERROR,
    TAP_RTP_SHORT_FRAME,
    TAP_RTP_FILE_OPEN_ERROR,
    TAP_RTP_FILE_WRITE_ERROR,
    TAP_RTP_NO_DATA
} tap_rtp_error_type_t;

typedef struct _tap_rtp_save_info_t {
    FILE *fp;
    uint32_t count;
    tap_rtp_error_type_t error_type;
    bool saved;
} tap_rtp_save_info_t;

typedef struct _rtpstream_info_calc {
    char *src_addr_str;
    uint16_t src_port;
    char *dst_addr_str;
    uint16_t dst_port;
    uint32_t ssrc;
    char *all_payload_type_names; /* Name of codec derived from fixed or dynamic codec names */
    uint32_t packet_count;
    uint32_t total_nr;
    uint32_t packet_expected; /* Count of expected packets, derived from length of RTP stream */
    int32_t lost_num;
    double lost_perc;
    double max_delta;
    double min_delta;
    double mean_delta;
    double min_jitter;
    double max_jitter;
    double max_skew;
    double mean_jitter;
    bool problem; /* Indication that RTP stream contains something unusual -GUI should indicate it somehow */
    double clock_drift_ms;
    double freq_drift_hz;
    double freq_drift_perc;
    double duration_ms;
    uint32_t sequence_err;
    double start_time_ms; /**< Unit is ms */
    uint32_t first_packet_num;
    uint32_t last_packet_num;
} rtpstream_info_calc_t;

/**
 * Functions for init and destroy of rtpstream_info_t and attached structures
 */
void rtpstream_info_init(rtpstream_info_t* info);
rtpstream_info_t *rtpstream_info_malloc_and_init(void);
void rtpstream_info_copy_deep(rtpstream_info_t *dest, const rtpstream_info_t *src);
rtpstream_info_t *rtpstream_info_malloc_and_copy_deep(const rtpstream_info_t *src);
void rtpstream_info_free_data(rtpstream_info_t* info);
void rtpstream_info_free_all(rtpstream_info_t* info);

/**
 * Compares two RTP stream infos (GCompareFunc style comparison function)
 *
 * @return -1,0,1
 */
int rtpstream_info_cmp(const void *aa, const void *bb);

/**
* Compares the endpoints of two RTP streams.
*
* @return true if the
*/
bool rtpstream_info_is_reverse(const rtpstream_info_t *stream_a, rtpstream_info_t *stream_b);

/**
 * Checks if payload_type is used in rtpstream.
 *
 * @returns true if is used
 */
bool rtpstream_is_payload_used(const rtpstream_info_t *stream_info, const uint8_t payload_type);

/****************************************************************************/
/* INTERFACE */

/**
* Registers the rtp_streams tap listener (if not already done).
* From that point on, the RTP streams list will be updated with every redissection.
* This function is also the entry point for the initialization routine of the tap system.
* So whenever rtp_stream.c is added to the list of WIRESHARK_TAP_SRCs, the tap will be registered on startup.
* If not, it will be registered on demand by the rtp_streams and rtp_analysis functions that need it.
*/
void register_tap_listener_rtpstream(rtpstream_tapinfo_t *tapinfo, const char *fstring, rtpstream_tap_error_cb tap_error);

/**
* Removes the rtp_streams tap listener (if not already done)
* From that point on, the RTP streams list won't be updated any more.
*/
void remove_tap_listener_rtpstream(rtpstream_tapinfo_t *tapinfo);

/**
* Cleans up memory of rtp streams tap.
*/
void rtpstream_reset(rtpstream_tapinfo_t *tapinfo);

void rtpstream_reset_cb(void*);
void rtp_write_header(rtpstream_info_t*, FILE*);
tap_packet_status rtpstream_packet_cb(void*, packet_info*, epan_dissect_t *, const void *, tap_flags_t);

/**
 * Evaluate rtpstream_info_t calculations
 */
void rtpstream_info_calculate(const rtpstream_info_t *strinfo, rtpstream_info_calc_t *calc);

/**
 * Free rtpstream_info_calc_t structure (internal items)
 */
void rtpstream_info_calc_free(rtpstream_info_calc_t *calc);

/**
 * Init analyse counters in rtpstream_info_t from pinfo
 */
void rtpstream_info_analyse_init(rtpstream_info_t *stream_info, const packet_info *pinfo, const struct _rtp_info *rtpinfo);

/**
 * Update analyse counters in rtpstream_info_t from pinfo
 */
void rtpstream_info_analyse_process(rtpstream_info_t *stream_info, const packet_info *pinfo, const struct _rtp_info *rtpinfo);

/**
 * Get hash key for rtpstream_info_t
 */
unsigned rtpstream_to_hash(const void *key);

/**
 * Insert new_stream_info into multihash
 */
void rtpstream_info_multihash_insert(GHashTable *multihash, rtpstream_info_t *new_stream_info);

/**
 * Lookup stream_info in stream_info multihash
 */
rtpstream_info_t *rtpstream_info_multihash_lookup(GHashTable *multihash, rtpstream_id_t *stream_id);

/**
 * GHFunc () for destroying GList in multihash
 */
void rtpstream_info_multihash_destroy_value(void *key, void *value, void *user_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_RTP_COMMON_H__ */
