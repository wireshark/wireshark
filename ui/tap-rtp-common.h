/** @file
 *
 * RTP streams handler functions used by tshark and wireshark
 *
 * Copyright 2008, Ericsson AB
 * By Balint Reczey <balint.reczey@ericsson.com>
 *
 * most functions are copied from ui/gtk/rtp_stream.c and ui/gtk/rtp_analysis.c
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
/**
 * @brief Initializes an rtpstream_info_t structure by setting all its fields to zero or NULL.
 *
 * @param info Pointer to the rtpstream_info_t structure to be initialized.
 */
void rtpstream_info_init(rtpstream_info_t* info);

/**
 * @brief Allocates memory for a new RTP stream info and initializes it.
 *
 * @return Pointer to the newly allocated and initialized RTP stream info.
 */
rtpstream_info_t *rtpstream_info_malloc_and_init(void);

/**
 * @brief Copies the contents of an RTP stream info structure to another.
 *
 * @param dest Pointer to the destination RTP stream info structure.
 * @param src Pointer to the source RTP stream info structure.
 */
void rtpstream_info_copy_deep(rtpstream_info_t *dest, const rtpstream_info_t *src);

/**
 * @brief Allocates memory for a new RTP stream info and copies data from an existing one.
 *
 * @param src Pointer to the source RTP stream info.
 * @return Pointer to the newly allocated and copied RTP stream info.
 */
rtpstream_info_t *rtpstream_info_malloc_and_copy_deep(const rtpstream_info_t *src);

/**
 * @brief Frees the data associated with an RTP stream info structure.
 *
 * @param info Pointer to the rtpstream_info_t structure whose data is to be freed.
 */
void rtpstream_info_free_data(rtpstream_info_t* info);

/**
 * @brief Frees all memory associated with an RTP stream info structure.
 *
 * @param info Pointer to the rtpstream_info_t structure whose memory is to be freed.
 */
void rtpstream_info_free_all(rtpstream_info_t* info);

/**
 * @brief Compares two RTP stream infos (GCompareFunc style comparison function)
 *
 * @param aa Pointer to the first RTP stream info.
 * @param bb Pointer to the second RTP stream info.
 * @return -1,0,1
 */
int rtpstream_info_cmp(const void *aa, const void *bb);

/**
 * @brief Compares the endpoints of two RTP streams.
 *
 * @param stream_a Pointer to the first RTP stream info.
 * @param stream_b Pointer to the second RTP stream info.
 * @return true if the streams are reverse of each other, false otherwise.
 */
bool rtpstream_info_is_reverse(const rtpstream_info_t *stream_a, rtpstream_info_t *stream_b);

/**
 * @brief Checks if payload_type is used in rtpstream.
 *
 * @param stream_info Pointer to the RTP stream info structure.
 * @param payload_type The payload type to check.
 * @return true if the payload type is used, false otherwise.
 */
bool rtpstream_is_payload_used(const rtpstream_info_t *stream_info, const uint8_t payload_type);

/****************************************************************************/
/* INTERFACE */

/**
* @brief Registers the rtp_streams tap listener (if not already done).
*
* From that point on, the RTP streams list will be updated with every redissection.
* This function is also the entry point for the initialization routine of the tap system.
* So whenever rtp_stream.c is added to the list of WIRESHARK_TAP_SRCs, the tap will be registered on startup.
* If not, it will be registered on demand by the rtp_streams and rtp_analysis functions that need it.
* @param tapinfo Pointer to the RTP streams tap info structure.
* @param fstring The filter string to apply to the tap listener.
* @param tap_error Callback function to be called if an error occurs during tap registration.
*/
void register_tap_listener_rtpstream(rtpstream_tapinfo_t *tapinfo, const char *fstring, rtpstream_tap_error_cb tap_error);

/**
* @brief Removes the rtp_streams tap listener (if not already done)
* @param tapinfo Pointer to the RTP streams tap info structure.
*/
void remove_tap_listener_rtpstream(rtpstream_tapinfo_t *tapinfo);

/**
* @brief Cleans up memory of rtp streams tap.
* @param tapinfo Pointer to the RTP streams tap info structure.
*/
void rtpstream_reset(rtpstream_tapinfo_t *tapinfo);

/**
 * @brief Callback function for resetting RTP stream information.
 * @param arg Pointer to user data.
 */
void rtpstream_reset_cb(void *arg);

/**
 * @brief Write the RTP header for a given stream information to a file.
 *
 * @param strinfo Pointer to the rtpstream_info_t structure containing the stream information.
 * @param file File pointer where the RTP header will be written.
 */
void rtp_write_header(rtpstream_info_t *strinfo, FILE *file);

/**
 * @brief Callback function for processing RTP packets.
 *
 * @param arg Pointer to user data (not used).
 * @param pinfo Packet information structure.
 * @param edt Epan dissector context.
 * @param arg2 Pointer to additional data (not used).
 * @param flags Tap flags.
 * @return Status of the packet processing.
 */
tap_packet_status rtpstream_packet_cb(void *arg, packet_info *pinfo, epan_dissect_t *edt, const void *arg2, tap_flags_t flags);

/**
 * @brief Evaluate rtpstream_info_t calculations
 * @param strinfo Pointer to the RTP stream info structure.
 * @param calc Pointer to the calculation structure.
 */
void rtpstream_info_calculate(const rtpstream_info_t *strinfo, rtpstream_info_calc_t *calc);

/**
 * @brief Free rtpstream_info_calc_t structure (internal items)
 * @param calc Pointer to the calculation structure.
 */
void rtpstream_info_calc_free(rtpstream_info_calc_t *calc);

/**
 * @brief Init analyse counters in rtpstream_info_t from pinfo
 * @param stream_info Pointer to the RTP stream info structure.
 * @param pinfo Pointer to the packet info structure.
 * @param rtpinfo Pointer to the RTP info structure.
 */
void rtpstream_info_analyse_init(rtpstream_info_t *stream_info, const packet_info *pinfo, const struct _rtp_info *rtpinfo);

/**
 * @brief Update analyse counters in rtpstream_info_t from pinfo
 * @param stream_info Pointer to the RTP stream info structure.
 * @param pinfo Pointer to the packet info structure.
 * @param rtpinfo Pointer to the RTP info structure.
 */
void rtpstream_info_analyse_process(rtpstream_info_t *stream_info, const packet_info *pinfo, const struct _rtp_info *rtpinfo);

/**
 * @brief Get hash key for rtpstream_info_t
 * @param key Pointer to the key.
 * @return Hash value.
 */
unsigned rtpstream_to_hash(const void *key);

/**
 * @brief Insert new_stream_info into multihash
 * @param multihash Pointer to the multihash.
 * @param new_stream_info Pointer to the new RTP stream info structure.
 */
void rtpstream_info_multihash_insert(GHashTable *multihash, rtpstream_info_t *new_stream_info);

/**
 * @brief Lookup stream_info in stream_info multihash
 * @param multihash Pointer to the multihash.
 * @param stream_id Pointer to the RTP stream ID.
 * @return Pointer to the found RTP stream info structure or NULL if not found.
 */
rtpstream_info_t *rtpstream_info_multihash_lookup(GHashTable *multihash, rtpstream_id_t *stream_id);

/**
 * @brief GHFunc () for destroying GList in multihash
 * @param key Pointer to the key.
 * @param value Pointer to the value.
 * @param user_data Pointer to user data.
 */
void rtpstream_info_multihash_destroy_value(void *key, void *value, void *user_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_RTP_COMMON_H__ */
