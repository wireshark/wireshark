/** @file
 *
 * Definitions for capture file summary data
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SUMMARY_H__
#define __SUMMARY_H__

#ifdef HAVE_LIBPCAP
#include "ui/capture.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct iface_summary_info_tag {
    char     *name;
    char     *descr;
    char     *cfilter;
    char     *isb_comment;
    uint64_t  drops;                 /**< number of packet drops */
    bool      drops_known;           /**< true if number of packet drops is known */
    int       snap;                  /**< Maximum captured packet length; 0 if not known */
    int       encap_type;            /**< wiretap encapsulation type */
} iface_summary_info;

#define HASH_STR_SIZE (65) /* Max hash size * 2 + '\0' */

typedef struct _summary_tally {
    uint64_t              bytes;              /**< total bytes */
    double                start_time;         /**< seconds, with msec resolution */
    double                stop_time;          /**< seconds, with msec resolution */
    double                elapsed_time;       /**< seconds, with msec resolution,
                                                includes time before first packet
                                                and after last packet */
    uint32_t              marked_count;       /**< number of marked packets */
    uint32_t              marked_count_ts;    /**< number of time-stamped marked packets */
    uint64_t              marked_bytes;       /**< total bytes in the marked packets */
    double                marked_start;       /**< time in seconds, with msec resolution */
    double                marked_stop;        /**< time in seconds, with msec resolution */
    uint32_t              ignored_count;      /**< number of ignored packets */
    uint32_t              packet_count;       /**< total number of packets in trace */
    uint32_t              packet_count_ts;    /**< total number of time-stamped packets in trace */
    uint32_t              filtered_count;     /**< number of filtered packets */
    uint32_t              filtered_count_ts;  /**< number of time-stamped filtered packets */
    uint64_t              filtered_bytes;     /**< total bytes in the filtered packets */
    double                filtered_start;     /**< time in seconds, with msec resolution */
    double                filtered_stop;      /**< time in seconds, with msec resolution */
    const char           *filename;           /**< path of capture file */
    int64_t               file_length;        /**< file length in bytes */
    char                  file_sha256[HASH_STR_SIZE];  /**< SHA256 hash of capture file */
    char                  file_sha1[HASH_STR_SIZE];    /**< SHA1 hash of capture file */
    int                   file_type;          /**< wiretap file type */
    wtap_compression_type compression_type;   /**< compression type of file, or uncompressed */
    int                   file_encap_type;    /**< wiretap encapsulation type for file */
    GArray               *packet_encap_types; /**< wiretap encapsulation types for packets */
    int                   snap;               /**< Maximum captured packet length; 0 if not known */
    bool                  drops_known;        /**< true if number of packet drops is known */
    uint64_t              drops;              /**< number of packet drops */
    const char           *dfilter;            /**< display filter */
    bool                  is_tempfile;
    /* capture related, use summary_fill_in_capture() to get values */
    GArray               *ifaces;
    bool                  legacy;
} summary_tally;

extern void
summary_fill_in(capture_file *cf, summary_tally *st);

#ifdef HAVE_LIBPCAP
extern void
summary_fill_in_capture(capture_file *cf, capture_options *capture_opts, summary_tally *st);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* summary.h */
