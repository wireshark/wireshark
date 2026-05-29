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

/**
 * @brief Summary metadata for a single capture interface.
 */
typedef struct iface_summary_info_tag {
    char     *name;          /**< Interface name (e.g., "eth0"). */
    char     *descr;         /**< Human-readable description of the interface. */
    char     *cfilter;       /**< Capture filter string active on this interface. */
    char     *isb_comment;   /**< Interface Statistics Block comment from the capture file. */
    uint64_t  drops;         /**< Number of packet drops on this interface. */
    bool      drops_known;   /**< True if the packet drop count is known. */
    int       snap;          /**< Maximum captured packet length; 0 if not known. */
    int       encap_type;    /**< Wiretap encapsulation type for this interface. */
} iface_summary_info;


/** @brief Maximum string length for a hex-encoded hash (max hash size × 2 + NUL terminator). */
#define HASH_STR_SIZE (65)


/**
 * @brief Aggregate statistics and metadata tallied across an entire capture file.
 */
typedef struct _summary_tally {
    uint64_t              bytes;              /**< Total bytes across all packets. */
    double                start_time;         /**< Timestamp of the first packet, in seconds with millisecond resolution. */
    double                stop_time;          /**< Timestamp of the last packet, in seconds with millisecond resolution. */
    double                cap_start_time;     /**< Capture start time, in seconds with millisecond resolution. */
    double                cap_end_time;       /**< Capture end time, in seconds with millisecond resolution. */
    double                elapsed_time;       /**< Total elapsed capture duration in seconds, including time before the
                                                   first packet and after the last packet. */
    uint32_t              marked_count;       /**< Number of marked packets. */
    uint32_t              marked_count_ts;    /**< Number of marked packets that carry a timestamp. */
    uint64_t              marked_bytes;       /**< Total bytes across all marked packets. */
    double                marked_start;       /**< Timestamp of the first marked packet, in seconds. */
    double                marked_stop;        /**< Timestamp of the last marked packet, in seconds. */
    uint32_t              ignored_count;      /**< Number of ignored packets. */
    uint32_t              packet_count;       /**< Total number of packets in the capture. */
    uint32_t              packet_count_ts;    /**< Total number of time-stamped packets in the capture. */
    uint32_t              filtered_count;     /**< Number of packets passing the display filter. */
    uint32_t              filtered_count_ts;  /**< Number of time-stamped packets passing the display filter. */
    uint64_t              filtered_bytes;     /**< Total bytes across all display-filtered packets. */
    double                filtered_start;     /**< Timestamp of the first display-filtered packet, in seconds. */
    double                filtered_stop;      /**< Timestamp of the last display-filtered packet, in seconds. */
    const char           *filename;           /**< Filesystem path of the capture file. */
    int64_t               file_length;        /**< Size of the capture file in bytes. */
    char                  file_sha256[HASH_STR_SIZE];  /**< Hex-encoded SHA-256 hash of the capture file. */
    char                  file_sha1[HASH_STR_SIZE];    /**< Hex-encoded SHA-1 hash of the capture file. */
    int                   file_type;          /**< Wiretap file type identifier. */
    ws_compression_type   compression_type;   /**< Compression type of the capture file, or uncompressed. */
    int                   file_encap_type;    /**< Wiretap encapsulation type for the file as a whole. */
    GArray               *packet_encap_types; /**< Array of wiretap encapsulation types seen across packets. */
    int                   snap;               /**< Maximum captured packet length; 0 if not known. */
    bool                  drops_known;        /**< True if the packet drop count is known. */
    uint64_t              drops;              /**< Total number of packet drops across all interfaces. */
    const char           *dfilter;            /**< Active display filter string, or NULL if none. */
    bool                  is_tempfile;        /**< True if the capture file is a temporary file. */
    /* Capture related — use summary_fill_in_capture() to populate these fields. */
    GArray               *ifaces;             /**< Array of @ref iface_summary_info entries, one per capture interface. */
    bool                  legacy;             /**< True if the capture file uses a legacy format lacking per-interface data. */
} summary_tally;

/**
 * @brief Fills in summary information for a capture file.
 *
 * @param cf Pointer to the capture file structure.
 * @param st Pointer to the summary tally structure where the results will be stored.
 */
extern void
summary_fill_in(capture_file *cf, summary_tally *st);

#ifdef HAVE_LIBPCAP
/**
 * @brief Fills in capture-specific summary information for a capture file.
 *
 * @param cf Pointer to the capture file structure.
 * @param capture_opts Pointer to the capture options structure.
 * @param st Pointer to the summary tally structure where the results will be stored.
 */
extern void
summary_fill_in_capture(capture_file *cf, capture_options *capture_opts, summary_tally *st);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* summary.h */
