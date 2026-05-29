/** @file
 *
 * Copyright 2006, Iskratel , Slovenia
 * By Jakob Bratkovic <j.bratkovic@iskratel.si> and
 * Miha Jemec <m.jemec@iskratel.si>
 *
 * based on rtp_stream.h
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __MCAST_STREAM_H__
#define __MCAST_STREAM_H__

#include <epan/tap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define MAX_SPEED 200000

/* typedefs for sliding window and buffer size */

/**
 * @brief Sliding window buffer tracking per-stream burst and bandwidth statistics.
 */
typedef struct buffer {
    nstime_t *buff;          /**< Array of packet arrival timestamps forming the sliding window. */
    int32_t first;           /**< Index of the first (oldest) element in the circular buffer. */
    int32_t last;            /**< Index of the last (newest) element in the circular buffer. */
    int32_t burstsize;       /**< Current burst size in number of packets. */
    int32_t topburstsize;    /**< Maximum burst size observed within the current refresh interval. */
    int32_t count;           /**< Running packet counter for this stream. */
    int32_t burststatus;     /**< Current burst alarm status flag. */
    int32_t numbursts;       /**< Total number of bursts detected. */
    int32_t buffusage;       /**< Current buffer usage level. */
    int32_t buffstatus;      /**< Current buffer alarm status flag. */
    int32_t numbuffalarms;   /**< Number of alarms triggered by buffer underruns. */
    int32_t topbuffusage;    /**< Peak buffer usage observed within the current refresh interval. */
    double maxbw;            /**< Maximum bandwidth usage in bits per second. */
} t_buffer;


/* defines an mcast stream */
/* XXX - Not all of these seem to be used? */

/**
 * @brief Holds statistics and metadata for a single detected multicast stream.
 */
typedef struct _mcast_stream_info {
    address src_addr;           /**< Source IP address of the multicast stream. */
    uint16_t src_port;          /**< Source UDP port of the multicast stream. */
    address dest_addr;          /**< Destination multicast group address. */
    uint16_t dest_port;         /**< Destination UDP port of the multicast stream. */
    uint32_t npackets;          /**< Total number of packets observed in this stream. */
    double apackets;            /**< Average number of packets per second. */
    uint64_t total_bytes;       /**< Total bytes transferred in this stream. */
    double average_bw;          /**< Average bandwidth usage in bits per second. */

    uint32_t first_frame_num;   /**< Frame number of the first captured packet in this stream. */
    nstime_t start_abs;         /**< Absolute start time (GMT) of this stream. */
    nstime_t start_rel;         /**< Stream start time relative to the first packet in the capture. */
    nstime_t stop_rel;          /**< Stream stop time relative to the first packet in the capture. */

    t_buffer element;           /**< Sliding window buffer used for burst and bandwidth analysis. */
} mcast_stream_info_t;

/**
 * @brief Forward declaration of the multicast stream tap info aggregate structure.
 */
typedef struct _mcaststream_tapinfo mcaststream_tapinfo_t;

/**
 * @brief Callback invoked to reset all multicast stream tap state.
 * @param tapinfo Pointer to the tap info structure to reset.
 */
typedef void (*mcaststream_tap_reset_cb)(mcaststream_tapinfo_t *tapinfo);

/**
 * @brief Callback invoked to redraw or refresh the multicast stream UI.
 * @param tapinfo Pointer to the tap info structure containing current stream data.
 */
typedef void (*mcaststream_tap_draw_cb)(mcaststream_tapinfo_t *tapinfo);

/**
 * @brief Aggregate tap structure holding information about all detected multicast streams.
 */
struct _mcaststream_tapinfo {
    void *user_data;                     /**< Opaque pointer to caller-supplied user data. */
    mcaststream_tap_reset_cb tap_reset;  /**< Callback invoked when the tap is reset. */
    mcaststream_tap_draw_cb tap_draw;    /**< Callback invoked when the tap data should be redrawn. */
    GList *strinfo_list;                 /**< Linked list of @ref mcast_stream_info_t stream entries. */
    uint32_t npackets;                   /**< Total number of multicast packets across all streams. */
    mcast_stream_info_t *allstreams;     /**< Aggregate statistics across all detected streams. */
    bool is_registered;                  /**< True if the tap listener is currently registered. */
};

/** @brief Packet rate threshold (packets/s) above which a burst alarm is triggered. */
extern int32_t mcast_stream_trigger;

/** @brief Buffer fill level threshold at which a buffer alarm is triggered. */
extern int32_t mcast_stream_bufferalarm;

/** @brief Burst measurement interval in milliseconds for the sliding window. */
extern uint16_t mcast_stream_burstint;

/** @brief Drain speed of the buffer during idle periods, in bits per second. */
extern int32_t mcast_stream_emptyspeed;

/** @brief Cumulative drain speed of the buffer over time, in bits per second. */
extern int32_t mcast_stream_cumulemptyspeed;

/****************************************************************************/
/* INTERFACE */

/**
 * @brief Registers the mcast_streams tap listener (if not already done).
 *
 * From that point on, the Mcast streams list will be updated with every redissection.
 * This function is also the entry point for the initialization routine of the tap system.
 * So whenever mcast_stream.c is added to the list of WIRESHARK_TAP_SRCs, the tap will be registered on startup.
 * If not, it will be registered on demand by the mcast_streams and mcast_analysis functions that need it.
 *
 * @param tapinfo The mcast stream tap state structure to populate.
 * @return NULL on success, or a GString describing the registration
 *         error (the caller must free it with g_string_free()).
 */
GString *register_tap_listener_mcast_stream(mcaststream_tapinfo_t *tapinfo);


/**
 * @brief Remove the mcast_streams tap listener.
 *
 * @param tapinfo The mcast stream tap state structure whose listener
 *                should be removed.
 */
void remove_tap_listener_mcast_stream(mcaststream_tapinfo_t *tapinfo);

/**
 * @brief Free all accumulated mcast stream tap data.
 *
 * @param tapinfo The mcast stream tap state structure to clear.
 */
void mcaststream_reset(mcaststream_tapinfo_t *tapinfo);

/**
 * @brief Tap packet callback for the mcast_streams tap.
 *
 * Tap callback (tap_packet_cb) for Mcast stream tap updates. Useful if for
 * some reason you can't register the default listener, but want to make use
 * of the existing Mcast calculations.
 *
 * @param tapdata Pointer to the @c mcaststream_tapinfo_t to update;
 *                cast from void* inside the function.
 * @param pinfo   Packet metadata for the current packet.
 * @param edt     The epan dissect context for the current packet.
 * @param data    Tap-specific data for the current packet.
 * @param flags   Tap flags for the current packet.
 * @return TAP_PACKET_REDRAW if the display should be refreshed after
 *         this packet, TAP_PACKET_DONT_REDRAW otherwise.
 */
tap_packet_status mcaststream_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *data, tap_flags_t flags);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MCAST_STREAM_H__ */
