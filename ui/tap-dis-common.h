/* tap-dis-common.h
 * DIS streams handler functions used by tshark and wireshark.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_DIS_COMMON_H__
#define __TAP_DIS_COMMON_H__

#include <stdio.h>

#include <glib.h>

#include <epan/address.h>
#include <epan/epan_dissect.h>
#include <epan/packet_info.h>
#include <epan/tap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Uniquely identifies a DIS (Distributed Interactive Simulation) stream by its network and radio addressing.
 */
typedef struct _disstream_id {
    address  src_addr;          /**< Source IP address of the stream */
    uint16_t src_port;          /**< Source UDP port of the stream */
    address  dst_addr;          /**< Destination IP address of the stream */
    uint16_t dst_port;          /**< Destination UDP port of the stream */
    uint16_t radio_id;          /**< DIS radio identifier within the entity */
    uint16_t entity_id_site;    /**< Site component of the DIS entity identifier */
    uint16_t entity_id_appl;    /**< Application component of the DIS entity identifier */
    uint16_t entity_id_entity;  /**< Entity component of the DIS entity identifier */
} disstream_id_t;


/**
 * @brief Captures the decoded content and timing metrics for a single DIS stream packet.
 */
typedef struct _disstream_packet {
    uint32_t  frame_num;              /**< Wireshark frame number of this packet */
    nstime_t  rel_time;               /**< Capture timestamp relative to the first packet in the stream */
    uint8_t   payload_type;           /**< DIS signal payload type identifier */
    guint     payload_len;            /**< Length of the payload data in bytes */
    guint8   *payload_data;           /**< Pointer to the raw payload bytes */
    double    delta_ms;               /**< Inter-packet arrival gap since the previous packet in milliseconds */
    double    jitter_ms;              /**< Instantaneous jitter estimate for this packet in milliseconds */
    uint32_t  estimated_lost_added;   /**< Number of packets estimated as lost before this one */
    bool      problem;                /**< True if a timing or sequencing anomaly was detected for this packet */
} disstream_packet_t;


/**
 * @brief Aggregated analysis state and statistics for a single DIS stream.
 */
typedef struct _disstream_info {
    disstream_id_t id; /**< Network and radio addressing tuple that uniquely identifies this stream */

    /* --- Stream metadata --- */
    uint8_t     payload_type;        /**< DIS signal payload type for this stream */
    const char *payload_type_str;    /**< Human-readable string describing @p payload_type */
    uint8_t     radio_input_source;  /**< DIS radio input source value */
    uint8_t     transmit_state;      /**< Current DIS transmitter state value */

    /* --- Packet and byte counts --- */
    uint32_t packet_count;             /**< Total number of packets observed in this stream */
    uint32_t signal_packet_count;      /**< Number of DIS Signal PDU packets in this stream */
    uint32_t transmitter_packet_count; /**< Number of DIS Transmitter PDU packets in this stream */
    uint64_t total_payload_bytes;      /**< Cumulative payload bytes across all packets */
    uint32_t estimated_lost_packets;   /**< Total number of packets estimated as lost during the stream */

    /* --- Frame and timing extents --- */
    uint32_t first_packet_num;       /**< Frame number of the first packet in the stream */
    uint32_t last_packet_num;        /**< Frame number of the last packet in the stream */
    uint32_t first_signal_frame_num; /**< Frame number of the first Signal PDU in the stream */
    uint32_t last_signal_frame_num;  /**< Frame number of the last Signal PDU in the stream */
    nstime_t start_rel_time;         /**< Relative timestamp of the first packet */
    nstime_t stop_rel_time;          /**< Relative timestamp of the last packet */

    /* --- Timing quality statistics --- */
    double max_delta_ms;    /**< Maximum inter-packet arrival gap observed, in milliseconds */
    double mean_delta_ms;   /**< Mean inter-packet arrival gap across the stream, in milliseconds */
    double max_jitter_ms;   /**< Maximum jitter value observed across the stream, in milliseconds */
    double mean_jitter_ms;  /**< Mean jitter value across the stream, in milliseconds */

    /* --- Stream status flags --- */
    bool transmission_stopped; /**< True if a Transmitter PDU indicated the transmission has stopped */
    bool problem;              /**< True if any packet in the stream recorded a timing or sequencing anomaly */

    /* --- Packet storage --- */
    GPtrArray *signal_packets; /**< Ordered array of ::disstream_packet_t pointers for Signal PDUs */

    /* --- Internal running analysis state (not for external use) --- */
    bool     first_timing_packet;    /**< True until the first timing reference packet has been processed */
    uint32_t timing_packet_count;    /**< Number of packets processed for timing analysis so far */
    double   start_arrival_ms;       /**< Arrival time of the first packet in milliseconds */
    double   prev_arrival_ms;        /**< Arrival time of the most recently processed packet in milliseconds */
    double   prev_nominal_ms;        /**< Expected nominal arrival time of the previous packet in milliseconds */
    double   first_tx_ms;            /**< Transmit timestamp of the first packet in milliseconds */
    double   prev_tx_ms;             /**< Transmit timestamp of the most recently processed packet in milliseconds */
    double   filtered_jitter_ms;     /**< Low-pass filtered jitter estimate used for running mean computation */
    double   excess_codec_time_ms;   /**< Accumulated excess codec processing time carried over between packets */
} disstream_info_t;


/**
 * @brief Selects the operation performed by the DIS stream tap on the collected stream data.
 */
typedef enum {
    DISSTREAM_TAP_ANALYSE, /**< Analyse the collected stream data and populate statistics */
    DISSTREAM_TAP_SAVE,    /**< Save the stream payload data to a file */
    DISSTREAM_TAP_MARK     /**< Mark all frames belonging to the stream in the packet list */
} disstream_tap_mode_t;

struct _disstream_tapinfo;
typedef void (*disstream_tap_draw_cb)(struct _disstream_tapinfo *tapinfo);
typedef void (*disstream_tap_reset_cb)(struct _disstream_tapinfo *tapinfo);
typedef void (*disstream_tap_error_cb)(GString *error);

/**
 * @brief Top-level tap context for DIS stream analysis, holding all discovered streams and tap configuration.
 */
typedef struct _disstream_tapinfo {
    GList      *strinfo_list;   /**< Ordered list of ::disstream_info_t pointers for all discovered streams */
    GHashTable *strinfo_hash;   /**< Hash table keying ::disstream_id_t to ::disstream_info_t for fast lookup */
    uint32_t    nstreams;       /**< Total number of DIS streams discovered so far */
    uint32_t    npackets;       /**< Total number of DIS packets processed across all streams */

    disstream_tap_mode_t  mode;          /**< Operation to perform on the collected stream data (see ::disstream_tap_mode_t) */
    disstream_info_t     *filter_stream; /**< If non-NULL, restricts tap processing to this specific stream */
    FILE                 *save_file;     /**< Output file handle used when @p mode is ::DISSTREAM_TAP_SAVE */

    disstream_tap_draw_cb  tap_draw;     /**< Callback invoked by the tap framework to redraw the stream analysis UI */
    disstream_tap_reset_cb tap_reset;    /**< Callback invoked by the tap framework to reset all stream state */
    bool                   is_registered; /**< True if this tap listener has been successfully registered with the tap framework */
} disstream_tapinfo_t;

/**
 * @brief Copy a disstream ID from one structure to another.
 *
 * @param src The source disstream ID to copy from.
 * @param dst The destination disstream ID to copy into.
 */
void disstream_id_copy(const disstream_id_t *src, disstream_id_t *dst);

/**
 * @brief Copy packet information into a disstream ID structure.
 *
 * @param pinfo The packet info containing source and destination addresses
 *              and ports.
 * @param dst   The disstream ID structure to copy the information into.
 */
void disstream_id_copy_pinfo(const packet_info *pinfo, disstream_id_t *dst);

/**
 * @brief Shallow-copy packet information into a disstream ID structure.
 *
 * Copies address and port fields by reference rather than duplicating them.
 *
 * @param pinfo The packet info containing source and destination addresses
 *              and ports.
 * @param dst   The disstream ID structure to copy the information into.
 */
void disstream_id_copy_pinfo_shallow(const packet_info *pinfo, disstream_id_t *dst);

/**
 * @brief Free the resources owned by a disstream ID.
 *
 * @param id The disstream ID to free.
 */
void disstream_id_free(disstream_id_t *id);

/**
 * @brief Compute a hash value for a disstream ID.
 *
 * @param id The disstream ID to hash.
 * @return The hash value.
 */
unsigned disstream_id_to_hash(const disstream_id_t *id);

/**
 * @brief Check whether two disstream IDs are equal.
 *
 * @param id1 The first disstream ID.
 * @param id2 The second disstream ID.
 * @return true if the IDs are equal, false otherwise.
 */
bool disstream_id_equal(const disstream_id_t *id1, const disstream_id_t *id2);

/**
 * @brief Initialize a disstream info structure.
 *
 * @param info The disstream info structure to initialize.
 */
void disstream_info_init(disstream_info_t *info);

/**
 * @brief Allocate and initialize a new disstream info structure.
 *
 * @return Pointer to the newly allocated and initialized structure.
 */
disstream_info_t *disstream_info_malloc_and_init(void);

/**
 * @brief Free the data owned by a disstream info structure without
 * freeing the structure itself.
 *
 * @param info The disstream info structure whose data to free.
 */
void disstream_info_free_data(disstream_info_t *info);

/**
 * @brief Free a disstream info structure and all its owned data.
 *
 * @param info The disstream info structure to free.
 */
void disstream_info_free_all(disstream_info_t *info);

/**
 * @brief Free a disstream packet and all its owned data.
 *
 * @param packet The disstream packet to free.
 */
void disstream_packet_free(disstream_packet_t *packet);

/**
 * @brief Register a tap listener for DIS stream analysis.
 *
 * @param tapinfo  The DIS stream tap info structure to populate.
 * @param fstring  The display filter string to apply to the tap.
 * @param tap_error Callback invoked when a tap error occurs.
 */
void register_tap_listener_disstream(disstream_tapinfo_t *tapinfo, const char *fstring,
    disstream_tap_error_cb tap_error);

/**
 * @brief Remove a previously registered DIS stream tap listener.
 *
 * @param tapinfo The DIS stream tap info structure to deregister.
 */
void remove_tap_listener_disstream(disstream_tapinfo_t *tapinfo);

/**
 * @brief Reset the DIS stream tap information.
 *
 * @param tapinfo The DIS stream tap info structure to reset.
 */
void disstream_reset(disstream_tapinfo_t *tapinfo);

/**
 * @brief Callback wrapper to reset the DIS stream tap information.
 *
 * @param arg Pointer to the @c disstream_tapinfo_t structure to reset.
 */
void disstream_reset_cb(void *arg);

/**
 * @brief Tap callback invoked for each DIS stream packet.
 *
 * @param arg   Pointer to the @c disstream_tapinfo_t structure.
 * @param pinfo The packet info for the current packet.
 * @param edt   The epan dissect structure for the current packet.
 * @param arg2  Protocol-specific data passed by the tap.
 * @param flags Tap flags for the current packet.
 * @return The tap packet status indicating whether to continue tapping.
 */
tap_packet_status disstream_packet_cb(void *arg, packet_info *pinfo, epan_dissect_t *edt,
    const void *arg2, tap_flags_t flags);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_DIS_COMMON_H__ */