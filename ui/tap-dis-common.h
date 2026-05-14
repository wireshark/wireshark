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

typedef struct _disstream_id {
    address src_addr;
    uint16_t src_port;
    address dst_addr;
    uint16_t dst_port;
    uint16_t radio_id;
    uint16_t entity_id_site;
    uint16_t entity_id_appl;
    uint16_t entity_id_entity;
} disstream_id_t;

typedef struct _disstream_packet {
    uint32_t frame_num;
    nstime_t rel_time;
    uint8_t payload_type;
    guint payload_len;
    guint8 *payload_data;
    double delta_ms;
    double jitter_ms;
    uint32_t estimated_lost_added;
    bool problem;
} disstream_packet_t;

typedef struct _disstream_info {
    disstream_id_t id;

    uint8_t payload_type;
    const char *payload_type_str;
    uint8_t radio_input_source;
    uint8_t transmit_state;

    uint32_t packet_count;
    uint32_t signal_packet_count;
    uint32_t transmitter_packet_count;
    uint64_t total_payload_bytes;
    uint32_t estimated_lost_packets;

    uint32_t first_packet_num;
    uint32_t last_packet_num;
    uint32_t first_signal_frame_num;
    uint32_t last_signal_frame_num;
    nstime_t start_rel_time;
    nstime_t stop_rel_time;

    double max_delta_ms;
    double mean_delta_ms;
    double max_jitter_ms;
    double mean_jitter_ms;

    bool transmission_stopped;
    bool problem;

    GPtrArray *signal_packets;

    /* Internal running analysis state. */
    bool first_timing_packet;
    uint32_t timing_packet_count;
    double start_arrival_ms;
    double prev_arrival_ms;
    double prev_nominal_ms;
    double first_tx_ms;
    double prev_tx_ms;
    double filtered_jitter_ms;
    double excess_codec_time_ms;
} disstream_info_t;

typedef enum {
    DISSTREAM_TAP_ANALYSE,
    DISSTREAM_TAP_SAVE,
    DISSTREAM_TAP_MARK
} disstream_tap_mode_t;

struct _disstream_tapinfo;
typedef void (*disstream_tap_draw_cb)(struct _disstream_tapinfo *tapinfo);
typedef void (*disstream_tap_reset_cb)(struct _disstream_tapinfo *tapinfo);
typedef void (*disstream_tap_error_cb)(GString *error);

typedef struct _disstream_tapinfo {
    GList *strinfo_list;
    GHashTable *strinfo_hash;
    uint32_t nstreams;
    uint32_t npackets;

    disstream_tap_mode_t mode;
    disstream_info_t *filter_stream;
    FILE *save_file;

    disstream_tap_draw_cb tap_draw;
    disstream_tap_reset_cb tap_reset;
    bool is_registered;
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