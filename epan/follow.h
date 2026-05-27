/** @file
 *
 * Copyright 1998 Mike Hall <mlh@io.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#pragma once
#include <epan/epan.h>
#include <epan/packet.h>
#include <wsutil/inet_cidr.h>
#include <epan/tap.h>
#include <epan/wmem_scopes.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Show Stream */
/**
 * @brief Indicates the direction of a network stream for display purposes.
 *
 * Used to filter or label stream data based on its origin.
 */
typedef enum {
    FROM_CLIENT, /**< Data originating from the client. */
    FROM_SERVER, /**< Data originating from the server. */
    BOTH_HOSTS   /**< Data from client or server. */
} show_stream_t;

/**
 * @brief Represents an IP address for a stream, supporting both IPv4 and IPv6.
 *
 * This union allows flexible storage of either an IPv4 or IPv6 address
 * for stream identification or filtering.
 */
typedef union _stream_addr {
    uint32_t ipv4;     /**< IPv4 address. */
    ws_in6_addr ipv6;  /**< IPv6 address structure. */
} stream_addr;

struct _follow_info;

#define SUBSTREAM_UNUSED	UINT64_C(0xFFFFFFFFFFFFFFFF)

/**
 * @brief Represents a single chunk of data from one side of a followed stream.
 */
typedef struct {
    bool       is_server;   /**< True if this record originated from the server, false if from the client. */
    uint32_t   packet_num;  /**< Packet number in the capture from which this record was extracted. */
    uint32_t   seq;         /**< TCP sequence number of this record; meaningful for TCP streams only. */
    nstime_t   abs_ts;      /**< Absolute timestamp of the packet that contained this record. */
    GByteArray* data;       /**< Raw payload bytes contributed by this record. */
} follow_record_t;

/**
 * @brief Aggregates all state for following and reassembling a single stream across both client and server directions.
 */
typedef struct _follow_info {
    show_stream_t show_stream;        /**< Which stream direction(s) to display (client, server, or both). */
    char*         filter_out_filter;  /**< Display filter string used to exclude this stream's packets from the main packet list. */
    GList*        payload;            /**< List of follow_record_t entries comprising the stream payload, stored in reverse order. */
    unsigned      bytes_written[2];   /**< Number of bytes written per direction; index with FROM_CLIENT or FROM_SERVER. */
    uint32_t      seq[2];             /**< Current TCP sequence number per direction; meaningful for TCP streams only. */
    GList*        fragments[2];       /**< Pending out-of-order TCP fragments per direction; meaningful for TCP streams only. */
    unsigned      client_port;        /**< Transport-layer port number of the client endpoint. */
    unsigned      server_port;        /**< Transport-layer port number of the server endpoint. */
    address       client_ip;          /**< Network-layer address of the client endpoint. */
    address       server_ip;          /**< Network-layer address of the server endpoint. */
    void*         gui_data;           /**< Opaque pointer to GUI-specific state for rendering the follow stream dialog. */
    uint64_t      stream_id;          /**< Unique identifier for the followed stream. */
    uint64_t      substream_id;       /**< Sub-stream identifier; used only by HTTP/2 and QUIC. */
} follow_info_t;

struct register_follow;
typedef struct register_follow register_follow_t;

/** Initialize the follow conversation/stream system.
 */
extern void follow_init(void);

typedef char* (*follow_conv_filter_func)(epan_dissect_t *edt, packet_info *pinfo, unsigned *stream, unsigned *sub_stream);
typedef char* (*follow_index_filter_func)(unsigned stream, unsigned sub_stream);
typedef char* (*follow_address_filter_func)(address* src_addr, address* dst_addr, int src_port, int dst_port);
typedef char* (*follow_port_to_display_func)(wmem_allocator_t *allocator, unsigned port);
typedef uint32_t (*follow_stream_count_func)(void);
typedef bool (*follow_sub_stream_id_func)(unsigned stream, unsigned sub_stream, bool le, unsigned *sub_stream_out);

/**
 * @brief Register a new follow stream.
 *
 * @param proto_id Protocol ID.
 * @param tap_listener TAP listener name.
 * @param conv_filter Conversation filter function.
 * @param index_filter Index filter function.
 * @param address_filter Address filter function.
 * @param port_to_display Port to display function.
 * @param tap_handler TAP handler function.
 * @param stream_count Stream count function.
 * @param sub_stream_id Sub-stream ID function.
 */
WS_DLL_PUBLIC
void register_follow_stream(const int proto_id, const char* tap_listener,
                            follow_conv_filter_func conv_filter, follow_index_filter_func index_filter, follow_address_filter_func address_filter,
                            follow_port_to_display_func port_to_display, tap_packet_cb tap_handler,
                            follow_stream_count_func stream_count, follow_sub_stream_id_func sub_stream_id);

/**
 * @brief Get protocol ID from registered follower
 *
 * @param follower Registered follower
 * @return protocol id of follower
 */
WS_DLL_PUBLIC int get_follow_proto_id(register_follow_t* follower);

/**
 * @brief Get tap name string from registered follower (used for register_tap_listener)
 *
 * @param follower Registered follower
 * @return tap name string of follower
 */
WS_DLL_PUBLIC const char* get_follow_tap_string(register_follow_t* follower);

/**
 * @brief Get a registered follower by protocol short name
 *
 * @param proto_short_name Protocol short name
 * @return tap registered follower if match, otherwise NULL
 */
WS_DLL_PUBLIC register_follow_t* get_follow_by_name(const char* proto_short_name);

/**
 * @brief Get a registered follower by protocol id
 *
 * @param proto_id Protocol Id
 * @return tap registered follower if match, otherwise NULL
 */
WS_DLL_PUBLIC register_follow_t* get_follow_by_proto_id(const int proto_id);

/**
 * @brief Provide function that builds a follow filter based on the current packet's conversation.
 *
 * @param follower [in] Registered follower
 * @return A filter function handler
 */
WS_DLL_PUBLIC follow_conv_filter_func get_follow_conv_func(register_follow_t* follower);

/**
 * @brief Provide function that builds a follow filter based on stream.
 *
 * @param follower [in] Registered follower
 * @return A filter function handler
 */
WS_DLL_PUBLIC follow_index_filter_func get_follow_index_func(register_follow_t* follower);

/**
 * @brief Provide function that builds a follow filter based on address/port pairs.
 *
 * @param follower [in] Registered follower
 * @return A filter function handler
 */
WS_DLL_PUBLIC follow_address_filter_func get_follow_address_func(register_follow_t* follower);

/**
 * @brief Provide function that resolves port number to name based on follower.
 *
 * @param follower [in] Registered follower
 * @return A port resolver function handler
 */
WS_DLL_PUBLIC follow_port_to_display_func get_follow_port_to_display(register_follow_t* follower);

/**
 * @brief Provide function that handles tap data (tap_packet_cb parameter of register_tap_listener)
 *
 * @param follower [in] Registered follower
 * @return A tap packet handler
 */
WS_DLL_PUBLIC tap_packet_cb get_follow_tap_handler(register_follow_t* follower);

/**
 * @brief Provide function that gets the total number of streams for a registered follower
 * The function can be NULL if the follower does not count the number of streams
 *
 * @param follower [in] Registered follower
 * @return A stream count handler
 */
WS_DLL_PUBLIC follow_stream_count_func get_follow_stream_count_func(register_follow_t* follower);

/**
 * @brief Retrieve the next sub-stream ID for a given stream and stream ID.
 *
 * Provide function that, for given stream and sub stream ids, searches for
 * the first sub stream id less than or equal (or greater than or equal) the
 * given sub stream id present on the given stream id. Returns true and the
 * sub stream id found, or false.
 * This is used by the GUI to select valid sub stream numbers, e.g. when
 * incrementing or decrementing the sub stream ID widget.
 * This function should be NULL if the follower does not have sub streams.
 *
 * @param follower [in] Registered follower
 * @return A sub stream id function handler
 */
WS_DLL_PUBLIC follow_sub_stream_id_func get_follow_sub_stream_id_func(register_follow_t* follower);

/** Tap function handler when dissector's tap provides follow data as a tvb.
 * Used by TCP, UDP and HTTP followers
 */
/**
 * @brief Tap listener for dissectors that export follow data via a tvb.
 *
 * @param tapdata   Opaque follow‑tap context (typically a follow_info struct).
 * @param pinfo     Packet metadata for the current frame.
 * @param edt       Dissection tree (unused).
 * @param data      Protocol‑specific follow data, expected to contain a tvb.
 * @param flags     Tap flags describing packet‑level conditions.
 * @return tap_packet_status indicating whether UI components should update.
 */
WS_DLL_PUBLIC tap_packet_status
follow_tvb_tap_listener(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags);

/**
 * @brief Iterator to walk all registered followers and execute func
 *
 * @param func action to be performed on all conversation tables
 * @param user_data any data needed to help perform function
 */
WS_DLL_PUBLIC void follow_iterate_followers(wmem_foreach_func func, void *user_data);

/**
 * @brief Generate -z stat (tap) name for a follower
 * Currently used only by TShark
 *
 * @param follower [in] Registered follower
 * @return A tap data handler
 */
WS_DLL_PUBLIC char* follow_get_stat_tap_string(register_follow_t* follower);

/**
 * @brief Clear payload, fragments, counters, addresses, and ports of follow_info_t
 * for retapping.
 *
 * Does not clear substream_id, which is used for selecting
 * which tvbs are tapped.
 * Free everything except the GUI element and the follow_info_t structure
 * itself
 *
 * @param info [in] follower info
 */
WS_DLL_PUBLIC void follow_reset_stream(follow_info_t* info);

/**
 * @brief Free follow_info_t structure
 * Free everything except the GUI element
 *
 * @param follow_info [in] follower info
 */
WS_DLL_PUBLIC void follow_info_free(follow_info_t* follow_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */
