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

#ifndef __FOLLOW_H__
#define __FOLLOW_H__

#include <epan/epan.h>
#include <epan/packet.h>
#include <epan/ipv6.h>
#include <epan/tap.h>
#include <epan/wmem_scopes.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
  TCP_STREAM = 0,
  UDP_STREAM,
  MAX_STREAM
} stream_type;

typedef enum {
    FRS_OK,
    FRS_OPEN_ERROR,
    FRS_READ_ERROR,
    FRS_PRINT_ERROR
} frs_return_t;

/* Type of follow we are doing */
typedef enum {
    FOLLOW_TCP,
    FOLLOW_TLS,
    FOLLOW_UDP,
    FOLLOW_DCCP,
    FOLLOW_HTTP,
    FOLLOW_HTTP2,
    FOLLOW_QUIC,
    FOLLOW_SIP,
} follow_type_t;

/* Show Type */
typedef enum {
    SHOW_ASCII,
    SHOW_CARRAY,
    SHOW_EBCDIC,
    SHOW_HEXDUMP,
    SHOW_RAW,
    SHOW_CODEC, // Ordered to match UTF-8 combobox index
    SHOW_YAML
} show_type_t;


/* Show Stream */
typedef enum {
    FROM_CLIENT,
    FROM_SERVER,
    BOTH_HOSTS
} show_stream_t;

typedef union _stream_addr {
  guint32 ipv4;
  ws_in6_addr ipv6;
} stream_addr;

struct _follow_info;

typedef gboolean (*follow_print_line_func)(char *, size_t, gboolean, void *);
typedef frs_return_t (*follow_read_stream_func)(struct _follow_info *follow_info, follow_print_line_func follow_print, void *arg);

#define SUBSTREAM_UNUSED	G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)

typedef struct {
    gboolean is_server;
    guint32 packet_num;
    guint32 seq; /* TCP only */
    nstime_t abs_ts; /**< Packet absolute time stamp */
    GByteArray *data;
} follow_record_t;

typedef struct _follow_info {
    show_stream_t   show_stream;
    char            *filter_out_filter;
    GList           *payload;   /* "follow_record_t" entries, in reverse order. */
    guint           bytes_written[2]; /* Index with FROM_CLIENT or FROM_SERVER for readability. */
    guint32         seq[2]; /* TCP only */
    GList           *fragments[2]; /* TCP only */
    guint           client_port;
    guint           server_port;
    address         client_ip;
    address         server_ip;
    void*           gui_data;
    guint64         substream_id;  /**< Sub-stream; used only by HTTP2 and QUIC */
} follow_info_t;

struct register_follow;
typedef struct register_follow register_follow_t;

typedef gchar* (*follow_conv_filter_func)(epan_dissect_t *edt, packet_info *pinfo, guint *stream, guint *sub_stream);
typedef gchar* (*follow_index_filter_func)(guint stream, guint sub_stream);
typedef gchar* (*follow_address_filter_func)(address* src_addr, address* dst_addr, int src_port, int dst_port);
typedef gchar* (*follow_port_to_display_func)(wmem_allocator_t *allocator, guint port);

WS_DLL_PUBLIC
void register_follow_stream(const int proto_id, const char* tap_listener,
                            follow_conv_filter_func conv_filter, follow_index_filter_func index_filter, follow_address_filter_func address_filter,
                            follow_port_to_display_func port_to_display, tap_packet_cb tap_handler);

/** Get protocol ID from registered follower
 *
 * @param follower Registered follower
 * @return protocol id of follower
 */
WS_DLL_PUBLIC int get_follow_proto_id(register_follow_t* follower);

/** Get tap name string from registered follower (used for register_tap_listener)
 *
 * @param follower Registered follower
 * @return tap name string of follower
 */
WS_DLL_PUBLIC const char* get_follow_tap_string(register_follow_t* follower);

/** Get a registered follower by protocol short name
 *
 * @param proto_short_name Protocol short name
 * @return tap registered follower if match, otherwise NULL
 */
WS_DLL_PUBLIC register_follow_t* get_follow_by_name(const char* proto_short_name);

/** Provide function that builds a follow filter based on the current packet's conversation.
 *
 * @param follower [in] Registered follower
 * @return A filter function handler
 */
WS_DLL_PUBLIC follow_conv_filter_func get_follow_conv_func(register_follow_t* follower);

/** Provide function that builds a follow filter based on stream.
 *
 * @param follower [in] Registered follower
 * @return A filter function handler
 */
WS_DLL_PUBLIC follow_index_filter_func get_follow_index_func(register_follow_t* follower);

/** Provide function that builds a follow filter based on address/port pairs.
 *
 * @param follower [in] Registered follower
 * @return A filter function handler
 */
WS_DLL_PUBLIC follow_address_filter_func get_follow_address_func(register_follow_t* follower);

/** Provide function that resolves port number to name based on follower.
 *
 * @param follower [in] Registered follower
 * @return A port resolver function handler
 */
WS_DLL_PUBLIC follow_port_to_display_func get_follow_port_to_display(register_follow_t* follower);

/** Provide function that handles tap data (tap_packet_cb parameter of register_tap_listener)
 *
 * @param follower [in] Registered follower
 * @return A tap packet handler
 */
WS_DLL_PUBLIC tap_packet_cb get_follow_tap_handler(register_follow_t* follower);


/** Tap function handler when dissector's tap provides follow data as a tvb.
 * Used by TCP, UDP and HTTP followers
 */
WS_DLL_PUBLIC tap_packet_status
follow_tvb_tap_listener(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags);

/** Interator to walk all registered followers and execute func
 *
 * @param func action to be performed on all converation tables
 * @param user_data any data needed to help perform function
 */
WS_DLL_PUBLIC void follow_iterate_followers(wmem_foreach_func func, gpointer user_data);

/** Generate -z stat (tap) name for a follower
 * Currently used only by TShark
 *
 * @param follower [in] Registered follower
 * @return A tap data handler
 */
WS_DLL_PUBLIC gchar* follow_get_stat_tap_string(register_follow_t* follower);

/** Clear counters, addresses and ports of follow_info_t
 *
 * @param info [in] follower info
 */
WS_DLL_PUBLIC void follow_reset_stream(follow_info_t* info);

/** Free follow_info_t structure
 * Free everything except the GUI element
 *
 * @param follow_info [in] follower info
 */
WS_DLL_PUBLIC void follow_info_free(follow_info_t* follow_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
