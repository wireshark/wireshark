/* conversation_table.h
 * GUI independent helper routines common to all conversations taps.
 * Refactored original conversations_table by Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CONVERSATION_TABLE_H__
#define __CONVERSATION_TABLE_H__

#include "conv_id.h"
#include "tap.h"
#include "conversation.h"
#include <epan/wmem_scopes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 *  Conversation definitions.
 */

typedef enum {
    CONV_FT_SRC_ADDRESS,
    CONV_FT_DST_ADDRESS,
    CONV_FT_ANY_ADDRESS,
    CONV_FT_SRC_PORT,
    CONV_FT_DST_PORT,
    CONV_FT_ANY_PORT
} conv_filter_type_e;

/* Filter direction */
typedef enum {
    CONV_DIR_A_TO_FROM_B,
    CONV_DIR_A_TO_B,
    CONV_DIR_A_FROM_B,
    CONV_DIR_A_TO_FROM_ANY,
    CONV_DIR_A_TO_ANY,
    CONV_DIR_A_FROM_ANY,
    CONV_DIR_ANY_TO_FROM_B,
    CONV_DIR_ANY_TO_B,
    CONV_DIR_ANY_FROM_B
} conv_direction_e;

/** Conversation hash + value storage
 * Hash table keys are conv_key_t. Hash table values are indexes into conv_array.
 */
typedef struct _conversation_hash_t {
    GHashTable  *hashtable;       /**< conversations hash table */
    GArray      *conv_array;      /**< array of conversation values */
    void        *user_data;       /**< "GUI" specifics (if necessary) */
    guint       flags;            /**< flags given to the tap packet */
} conv_hash_t;

/** Key for hash lookups */
typedef struct _conversation_key_t {
    address     addr1;
    address     addr2;
    guint32     port1;
    guint32     port2;
    conv_id_t   conv_id;
} conv_key_t;

typedef struct {
    address  myaddress;
    guint32  port;
} endpoint_key_t;

/*
 * For backwards source compatibiity.
 * Yes, G_DEPRECATED_FOR() has to be at the beginning, so that this
 * works with MSVC.
 */
G_DEPRECATED_FOR(endpoint_key_t)
typedef endpoint_key_t host_key_t;

struct _conversation_item_t;
typedef const char* (*conv_get_filter_type)(struct _conversation_item_t* item, conv_filter_type_e filter);

typedef struct _ct_dissector_info {
    conv_get_filter_type get_filter_type;
} ct_dissector_info_t;

struct _endpoint_item_t;
typedef const char* (*endpoint_get_filter_type)(struct _endpoint_item_t* item, conv_filter_type_e filter_type);

typedef struct _et_dissector_info {
    endpoint_get_filter_type get_filter_type;
} et_dissector_info_t;

/* For backwards source compatibiity */
G_DEPRECATED_FOR(et_dissector_info_t)
typedef et_dissector_info_t hostlist_dissector_info_t;

#define CONV_FILTER_INVALID "INVALID"


struct register_ct;
typedef void (*conv_gui_init_cb)(struct register_ct* ct, const char *filter);

typedef void (*endpoint_gui_init_cb)(struct register_ct* ct, const char *filter);

/**
 * Structure for information about a registered conversation table;
 * this information is for both the conversation table and any
 * endpoint table associated with it.
 */
typedef struct register_ct register_ct_t;

/** Conversation list information */
typedef struct _conversation_item_t {
    ct_dissector_info_t *dissector_info; /**< conversation information provided by dissector */
    address             src_address;    /**< source address */
    address             dst_address;    /**< destination address */
    conversation_type   ctype;          /**< conversation key_type (e.g. CONVERSATION_TCP) */
    guint32             src_port;       /**< source port */
    guint32             dst_port;       /**< destination port */
    conv_id_t           conv_id;        /**< conversation id */

    guint64             rx_frames;      /**< number of received packets */
    guint64             tx_frames;      /**< number of transmitted packets */
    guint64             rx_bytes;       /**< number of received bytes */
    guint64             tx_bytes;       /**< number of transmitted bytes */

    guint64             rx_frames_total;      /**< number of received packets total */
    guint64             tx_frames_total;      /**< number of transmitted packets total */
    guint64             rx_bytes_total;       /**< number of received bytes total */
    guint64             tx_bytes_total;       /**< number of transmitted bytes total */

    nstime_t            start_time;     /**< relative start time for the conversation */
    nstime_t            stop_time;      /**< relative stop time for the conversation */
    nstime_t            start_abs_time; /**< absolute start time for the conversation */

    gboolean filtered;                  /**< the entry contains only filtered data */
} conv_item_t;

/** Endpoint information */
typedef struct _endpoint_item_t {
    et_dissector_info_t *dissector_info; /**< endpoint information provided by dissector */
    address myaddress;      /**< address */
    endpoint_type etype;    /**< endpoint_type (e.g. ENDPOINT_TCP) */
    guint32 port;           /**< port */

    guint64 rx_frames;      /**< number of received packets */
    guint64 tx_frames;      /**< number of transmitted packets */
    guint64 rx_bytes;       /**< number of received bytes */
    guint64 tx_bytes;       /**< number of transmitted bytes */

    guint64 rx_frames_total;      /**< number of received packets total */
    guint64 tx_frames_total;      /**< number of transmitted packets total */
    guint64 rx_bytes_total;       /**< number of received bytes total */
    guint64 tx_bytes_total;       /**< number of transmitted bytes total */

    gboolean modified;      /**< new to redraw the row */
    gboolean filtered;      /**< the entry contains only filtered data */

} endpoint_item_t;

/* For backwards source compatibility */
G_DEPRECATED_FOR(endpoint_item_t)
typedef endpoint_item_t hostlist_talker_t;

#define ENDPOINT_TAP_PREFIX     "endpoints"

/** Register the conversation table for the conversation and endpoint windows.
 *
 * @param proto_id is the protocol with conversation
 * @param hide_ports hide the port columns
 * @param conv_packet_func the registered conversation tap name
 * @param endpoint_packet_func the registered endpoint tap name
 */
WS_DLL_PUBLIC void register_conversation_table(const int proto_id, gboolean hide_ports, tap_packet_cb conv_packet_func, tap_packet_cb endpoint_packet_func);

/** Should port columns be hidden?
 *
 * @param ct Registered conversation table
 * @return TRUE if port columns should be hidden for this conversation table.
 */
WS_DLL_PUBLIC gboolean get_conversation_hide_ports(register_ct_t* ct);

/** Get protocol ID of a conversation table
 *
 * @param ct Registered conversation tble
 * @return protocol id of conversation table
 */
WS_DLL_PUBLIC int get_conversation_proto_id(register_ct_t* ct);

/** Get conversation tap function handler of a conversation tble
 *
 * @param ct Registered conversation table
 * @return conversation tap function handler of conversation table
 */
WS_DLL_PUBLIC tap_packet_cb get_conversation_packet_func(register_ct_t* ct);

/** Get endpoint tap function handler for a conversation table
 *
 * @param ct Registered conversation table
 * @return endpoint tap function handler of conversation table
 */
WS_DLL_PUBLIC tap_packet_cb get_endpoint_packet_func(register_ct_t* ct);

/* For backwards source and binary compatibility */
G_DEPRECATED_FOR(get_endpoint_packet_func)
WS_DLL_PUBLIC tap_packet_cb get_hostlist_packet_func(register_ct_t* ct);


/** get conversation table from protocol ID
 *
 * @param proto_id protocol ID
 * @return conversation table for that protocol ID
 */
WS_DLL_PUBLIC register_ct_t* get_conversation_by_proto_id(int proto_id);

/** Register "initialization function" used by the GUI to create conversation
 * table display in GUI
 *
 * @param init_cb callback function that will be called when converation table "display
 * is instantiated in GUI
 */
WS_DLL_PUBLIC void conversation_table_set_gui_info(conv_gui_init_cb init_cb);

/** Register "initialization function" used by the GUI to create endpoint
 * table display in GUI
 *
 * @param init_cb callback function that will be called when endpoint table "display"
 * is instantiated in GUI
 */
WS_DLL_PUBLIC void endpoint_table_set_gui_info(endpoint_gui_init_cb init_cb);

/* For backwards source and binary compatibility */
G_DEPRECATED_FOR(endpoint_table_set_gui_info)
WS_DLL_PUBLIC void hostlist_table_set_gui_info(endpoint_gui_init_cb init_cb);

/** Iterator to walk converation tables and execute func
 *
 * @param func action to be performed on all converation tables
 * @param user_data any data needed to help perform function
 */
WS_DLL_PUBLIC void conversation_table_iterate_tables(wmem_foreach_func func, void* user_data);

/** Total number of converation tables
 */
WS_DLL_PUBLIC guint conversation_table_get_num(void);

/** Remove all entries from the conversation table.
 *
 * @param ch the table to reset
 */
WS_DLL_PUBLIC void reset_conversation_table_data(conv_hash_t *ch);

/** Remove all entries from the endpoint table.
 *
 * @param ch the table to reset
 */
WS_DLL_PUBLIC void reset_endpoint_table_data(conv_hash_t *ch);

/* For backwards source and binary compatibility */
G_DEPRECATED_FOR(reset_endpoint_table_data)
WS_DLL_PUBLIC void reset_hostlist_table_data(conv_hash_t *ch);

/** Initialize dissector conversation for stats and (possibly) GUI.
 *
 * @param opt_arg filter string to compare with dissector
 * @param userdata register_ct_t* for dissector conversation table
 */
WS_DLL_PUBLIC void dissector_conversation_init(const char *opt_arg, void* userdata);

/** Initialize dissector endpoint for stats and (possibly) GUI.
 *
 * @param opt_arg filter string to compare with dissector
 * @param userdata register_ct_t* for dissector conversation table
 */
WS_DLL_PUBLIC void dissector_endpoint_init(const char *opt_arg, void* userdata);

/* For backwards source and binary compatibility */
G_DEPRECATED_FOR(dissector_endpoint_init)
WS_DLL_PUBLIC void dissector_hostlist_init(const char *opt_arg, void* userdata);

/** Get the string representation of an address.
 *
 * @param allocator The wmem allocator to use when allocating the string
 * @param addr The address.
 * @param resolve_names Enable name resolution.
 * @return A string representing the address.
 */
WS_DLL_PUBLIC char *get_conversation_address(wmem_allocator_t *allocator, address *addr, gboolean resolve_names);

/** Get the string representation of a port.
 *
 * @param allocator The wmem allocator to use when allocating the string
 * @param port The port number.
 * @param ctype The conversation type.
 * @param resolve_names Enable name resolution.
 * @return A string representing the port.
 *
 * XXX - this should really be a *port* type, as we just supply a port.
 */
WS_DLL_PUBLIC char *get_conversation_port(wmem_allocator_t *allocator, guint32 port, conversation_type ctype, gboolean resolve_names);

/** Get the string representation of the port for an endpoint_item_t.
 *
 * @param allocator The wmem allocator to use when allocating the string
 *
 * @param item Pointer to the endpoint_item_t
 * @param resolve_names Enable name resolution.
 * @return A string representing the port.
 *
 * XXX - this should really be a *port* type, as we just supply a port.
 */
WS_DLL_PUBLIC char *get_endpoint_port(wmem_allocator_t *allocator, endpoint_item_t *item, gboolean resolve_names);

/** Get a display filter for the given conversation and direction.
 *
 * @param conv_item The conversation.
 * @param direction The desired direction.
 * @return An g_allocated string representing the conversation that must be freed
 */
WS_DLL_PUBLIC char *get_conversation_filter(conv_item_t *conv_item, conv_direction_e direction);

/** Get a display filter for the given endpoint.
 *
 * @param endpoint_item The endpoint.
 * @return A string, allocated using the wmem NULL allocator,
 * representing the conversation.
 */
WS_DLL_PUBLIC char *get_endpoint_filter(endpoint_item_t *endpoint_item);

/* For backwards source and binary compatibility */
G_DEPRECATED_FOR(get_endpoint_filter)
WS_DLL_PUBLIC char *get_hostlist_filter(endpoint_item_t *endpoint_item);

/** Add some data to the conversation table.
 *
 * @param ch the table to add the data to
 * @param src source address
 * @param dst destination address
 * @param src_port source port
 * @param dst_port destination port
 * @param num_frames number of packets
 * @param num_bytes number of bytes
 * @param ts timestamp
 * @param abs_ts absolute timestamp
 * @param ct_info callback handlers from the dissector
 * @param ctype the conversation type (e.g. CONVERSATION_TCP)
 */
WS_DLL_PUBLIC void add_conversation_table_data(conv_hash_t *ch, const address *src, const address *dst,
    guint32 src_port, guint32 dst_port, int num_frames, int num_bytes, nstime_t *ts, nstime_t *abs_ts,
    ct_dissector_info_t *ct_info, conversation_type ctype);

/** Add some data to the conversation table, passing a value to be used in
 *  addition to the address and port quadruple to uniquely identify the
 *  conversation.
 *
 * @param ch the table to add the data to
 * @param src source address
 * @param dst destination address
 * @param src_port source port
 * @param dst_port destination port
 * @param num_frames number of packets
 * @param num_bytes number of bytes
 * @param ts timestamp
 * @param abs_ts absolute timestamp
 * @param ct_info callback handlers from the dissector
 * @param ctype the conversation type (e.g. CONVERSATION_TCP)
 * @param conv_id a value to help differentiate the conversation in case the address and port quadruple is not sufficiently unique
 */
WS_DLL_PUBLIC void
add_conversation_table_data_with_conv_id(conv_hash_t *ch, const address *src, const address *dst, guint32 src_port,
    guint32 dst_port, conv_id_t conv_id, int num_frames, int num_bytes,
    nstime_t *ts, nstime_t *abs_ts, ct_dissector_info_t *ct_info,
    conversation_type ctype);

/** Add some data to the endpoint table.
 *
 * @param ch the table hash to add the data to
 * @param addr address
 * @param port port
 * @param sender TRUE, if this is a sender
 * @param num_frames number of packets
 * @param num_bytes number of bytes
 * @param et_info endpoint information provided by dissector
 * @param etype the endpoint type (e.g. ENDPOINT_TCP)
 */
WS_DLL_PUBLIC void add_endpoint_table_data(conv_hash_t *ch, const address *addr,
    guint32 port, gboolean sender, int num_frames, int num_bytes, et_dissector_info_t *et_info, endpoint_type etype);

/* For backwards source and binary compatibility */
G_DEPRECATED_FOR(add_endpoint_table_data)
WS_DLL_PUBLIC void add_hostlist_table_data(conv_hash_t *ch, const address *addr,
    guint32 port, gboolean sender, int num_frames, int num_bytes, et_dissector_info_t *et_info, endpoint_type etype);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CONVERSATION_TABLE_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
