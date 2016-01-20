/* conversation_table.h
 * GUI independent helper routines common to all conversations taps.
 * Refactored original conversations_table by Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __CONVERSATION_TABLE_H__
#define __CONVERSATION_TABLE_H__

#include "conv_id.h"
#include "tap.h"

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
} host_key_t;

struct _conversation_item_t;
typedef const char* (*conv_get_filter_type)(struct _conversation_item_t* item, conv_filter_type_e filter);

typedef struct _ct_dissector_info {
    conv_get_filter_type get_filter_type;
} ct_dissector_info_t;

struct _hostlist_talker_t;
typedef const char* (*host_get_filter_type)(struct _hostlist_talker_t* item, conv_filter_type_e filter_type);

typedef struct _hostlist_dissector_info {
    host_get_filter_type get_filter_type;
} hostlist_dissector_info_t;

#define CONV_FILTER_INVALID "INVALID"


struct register_ct;
typedef void (*conv_gui_init_cb)(struct register_ct* ct, const char *filter);

typedef void (*host_gui_init_cb)(struct register_ct* host, const char *filter);

/** Structure for information about a registered conversation */
typedef struct register_ct register_ct_t;

/** Conversation information */
typedef struct _conversation_item_t {
    ct_dissector_info_t *dissector_info; /**< conversation information provided by dissector */
    address             src_address;    /**< source address */
    address             dst_address;    /**< destination address */
    port_type           ptype;          /**< port_type (e.g. PT_TCP) */
    guint32             src_port;       /**< source port */
    guint32             dst_port;       /**< destination port */
    conv_id_t           conv_id;        /**< conversation id */

    guint64             rx_frames;      /**< number of received packets */
    guint64             tx_frames;      /**< number of transmitted packets */
    guint64             rx_bytes;       /**< number of received bytes */
    guint64             tx_bytes;       /**< number of transmitted bytes */

    nstime_t            start_time;     /**< relative start time for the conversation */
    nstime_t            stop_time;      /**< relative stop time for the conversation */
    nstime_t            start_abs_time; /**< absolute start time for the conversation */

    gboolean            modified;       /**< new to redraw the row (only used in GTK+) */
} conv_item_t;

/** Hostlist information */
typedef struct _hostlist_talker_t {
    hostlist_dissector_info_t *dissector_info; /**< conversation information provided by dissector */
    address myaddress;      /**< address */
    port_type  ptype;       /**< port_type (e.g. PT_TCP) */
    guint32 port;           /**< port */

    guint64 rx_frames;      /**< number of received packets */
    guint64 tx_frames;      /**< number of transmitted packets */
    guint64 rx_bytes;       /**< number of received bytes */
    guint64 tx_bytes;       /**< number of transmitted bytes */

    gboolean modified;      /**< new to redraw the row */

} hostlist_talker_t;

#define HOSTLIST_TAP_PREFIX     "endpoints"

/** Register the conversation table for the conversation and endpoint windows.
 *
 * @param proto_id is the protocol with conversation
 * @param hide_ports hide the port columns
 * @param conv_packet_func the registered conversation tap name
 * @param hostlist_func the registered hostlist tap name
 */
extern void register_conversation_table(const int proto_id, gboolean hide_ports, tap_packet_cb conv_packet_func, tap_packet_cb hostlist_func);

/** Should port columns be hidden?
 *
 * @param ct Registered conversation
 * @return TRUE if port columns should be hidden for this conversation type.
 */
WS_DLL_PUBLIC gboolean get_conversation_hide_ports(register_ct_t* ct);

/** Get protocol ID from conversation
 *
 * @param ct Registered conversation
 * @return protocol id of conversation
 */
WS_DLL_PUBLIC int get_conversation_proto_id(register_ct_t* ct);

/** Get tap function handler from conversation
 *
 * @param ct Registered conversation
 * @return tap function handler of conversation
 */
WS_DLL_PUBLIC tap_packet_cb get_conversation_packet_func(register_ct_t* ct);

/** Get tap function handler from hostlist
 *
 * @param ct Registered conversation
 * @return tap function handler of conversation
 */
WS_DLL_PUBLIC tap_packet_cb get_hostlist_packet_func(register_ct_t* ct);

/** get conversation from protocol ID
 *
 * @param proto_id protocol ID
 * @return tap function handler of conversation
 */
WS_DLL_PUBLIC register_ct_t* get_conversation_by_proto_id(int proto_id);

/** Register "initialization function" used by the GUI to create conversation
 * table display in GUI
 *
 * @param init_cb callback function that will be called when converation table "display
 * is instantiated in GUI
 */
WS_DLL_PUBLIC void conversation_table_set_gui_info(conv_gui_init_cb init_cb);

/** Register "initialization function" used by the GUI to create hostlist
 * table display in GUI
 *
 * @param init_cb callback function that will be called when hostlist "display"
 * is instantiated in GUI
 */
WS_DLL_PUBLIC void hostlist_table_set_gui_info(host_gui_init_cb init_cb);

/** Interator to walk converation tables and execute func
 * a GUI menu (only used in GTK)
 *
 * @param func action to be performed on all converation tables
 * @param user_data any data needed to help perform function
 */
WS_DLL_PUBLIC void conversation_table_iterate_tables(GFunc func, gpointer user_data);

/** Total number of converation tables
 */
WS_DLL_PUBLIC guint conversation_table_get_num(void);

/** Get conversation table by its number
 * Tables are ordered alphabetically by title.
 *
 * @param table_num Item to fetch.
 * @return table pointer or NULL.
 */
WS_DLL_PUBLIC register_ct_t* get_conversation_table_by_num(guint table_num);

/** Remove all entries from the conversation table.
 *
 * @param ch the table to reset
 */
WS_DLL_PUBLIC void reset_conversation_table_data(conv_hash_t *ch);

/** Remove all entries from the hostlist table.
 *
 * @param ch the table to reset
 */
WS_DLL_PUBLIC void reset_hostlist_table_data(conv_hash_t *ch);

/** Initialize dissector conversation for stats and (possibly) GUI.
 *
 * @param opt_arg filter string to compare with dissector
 * @param userdata register_ct_t* for dissector conversation
 */
WS_DLL_PUBLIC void dissector_conversation_init(const char *opt_arg, void* userdata);

/** Initialize dissector hostlist for stats and (possibly) GUI.
 *
 * @param opt_arg filter string to compare with dissector
 * @param userdata register_ct_t* for dissector conversation
 */
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
 * @param ptype The port type.
 * @param resolve_names Enable name resolution.
 * @return A string representing the port.
 */
WS_DLL_PUBLIC char *get_conversation_port(wmem_allocator_t *allocator, guint32 port, port_type ptype, gboolean resolve_names);

/** Get a display filter for the given conversation and direction.
 *
 * @param conv_item The conversation.
 * @param direction The desired direction.
 * @return An g_allocated string representing the conversation that must be freed
 */
WS_DLL_PUBLIC char *get_conversation_filter(conv_item_t *conv_item, conv_direction_e direction);

/** Get a display filter for the given hostlist.
 *
 * @param host The hostlist.
 * @return A string, allocated using the wmem NULL allocator,
 * representing the conversation.
 */
WS_DLL_PUBLIC char *get_hostlist_filter(hostlist_talker_t *host);

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
 * @param ptype the port type (e.g. PT_TCP)
 */
extern void add_conversation_table_data(conv_hash_t *ch, const address *src, const address *dst,
            guint32 src_port, guint32 dst_port, int num_frames, int num_bytes, nstime_t *ts, nstime_t *abs_ts,
            ct_dissector_info_t *ct_info, port_type ptype);

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
 * @param ptype the port type (e.g. PT_TCP)
 * @param conv_id a value to help differentiate the conversation in case the address and port quadruple is not sufficiently unique
 */
extern void
add_conversation_table_data_with_conv_id(conv_hash_t *ch, const address *src, const address *dst, guint32 src_port,
    guint32 dst_port, conv_id_t conv_id, int num_frames, int num_bytes,
    nstime_t *ts, nstime_t *abs_ts, ct_dissector_info_t *ct_info, port_type ptype);

/** Add some data to the table.
 *
 * @param ch the table hash to add the data to
 * @param addr address
 * @param port port
 * @param sender TRUE, if this is a sender
 * @param num_frames number of packets
 * @param num_bytes number of bytes
 * @param host_info conversation information provided by dissector
 * @param port_type_val the port type (e.g. PT_TCP)
 */
void add_hostlist_table_data(conv_hash_t *ch, const address *addr,
                             guint32 port, gboolean sender, int num_frames, int num_bytes, hostlist_dissector_info_t *host_info, port_type port_type_val);

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
