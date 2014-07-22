/* conversation_hash.h
 * Copied from gtk/conversations_table.h   2003 Ronnie Sahlberg
 * Helper routines common to all conversations taps.
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

#ifndef __CONVERSATION_HASH_H__
#define __CONVERSATION_HASH_H__

#include <epan/address.h>
#include <epan/conv_id.h>

#include <wsutil/nstime.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 *  Conversation lists.
 */

/** Conversation types */
/* Sort alphabetically by title */
typedef enum {
    CONV_TYPE_ETHERNET,
    CONV_TYPE_FIBRE_CHANNEL,
    CONV_TYPE_FDDI,
    CONV_TYPE_IPV4,
    CONV_TYPE_IPV6,
    CONV_TYPE_IPX,
    CONV_TYPE_JXTA,
    CONV_TYPE_NCP,
    CONV_TYPE_RSVP,
    CONV_TYPE_SCTP,
    CONV_TYPE_TCP,
    CONV_TYPE_TOKEN_RING,
    CONV_TYPE_UDP,
    CONV_TYPE_USB,
    CONV_TYPE_WLAN,
    N_CONV_TYPES
} conversation_type_e;

typedef enum {
    CONV_COLUMN_SRC_ADDR,
    CONV_COLUMN_SRC_PORT,
    CONV_COLUMN_DST_ADDR,
    CONV_COLUMN_DST_PORT,
    CONV_COLUMN_PACKETS,
    CONV_COLUMN_BYTES,
    CONV_COLUMN_PKT_AB,
    CONV_COLUMN_BYTES_AB,
    CONV_COLUMN_PKT_BA,
    CONV_COLUMN_BYTES_BA,
    CONV_COLUMN_START,
    CONV_COLUMN_DURATION,
    CONV_COLUMN_BPS_AB,
    CONV_COLUMN_BPS_BA,
    CONV_NUM_COLUMNS,
    CONV_INDEX_COLUMN = CONV_NUM_COLUMNS
} column_type_e;

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

extern const char *column_titles[CONV_NUM_COLUMNS];
extern const char *conn_a_title;
extern const char *conn_b_title;

/** Conversation hash + value storage
 * Hash table keys are conv_key_t. Hash table values are indexes into conv_array.
 */
typedef struct _conversation_hash_t {
    GHashTable  *hashtable;       /**< conversations hash table */
    GArray      *conv_array;      /**< array of conversation values */
} conv_hash_t;

/** Key for hash lookups */
typedef struct _conversation_key_t {
    address     addr1;
    address     addr2;
    guint32     port1;
    guint32     port2;
    conv_id_t   conv_id;
} conv_key_t;

/** Conversation information */
typedef struct _conversation_item_t {
    conversation_type_e conv_type;      /**< conversation type */
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

    nstime_t            start_time;     /**< start time for the conversation */
    nstime_t            stop_time;      /**< stop time for the conversation */

    gboolean            modified;       /**< new to redraw the row */
} conv_item_t;

/** Compute the hash value for two given address/port pairs.
 * (Parameter type is gconstpointer for GHashTable compatibility.)
 *
 * @param key Conversation. MUST point to a conv_key_t struct.
 * @return Computed key hash.
 */
guint conversation_hash(gconstpointer key);

/** Compare two conversation keys for an exact match.
 * (Parameter types are gconstpointer for GHashTable compatibility.)
 *
 * @param key1 First conversation. MUST point to a conv_key_t struct.
 * @param key2 Second conversation. MUST point to a conv_key_t struct.
 * @return TRUE if conversations are equal, FALSE otherwise.
 */
gboolean conversation_equal(gconstpointer key1, gconstpointer key2);

/** Remove all entries from the conversation table.
 *
 * @param ch the table to reset
 */
extern void reset_conversation_table_data(conv_hash_t *ch);

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
 * @param ptype the port type (e.g. PT_TCP)
 */
extern void add_conversation_table_data(conv_hash_t *ch, const address *src, const address *dst,
            guint32 src_port, guint32 dst_port, int num_frames, int num_bytes, nstime_t *ts,
            conversation_type_e conv_type, port_type ptype);

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
 * @param ptype the port type (e.g. PT_TCP)
 * @param conv_id a value to help differentiate the conversation in case the address and port quadruple is not sufficiently unique
 */
extern void
add_conversation_table_data_with_conv_id(conv_hash_t *ch,
    const address *src,
    const address *dst,
    guint32 src_port,
    guint32 dst_port,
    conv_id_t conv_id,
    int num_frames,
    int num_bytes,
    nstime_t *ts,
    conversation_type_e conv_type,
    port_type ptype);

/** Conversation title
 *
 * @param conv_type Conversation type
 * @return Title for this conversation type, e.g. "IPv4".
 */
extern const char *
conversation_title(conversation_type_e conv_type);

/** Find the conversation type for a given title.
 *
 * @param title Conversation title
 * @return Conversation type, e.g. CONV_TYPE_IPV4 or CONV_TYPE_TCP if not found.
 */
extern conversation_type_e
conversation_title_to_type(const char *title);

/** Conversation tap name
 *
 * @param conv_type Conversation type
 * @return Tap name for this conversation type, e.g. "tcp".
 */
extern const char *
conversation_tap_name(conversation_type_e conv_type);

/** Should port columns be hidden?
 *
 * @param conv_type Conversation type
 * @return TRUE if port columns should be hidden for this conversation type.
 */
extern gboolean conversation_hide_ports(conversation_type_e conv_type);

/** Get the string representation of an address.
 *
 * @param addr The address.
 * @param resolve_names Enable name resolution.
 * @return An ep_allocated string representing the address.
 */
const char *get_conversation_address(address *addr, gboolean resolve_names);

/** Get the string representation of a port.
 *
 * @param port The port number.
 * @param ptype The port type.
 * @param resolve_names Enable name resolution.
 * @return An ep_allocated string representing the port.
 */
const char *get_conversation_port(guint32 port, port_type ptype, gboolean resolve_names);

/** Get a display filter for the given conversation and direction.
 *
 * @param conv_item The conversation.
 * @param direction The desired direction.
 * @return An ep_allocated string representing the conversation.
 */
const char *get_conversation_filter(conv_item_t *conv_item, conv_direction_e direction);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CONVERSATION_HASH_H__ */

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
