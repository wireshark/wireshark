/* conversation.h
 * Routines for building lists of packets that are part of a "conversation"
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CONVERSATION_H__
#define __CONVERSATION_H__

#include "ws_symbol_export.h"

#include "packet.h"			/* for conversation dissector type */
#include <epan/wmem_scopes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @file
 * The conversation API lets you correlate packets based on values in a
 * packet, typically address+port tuples. You can search for conversations
 * based on their value tuples and attach data to them.
 */

/**
 * Flags to pass to "conversation_new()" to indicate that the address 2
 * and/or port 2 values for the conversation should be wildcards.
 * The CONVERSATION_TEMPLATE option tells that any of the other supplied
 * port and / or address wildcards will be used to match an infinite number
 * of new connections to the conversation(s) that have the CONVERSATION_-
 * TEMPLATE flag set. Any conversation created without the CONVERSATION_-
 * TEMPLATE flag will be altered once the first connections (connection
 * oriented protocols only) to include the newly found information which
 * matched the wildcard options.
 */
#define NO_ADDR2 0x01
#define NO_PORT2 0x02
#define NO_PORT2_FORCE 0x04
#define CONVERSATION_TEMPLATE 0x08

/**
 * Flags to pass to "find_conversation()" to indicate that the address B
 * and/or port B search arguments are wildcards.
 */
#define NO_MASK_B 0xFFFF0000
#define NO_ADDR_B 0x00010000
#define NO_PORT_B 0x00020000

/** Flags to handle endpoints */
#define USE_LAST_ENDPOINT 0x08		/**< Use last endpoint created, regardless of type */

/* Types of port numbers Wireshark knows about. */
typedef enum {
    ENDPOINT_NONE,			/* no endpoint */
    ENDPOINT_SCTP,			/* SCTP */
    ENDPOINT_TCP,			/* TCP */
    ENDPOINT_UDP,			/* UDP */
    ENDPOINT_DCCP,			/* DCCP */
    ENDPOINT_IPX,			/* IPX sockets */
    ENDPOINT_NCP,			/* NCP connection */
    ENDPOINT_EXCHG,			/* Fibre Channel exchange */
    ENDPOINT_DDP,			/* DDP AppleTalk connection */
    ENDPOINT_SBCCS,			/* FICON */
    ENDPOINT_IDP,			/* XNS IDP sockets */
    ENDPOINT_TIPC,			/* TIPC PORT */
    ENDPOINT_USB,			/* USB endpoint 0xffff means the host */
    ENDPOINT_I2C,
    ENDPOINT_IBQP,			/* Infiniband QP number */
    ENDPOINT_BLUETOOTH,
    ENDPOINT_TDMOP,
    ENDPOINT_DVBCI,
    ENDPOINT_ISO14443,
    ENDPOINT_ISDN,			/* ISDN channel number */
    ENDPOINT_H223,			/* H.223 logical channel number */
    ENDPOINT_X25,			/* X.25 logical channel number */
    ENDPOINT_IAX2,			/* IAX2 call id */
    ENDPOINT_DLCI,			/* Frame Relay DLCI */
    ENDPOINT_ISUP,			/* ISDN User Part CIC */
    ENDPOINT_BICC,			/* BICC Circuit identifier */
    ENDPOINT_GSMTAP,
    ENDPOINT_IUUP,
    ENDPOINT_DVBBBF,        /* DVB Base Band Frame ISI/PLP_ID */
    ENDPOINT_IWARP_MPA,		/* iWarp MPA */
    ENDPOINT_BT_UTP,        /* BitTorrent uTP Connection ID */
    ENDPOINT_LOG,			/* Logging source */
} endpoint_type;

/**
 * Conversation element type.
 */
typedef enum {
    CE_ENDPOINT,
    CE_ADDRESS,
    CE_PORT,
    CE_STRING,
    CE_UINT,
    CE_UINT64,
} conversation_element_type;

/**
 * Elements used to identify conversations for *_full routines and pinfo->conv_elements.
 * Arrays must be terminated with an element .type set to CE_ENDPOINT.
 */
typedef struct conversation_element {
    conversation_element_type type;
    union {
        endpoint_type endpoint_type_val;
        address addr_val;
        unsigned int port_val;
        const char *str_val;
        unsigned int uint_val;
        uint64_t uint64_val;
    };
} conversation_element_t;

/**
 * Data structure representing a conversation.
 */
typedef struct conversation {
    struct conversation *next;	/** pointer to next conversation on hash chain */
    struct conversation *last;	/** pointer to the last conversation on hash chain */
    struct conversation *latest_found; /** pointer to the last conversation on hash chain */
    guint32	conv_index;		/** unique ID for conversation */
    guint32 setup_frame;		/** frame number that setup this conversation */
    /* Assume that setup_frame is also the lowest frame number for now. */
    guint32 last_frame;		/** highest frame number in this conversation */
    wmem_tree_t *data_list;		/** list of data associated with conversation */
    wmem_tree_t *dissector_tree;	/** tree containing protocol dissector client associated with conversation */
    guint	options;		/** wildcard flags */
    conversation_element_t *key_ptr;	/** Keys are conversation element arrays terminated with a CE_ENDPOINT */
} conversation_t;

struct endpoint;
typedef struct endpoint* endpoint_t;

WS_DLL_PUBLIC const address* conversation_key_addr1(const conversation_element_t *key);
WS_DLL_PUBLIC guint32 conversation_key_port1(const conversation_element_t *key);
WS_DLL_PUBLIC const address* conversation_key_addr2(const conversation_element_t *key);
WS_DLL_PUBLIC guint32 conversation_key_port2(const conversation_element_t *key);

/**
 * Create a new hash tables for conversations.
 */
extern void conversation_init(void);

/**
 * Initialize some variables every time a file is loaded or re-loaded.
 */
extern void conversation_epan_reset(void);

/**
 * Create a new conversation identified by a list of elements.
 * @param setup_frame The first frame in the conversation.
 * @param elements An array of element types and values. Must not be NULL. Must be terminated with a CE_ENDPOINT element.
 * @return The new conversation.
 */
WS_DLL_PUBLIC WS_RETNONNULL conversation_t *conversation_new_full(const guint32 setup_frame, conversation_element_t *elements);

/**
 * Given two address/port pairs for a packet, create a new conversation
 * identified by address/port pairs.
 *
 * The options field is used to specify whether the address 2 value
 * and/or port 2 value are not given and any value is acceptable
 * when searching for this conversation. Null address values will
 * be replaced with empty (AT_NONE) addresses.
 *
 * @param setup_frame The first frame in the conversation.
 * @param addr1 The first address in the identifying tuple.
 * @param addr2 The second address in the identifying tuple.
 * @param etype The endpoint type.
 * @param port1 The first port in the identifying tuple.
 * @param port2 The second port in the identifying tuple.
 * @param options NO_ADDR2, NO_PORT2, NO_PORT2_FORCE, or CONVERSATION_TEMPLATE.
 *        Options except for NO_PORT2 and NO_PORT2_FORCE can be ORed.
 * @return The new conversation.
 */
WS_DLL_PUBLIC WS_RETNONNULL conversation_t *conversation_new(const guint32 setup_frame, const address *addr1, const address *addr2,
    const endpoint_type etype, const guint32 port1, const guint32 port2, const guint options);

WS_DLL_PUBLIC WS_RETNONNULL conversation_t *conversation_new_by_id(const guint32 setup_frame, const endpoint_type etype, const guint32 id);

/**
 * Search for a conversation based on the structure and values of an element list.
 * @param frame_num Frame number. Must be greater than or equal to the conversation's initial frame number.
 * @param elements An array of element types and values. Must not be NULL. Must be terminated with a CE_ENDPOINT element.
 * @return The matching conversation if found, otherwise NULL.
 */
WS_DLL_PUBLIC conversation_t *find_conversation_full(const guint32 frame_num, conversation_element_t *elements);

/**
 * Given two address/port pairs for a packet, search for a conversation
 * containing packets between those address/port pairs.  Returns NULL if
 * not found.
 *
 * We try to find the most exact match that we can, and then proceed to
 * try wildcard matches on the "addr_b" and/or "port_b" argument if a more
 * exact match failed.
 *
 * Either or both of the "addr_b" and "port_b" arguments may be specified as
 * a wildcard by setting the NO_ADDR_B or NO_PORT_B flags in the "options"
 * argument.  We do only wildcard matches on addresses and ports specified
 * as wildcards.
 *
 * I.e.:
 *
 *	if neither "addr_b" nor "port_b" were specified as wildcards, we
 *	do an exact match (addr_a/port_a and addr_b/port_b) and, if that
 *	succeeds, we return a pointer to the matched conversation;
 *
 *	otherwise, if "port_b" wasn't specified as a wildcard, we try to
 *	match any address 2 with the specified port 2 (addr_a/port_a and
 *	{any}/addr_b) and, if that succeeds, we return a pointer to the
 *	matched conversation;
 *
 *	otherwise, if "addr_b" wasn't specified as a wildcard, we try to
 *	match any port 2 with the specified address 2 (addr_a/port_a and
 *	addr_b/{any}) and, if that succeeds, we return a pointer to the
 *	matched conversation;
 *
 *	otherwise, we try to match any address 2 and any port 2
 *	(addr_a/port_a and {any}/{any}) and, if that succeeds, we return
 *	a pointer to the matched conversation;
 *
 *	otherwise, we found no matching conversation, and return NULL.
 *
 * Null address values will be replaced with empty (AT_NONE) addresses.
 *
 * @param frame_num Frame number. Must be greater than or equal to the conversation's initial frame number.
 * @param addr_a The first address in the identifying tuple.
 * @param addr_b The second address in the identifying tuple.
 * @param etype The endpoint type.
 * @param port_a The first port in the identifying tuple.
 * @param port_b The second port in the identifying tuple.
 * @param options Wildcard options as described above.
 * @return The matching conversation if found, otherwise NULL.
 */
WS_DLL_PUBLIC conversation_t *find_conversation(const guint32 frame_num, const address *addr_a, const address *addr_b,
    const endpoint_type etype, const guint32 port_a, const guint32 port_b, const guint options);

WS_DLL_PUBLIC conversation_t *find_conversation_by_id(const guint32 frame, const endpoint_type etype, const guint32 id);

/**  A helper function that calls find_conversation() using data from pinfo
 *  The frame number and addresses are taken from pinfo.
 */
WS_DLL_PUBLIC conversation_t *find_conversation_pinfo(packet_info *pinfo, const guint options);

/**
 * A helper function that calls find_conversation() and, if a conversation is
 * not found, calls conversation_new().
 * The frame number and addresses are taken from pinfo.
 * No options are used, though we could extend this API to include an options
 * parameter.
 *
 * @param pinfo Packet info.
 * @return The existing or new conversation.
 */
WS_DLL_PUBLIC WS_RETNONNULL conversation_t *find_or_create_conversation(packet_info *pinfo);

/**  A helper function that calls find_conversation_by_id() and, if a
 *  conversation is not found, calls conversation_new_by_id().
 *  The frame number is taken from pinfo.
 */
WS_DLL_PUBLIC WS_RETNONNULL conversation_t *find_or_create_conversation_by_id(packet_info *pinfo, const endpoint_type etype, const guint32 id);

/** Associate data with a conversation.
 * @param conv Conversation. Must not be NULL.
 * @param proto Protocol ID.
 * @param proto_data Pointer to the data to associate.
 */
WS_DLL_PUBLIC void conversation_add_proto_data(conversation_t *conv, const int proto, void *proto_data);

/** Fetch data associated with a conversation.
 * @param conv Conversation. Must not be NULL.
 * @param proto Protocol ID.
 * @return The data previously set with conversation_add_proto_data, otherwise NULL.
 */
WS_DLL_PUBLIC void *conversation_get_proto_data(const conversation_t *conv, const int proto);

/** Remove data associated with a conversation.
 * @param conv Conversation. Must not be NULL.
 * @param proto Protocol ID.
 */
WS_DLL_PUBLIC void conversation_delete_proto_data(conversation_t *conv, const int proto);

WS_DLL_PUBLIC void conversation_set_dissector(conversation_t *conversation, const dissector_handle_t handle);

WS_DLL_PUBLIC void conversation_set_dissector_from_frame_number(conversation_t *conversation,
    const guint32 starting_frame_num, const dissector_handle_t handle);

WS_DLL_PUBLIC dissector_handle_t conversation_get_dissector(conversation_t *conversation, const guint32 frame_num);

/**
 * Save address+port information in the current packet info which can be matched by
 * find_conversation_pinfo. Supports wildcarding.
 * @param pinfo Packet info.
 * @param addr1 The first address in the identifying tuple.
 * @param addr2 The second address in the identifying tuple.
 * @param etype The endpoint type.
 * @param port1 The first port in the identifying tuple.
 * @param port2 The second port in the identifying tuple.
 */
WS_DLL_PUBLIC void conversation_create_endpoint(struct _packet_info *pinfo, address* addr1, address* addr2,
    endpoint_type etype, guint32 port1, guint32	port2);

/**
 * Save ID information in the current packet info which can be matched by
 * conversation_get_endpoint_by_id. Does not support wildcarding.
 * @param pinfo Packet info.
 * @param etype The endpoint type.
 * @param id A unique ID.
 */
WS_DLL_PUBLIC void conversation_create_endpoint_by_id(struct _packet_info *pinfo,
    endpoint_type etype, guint32 id);

/**
 * @brief conversation_get_endpoint_by_id
 * @param pinfo Packet info.
 * @param etype The endpoint type.
 * @param options USE_LAST_ENDPOINT or 0.
 * @return The endpoint ID if successful, or 0 on failure.
 */
WS_DLL_PUBLIC guint32 conversation_get_endpoint_by_id(struct _packet_info *pinfo,
    endpoint_type etype, const guint options);

/**
 * Given two address/port pairs for a packet, search for a matching
 * conversation and, if found and it has a conversation dissector,
 * call that dissector and return TRUE, otherwise return FALSE.
 *
 * This helper uses call_dissector_only which will NOT call the default
 * "data" dissector if the packet was rejected.
 * Our caller is responsible to call the data dissector explicitly in case
 * this function returns FALSE.
 */
WS_DLL_PUBLIC gboolean try_conversation_dissector(const address *addr_a, const address *addr_b, const endpoint_type etype,
    const guint32 port_a, const guint32 port_b, tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, void* data, const guint options);

WS_DLL_PUBLIC gboolean try_conversation_dissector_by_id(const endpoint_type etype, const guint32 id, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree, void* data);

/* These routines are used to set undefined values for a conversation */

/**
 * Set the second port in a conversation created with conversation_new.
 * @param conv Conversation. Must be created with conversation_new.
 * @param port The second port to set.
 */
WS_DLL_PUBLIC void conversation_set_port2(conversation_t *conv, const guint32 port);

/**
 * Set the second address in a conversation created with conversation_new.
 * @param conv Conversation. Must be created with conversation_new.
 * @param port The second address to set.
 */
WS_DLL_PUBLIC void conversation_set_addr2(conversation_t *conv, const address *addr);

/**
 * @brief Get a hash table of conversation hash table.
 *
 * @return A wmem_map_t * of (const char *: wmem_map_t *).
 * Each value is a wmem_map_t * of (const conversation_element_t *: void *).
 */
WS_DLL_PUBLIC wmem_map_t *get_conversation_hashtables(void);

/* Temporary function to handle port_type to endpoint_type conversion
   For now it's a 1-1 mapping, but the intention is to remove
   many of the port_type instances in favor of endpoint_type
 */
WS_DLL_PUBLIC endpoint_type conversation_pt_to_endpoint_type(port_type pt);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* conversation.h */
