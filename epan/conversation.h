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
#define NO_PORTS 0x010

/**
 * Flags to pass to "find_conversation()" to indicate that the address B
 * and/or port B search arguments are wildcards.
 */
#define NO_MASK_B 0xFFFF0000
#define NO_ADDR_B 0x00010000
#define NO_PORT_B 0x00020000
#define NO_PORT_X 0x00040000
#define NO_ANC    0x00080000

/** Flags to handle endpoints */
#define USE_LAST_ENDPOINT 0x08		/**< Use last endpoint created, regardless of type */

/* Types of conversations Wireshark knows about. */
/* XXX: There should be a way to register conversation types used only
 * within one dissector, similar to address types, instead of changing
 * the global typedef.
 */
typedef enum {
    CONVERSATION_NONE,		/* no conversation key */
    CONVERSATION_SCTP,		/* SCTP */
    CONVERSATION_TCP,		/* TCP address/port pairs */
    CONVERSATION_UDP,		/* UDP address/port pairs */
    CONVERSATION_DCCP,		/* DCCP */
    CONVERSATION_IPX,		/* IPX sockets */
    CONVERSATION_NCP,		/* NCP connection */
    CONVERSATION_EXCHG,		/* Fibre Channel exchange */
    CONVERSATION_DDP,		/* DDP AppleTalk address/port pair */
    CONVERSATION_SBCCS,		/* FICON */
    CONVERSATION_IDP,		/* XNS IDP sockets */
    CONVERSATION_TIPC,		/* TIPC PORT */
    CONVERSATION_USB,		/* USB endpoint 0xffff means the host */
    CONVERSATION_I2C,
    CONVERSATION_IBQP,		/* Infiniband QP number */
    CONVERSATION_BLUETOOTH,
    CONVERSATION_TDMOP,
    CONVERSATION_DVBCI,
    CONVERSATION_ISO14443,
    CONVERSATION_ISDN,		/* ISDN channel number */
    CONVERSATION_H223,		/* H.223 logical channel number */
    CONVERSATION_X25,		/* X.25 logical channel number */
    CONVERSATION_IAX2,		/* IAX2 call id */
    CONVERSATION_DLCI,		/* Frame Relay DLCI */
    CONVERSATION_ISUP,		/* ISDN User Part CIC */
    CONVERSATION_BICC,		/* BICC Circuit identifier */
    CONVERSATION_GSMTAP,
    CONVERSATION_IUUP,
    CONVERSATION_DVBBBF,	/* DVB Base Band Frame ISI/PLP_ID */
    CONVERSATION_IWARP_MPA,	/* iWarp MPA */
    CONVERSATION_BT_UTP,	/* BitTorrent uTP Connection ID */
    CONVERSATION_LOG,		/* Logging source */
    CONVERSATION_LTP,		/* LTP Engine ID and Session Number */
    CONVERSATION_MCTP,
    CONVERSATION_NVME_MI,       /* NVMe management interface */
    CONVERSATION_BP,		/* Bundle Protocol endpoint IDs */
    CONVERSATION_SNMP,		/* SNMP */
    CONVERSATION_QUIC,		/* QUIC */
    CONVERSATION_IDN,
    CONVERSATION_IP,		/* IP */
    CONVERSATION_IPV6,		/* IPv6 */
    CONVERSATION_ETH,           /* ETHERNET classic */
    CONVERSATION_ETH_NN,        /* ETHERNET deinterlaced Interface:N VLAN:N */
    CONVERSATION_ETH_NV,        /* ETHERNET deinterlaced Interface:N VLAN:Y */
    CONVERSATION_ETH_IN,        /* ETHERNET deinterlaced Interface:Y VLAN:N */
    CONVERSATION_ETH_IV,        /* ETHERNET deinterlaced Interface:Y VLAN:Y */
    CONVERSATION_VSPC_VMOTION,	/* VMware vSPC vMotion (Telnet) */
    CONVERSATION_OPENVPN,
} conversation_type;

/*
 * XXX - for now, we just #define these to be the same as the
 * corresponding CONVERSATION_ values, for backwards source
 * compatibility.
 *
 * In the long term, we should make this into a separate enum,
 * with elements corresponding to conversation types that do
 * not have known endpoints removed.
 */
/* Types of conversation endpoints Wireshark knows about. */
#define ENDPOINT_NONE		CONVERSATION_NONE
#define ENDPOINT_SCTP		CONVERSATION_SCTP
#define ENDPOINT_TCP		CONVERSATION_TCP
#define ENDPOINT_UDP		CONVERSATION_UDP
#define ENDPOINT_DCCP		CONVERSATION_DCCP
#define ENDPOINT_IPX		CONVERSATION_IPX
#define ENDPOINT_NCP		CONVERSATION_NCP
#define ENDPOINT_EXCHG		CONVERSATION_EXCHG
#define ENDPOINT_DDP		CONVERSATION_DDP
#define ENDPOINT_SBCCS		CONVERSATION_SBCCS
#define ENDPOINT_IDP		CONVERSATION_IDP
#define ENDPOINT_TIPC		CONVERSATION_TIPC
#define ENDPOINT_USB		CONVERSATION_USB
#define ENDPOINT_I2C		CONVERSATION_I2C
#define ENDPOINT_IBQP		CONVERSATION_IBQP
#define ENDPOINT_BLUETOOTH	CONVERSATION_BLUETOOTH
#define ENDPOINT_TDMOP		CONVERSATION_TDMOP
#define ENDPOINT_DVBCI		CONVERSATION_DVBCI
#define ENDPOINT_ISO14443	CONVERSATION_ISO14443
#define ENDPOINT_ISDN		CONVERSATION_ISDN
#define ENDPOINT_H223		CONVERSATION_H223
#define ENDPOINT_X25		CONVERSATION_X25
#define ENDPOINT_IAX2		CONVERSATION_IAX2
#define ENDPOINT_DLCI		CONVERSATION_DLCI
#define ENDPOINT_ISUP		CONVERSATION_ISUP
#define ENDPOINT_BICC		CONVERSATION_BICC
#define ENDPOINT_GSMTAP		CONVERSATION_GSMTAP
#define ENDPOINT_IUUP		CONVERSATION_IUUP
#define ENDPOINT_DVBBBF		CONVERSATION_DVBBBF
#define ENDPOINT_IWARP_MPA	CONVERSATION_IWARP_MPA
#define ENDPOINT_BT_UTP		CONVERSATION_BT_UTP
#define ENDPOINT_LOG		CONVERSATION_LOG
#define ENDPOINT_MCTP		CONVERSATION_MCTP
#define ENDPOINT_NVME_MI	CONVERSATION_NVME_MI
#define ENDPOINT_SNMP		CONVERSATION_SNMP

typedef conversation_type endpoint_type;

/**
 * Conversation element type.
 */
typedef enum {
    CE_CONVERSATION_TYPE,   /* CONVERSATION_ value */
    CE_ADDRESS,             /* address */
    CE_PORT,                /* unsigned integer representing a port */
    CE_STRING,              /* string */
    CE_UINT,                /* unsigned integer not representing a port */
    CE_UINT64,              /* 64-bit unsigned integer */
    CE_INT,                 /* signed integer */
    CE_INT64,               /* signed integer */
    CE_BLOB,                /* arbitrary binary data */
} conversation_element_type;

/**
 * Elements used to identify conversations for *_full routines and
 * pinfo->conv_elements.
 * Arrays must be terminated with an element .type set to CE_CONVERSATION_TYPE.
 *
 * This is currently set only by conversation_set_elements_by_id(); it
 * is not set for conversations identified by address/port endpoints.
 *
 * In find_conversation_pinfo() and find_or_create_conversation(), if
 * any dissector has set this, then, unless some dissector has set the
 * pair of address/port endpoints (see below), the array of elements
 * is used to look up or create the conversation.  Otherwise, the
 * current addresses and ports in the packet_info structure are used.
 *
 * XXX - is there any reason why we shouldn't use an array of conversation
 * elements, with the appropriate addresses and ports, and set it for
 * all protocols that use conversations specified by a pair of address/port
 * endpoints?  That might simplify find_conversation_pinfo() by having
 * them always use the array of elements if it's present, and just fail if
 * it's not.
 */
typedef struct conversation_element {
    conversation_element_type type;
    union {
        conversation_type conversation_type_val;
        address addr_val;
        unsigned int port_val;
        const char *str_val;
        unsigned int uint_val;
        uint64_t uint64_val;
        int int_val;
        int64_t int64_val;
        struct {
            const uint8_t *val;
            size_t len;
        } blob;
    };
} conversation_element_t;

/**
 * Data structure representing a conversation.
 */
typedef struct conversation {
    struct conversation *next;	/** pointer to next conversation on hash chain */
    struct conversation *last;	/** pointer to the last conversation on hash chain */
    struct conversation *latest_found; /** pointer to the last conversation on hash chain */
    uint32_t	conv_index;		/** unique ID for conversation */
    uint32_t setup_frame;		/** frame number that setup this conversation */
    /* Assume that setup_frame is also the lowest frame number for now. */
    uint32_t last_frame;		/** highest frame number in this conversation */
    wmem_tree_t *data_list;		/** list of data associated with conversation */
    wmem_tree_t *dissector_tree;	/** tree containing protocol dissector client associated with conversation */
    unsigned	options;		/** wildcard flags */
    conversation_element_t *key_ptr;	/** Keys are conversation element arrays terminated with a CE_CONVERSATION_TYPE */
} conversation_t;

/*
 * For some protocols, we store, in the packet_info structure, a pair
 * of address/port endpoints, for use by code that might want to
 * construct a conversation for that protocol.
 *
 * This appears to have been done in order to allow protocols to save
 * that information *without* overwriting the addresses or ports in the
 * packet_info structure, so that the other code that uses those values,
 * such as the code that fills in the address and port columns in the
 * packet summary, will pick up the values put there by protocols such
 * as IP and UDP, rather than the values put there by protocols such as
 * TDMoP, FCIP, TIPC, and DVB Dynamic Mode Adaptation. See commit
 * 66b441f3d63e21949530d672bf1406dea94ed254 and issue #11340.
 *
 * That is set by conversation_set_conv_addr_port_endpoints().
 *
 * In find_conversation_pinfo() and find_or_create_conversation(), if
 * any dissector has set this, that address/port endpoint pair is used
 * to look up or create the conversation.
 *
 * Prior to 4.0, conversations identified by a single integer value
 * (such as a circuit ID) were handled by creating a pair of address/port
 * endpoints with null addresses, the first port equal to the integer
 * value, the second port missing, and a port type being an ENDPOINT_
 * type specifying the protocol for the conversation.  Now we use an
 * array of elements, with a CE_UINT value for the integer followed
 * by a CE_CONVERSATION_TYPE value specifying the protocol for the
 * conversation.
 *
 * XXX - is there any reason why we shouldn't use an array of conversation
 * elements, with the appropriate addresses and ports, instead of this
 * structure?  It would at least simplify find_conversation_pinfo() and
 * find_or_create_conversation().
 */
struct conversation_addr_port_endpoints;
typedef struct conversation_addr_port_endpoints* conversation_addr_port_endpoints_t;

WS_DLL_PUBLIC const address* conversation_key_addr1(const conversation_element_t *key);
WS_DLL_PUBLIC uint32_t conversation_key_port1(const conversation_element_t *key);
WS_DLL_PUBLIC const address* conversation_key_addr2(const conversation_element_t *key);
WS_DLL_PUBLIC uint32_t conversation_key_port2(const conversation_element_t *key);

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
 * @param elements An array of element types and values. Must not be NULL. Must be terminated with a CE_CONVERSATION_TYPE element.
 * @return The new conversation.
 */
WS_DLL_PUBLIC WS_RETNONNULL conversation_t *conversation_new_full(const uint32_t setup_frame, conversation_element_t *elements);

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
 * @param ctype The conversation type.
 * @param port1 The first port in the identifying tuple.
 * @param port2 The second port in the identifying tuple.
 * @param options NO_ADDR2, NO_PORT2, NO_PORT2_FORCE, or CONVERSATION_TEMPLATE.
 *        Options except for NO_PORT2 and NO_PORT2_FORCE can be ORed.
 * @return The new conversation.
 */
WS_DLL_PUBLIC WS_RETNONNULL conversation_t *conversation_new(const uint32_t setup_frame, const address *addr1, const address *addr2,
    const conversation_type ctype, const uint32_t port1, const uint32_t port2, const unsigned options);

WS_DLL_PUBLIC WS_RETNONNULL conversation_t *conversation_new_by_id(const uint32_t setup_frame, const conversation_type ctype, const uint32_t id);

/**
 *
 */
WS_DLL_PUBLIC WS_RETNONNULL conversation_t *conversation_new_deinterlaced(const uint32_t setup_frame, const address *addr1, const address *addr2,
    const conversation_type ctype, const uint32_t port1, const uint32_t port2, const uint32_t anchor, const unsigned options);

/**
 * Create a deinterlacer conversation, based on two addresses,
 * a type, and several keys (VLAN, Mac, Interface).
 *
 * @param setup_frame The first frame in the conversation.
 * @param addr1 The first address in the identifying tuple.
 * @param addr2 The second address in the identifying tuple.
 * @param ctype The conversation type.
 * @param key1  The first key in the identifying tuple.
 * @param key2  The second key in the identifying tuple.
 * @param key3  The third key in the identifying tuple.
 * @return The new conversation.
 */
WS_DLL_PUBLIC WS_RETNONNULL conversation_t *conversation_new_deinterlacer(const uint32_t setup_frame, const address *addr1, const address *addr2,
    const conversation_type ctype, const uint32_t key1, const uint32_t key2, const uint32_t key3);

/**
 * A helper function for creating conversations according to the runtime deinterlacing strategy,
 * which means the returned conversation is either a classic (historical) object, or a deinterlaced one.
 *
 * @param pinfo Packet info.
 * @param ctype The conversation type.
 * @param options NO_ADDR2, NO_PORT2, NO_PORT2_FORCE, or CONVERSATION_TEMPLATE.
 *        Options except for NO_PORT2 and NO_PORT2_FORCE can be ORed.
 * @return The new conversation.
 */
WS_DLL_PUBLIC WS_RETNONNULL conversation_t *conversation_new_strat(packet_info *pinfo, const conversation_type ctype, const unsigned options);

/**
 * Search for a conversation based on the structure and values of an element list.
 * @param frame_num Frame number. Must be greater than or equal to the conversation's initial frame number.
 * @param elements An array of element types and values. Must not be NULL. Must be terminated with a CE_CONVERSATION_TYPE element.
 * @return The matching conversation if found, otherwise NULL.
 */
WS_DLL_PUBLIC conversation_t *find_conversation_full(const uint32_t frame_num, conversation_element_t *elements);

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
 * @param ctype The conversation type.
 * @param port_a The first port in the identifying tuple.
 * @param port_b The second port in the identifying tuple.
 * @param options Wildcard options as described above.
 * @return The matching conversation if found, otherwise NULL.
 */
WS_DLL_PUBLIC conversation_t *find_conversation(const uint32_t frame_num, const address *addr_a, const address *addr_b,
    const conversation_type ctype, const uint32_t port_a, const uint32_t port_b, const unsigned options);

WS_DLL_PUBLIC conversation_t *find_conversation_deinterlaced(const uint32_t frame_num, const address *addr_a, const address *addr_b,
    const conversation_type ctype, const uint32_t port_a, const uint32_t port_b, const uint32_t anchor, const unsigned options);

WS_DLL_PUBLIC conversation_t *find_conversation_deinterlacer(const uint32_t frame_num, const address *addr_a, const address *addr_b,
    const conversation_type ctype, const uint32_t key_a, const uint32_t key_b, const uint32_t key_c);

/**  A wrapper function of find_conversation_deinterlacer() using data from pinfo,
 *  which evaluates the execution context first (user preference, VLAN, interface,..),
 *  and then calls find_conversation_deinterlacer().
 *  The frame number and addresses are taken from pinfo.
 */
WS_DLL_PUBLIC conversation_t *find_conversation_deinterlacer_pinfo(const packet_info *pinfo);

WS_DLL_PUBLIC conversation_t *find_conversation_by_id(const uint32_t frame, const conversation_type ctype, const uint32_t id);

/**  A helper function that calls find_conversation() using data from pinfo,
 *  and returns a conversation according to the runtime deinterlacing strategy.
 *  The frame number and addresses are taken from pinfo.
 */
WS_DLL_PUBLIC conversation_t *find_conversation_strat(const packet_info *pinfo, const conversation_type ctype, const unsigned options);

/**  A helper function that calls find_conversation() using data from pinfo
 *  The frame number and addresses are taken from pinfo.
 */
WS_DLL_PUBLIC conversation_t *find_conversation_pinfo(const packet_info *pinfo, const unsigned options);

/**  A helper function that calls find_conversation() using data from pinfo.
 *  It's a simplified version of find_conversation_pinfo() to avoid
 *  unnecessary checks and be limited to read-only, which is the minimal
 *  need for displaying packets in packet_list.
 *  The frame number and addresses are taken from pinfo.
 */
WS_DLL_PUBLIC conversation_t *find_conversation_pinfo_ro(const packet_info *pinfo, const unsigned options);

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
WS_DLL_PUBLIC WS_RETNONNULL conversation_t *find_or_create_conversation_by_id(packet_info *pinfo, const conversation_type ctype, const uint32_t id);

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
    const uint32_t starting_frame_num, const dissector_handle_t handle);

WS_DLL_PUBLIC dissector_handle_t conversation_get_dissector(conversation_t *conversation, const uint32_t frame_num);

/**
 * Save address+port information in the current packet info; it can be matched
 * by find_conversation_pinfo or find_conversation.
 * Supports wildcarding.
 * @param pinfo Packet info.
 * @param addr1 The first address in the identifying tuple.
 * @param addr2 The second address in the identifying tuple.
 * @param ctype The conversation type.
 * @param port1 The first port in the identifying tuple.
 * @param port2 The second port in the identifying tuple.
 */
WS_DLL_PUBLIC void conversation_set_conv_addr_port_endpoints(struct _packet_info *pinfo, address* addr1, address* addr2,
    conversation_type ctype, uint32_t port1, uint32_t port2);

/**
 * Save conversation elements including ID information in the current
 * packet info which can be matched by conversation_get_id_from_elements.
 * Does not support wildcarding.
 * @param pinfo Packet info.
 * @param ctype The conversation type.
 * @param id A unique ID.
 */
WS_DLL_PUBLIC void conversation_set_elements_by_id(struct _packet_info *pinfo,
    conversation_type ctype, uint32_t id);

/**
 * @brief Get the ID value from the conversation elements in the packet info.
 * @param pinfo Packet info.
 * @param ctype The conversation type.
 * @param options USE_LAST_ENDPOINT or 0.
 * @return The ID value from the elements if successful, or 0
 *   on failure.
 */
WS_DLL_PUBLIC uint32_t conversation_get_id_from_elements(struct _packet_info *pinfo,
    conversation_type ctype, const unsigned options);

/**
 * Given two address/port pairs for a packet, search for a matching
 * conversation and, if found and it has a conversation dissector,
 * call that dissector and return true, otherwise return false.
 *
 * This helper uses call_dissector_only which will NOT call the default
 * "data" dissector if the packet was rejected.
 * Our caller is responsible to call the data dissector explicitly in case
 * this function returns false.
 */
WS_DLL_PUBLIC bool try_conversation_dissector(const address *addr_a, const address *addr_b, const conversation_type ctype,
    const uint32_t port_a, const uint32_t port_b, tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, void* data, const unsigned options);

WS_DLL_PUBLIC bool try_conversation_dissector_by_id(const conversation_type ctype, const uint32_t id, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree, void* data);

/* These routines are used to set undefined values for a conversation */

/**
 * Set the second port in a conversation created with conversation_new.
 * @param conv Conversation. Must be created with conversation_new.
 * @param port The second port to set.
 */
WS_DLL_PUBLIC void conversation_set_port2(conversation_t *conv, const uint32_t port);

/**
 * Set the second address in a conversation created with conversation_new.
 * @param conv Conversation. Must be created with conversation_new.
 * @param addr The second address to set.
 */
WS_DLL_PUBLIC void conversation_set_addr2(conversation_t *conv, const address *addr);

/**
 * @brief Get a hash table of conversation hash table.
 *
 * @return A wmem_map_t * of (const char *: wmem_map_t *).
 * Each value is a wmem_map_t * of (const conversation_element_t *: void *).
 */
WS_DLL_PUBLIC wmem_map_t *get_conversation_hashtables(void);

/* Temporary function to handle port_type to conversation_type conversion
   For now it's a 1-1 mapping, but the intention is to remove
   many of the port_type instances in favor of conversation_type
 */
WS_DLL_PUBLIC conversation_type conversation_pt_to_conversation_type(port_type pt);

/* Temporary function to handle port_type to endpoint_type conversion
   For now it's a 1-1 mapping, but the intention is to remove
   many of the port_type instances in favor of endpoint_type
 */
WS_DLL_PUBLIC endpoint_type conversation_pt_to_endpoint_type(port_type pt);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* conversation.h */
