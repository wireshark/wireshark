/* packet-dof.c
 * Routines for Distributed Object Framework (DOF) Wireshark Support
 * Copyright 2015 Bryant Eastham <bryant.eastham[AT]us.panasonic.com>
 * See https://opendof.org for more information.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* INTRODUCTION
 * This very large dissector implements packet decoding for the entire
 * protocol suite of the OpenDOF Project. The OpenDOF Project
 * (https://opendof.org) is an open-source IoT platform with
 * implementations in Java, C#, and C. The protocols are documented
 * on the web site, and the IP ports referenced are registered with IANA.
 *
 * "DOF" stands for Distributed Object Framework. The protocols define
 * a complete protocol stack that can sit on top of a variety of transports.
 * The stack itself is called the DPS, or "DOF Protocol Stack". It
 * is a layered stack including a Network, Presentation, and Application
 * layer. The underlying transport can be anything, these dissectors
 * hook in to UDP and TCP. To the Wireshark user, however, this is
 * referred to as "dof" and not "dps".
 *
 * The following protocols are defined in the stack and implemented
 * here:
 *   DNP    - DOF Network Protocol (versions: 0, 1)
 *   DPP    - DOF Presentation Protocol (version: 0, 2) [1 is reserved and not supported]
 *   DAP    - DOF Application Protocols:
 *   DSP    - DOF Session Protocol (versions: 0)
 *   OAP    - Object Access Protocol (versions: 1)
 *   TEP    - Ticket Exchange Protocol (versions: 128)
 *   TRP    - Ticket Request Protocol (versions: 129)
 *   SGMP   - Secure Group Management Protocol (versions: 130)
 *   DOFSEC - DOF Security Protocols:
 *   CCM    - Chained mode
 *   TUN    - A tunneling protocol for embedding DOF in other protocols.
 */

/* VERSIONS AND NAMING
 * There are several different ways in which "versions" are used
 * throughout the dissector. First, each of the DNP and DPP layers
 * has a defined 'version'. The DOF Application Protocols are also
 * distinguished by versioning, but it is actually the registered
 * application ID that is the version. This is complicated by
 * the fact that many of the application IDs represent the same
 * version of a protocol from a capability perspective (and
 * a user perspective) with the difference being some attribute
 * of the protocol - for example the security primitives used.
 *
 * Another means of versioning is by specification document.
 * In this case the document is identified by a year and sequence,
 * with specifications and PDUs using a name and sequence.
 * Naming of fields and variables will use these identifiers
 * as they are the easiest way to tie the code to the specifications.
 *
 * The specification documents are also the easiest way (although
 * maybe not the clearest) to expose fields to the Wireshar user.
 * A consistent naming is used, which is:
 *
 *   (spec)-pdu-(seq)-(field)
 *   For example: dof-2009-1-pdu-1-value
 *
 * Variable naming includes a protocol name to provide clarity.
 *
 * This is not the clearest from a user perspective, but it
 * has the benefit of tying directly to the specifications
 * themselves and uniquely identifies each field.
 *
 * Routines that dissect are uniformly named by the PDU
 * that they dissect using the PDU specification document
 * and PDU name from that document as follows:
 *
 *   dissect_(spec)_(name)
 */

/* DISSECTOR DESIGN
 * The original work on these dissectors began over ten years ago, but
 * shared only within Panasonic. During the opening of the protocols in
 * March of 2015 the decision was made to contribute the code to the Wireshark
 * community. During this process the plugin approach was rejected and the
 * entire set made into standard dissectors, and further to that all of the
 * dissectors were merged into a single file.
 *
 * There are several types of supported dissectors that are part of the DPS family.
 * At the lowest level are the transport dissectors. The responsibility
 * of these dissectors is to determine the transport session information, pass
 * DPS packets to the DPS dissector, and properly maintain the dof_api_data
 * structure.
 *
 * The DPS dissector API comprises:
 *    1. The structure (dof_api_data) that is passed in the data field to the DPS
 *       dissector. Transport plugins must understand this.
 *    2. The dof_transport_session structure, which contains all transport
 *       information that is passed to the DPS dissector.
 *    3. The name of the DPS dissector.
 *
 * The DPS dissector API extends to dissectors that are called by the DPS dissectors.
 *
 * Finally, there is the DPS Security Mode dissectors. These dissectors are passed
 * additional security context information and it is their job to decrypt packets
 * and pass them to higher-level dissectors.
 *
 * The DOF Protocol Stack is strictly layered with minimal (and defined) state
 * exchanged between layers. This allows a fairly structured design, using
 * dissector tables at each layer. The main DPS dissector receives packets
 * from the transport hooks, and then dissects the packet layer by layer using
 * the different dissector tables. Dissectors and the DNP, DPP, and DAP layers.
 *
 * In addition to the main protocol stack with its associated protocols there are
 * additional common data elements that include extensibility. If an extension
 * is found then it will be used to dissect, otherwise the base dissector will be
 * used.
 */

/* SESSIONS
 * DOF defines sessions at many different levels, and state is always associated
 * with a session. Much of the power (and complexity) of these dissectors relates
 * to accurately tracking and maintaining context for each session, and displaying
 * context-related decode information based on the session. This includes, for
 * example, decoding encrypted data (including multicast group traffic) and
 * showing full packet information even when the packet data uses aliases or
 * other context specific data.
 *
 * Sessions are an extremely complex part of the dissectors because they occur at
 * so many different levels, and that they are temporal in nature while wireshark
 * is not. This means that all data structures that deal with sessions must deal
 * with both the level and the time of the packet.
 *
 * The levels are:
 *   1. Transport. These sessions are defined by the transport, and transport
 *      addresses. As in the transports, there is no transport information allowed
 *      at the dps level, but transport information is allowed to influence other
 *      decisions. Every dps packet must be part of a transport session. Transport
 *      sessions are usually managed as conversations in Wireshark. Each transport
 *      session is has an identifier that is defined by the DPS plugin the first
 *      time a packet in the transport session is passed to the plugin.
 *   2. DPS. These sessions are defined by DPS, and are part of the DNP definition.
 *      These sessions are also assigned a unique DPS session identifier.
 *
 *   3. Security (Optional). Security sessions always exist inside of
 *      an DPS session. Security sessions are further divided into epochs, keys, etc.
 *
 * Temporal information is always associated with packet numbers, which always increase.
 * This temporal information is used during the first pass to create sessions by
 * determining that a new packet doesn't belong to a previous session.
 *
 * During the first pass the data structures are referenced from the transport
 * session information up. The goal of the first pass is to create the most specific
 * session information and associate each packet with the appropriate session. These
 * sessions refer to more general session information.
 *
 * In order to make lookups easier, the most fine-grainded sessions are assigned
 * unique identifiers. Secure sessions are always born unsecure (during security
 * negotiation). These use the same session identifiers, but the state for the
 * secure and unsecured times are separated. Once a session is secured it never
 * transitions back to unsecured.
 *
 * MEMBERSHIP
 * Each packet is sent by a member of the session. Session members have state related
 * to the session. Packets are received by either a member of the session or the
 * session itself (implying all members). This means that packet state can come
 * from:
 *   1. The sender.
 *   2. The receiver (if directed to a receiver).
 *   3. The session.
 * The identity of a member is always a combination of transport and dps information.
 * However, the state of the membership is in the context of the session, keyed by
 * the sender.
 *
 * In order to make lookups easier, each unique sender in the system is
 * assigned a unique identifier.
 */

#include <config.h>

#include <ctype.h>
#include <stdio.h>
#include <glib.h>

#ifdef HAVE_LIBGCRYPT
#include <wsutil/wsgcrypt.h>
#if (defined GCRYPT_VERSION_NUMBER) && (GCRYPT_VERSION_NUMBER  >= 0x010600)
#define LIBGCRYPT_OK
#endif
#endif

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/proto_data.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <wsutil/aes.h>
#include <wsutil/str_util.h>
#include <epan/to_str.h>
#include "packet-tcp.h"

/* DEFINES, STRUCTURES, AND SUPPORT METHOD DECLARATIONS
 * The following sections includes preprocessor definitions, structure definitions,
 * and method declarations for all dissectors.
 * The ordering is by DPS stack order, general first and then by protocols.
 */

/**
 * GENERAL SUPPORT STRUCTURES
 * The following structures represent state that must be maintained for
 * the dissectors to operate. They are not directly related to protocol
 * information.
 */

/**
 * This structure represents a SID, or Sender ID, in the system.
 * This is allocated as global memory, and must be freed. SIDs
 * are Object IDs, and can be displayed in hex but preferrably
 * using the OID output format. Even though the OID contains
 * a length, we prefix this buffer with a length (which must
 * be less than 255 by the definition of a SID.
 * SIDs are not versioned, so they can be used universally in
 * any protocol version.
 */
typedef guint8 *dof_2009_1_pdu_19_sid;

/**
 * This structure encapsulates an OPID, which is the combination of
 * a source identifier (SID, and OID) and a packet number. This is a separate
 * structure because some operations actually contain multiple opids, but need
 * to be placed in the appropriate data structures based on SID lookup. This
 * structure can be used as a key in different hash tables.
 */
typedef struct _dpp_opid
{
    guint op_sid_id;
    dof_2009_1_pdu_19_sid op_sid;
    guint op_cnt;
} dof_2009_1_pdu_20_opid;

/**
 * This structure contains all of the transport session information
 * related to a particular session, but not related to the packet
 * within that session. That information is separated to allow
 * reuse of the structure.
 */
typedef struct _dof_transport_session
{
    /**
     * TRANSPORT ID: This is a unique identifier for each transport,
     * used to prevent aliasing of the SENDER ID value in the
     * transport packet structure. It contains the protocol id
     * assigned by Wireshark (unique per protocol).
     */
    gint transport_id;

    /**
     * For new sessions, this is left zero. The DPS dissector will
     * set this value.
     */
    guint32 transport_session_id;

    /**
     * Timestamp of start of session.
     */
    nstime_t session_start_ts;

    /**
     * Whether negotiation is required on this session.
     */
    gboolean negotiation_required;

    /**
     * The frame number where negotiation was complete, or zero if not complete.
     */
    guint32 negotiation_complete_at;

    /**
     * The time when negotiation was complete, or zero if not complete.
     */
    nstime_t negotiation_complete_at_ts;

    /**
     * Type of transport session.
     */
    gboolean is_streaming;  /* Inverse is 'is_datagram'. */

    /**
     * Cardinality of transport session.
     */
    gboolean is_2_node; /* Inverse is 'is_n_node'. */
} dof_transport_session;

typedef struct _dof_transport_packet
{
    /**
     * Source of packet (if known, default is server).
     */
    gboolean is_sent_by_client; /* Inverse is 'is_sent_by_server'. */

    /**
     * SENDER ID/RECEIVER ID: A unique value that identifies the unique
     * transport sender/receiver address. This number is based on only
     * the transport, and not session, information.
     */
    guint sender_id;
    guint receiver_id;
} dof_transport_packet;

/**
 * This structure maintains security state throughout an DPS session.
 * It is managed by the key exchange protocol, and becomes effective
 * at different dps packets in each communication direction. Decrypting
 * a packet requires that this structure exists.
 */
typedef struct _dof_session_key_exchange_data
{
    /**
     * The frame at which this becomes valid for initiator packets.
     */
    guint32 i_valid;

    /**
     * The frame at which this becomes valid for responder packets.
     */
    guint32 r_valid;

    /**
     * SECURITY MODE: The security mode for a secure session. Set
     * by the key exchange dissector.
     */
    guint32 security_mode;

    /**
     * SECURITY MODE INITIALIZATION DATA: Determined by the key exchange
     * protocol and passed here for the reference of the security mode.
     */
    guint32 security_mode_data_length;
    guint8 *security_mode_data;

    /**
     * SECURITY MODE DATA: Created and managed by the security mode
     * dissector.
     */
    void *security_mode_key_data;

    /**
     * SESSION KEY: Pointer to seasonal data that holds the encryption key.
     */
    guint8 *session_key;

    /**
     * The next security data in this session.
     */
    struct _dof_session_key_exchange_data *next;
} dof_session_key_exchange_data;

/**
 * This structure contains security keys that should be tried with
 * sessions that otherwise are not known.
 */
typedef struct _dof_session_key_data
{
    guint8 *session_key;
} dof_session_key_data;

/**
 * This structure contains security keys for groups.
 */
typedef struct _dof_group_data
{
    guint8 *domain;
    guint8 domain_length;
    guint8 *identity;
    guint8 identity_length;
    guint8 *kek;
} dof_group_data;

/**
 * This structure contains security keys for non-group identities.
 */
typedef struct _dof_identity_data
{
    guint8 *domain;
    guint8 domain_length;
    guint8 *identity;
    guint8 identity_length;
    guint8 *secret;
} dof_identity_data;

/**
 * This structure exists for global security state. It exposes the
 * configuration data associated with DPS, and also is a common location
 * that learned security information is stored. Each dof_packet_data will
 * contain a pointer to this structure - there is only one for the entire
 * DPS.
 */
typedef struct _dof_security_data
{
    /* Array of session_keys. */
    dof_session_key_data *session_key;
    guint16 session_key_count;

    /* Array of group data. */
    dof_group_data *group_data;
    guint16 group_data_count;

    /* Array of identity data. */
    dof_identity_data *identity_data;
    guint16 identity_data_count;

    /* Global sessions. */
    /*TODO: Figure this out */
    /* dof_session_list* sessions; */
} dof_security_data;

/**
 * This structure represents a key that is learned for a group and epoch.
 */
struct _dof_learned_group_data;
typedef struct _dof_learned_group_auth_data
{
    guint32 epoch;
    guint8 *kek;
    guint mode_length;
    guint8 *mode;
    guint16 security_mode;
    struct _dof_learned_group_data *parent;
    struct _dof_learned_group_auth_data *next;
} dof_learned_group_auth_data;

/**
 * This structure represents a group that is learned about.
 */
typedef struct _dof_learned_group_data
{
    guint8 domain_length;
    guint8 *domain;
    guint8 group_length;
    guint8 *group;
    guint32 ssid;

    dof_learned_group_auth_data *keys;
    struct _dof_learned_group_data *next;
} dof_learned_group_data;

/**
 * This structure exists for each secure DPS session. This is kept in
 * addition to the normal session
 * Each packet that has state will contain a reference to one of these.
 *
 * Information in this structure is invariant for the duration of the
 * session *or* is only used during the initial pass through the packets.
 * Information that changes (for example, security parameters, keys, etc.)
 * needs to be maintained separately, although this structure is the
 * starting place for this information.
 *
 * This structure is initialized to zero.
 */
struct _dof_session_data;
typedef struct _dof_secure_session_data
{
    /**
     * SSID: Zero is typically used for streaming sessions.
     */
    guint32 ssid;

    /**
     * DOMAIN LENGTH: The length of the security domain, greater than
     * zero for secure sessions. Set by the key exchange dissector.
     */
    guint8 domain_length;

    /**
     * DOMAIN: The security domain itself, seasonal storage, non-null
     * for secure sessions. Set by the key exchange dissector.
     */
    guint8 *domain;

    /**
     * SESSION SECURITY: This is a list of security data for this
     * session, created by the key exchange protocol.
     */
    dof_session_key_exchange_data *session_security_data;
    dof_session_key_exchange_data *session_security_data_last;

    /**
     * NEXT: This is the next secure session related to the parent
     * unsecure session. Protocols can define new secure sessions and
     * add them to this list. DPP then finds the correct secure session
     * for a secure packet and caches it.
     */
    struct _dof_secure_session_data *next;
    struct _dof_session_data *parent;
    guint32 original_session_id;
    gboolean is_2_node;
} dof_secure_session_data;

/**
 * This structure exists for each DPS session. Secure sessions have an
 * additional data structure that includes the secure session information.
 * Each packet that has state will contain a reference to one of these.
 *
 * Information in this structure is invariant for the duration of the
 * session *or* is only used during the initial pass through the packets.
 * Information that changes (for example, security parameters, keys, etc.)
 * needs to be maintained separately, although this structure is the
 * starting place for this information.
 *
 * This structure is initialized to zero.
 */
typedef struct _dof_session_data
{
    /**
     * SESSION ID: Set when the session is created, required.
     */
    guint32 session_id;

    /**
     * DPS ID: The type of DPS SENDER ID (in the packet data) to prevent
     * aliasing. Since DPS senders identifiers relate to DNP, this is the
     * DNP version number.
     */
    guint8 dof_id;

    /**
     * SECURE SESSIONS: When secure sessions are created from this
     * unsecure session then they are added to this list. Each member
     * of the list must be distinguished.
     */
    dof_secure_session_data *secure_sessions;

    /**
     * Protocol-specific data.
     */
    GSList *data_list;
} dof_session_data;

/* DOF Security Structures. */
/* Return structures for different packets. */

typedef struct _dof_2008_16_security_3_1
{
    tvbuff_t *identity;
} dof_2008_16_security_3_1;

typedef struct _dof_2008_16_security_4
{
    tvbuff_t *identity;
    tvbuff_t *nonce;
} dof_2008_16_security_4;

typedef struct _dof_2008_16_security_6_1
{
    tvbuff_t *i_identity;
    tvbuff_t *i_nonce;
    guint16 security_mode;
    guint32 security_mode_data_length;
    guint8 *security_mode_data;
} dof_2008_16_security_6_1;

typedef struct _dof_2008_16_security_6_2
{
    tvbuff_t *r_identity;
    tvbuff_t *r_nonce;
} dof_2008_16_security_6_2;


/**
 * This structure defines the address for Wireshark transports. There is no
 * DPS information associated here.
 */
typedef struct _ws_node
{
    address addr;
    guint32 port;
} ws_node;

typedef struct _dof_session_list
{
    dof_session_data *session;
    struct _dof_session_list *next;
} dof_session_list;

/**
 * DOF PACKET DATA
 * This structure exists for each DOF packet. There is ABSOLUTELY NO
 * transport-specific information here, although there is a session
 * number which may relate to transport information indirectly through
 * a transport session.
 * There will be one of these for each DOF packet, even if the corresponding
 * Wireshark frame has multiple DOF packets encapsulated in it. The key
 * to this structure is the operation identifier, and there is a hash
 * lookup to go from an operation identifier to this structure.
 */
typedef struct _dof_packet_data
{
    /**
     * NON-DPS FIELDS, USED FOR WIRESHARK COMMUNICATION/PROCESSING
     * Protocol-specific data.
     */
    GSList *data_list;

    /**
     * The Wireshark frame. Note that a single frame can have multiple DPS packets.
     */
    guint32 frame;

    /**
     * The DPS frame/packet. This number is unique in the entire trace.
     */
    guint32 dof_frame;

    /**
     * Packet linked list for all dps packets.
     */
    struct _dof_packet_data *next;

    /**
     * DPS FIELDS
     * Indicator that the packet has already been processed. Processed packets
     * have all their fields set that can be determined. Further attempts to
     * determine NULL fields are worthless.
     */
    gboolean processed;

    /**
     * SUMMARY: An operation summary, displayed in the Operation History. This is seasonal
     * data, managed by the DPP dissector.
     */
    const gchar *summary;

    /**
     * SENDER ID/RECEIVER ID: An identifier for each unique sender/receiver according to DPS.
     * This augments the transport SENDER ID/RECEIVER ID in determining each
     * unique sender.
     */
    gint sender_id;
    gint receiver_id;

    /**
     * DPP INFORMATION - CACHED INFORMATION
     */
    gboolean is_command;    /* Inverse is 'is_response'. */
    gboolean is_sent_by_initiator;

    /**
     * SENDER SID ID/RECEIVER SID ID: An identifier for the sid associated with this packet's sender.
     * Zero indicates that it has not been assigned. Assigned by the DPP
     * dissector.
     */
    guint sender_sid_id;
    guint receiver_sid_id;

    /**
     * SENDER SID/RECEIVER SID: The SID of the sender/receiver, or NULL if not known.
     */
    dof_2009_1_pdu_19_sid sender_sid;
    dof_2009_1_pdu_19_sid receiver_sid;

    /**
     * Operation references.
     */
    gboolean has_opid;
    dof_2009_1_pdu_20_opid op;
    gboolean has_referenced_opid;
    dof_2009_1_pdu_20_opid ref_op;

    struct _dof_packet_data *opid_first;
    struct _dof_packet_data *opid_next;
    struct _dof_packet_data *opid_last;
    struct _dof_packet_data *opid_first_response;
    struct _dof_packet_data *opid_next_response;
    struct _dof_packet_data *opid_last_response;

    /**
     * SECURITY INFORMATION - CACHED
     */
    const gchar *security_session_error;
    dof_session_key_exchange_data *security_session;
    void *security_packet;
    guint8 *decrypted_buffer;
    tvbuff_t *decrypted_tvb;
    guint16 decrypted_offset;
    gchar *decrypted_buffer_error;


    /**
     * OPERATION DATA: Generic data, seasonal, owned by the application protocol dissector
     * for this packet.
     */
    void *opid_data;
} dof_packet_data;


/**
 * This structure represents globals that are passed to all dissectors.
 */
typedef struct _dof_globals
{
    guint32 next_transport_session;
    guint32 next_session;
    dof_packet_data *dof_packet_head;
    dof_packet_data *dof_packet_tail;
    dof_security_data *global_security;
    dof_learned_group_data *learned_group_data;
    gboolean decrypt_all_packets;
    gboolean track_operations;
    guint track_operations_window;
} dof_globals;

/**
 * This structure contains all information that is passed between
 * transport dissectors/plugins and the DPS dissector. It is allocated
 * by the transport plugin, and its fields are set as described here.
 */
typedef struct _dof_api_data
{
    /**
     * TRANSPORT SESSION: Set by the transport dissector, required.
     */
    dof_transport_session *transport_session;

    /**
     * TRANSPORT PACKET: Set by the transport dissector, required.
     */
    dof_transport_packet *transport_packet;

    /**
     * DPS SESSION: Set by the DPS dissector.
     */
    dof_session_data *session;

    /**
     * DPS DATA: Set by the DPS dissector.
     */
    dof_packet_data *packet;

    /**
     * DPS SECURE SESSION: Set by the DPP dissector.
     */
    dof_secure_session_data *secure_session;
} dof_api_data;

/**
 * This set of types defines the Security Mode dissector API.
 * This structure identifies the context of the dissection,
 * allowing a single structure to know what part of the packet
 * of sequence of packets it is working with.
 *
 * Structure for Security Mode of Operation dissectors.
 */
typedef enum _dof_secmode_context
{
    INITIALIZE,
    HEADER,
    TRAILER
} dof_secmode_context;

/* Seasonal, initialized to zero. */
typedef struct _dof_secmode_api_data
{
    /**
     * API VERSION: Set by the DPS dissector, required.
     * MUST BE THE FIRST FIELD.
     */
    guint8 version;

    /**
     * CONTEXT: Set the DPS dissector, required.
     */
    dof_secmode_context context;

    /**
     * SECURITY MODE OFFSET: The packet offset from the DPP header of the security mode.
     */
    guint security_mode_offset;

    /**
     * API DATA: Set by the DPS dissector, required.
     */
    dof_api_data *dof_api;

    /**
     * SECURE SESSION DATA: Controlled by the caller, either associated
     * with the current packet (HEADER mode) or not (other modes).
     * Used to access session information.
     */
    dof_secure_session_data *secure_session;

    /**
     * KEY EXCHANGE: Controlled by the caller, represents the key exchange
     * for INITIALIZE mode.
     */
    dof_session_key_exchange_data *session_key_data;
} dof_secmode_api_data;

/* These should be the only non-static declarations in the file. */
void proto_register_dof(void);
void proto_reg_handoff_dof(void);

/* Dissector routines. */
static int dissect_2008_1_dsp_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_2008_16_security_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_3_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_3_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_6_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_6_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_6_3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_9(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_11(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2008_16_security_13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2009_11_type_4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_2009_11_type_5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static const gchar* dof_oid_create_standard_string(guint32 bufferSize, const guint8 *pOIDBuffer);
static const gchar* dof_iid_create_standard_string(guint32 bufferSize, const guint8 *pIIDBuffer);
static guint8 dof_oid_create_internal(const char *oid, guint32 *size, guint8 *buffer);
static void dof_oid_new_standard_string(const char *data, guint32 *rsize, guint8 **oid);
static gint read_c4(tvbuff_t *tvb, gint offset, guint32 *v, gint *len);
static void validate_c4(packet_info *pinfo, proto_item *pi, guint32, gint len);
static gint read_c3(tvbuff_t *tvb, gint offset, guint32 *v, gint *len);
static void validate_c3(packet_info *pinfo, proto_item *pi, guint32, gint len);
static gint read_c2(tvbuff_t *tvb, gint offset, guint16 *v, gint *len);
static void validate_c2(packet_info *pinfo, proto_item *pi, guint16, gint len);

static gint dof_dissect_pdu(dissector_t dissector, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *result);
static gint dof_dissect_pdu_as_field(dissector_t disector, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int item, int ett, void *result);

#if 0 /* TODO not used yet */
static void dof_session_add_proto_data(dof_session_data *session, int proto, void *proto_data);
static void* dof_session_get_proto_data(dof_session_data *session, int proto);
static void dof_session_delete_proto_data(dof_session_data *session, int proto);
#endif

static void dof_packet_add_proto_data(dof_packet_data *packet, int proto, void *proto_data);
static void* dof_packet_get_proto_data(dof_packet_data *packet, int proto);
#if 0 /* TODO not used yet */
static void dof_packet_delete_proto_data(dof_packet_data *packet, int proto);
#endif

/* DOF PROTOCOL STACK */
#define DOF_PROTOCOL_STACK "DOF Protocol Stack"

/**
 * PORTS
 * The following ports are registered with IANA and used to hook transport
 * dissectors into the lower-level Wireshark transport dissectors.
 *
 * Related to these ports is the usage of conversations for DOF. The goal of
 * using Wireshark conversations is to guarantee that DPS data is available for
 * any DPS packet. However, there is no assumption that Wireshark conversations
 * map in any way to DOF sessions.
 *
 * One exception to this use is in discovery of DOF servers. The DOF_MCAST_NEG_SEC_UDP_PORT
 * is watched for all traffic. A "wildcard" conversation is then created for the
 * source address, and the DPS dissector is associated with that port. In this
 * way, servers on non-standard ports will automatically be decoded using DPS.
 */
#define DOF_P2P_NEG_SEC_UDP_PORT    3567
#define DOF_P2P_NEG_SEC_TCP_PORT    3567
/* Reserved UDP port                3568*/
#define DOF_TUN_SEC_TCP_PORT        3568
#define DOF_MCAST_NEG_SEC_UDP_PORT  5567
#define DOF_P2P_SEC_TCP_PORT        5567
/* Reserved UDP port                8567*/
#define DOF_TUN_NON_SEC_TCP_PORT    8567

/* This is needed to register multicast sessions with the UDP handler. */
static dissector_handle_t dof_udp_handle;

static int proto_2008_1_dof = -1;
static int proto_2008_1_dof_tcp = -1;
static int proto_2008_1_dof_udp = -1;

static int hf_2008_1_dof_session = -1;
static int hf_2008_1_dof_is_2_node = -1;
static int hf_2008_1_dof_is_streaming = -1;
static int hf_2008_1_dof_is_from_client = -1;
static int hf_2008_1_dof_frame = -1;
static int hf_2008_1_dof_session_transport = -1;

static int ett_2008_1_dof = -1;

/* DOF Tunnel Protocol */

/* UDP Registrations */
#define TUNNEL_PROTOCOL_STACK "DOF Tunnel Protocol Stack"
#define TUNNEL_APPLICATION_PROTOCOL "DOF Tunnel Protocol"

static dissector_table_t dof_tun_app_dissectors;

/***** TUNNEL *****/
static int proto_2012_1_tunnel = -1;

static int ett_2012_1_tunnel = -1;

static int hf_2012_1_tunnel_1_version = -1;
static int hf_2012_1_tunnel_1_length = -1;

/* DOF NETWORK PROTOCOL */
#define DNP_MAX_VERSION 1
#define DOF_NETWORK_PROTOCOL "DOF Network Protocol"

static dissector_table_t dnp_dissectors;
static dissector_table_t dnp_framing_dissectors;

static int proto_2008_1_dnp = -1;

static int hf_2008_1_dnp_1_version = -1;
static int hf_2008_1_dnp_1_flag = -1;

static int ett_2008_1_dnp = -1;
static int ett_2008_1_dnp_header = -1;

/* DNP V0 */
static int proto_2008_1_dnp_0 = -1;

static int hf_2008_1_dnp_0_1_1_padding = -1;
static int hf_2008_1_dnp_0_1_1_version = -1;

/* DNP V1 */
#define DNP_V1_DEFAULT_FLAGS    (0)
static int proto_2009_9_dnp_1 = -1;

static int hf_2009_9_dnp_1_flags = -1;
static int hf_2009_9_dnp_1_flag_length = -1;
static int hf_2009_9_dnp_1_length = -1;
static int hf_2009_9_dnp_1_flag_srcport = -1;
static int hf_2009_9_dnp_1_srcport = -1;
static int hf_2009_9_dnp_1_flag_dstport = -1;
static int hf_2009_9_dnp_1_dstport = -1;

static int ett_2009_9_dnp_1_flags = -1;

static const int *bitmask_2009_9_dnp_1_flags[] = {
    &hf_2009_9_dnp_1_flag_length,
    &hf_2009_9_dnp_1_flag_srcport,
    &hf_2009_9_dnp_1_flag_dstport,
    NULL
};

/* DOF PRESENTATION PROTOCOL */
#define DOF_PRESENTATION_PROTOCOL "DOF Presentation Protocol"

static dissector_table_t dof_dpp_dissectors;

static int proto_2008_1_dpp = -1;

static int hf_2008_1_dpp_sid_num = -1;
static int hf_2008_1_dpp_rid_num = -1;
static int hf_2008_1_dpp_sid_str = -1;
static int hf_2008_1_dpp_rid_str = -1;
static int hf_2008_1_dpp_first_command = -1;
static int hf_2008_1_dpp_last_command = -1;
static int hf_2008_1_dpp_first_response = -1;
static int hf_2008_1_dpp_last_response = -1;
static int hf_2008_1_dpp_related_frame = -1;
static int hf_2008_1_dpp_1_version = -1;
static int hf_2008_1_dpp_1_flag = -1;

static int ett_2008_1_dpp = -1;
static int ett_2008_1_dpp_1_header = -1;

/* DPP V0 */
static int proto_2008_1_dpp_0 = -1;

static int hf_2008_1_dpp_0_1_1_version = -1;

/* DPP V1 - RESERVED, NOT SUPPORTED */

/* DPP V2 */
#define DPP_V2_DEFAULT_FLAGS    (0)
#define DPP_V2_SEC_FLAG_E (0x80)
#define DPP_V2_SEC_FLAG_D (0x08)
#define DPP_V2_SEC_FLAG_P (0x04)
#define DPP_V2_SEC_FLAG_A (0x02)
#define DPP_V2_SEC_FLAG_S (0x01)

static int proto_2009_12_dpp = -1;
static int proto_2009_12_dpp_common = -1;

/* TODO: The complete on final and final flags are not covered. */
static int hf_2009_12_dpp_2_1_flags = -1;
static int hf_2009_12_dpp_2_1_flag_security = -1;
static int hf_2009_12_dpp_2_1_flag_opid = -1;
static int hf_2009_12_dpp_2_1_flag_seq = -1;
static int hf_2009_12_dpp_2_1_flag_retry = -1;
static int hf_2009_12_dpp_2_1_flag_cmdrsp = -1;
static int hf_2009_12_dpp_2_3_sec_flags = -1;
static int hf_2009_12_dpp_2_3_sec_flag_secure = -1;
static int hf_2009_12_dpp_2_3_sec_flag_rdid = -1;
static int hf_2009_12_dpp_2_3_sec_flag_partition = -1;
static int hf_2009_12_dpp_2_3_sec_flag_ssid = -1;
static int hf_2009_12_dpp_2_3_sec_flag_as = -1;
static int hf_2009_12_dpp_2_3_sec_ssid = -1;
static int hf_2009_12_dpp_2_3_sec_rdid = -1;
static int hf_2009_12_dpp_2_3_sec_remote_partition = -1;
static int hf_2009_12_dpp_2_3_sec_partition = -1;
static int hf_2009_12_dpp_2_1_opcnt = -1;
static int hf_2009_12_dpp_2_1_seq = -1;
static int hf_2009_12_dpp_2_1_retry = -1;
static int hf_2009_12_dpp_2_1_delay = -1;
static int hf_2009_12_dpp_2_14_opcode = -1;

static int ett_2009_12_dpp_2_1_flags = -1;
static int ett_2009_12_dpp_2_3_security = -1;
static int ett_2009_12_dpp_2_3_sec_flags = -1;
static int ett_2009_12_dpp_2_3_sec_remote_partition = -1;
static int ett_2009_12_dpp_2_3_sec_partition = -1;
static int ett_2009_12_dpp_2_opid = -1;
static int ett_2009_12_dpp_2_opid_history = -1;

static int ett_2009_12_dpp_common = -1;

static const value_string strings_2009_12_dpp_opid_types[] = {
    { 0, "Not Present" },
    { 1, "SID [Sender]" },
    { 2, "SID [Receiver]" },
    { 3, "SID [Explicit]" },
    { 0, NULL }
};

#define OP_2009_12_RESPONSE_FLAG      (0x80)
#define OP_2009_12_NODE_DOWN_CMD      (0)
#define OP_2009_12_NODE_DOWN_RSP      (OP_2009_12_RESPONSE_FLAG|OP_2009_12_NODE_DOWN_CMD)
#define OP_2009_12_SOURCE_LOST_CMD    (1)
#define OP_2009_12_SOURCE_LOST_RSP    (OP_2009_12_RESPONSE_FLAG|OP_2009_12_SOURCE_LOST_CMD)
#define OP_2009_12_RENAME_CMD         (2)
#define OP_2009_12_RENAME_RSP         (OP_2009_12_RESPONSE_FLAG|OP_2009_12_RENAME_CMD)
#define OP_2009_12_PING_CMD           (3)
#define OP_2009_12_PING_RSP           (OP_2009_12_RESPONSE_FLAG|OP_2009_12_PING_CMD)
#define OP_2009_12_CANCEL_ALL_CMD     (4)
#define OP_2009_12_CANCEL_ALL_RSP     (OP_2009_12_RESPONSE_FLAG|OP_2009_12_CANCEL_ALL_CMD)
#define OP_2009_12_HEARTBEAT_CMD      (5)
#define OP_2009_12_HEARTBEAT_RSP      (OP_2009_12_RESPONSE_FLAG|OP_2009_12_HEARTBEAT_CMD)
#define OP_2009_12_QUERY_CMD          (6)
#define OP_2009_12_QUERY_RSP          (OP_2009_12_RESPONSE_FLAG|OP_2009_12_QUERY_CMD)
#define OP_2009_12_SOURCE_FOUND_CMD   (8)
#define OP_2009_12_SOURCE_FOUND_RSP   (OP_2009_12_RESPONSE_FLAG|OP_2009_12_SOURCE_FOUND_CMD)

static const value_string strings_2009_12_dpp_common_opcodes[] = {
    { OP_2009_12_NODE_DOWN_CMD, "DPP Node Down" },
    { OP_2009_12_NODE_DOWN_RSP, "DPP Node Down Response (Illegal)" },
    { OP_2009_12_SOURCE_LOST_CMD, "DPP Source Lost" },
    { OP_2009_12_SOURCE_LOST_RSP, "DPP Source Lost Response (Illegal)" },
    { OP_2009_12_SOURCE_FOUND_CMD, "DPP Source Found" },
    { OP_2009_12_SOURCE_FOUND_RSP, "DPP Source Found Response (Illegal)" },
    { OP_2009_12_RENAME_CMD, "DPP Rename" },
    { OP_2009_12_RENAME_RSP, "DPP Rename Response (Illegal)" },
    { OP_2009_12_PING_CMD, "DPP Ping" },
    { OP_2009_12_PING_RSP, "DPP Ping Response" },
    { OP_2009_12_HEARTBEAT_CMD, "DPP Heartbeat" },
    { OP_2009_12_HEARTBEAT_RSP, "DPP Heartbeat Response (Illegal)" },
    { OP_2009_12_QUERY_CMD, "DPP Query" },
    { OP_2009_12_QUERY_RSP, "DPP Query Response" },
    { OP_2009_12_CANCEL_ALL_CMD, "DPP Cancel All" },
    { OP_2009_12_CANCEL_ALL_RSP, "DPP Cancel All Response (Illegal)" },
    { 0, NULL }
};

/* DOF APPLICATION PROTOCOL */
#define DOF_APPLICATION_PROTOCOL "DOF Application Protocol"

static dissector_table_t app_dissectors;

static int proto_2008_1_app = -1;

static int hf_2008_1_app_version = -1;

/* DAP V0 (DSP - DOF SESSION PROTOCOL) */
/* Note that DSP is *always* appid 0 and so it violates the standard naming rule. */
static dissector_table_t dsp_option_dissectors;

static int hf_2008_1_dsp_12_opcode = -1;
static int hf_2008_1_dsp_attribute_code = -1;
static int hf_2008_1_dsp_attribute_data = -1;
static int hf_2008_1_dsp_value_length = -1;
static int hf_2008_1_dsp_value_data = -1;

static const value_string strings_2008_1_dsp_attribute_codes[] = {
    { 0, "TEP Family" },
    { 1, "OAP Family" },
    { 2, "CCM Family" },
    { 3, "TRP Family" },
    { 255, "General" },
    { 0, NULL }
};

#define DOF_PROTOCOL_DSP 0
#define DSP_OAP_FAMILY 0x010000

static int proto_2008_1_dsp = -1;

#define OP_2008_1_RSP                   (0x80)
#define OP_2008_1_QUERY_CMD             0
#define OP_2008_1_QUERY_RSP             (OP_2008_1_RSP|OP_2008_1_QUERY_CMD)
#define OP_2008_1_CONFIG_REQ            1
#define OP_2008_1_CONFIG_ACK            (OP_2008_1_RSP|2)
#define OP_2008_1_CONFIG_NAK            (OP_2008_1_RSP|3)
#define OP_2008_1_CONFIG_REJ            (OP_2008_1_RSP|4)
#define OP_2008_1_TERMINATE_CMD         5
#define OP_2008_1_TERMINATE_RSP         (OP_2008_1_RSP|OP_2008_1_TERMINATE_CMD)
#define OP_2008_1_OPEN_CMD              6
#define OP_2008_1_OPEN_RSP              (OP_2008_1_RSP|OP_2008_1_OPEN_CMD)
#define OP_2008_1_OPEN_SECURE_RSP       (OP_2008_1_RSP|7)

static const value_string strings_2008_1_dsp_opcodes[] = {
    { OP_2008_1_QUERY_CMD, "DSP Query" },
    { OP_2008_1_QUERY_RSP, "DSP Query Response" },
    { OP_2008_1_CONFIG_REQ, "DSP Request" },
    { OP_2008_1_CONFIG_ACK, "DSP ACK Response" },
    { OP_2008_1_CONFIG_NAK, "DSP NAK Response" },
    { OP_2008_1_CONFIG_REJ, "DSP REJ Response" },
    { OP_2008_1_TERMINATE_CMD, "DSP Terminate/Close Request" },
    { OP_2008_1_TERMINATE_RSP, "DSP Terminate/Close Response" },
    { OP_2008_1_OPEN_CMD, "DSP Open" },
    { OP_2008_1_OPEN_RSP, "DSP Open Response" },
    { OP_2008_1_OPEN_SECURE_RSP, "DSP Open Secure Response" },
    { 0, NULL }
};

#define DSP_AVP_AUTHENTICATION          0
#define DSP_AVP_APPLICATION             1

#if 0 /* not used yet */
static const value_string strings_2008_1_dsp_attributes[] = {
    { DSP_AVP_AUTHENTICATION, "Authentication Protocol" },
    { DSP_AVP_APPLICATION, "Application Protocol" },
    { 0, NULL }
};

static const value_string strings_2008_1_dsp_values[] = {
    { 1, "DOF Object Access Protocol (version 1)" },
    { 3, "DOF Ticket Exchange Protocol (version 1)" },
    { 0, NULL }
};
#endif

static int ett_2008_1_dsp_12 = -1;
static int ett_2008_1_dsp_12_options = -1;
static int ett_2008_1_dsp_12_option = -1;

/* DAP V1 (OAP - OBJECT ACCESS PROTOCOL V1) */
/* This is the defined protocol id for OAP. */
#define DOF_PROTOCOL_OAP_1 1
/* There are two "protocols", one hooks into DSP and the other to DOF. */
static int proto_oap_1 = -1;
static int proto_oap_1_dsp = -1;

/* OAP DSP protocol items. */
static int hf_oap_1_dsp_option = -1;

/* OAP protocol items. */
static int hf_oap_1_opcode = -1;

static int hf_oap_1_alias_size = -1;
static int hf_oap_1_flags = -1;
static int hf_oap_1_exception_internal_flag = -1;
static int hf_oap_1_exception_final_flag = -1;
static int hf_oap_1_exception_provider_flag = -1;
static int hf_oap_1_cmdcontrol = -1;
static int hf_oap_1_cmdcontrol_cache_flag = -1;
static int hf_oap_1_cmdcontrol_verbosity_flag = -1;
static int hf_oap_1_cmdcontrol_noexecute_flag = -1;
static int hf_oap_1_cmdcontrol_ack_flag = -1;
static int hf_oap_1_cmdcontrol_delay_flag = -1;
static int hf_oap_1_cmdcontrol_heuristic_flag = -1;
static int hf_oap_1_cmdcontrol_heuristic = -1;
static int hf_oap_1_cmdcontrol_cache = -1;
static int hf_oap_1_cmdcontrol_ackcnt = -1;
static int hf_oap_1_cmdcontrol_ack = -1;

#if 0 /* not used yet */
static int hf_oap_1_opinfo_start_frame = -1;
static int hf_oap_1_opinfo_end_frame = -1;
static int hf_oap_1_opinfo_timeout = -1;
#endif

static int hf_oap_1_providerid = -1;
static int ett_oap_1_1_providerid = -1;

static int hf_oap_1_objectid = -1;
static int ett_oap_1_objectid = -1;

static int hf_oap_1_interfaceid = -1;
static int hf_oap_1_itemid = -1;

#if 0 /* not used yet */
static int hf_oap_1_distance = -1;
#endif

static int hf_oap_1_alias = -1;
static int hf_oap_1_alias_frame = -1;

static int hf_oap_1_subscription_delta = -1;
static int hf_oap_1_update_sequence = -1;
static int hf_oap_1_value_list = -1;

static int ett_oap_1_dsp = -1;
static int ett_oap_1_dsp_options = -1;

static int ett_oap_1 = -1;
static int ett_oap_1_opinfo = -1;
static int ett_oap_1_cmdcontrol = -1;
static int ett_oap_1_cmdcontrol_flags = -1;
static int ett_oap_1_cmdcontrol_ack = -1;
static int ett_oap_1_alias = -1;

static const int *bitmask_oap_1_cmdcontrol_flags[] = {
    &hf_oap_1_cmdcontrol_cache_flag,
    &hf_oap_1_cmdcontrol_verbosity_flag,
    &hf_oap_1_cmdcontrol_noexecute_flag,
    &hf_oap_1_cmdcontrol_ack_flag,
    &hf_oap_1_cmdcontrol_delay_flag,
    &hf_oap_1_cmdcontrol_heuristic_flag,
    NULL
};

static expert_field ei_oap_no_session = EI_INIT;

static GHashTable *oap_1_alias_to_binding = NULL;

#define OAP_1_RESPONSE                    (0x80)
#define OAP_1_CMD_ACTIVATE                28
#define OAP_1_RSP_ACTIVATE                (OAP_1_CMD_ACTIVATE|OAP_1_RESPONSE)
#define OAP_1_CMD_ADVERTISE               5
#define OAP_1_RSP_ADVERTISE               (OAP_1_CMD_ADVERTISE|OAP_1_RESPONSE)
#define OAP_1_CMD_CHANGE                  2
#define OAP_1_RSP_CHANGE                  (OAP_1_CMD_CHANGE|OAP_1_RESPONSE)
#define OAP_1_CMD_CONNECT                 4
#define OAP_1_RSP_CONNECT                 (OAP_1_CMD_CONNECT|OAP_1_RESPONSE)
#define OAP_1_CMD_DEFINE                  6
#define OAP_1_RSP_DEFINE                  (OAP_1_CMD_DEFINE|OAP_1_RESPONSE)
#define OAP_1_CMD_EXCEPTION               9
#define OAP_1_RSP_EXCEPTION               (OAP_1_CMD_EXCEPTION|OAP_1_RESPONSE)
#define OAP_1_CMD_FULL_CONNECT            3
#define OAP_1_RSP_FULL_CONNECT            (OAP_1_CMD_FULL_CONNECT|OAP_1_RESPONSE)
#define OAP_1_CMD_GET                     10
#define OAP_1_RSP_GET                     (OAP_1_CMD_GET|OAP_1_RESPONSE)
#define OAP_1_CMD_INVOKE                  12
#define OAP_1_RSP_INVOKE                  (OAP_1_CMD_INVOKE|OAP_1_RESPONSE)
#define OAP_1_CMD_OPEN                    14
#define OAP_1_RSP_OPEN                    (OAP_1_CMD_OPEN|OAP_1_RESPONSE)
#define OAP_1_CMD_PROVIDE                 16
#define OAP_1_RSP_PROVIDE                 (OAP_1_CMD_PROVIDE|OAP_1_RESPONSE)
#define OAP_1_CMD_REGISTER                25
#define OAP_1_RSP_REGISTER                (OAP_1_CMD_REGISTER|OAP_1_RESPONSE)
#define OAP_1_CMD_SET                     20
#define OAP_1_RSP_SET                     (OAP_1_CMD_SET|OAP_1_RESPONSE)
#define OAP_1_CMD_SIGNAL                  22
#define OAP_1_RSP_SIGNAL                  (OAP_1_CMD_SIGNAL|OAP_1_RESPONSE)
#define OAP_1_CMD_SUBSCRIBE               24
#define OAP_1_RSP_SUBSCRIBE               (OAP_1_CMD_SUBSCRIBE|OAP_1_RESPONSE)
#define OAP_1_CMD_WATCH                   30
#define OAP_1_RSP_WATCH                   (OAP_1_CMD_WATCH|OAP_1_RESPONSE)

static const value_string oap_opcode_strings[] = {
    { OAP_1_CMD_ACTIVATE, "OAP Activate" },
    { OAP_1_RSP_ACTIVATE, "OAP Activate Response (Illegal)" },
    { OAP_1_CMD_ADVERTISE, "OAP Advertise" },
    { OAP_1_RSP_ADVERTISE, "OAP Advertise Response (Illegal)" },
    { OAP_1_CMD_CHANGE, "OAP Change" },
    { OAP_1_RSP_CHANGE, "OAP Change Response (Illegal)" },
    { OAP_1_CMD_CONNECT, "OAP Connect" },
    { OAP_1_RSP_CONNECT, "OAP Connect Response (Illegal)" },
    { OAP_1_CMD_DEFINE, "OAP Define" },
    { OAP_1_RSP_DEFINE, "OAP Define Response" },
    { OAP_1_CMD_EXCEPTION, "OAP Exception (Illegal)" },
    { OAP_1_RSP_EXCEPTION, "OAP Exception Response" },
    { OAP_1_CMD_FULL_CONNECT, "OAP Full Connect" },
    { OAP_1_RSP_FULL_CONNECT, "OAP Full Connect Response (Illegal)" },
    { OAP_1_CMD_GET, "OAP Get" },
    { OAP_1_RSP_GET, "OAP Get Response" },
    { OAP_1_CMD_INVOKE, "OAP Invoke" },
    { OAP_1_RSP_INVOKE, "OAP Invoke Response" },
    { OAP_1_CMD_OPEN, "OAP Open" },
    { OAP_1_RSP_OPEN, "OAP Open Response" },
    { OAP_1_CMD_PROVIDE, "OAP Provide" },
    { OAP_1_RSP_PROVIDE, "OAP Provide Response (Illegal)" },
    { OAP_1_CMD_REGISTER, "OAP Register" },
    { OAP_1_RSP_REGISTER, "OAP Register Response" },
    { OAP_1_CMD_SET, "OAP Set" },
    { OAP_1_RSP_SET, "OAP Set Response" },
    { OAP_1_CMD_SIGNAL, "OAP Signal" },
    { OAP_1_RSP_SIGNAL, "OAP Signal Response (Illegal)" },
    { OAP_1_CMD_SUBSCRIBE, "OAP Subscribe" },
    { OAP_1_RSP_SUBSCRIBE, "OAP Subscribe Response" },
    { OAP_1_CMD_WATCH, "OAP Watch" },
    { OAP_1_RSP_WATCH, "OAP Watch Response (Illegal)" },

    { 0, NULL }
};

typedef struct _alias_key
{
    guint32 session;
    guint32 sender;
    guint32 alias;
} oap_1_alias_key;

static guint oap_1_alias_hash_func(gconstpointer ptr)
{
    const oap_1_alias_key *key = (const oap_1_alias_key *)ptr;
    return g_int_hash(&key->session) + g_int_hash(&key->sender) + g_int_hash(&key->alias);
}

static int oap_1_alias_equal_func(gconstpointer ptr1, gconstpointer ptr2)
{
    const oap_1_alias_key *key1 = (const oap_1_alias_key *)ptr1;
    const oap_1_alias_key *key2 = (const oap_1_alias_key *)ptr2;

    if (key1->session != key2->session)
        return 0;

    if (key1->sender != key2->sender)
        return 0;

    if (key1->alias != key2->alias)
        return 0;

    return 1;
}

typedef struct
{
    guint8 *oid;
    guint16 oid_length;
    guint8 *iid;
    guint16 iid_length;
    guint32 frame;
} oap_1_binding;

typedef struct oap_1_binding_list
{
    oap_1_binding *binding;
    struct oap_1_binding_list *next;
} oap_1_binding_list;

typedef struct
{
    oap_1_binding *resolved_alias;
} oap_1_packet_data;

static oap_1_binding* oap_1_resolve_alias(oap_1_alias_key *key);

static int oap_1_tree_add_alias(dof_api_data *api_data, oap_1_packet_data *oap_packet _U_, dof_packet_data *packet, proto_tree *tree, tvbuff_t *tvb, gint offset, guint8 alias_length, guint8 resolve)
{
    dof_session_data *session = api_data->session;
    proto_item *ti;
    proto_tree *options_tree;

    if (alias_length == 0)
    /* TODO: Output error. */
        return offset;

    if (session == NULL)
    /* TODO: Output error. */
        return offset;

    ti = proto_tree_add_item(tree, hf_oap_1_alias, tvb, offset, alias_length, ENC_BIG_ENDIAN);

    if (resolve)
    {
        oap_1_binding *binding = NULL;
        oap_1_alias_key key;
        int i;
        guint32 alias;

        alias = 0;
        for (i = 0; i < alias_length; i++)
            alias = (alias << 8) | tvb_get_guint8(tvb, offset + i);

        key.session = session->session_id;
        key.sender = packet->sender_id;
        key.alias = alias;
        binding = oap_1_resolve_alias(&key);
        if (binding)
        {
            options_tree = proto_item_add_subtree(ti, ett_oap_1_alias);

            /* Decode the Interface */
            ti = proto_tree_add_bytes_format_value(tree, hf_oap_1_interfaceid, tvb, offset, alias_length, binding->iid, "%s", dof_iid_create_standard_string(binding->iid_length, binding->iid));
            PROTO_ITEM_SET_GENERATED(ti);

            /* Decode the Object ID */
            ti = proto_tree_add_bytes_format_value(tree, hf_oap_1_objectid, tvb, offset, alias_length, binding->oid, "%s", dof_oid_create_standard_string(binding->oid_length, binding->oid));
            PROTO_ITEM_SET_GENERATED(ti);

            proto_tree_add_uint_format(options_tree, hf_oap_1_alias_frame,
                                       tvb, 0, 0, binding->frame,
                                       "This alias is defined in frame %u",
                                       binding->frame);
        }
    }

    return offset + alias_length;
}

static int oap_1_tree_add_interface(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    guint8 registry;
    guint8 len;

    registry = tvb_get_guint8(tvb, offset);
    len = registry & 0x03;
    if (len == 0)
        len = 16;
    else
        len = 1 << (len - 1);

    proto_tree_add_item(tree, hf_oap_1_interfaceid, tvb, offset, 1 + len, ENC_NA);
    return offset + 1 + len;
}

static int oap_1_tree_add_binding(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    guint8 len;
  /*  guint8 cl; */

    len = tvb_get_guint8(tvb, offset);
    len = len & 0x03;
    if (len == 0)
        len = 16;
    else
        len = 1 << (len - 1);

    proto_tree_add_item(tree, hf_oap_1_interfaceid, tvb, offset, 1 + len, ENC_NA);
    offset += 1 + len;

#if 0 /* this seems to be dead code - check! */
    cl = tvb_get_guint8(tvb, offset);
    if (cl & 0x80)
        len = tvb_get_guint8(tvb, offset + 2);
    else
        len = tvb_get_guint8(tvb, offset + 1);
#endif

    offset = dof_dissect_pdu_as_field(dissect_2009_11_type_4, tvb, pinfo, tree,
                                      offset, hf_oap_1_objectid, ett_oap_1_objectid, NULL);
    return offset;
}

static int oap_1_tree_add_cmdcontrol(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_item *ti;
    proto_tree *opinfo_tree;
    guint8 flags;

    flags = tvb_get_guint8(tvb, offset);

    ti = proto_tree_add_bitmask(tree, tvb, offset, hf_oap_1_cmdcontrol, ett_oap_1_cmdcontrol_flags, bitmask_oap_1_cmdcontrol_flags, ENC_NA);
    opinfo_tree = proto_item_add_subtree(ti, ett_oap_1_cmdcontrol);

    proto_tree_add_item(opinfo_tree, hf_oap_1_cmdcontrol_cache_flag, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(opinfo_tree, hf_oap_1_cmdcontrol_verbosity_flag, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(opinfo_tree, hf_oap_1_cmdcontrol_noexecute_flag, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(opinfo_tree, hf_oap_1_cmdcontrol_ack_flag, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(opinfo_tree, hf_oap_1_cmdcontrol_delay_flag, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(opinfo_tree, hf_oap_1_cmdcontrol_heuristic_flag, tvb, offset, 1, ENC_NA);

    offset += 1;

    if (flags & 0x01)
    {
        /* Heuristic */
        gint heur_len;
        guint16 heur;
        proto_item *pi;

        read_c2(tvb, offset, &heur, &heur_len);
        pi = proto_tree_add_uint_format(opinfo_tree, hf_oap_1_cmdcontrol_heuristic, tvb, offset, heur_len, heur, "Heuristic Value: %hu", heur);
        validate_c2(pinfo, pi, heur, heur_len);
        offset += heur_len;
    }

    if (flags & 0x04)
    {
        /* Ack List */
        guint8 ackcnt;
        guint8 i;

        ackcnt = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(opinfo_tree, hf_oap_1_cmdcontrol_ackcnt, tvb, offset, 1, ENC_NA);
        offset += 1;

        for (i = 0; i < ackcnt; i++)
        {
            offset = dof_dissect_pdu_as_field(dissect_2009_11_type_4, tvb, pinfo, opinfo_tree,
                                              offset, hf_oap_1_cmdcontrol_ack, ett_oap_1_cmdcontrol_ack, NULL);
        }
    }

    if (flags & 0x40)
    {
        /* Cache Delay */
        gint cache_len;
        guint16 cache;
        proto_item *pi;

        read_c2(tvb, offset, &cache, &cache_len);
        pi = proto_tree_add_uint_format(opinfo_tree, hf_oap_1_cmdcontrol_cache, tvb, offset, cache_len, cache, "Cache Delay: %hu", cache);
        validate_c2(pinfo, pi, cache, cache_len);
        offset += cache_len;
    }

    return offset;
}

/**
 * Define an alias. This routine is called for each Provide operation that includes an alias assignment.
 * It is also called for retries of Provide operations.
 * The alias is defined for the duration of the Provide. This means that if the operation is cancelled
 * then the alias should no longer be valid.
 * The alias is associated with an oap_session, an dof_node, and the alias itself. Aliases
 * may be reused as long as the previous use has expired, and so the list is stored in reverse
 * order.
 *
 * NOTE: The alias is passed as a structure pointer, and must be reallocated if it is stored in
 * the hash.
 */
static void oap_1_define_alias(dof_api_data *api_data, guint32 alias, oap_1_binding *binding)
{
    /* The definer of an alias is the sender, in the session. */
    dof_session_data *session = api_data->session;
    dof_packet_data *packet = (dof_packet_data *)api_data->packet;
    guint32 session_id;
    guint32 sender_id;
    oap_1_alias_key key;

    if (!session)
        return;

    session_id = session->session_id;
    sender_id = packet->sender_id;

    if (!binding)
        return;

    key.session = session_id;
    key.sender = sender_id;
    key.alias = alias;

    /* If there isn't an entry for the alias, then we need to create one.
    * The first entry will be the binding we are defining.
    */
    if (!g_hash_table_lookup(oap_1_alias_to_binding, &key))
    {
        oap_1_alias_key *alias_ptr = (oap_1_alias_key *)wmem_alloc0(wmem_file_scope(), sizeof(oap_1_alias_key));
        memcpy(alias_ptr, &key, sizeof(oap_1_alias_key));
        g_hash_table_insert(oap_1_alias_to_binding, alias_ptr, binding);
    }
}

/**
 * Given an oap_alias, resolve it to an oap_1_binding. This assumes that the destination of the
 * packet is the one that defined the alias.
 */
static oap_1_binding* oap_1_resolve_alias(oap_1_alias_key *key)
{
    /* The first lookup is inside the session based on defining node. */
    return (oap_1_binding *)g_hash_table_lookup(oap_1_alias_to_binding, key);
}

/* DAP V128 (TEP - TICKET EXCHANGE PROTOCOL V1) */
#define DOF_PROTOCOL_TEP 128
#define DSP_TEP_FAMILY 0x000000
static int proto_tep = -1;
static int proto_tep_dsp = -1;

static int hf_dsp_option = -1;

static int ett_tep_operation = -1;
static int hf_tep_operation = -1;
static int hf_tep_operation_type = -1;
static int hf_tep_opcode = -1;
static int hf_tep_k = -1;
static int hf_tep_c = -1;
static int hf_tep_reject_code = -1;
static int hf_tep_reject_data = -1;

static const true_false_string tep_optype_vals = { "DPP Response", "DPP Command" };

/* TEP.2.1 */
static int ett_tep_2_1_domain = -1;
static int hf_tep_2_1_domain = -1;
static int ett_tep_2_1_initiator_block = -1;
static int hf_tep_2_1_initiator_block = -1;
static int hf_tep_2_1_ticket_confirmation = -1;

/* TEP.2.2 */
static int ett_tep_2_2_initiator_ticket = -1;
static int hf_tep_2_2_initiator_ticket = -1;
static int hf_tep_2_2_ticket_confirmation = -1;
static int ett_tep_2_2_responder_initialization = -1;
static int hf_tep_2_2_responder_initialization = -1;
static int ett_tep_2_2_responder_block = -1;
static int hf_tep_2_2_responder_block = -1;
static int ett_tep_2_2_authenticator_initialization = -1;
static int hf_tep_2_2_authenticator_initialization = -1;

/* TEP.2.2.1 */
static int hf_tep_2_2_1_state_identifier = -1;
static int ett_tep_2_2_1_initial_state = -1;
static int hf_tep_2_2_1_initial_state = -1;

static int hf_tep_session_key = -1;

static int ett_tep_dsp = -1;
static int ett_tep_dsp_options = -1;
static int ett_tep = -1;

#if 0 /* not used yet */
static const value_string tep_filter_existing[] = {
    { 1, "Include Existing Matches" },
    { 0, "Exclude Existing Matches" },
    { 0, NULL }
};
#endif

#define TEP_OPCODE_RSP                                                  (0x80)
#define TEP_OPCODE_C                                                    (0x20)
#define TEP_OPCODE_K                                                    (0x10)
#define TEP_PDU_REJECT                                                  (TEP_OPCODE_RSP|0)
#define TEP_PDU_REQUEST                                                 (1)
#define TEP_PDU_END_SESSION                                             (5)
#define TEP_PDU_SESSION_ENDING                                  (6)

#define TEP_PDU_REQUEST_KEY                                             (TEP_OPCODE_K|TEP_PDU_REQUEST)
#define TEP_PDU_CONFIRM                                                 (TEP_OPCODE_C|TEP_PDU_REQUEST)
#define TEP_PDU_ACCEPT                                                  (TEP_OPCODE_RSP|TEP_PDU_REQUEST)
#define TEP_PDU_CONFIRM_ACK                                             (TEP_OPCODE_RSP|TEP_OPCODE_C|TEP_PDU_REQUEST)

static const value_string tep_opcode_strings[] = {
    { TEP_PDU_REJECT, "TEP Reject" },
    { TEP_PDU_REQUEST, "TEP Request" },
    { TEP_PDU_END_SESSION, "TEP End Session" },
    { TEP_PDU_SESSION_ENDING, "TEP Session Ending" },

    { TEP_PDU_REQUEST_KEY, "TEP Rekey" },
    { TEP_PDU_CONFIRM, "TEP Confirm" },
    { TEP_PDU_ACCEPT, "TEP Accept" },
    { TEP_PDU_CONFIRM_ACK, "TEP Confirm Ack" },

    { 0, NULL }
};

#if 0 /* not use yet */
static const value_string tep_error_strings[] = {
    { 1, "Parse Error" },
    { 2, "Access Denied" },
    { 3, "Duration Not Supported" },
    { 4, "Authentication Failed" },
    { 0, NULL }
};
#endif

/* Initialized to zero. */
typedef struct tep_rekey_data
{
    /* Stored from the K bit of the Request PDU. */
    gboolean is_rekey;

    /* Stored from the key request for non-secure rekeys. Otherwise 0 and NULL. */
    guint8 domain_length;
    guint8 *domain;

    /* Stored from the identity of the Request PDU. Seasonal. */
    guint8 *i_identity;
    guint8 i_identity_length;

    /* Stored from the nonce of the Request PDU. Seasonal. */
    guint8 *i_nonce;
    guint8 i_nonce_length;

    /* Stored from the identity of the Request response PDU. Seasonal. */
    guint8 *r_identity;
    guint8 r_identity_length;

    /* Stored from the nonce of the Request response PDU. Seasonal. */
    guint8 *r_nonce;
    guint8 r_nonce_length;

    guint16 security_mode;
    guint32 security_mode_data_length;
    guint8 *security_mode_data;

    /* Security session data for this rekey, if is_rekey is TRUE. */
    dof_session_key_exchange_data *key_data;
} tep_rekey_data;

/* DAP V129 (TRP - TICKET REQUEST PROTOCOL V2) */
#define DOF_PROTOCOL_TRP 129
#define DSP_TRP_FAMILY 0x030000
typedef struct _trp_packet_data
{
    guint8 *domain;
    guint8 domain_length;
    guint8 *identity;
    guint8 identity_length;
    guint8 *group;
    guint8 group_length;
    guint8 *block_I;
    guint16 block_I_length;
    guint8 *secret;
    gboolean kek_known;
} trp_packet_data;


static int proto_trp = -1;
static int proto_trp_dsp = -1;

static int hf_trp_dsp_option = -1;

static int hf_trp_opcode = -1;
static int hf_domain = -1;
static int hf_identity_resolution = -1;
static int hf_initiator_request = -1;
static int hf_responder_request = -1;
static int hf_initiator_ticket = -1;
static int hf_responder_ticket = -1;
static int hf_authentication_block = -1;
static int hf_group_identifier = -1;
static int hf_node_identifier = -1;
static int hf_thb = -1;
static int hf_tmin = -1;
static int hf_tmax = -1;
static int hf_trp_epoch = -1;
static int hf_sidg = -1;
static int hf_security_scope = -1;
static int hf_security_mode = -1;
static int hf_ssid = -1;
#if 0 /* not used yet */
static int hf_initiator_pg = -1;
#endif
static int hf_initiator_validation = -1;
static int hf_responder_pg = -1;
static int hf_responder_validation = -1;

static int hf_trp_errorcode = -1;
static int hf_trp_duration = -1;
#if 0 /* not used yet */
static int hf_trp_rnonce = -1;
static int hf_trp_pnonce = -1;
static int hf_trp_reqid = -1;
static int hf_trp_provid = -1;
static int hf_trp_perm_count = -1;
static int hf_trp_perm_type = -1;
static int hf_trp_perm_rcache = -1;
static int hf_trp_perm_rsrp = -1;
static int hf_trp_perm_rsrp_a = -1;
static int hf_trp_perm_rsrp_u = -1;
static int hf_trp_perm_rflags = -1;
static int hf_trp_perm_pcache = -1;
static int hf_trp_perm_psrp = -1;
static int hf_trp_perm_psrp_a = -1;
static int hf_trp_perm_psrp_u = -1;
static int hf_trp_perm_psrp_b = -1;
static int hf_trp_perm_psrp_s = -1;
static int hf_trp_perm_pflags = -1;
static int hf_trp_confirmation = -1;
static int hf_trp_perm_pke = -1;
static int hf_trp_perm_pka = -1;
#endif

static int ett_trp_dsp = -1;
static int ett_trp = -1;
static int ett_domain = -1;
static int ett_identity_resolution = -1;
static int ett_initiator_request = -1;
static int ett_initiator_ticket = -1;
static int ett_responder_request = -1;
static int ett_responder_ticket = -1;
static int ett_authentication_block = -1;
static int ett_group_identifier = -1;
static int ett_node_identifier = -1;
static int ett_sidg = -1;
static int ett_security_scope = -1;
static int ett_security_mode = -1;
static int ett_initiator_pg = -1;
static int ett_initiator_validation = -1;
static int ett_responder_pg = -1;
static int ett_responder_validation = -1;


static int ett_trp_permset = -1;
static int ett_srp_flags = -1;
static int ett_trp_ticket = -1;

static expert_field ei_trp_initiator_id_known = EI_INIT;
static expert_field ei_trp_kek_discovered = EI_INIT;

#define TRP_RESPONSE                    (0x80)

#define TRP_RSP_REJECT                                                  (TRP_RESPONSE|0)
#define TRP_CMD_REQUEST_KEK                                             (1)
#define TRP_RSP_REQUEST_KEK                                             (TRP_RESPONSE|TRP_CMD_REQUEST_KEK)
#define TRP_CMD_REQUEST_RANDOM                                  (2)
#define TRP_RSP_REQUEST_RANDOM                                  (TRP_RESPONSE|TRP_CMD_REQUEST_RANDOM)
#define TRP_CMD_REQUEST_SESSION                                 (3)
#define TRP_RSP_REQUEST_SESSION                                 (TRP_RESPONSE|TRP_CMD_REQUEST_SESSION)
#define TRP_CMD_REQUEST_SECURITY_SCOPES                 (4)
#define TRP_RSP_REQUEST_SECURITY_SCOPES                 (TRP_RESPONSE|TRP_CMD_REQUEST_SECURITY_SCOPES)
#define TRP_CMD_RESOLVE_CREDENTIAL                              (6)
#define TRP_RSP_RESOLVE_CREDENTIAL                              (TRP_RESPONSE|TRP_CMD_RESOLVE_CREDENTIAL)
#define TRP_CMD_REQUEST_LOCAL_DOMAIN                    (7)
#define TRP_RSP_REQUEST_LOCAL_DOMAIN                    (TRP_RESPONSE|TRP_CMD_REQUEST_LOCAL_DOMAIN)
#define TRP_CMD_REQUEST_REMOTE_DOMAIN                   (8)
#define TRP_RSP_REQUEST_REMOTE_DOMAIN                   (TRP_RESPONSE|TRP_CMD_REQUEST_REMOTE_DOMAIN)
#define TRP_RSP_REQUEST_DISCOVERED_REMOTE_DOMAIN        (TRP_RESPONSE|0x0A)
#define TRP_CMD_VALIDATE_CREDENTIAL                             (9)
#define TRP_RSP_VALIDATE_CREDENTIAL                             (TRP_RESPONSE|TRP_CMD_VALIDATE_CREDENTIAL)

static const value_string trp_opcode_strings[] = {
    { TRP_RSP_REJECT, "Reject" },

    { TRP_CMD_REQUEST_KEK, "TRP Request KEK" },
    { TRP_RSP_REQUEST_KEK, "TRP Request KEK Response" },

    { TRP_CMD_REQUEST_RANDOM, "TRP Request Random" },
    { TRP_RSP_REQUEST_RANDOM, "TRP Request Random Response" },

    { TRP_CMD_REQUEST_SESSION, "TRP Request Session" },
    { TRP_RSP_REQUEST_SESSION, "TRP Request Session Response" },

    { TRP_CMD_REQUEST_SECURITY_SCOPES, "TRP Request Security Scopes" },
    { TRP_RSP_REQUEST_SECURITY_SCOPES, "TRP Request Security Scopes Response" },

    { TRP_CMD_RESOLVE_CREDENTIAL, "TRP Resolve Credential" },
    { TRP_RSP_RESOLVE_CREDENTIAL, "TRP Resolve Credential Response" },

    { TRP_CMD_REQUEST_LOCAL_DOMAIN, "TRP Request Local Domain" },
    { TRP_RSP_REQUEST_LOCAL_DOMAIN, "TRP Request Local Domain Response" },

    { TRP_CMD_REQUEST_REMOTE_DOMAIN, "TRP Request Remote Domain" },
    { TRP_RSP_REQUEST_REMOTE_DOMAIN, "TRP Request Remote Domain Response" },
    { TRP_RSP_REQUEST_DISCOVERED_REMOTE_DOMAIN, "TRP Request Discovered Remote Domain Response" },

    { TRP_CMD_VALIDATE_CREDENTIAL, "TRP Validate Credential" },
    { TRP_RSP_VALIDATE_CREDENTIAL, "TRP Validate Credential Response" },

    { 0, NULL }
};

static const value_string trp_error_strings[] = {
    { 1, "Parse Error" },
    { 2, "Access Denied" },
    { 3, "Unknown Initiator" },
    { 4, "Unknown Responder" },
    { 5, "Unknown Domain" },
    { 6, "High Load" },
    { 7, "Bad Mode" },
    { 8, "Incompatible Security Identifiers" },
    { 127, "Internal Error" },

    { 0, NULL }
};

/* DAP V130 (SGMP - SECURE GROUP MANAGEMENT PROTOCOL V1) */
#define DOF_PROTOCOL_SGMP       130
typedef struct _sgmp_packet_data
{
    guint8 domain_length;
    guint8 *domain;

    guint8 group_length;
    guint8 *group;

    guint16 epoch;
    guint8 *kek;

    guint I_length;
    guint8 *I;
    guint A_length;
    guint8 *A;

    dof_session_data *request_session;
} sgmp_packet_data;

static int proto_sgmp = -1;

static int hf_opcode = -1;
static int hf_sgmp_domain = -1;
static int hf_sgmp_epoch = -1;
static int hf_initiator_block = -1;
static int hf_sgmp_security_scope = -1;
static int hf_initial_state = -1;
static int hf_latest_version = -1;
static int hf_desire = -1;
static int hf_ticket = -1;
static int hf_sgmp_tmin = -1;
static int hf_tie_breaker = -1;
static int hf_delay = -1;
static int hf_key = -1;

static int ett_sgmp = -1;
static int ett_sgmp_domain = -1;
static int ett_initiator_block = -1;
static int ett_sgmp_security_scope = -1;
static int ett_initial_state = -1;
static int ett_ticket = -1;

#define SGMP_RESPONSE                                   (0x80)
#define SGMP_CMD_HEARTBEAT                              (0)
#define SGMP_RSP_HEARTBEAT                              (SGMP_CMD_HEARTBEAT|SGMP_RESPONSE)
#define SGMP_CMD_EPOCH_CHANGED                  (1)
#define SGMP_RSP_EPOCH_CHANGED                  (SGMP_CMD_EPOCH_CHANGED|SGMP_RESPONSE)
#define SGMP_CMD_REKEY                                  (2)
#define SGMP_RSP_REKEY                                  (SGMP_CMD_REKEY|SGMP_RESPONSE)
#define SGMP_CMD_REQUEST_GROUP                  (3)
#define SGMP_RSP_REQUEST_GROUP                  (SGMP_CMD_REQUEST_GROUP|SGMP_RESPONSE)
#define SGMP_CMD_REKEY_EPOCH                    (5)
#define SGMP_RSP_REKEY_EPOCH                    (SGMP_CMD_REKEY_EPOCH|SGMP_RESPONSE)
#define SGMP_CMD_REKEY_MERGE                    (7)
#define SGMP_RSP_REKEY_MERGE                    (SGMP_CMD_REKEY_MERGE|SGMP_RESPONSE)

static const value_string sgmp_opcode_strings[] = {
    { SGMP_CMD_HEARTBEAT, "SGMP Heartbeat" },
    { SGMP_RSP_HEARTBEAT, "SGMP Heartbeat Response (Illegal)" },
    { SGMP_CMD_EPOCH_CHANGED, "SGMP Epoch Changed" },
    { SGMP_RSP_EPOCH_CHANGED, "SGMP Epoch Changed Response (Illegal)" },
    { SGMP_CMD_REKEY, "SGMP Rekey" },
    { SGMP_RSP_REKEY, "SGMP Rekey Response (Illegal)" },
    { SGMP_CMD_REQUEST_GROUP, "SGMP Request Group" },
    { SGMP_RSP_REQUEST_GROUP, "SGMP Request Group Response" },
    { SGMP_CMD_REKEY_EPOCH, "SGMP Rekey Epoch" },
    { SGMP_RSP_REKEY_EPOCH, "SGMP Rekey Epoch Response (Illegal)" },
    { SGMP_CMD_REKEY_MERGE, "SGMP Rekey Merge" },
    { SGMP_RSP_REKEY_MERGE, "SGMP Rekey Merge Response (Illegal)" },

    { 0, NULL }
};


#if 0 /* TODO not used yet */
static gboolean sgmp_validate_session_key(sgmp_packet_data *cmd_data, guint8 *confirmation, guint8 *kek, guint8 *key)
{
#ifdef LIBGCRYPT_OK
    gcry_mac_hd_t hmac;
    gcry_error_t result;

    result = gcry_mac_open(&hmac, GCRY_MAC_HMAC_SHA256, 0, NULL);
    if (result != 0)
        return FALSE;

    gcry_mac_setkey(hmac, kek, 32);
    gcry_mac_write(hmac, cmd_data->I, cmd_data->I_length);
    gcry_mac_write(hmac, cmd_data->A, cmd_data->A_length);
    gcry_mac_write(hmac, key, 32);
    result = gcry_mac_verify(hmac, confirmation, sizeof(confirmation));
    return result == 0;
#else
    return FALSE;
#endif
}
#endif

/* DOF SECURITY PROTOCOL */
#define DOF_SECURITY_PROTOCOL "DOF Security Protocol"
static dissector_table_t dof_sec_dissectors;
#define AS_ASSIGNED_SSID 0x40000000

/* DOFSEC Vxxxx (CCM - COUNTER WITH CBC-MAC PROTOCOL V1) */
#define DOF_PROTOCOL_CCM 24577
#define DSP_CCM_FAMILY 0x020000

static int proto_ccm_app = -1;
static int proto_ccm = -1;
static int proto_ccm_dsp = -1;

static int hf_ccm_dsp_option = -1;
static int hf_ccm_dsp_strength_count = -1;
static int hf_ccm_dsp_strength = -1;
static int hf_ccm_dsp_e_flag = -1;
static int hf_ccm_dsp_m_flag = -1;
static int hf_ccm_dsp_tmax = -1;
static int hf_ccm_dsp_tmin = -1;

static const value_string ccm_strengths[] = {
    { 1, "256-bit" },
    { 2, "192-bit" },
    { 3, "128-bit" },
    { 0, NULL }
};
static int hf_ccm_opcode = -1;

static int hf_epp_v1_ccm_flags = -1;
static int hf_epp_v1_ccm_flags_manager = -1;
static int hf_epp_v1_ccm_flags_period = -1;
static int hf_epp_v1_ccm_flags_target = -1;
static int hf_epp_v1_ccm_flags_next_nid = -1;
static int hf_epp_v1_ccm_flags_packet = -1;
static int hf_epp_v1_ccm_tnid = -1;
static int hf_epp_v1_ccm_nnid = -1;
static int hf_epp_v1_ccm_nid = -1;
static int hf_epp_v1_ccm_slot = -1;
static int hf_epp_v1_ccm_pn = -1;

static int ett_header = -1;
static int ett_epp_v1_ccm_flags = -1;

static int ett_ccm_dsp_option = -1;
static int ett_ccm_dsp = -1;
static int ett_ccm = -1;

static expert_field ei_decode_failure = EI_INIT;

typedef struct _ccm_session_data
{
    guint protocol_id;
    void *cipher_data;
    GHashTable *cipher_data_table;
    /* Starts at 1, incrementing for each new key. */
    guint32 period;
    /* Mapping from wire period to absolute periods. */
    guint8 periods[8];
    guint8 cipher;
    gboolean encrypted;
    guint8 mac_len;
    guint32 client_datagram_number;
    guint32 server_datagram_number;
} ccm_session_data;

typedef struct _ccm_packet_data
{
    guint32 nid;
    guint32 dn;
    guint32 period;
} ccm_packet_data;

#define CCM_PDU_PROBE            (0)

static const value_string ccm_opcode_strings[] = {
    { CCM_PDU_PROBE, "Probe" },
    { 0, NULL }
};

/* DOF OBJECT IDENTIFIER (OID) */
#define DOF_OBJECT_IDENTIFIER "DOF Object Identifier"

static dissector_handle_t dof_oid_handle;
static dissector_handle_t undissected_data_handle;

static int oid_proto = -1;

static int hf_oid_class = -1;
static int hf_oid_header = -1;
static int hf_oid_attribute = -1;
static int hf_oid_length = -1;
static int hf_oid_data = -1;
static int hf_oid_all_attribute_data = -1;
static int hf_oid_attribute_header = -1;
static int hf_oid_attribute_attribute = -1;
static int hf_oid_attribute_id = -1;
static int hf_oid_attribute_length = -1;
static int hf_oid_attribute_data = -1;
static int hf_oid_attribute_oid = -1;

static int ett_oid = -1;
static int ett_oid_header = -1;
static int ett_oid_attribute = -1;
static int ett_oid_attribute_header = -1;
static int ett_oid_attribute_oid = -1;

/**
 * EXPERT INFOS
 * Expert infos are related to either a PDU type or a specification, and so
 * they are listed separately.
 */
#if 0
static expert_field ei_undecoded = EI_INIT;
#endif
static expert_field ei_malformed = EI_INIT;
static expert_field ei_implicit_no_op = EI_INIT;
static expert_field ei_c2_c3_c4_format = EI_INIT;
static expert_field ei_type_4_header_zero = EI_INIT;
static expert_field ei_dof_10_flags_zero = EI_INIT;
#if 0
static expert_field ei_dof_13_length_specified = EI_INIT;
#endif

static expert_field ei_dpp2_dof_10_flags_zero = EI_INIT;
static expert_field ei_dpp_default_flags = EI_INIT;
static expert_field ei_dpp_explicit_sender_sid_included = EI_INIT;
static expert_field ei_dpp_explicit_receiver_sid_included = EI_INIT;
static expert_field ei_dpp_no_security_context = EI_INIT;
static expert_field ei_dof_6_timeout = EI_INIT;

static expert_field ei_security_3_1_invalid_stage = EI_INIT;
static expert_field ei_security_4_invalid_bit = EI_INIT;
static expert_field ei_security_13_out_of_range = EI_INIT;

/**
 * SOURCE IDENTIFIER (SID) SUPPORT
 * Source identifiers are used as part of operation tracking in the
 * DOF Protocol Stack. They are version independent, and associated with
 * a node in the DOF mesh network. Each session is associated with a SID.
 *
 * DPP Manages the SID information, since it is DPP that learns about SIDs.
 * SIDs are complicated because the can be 'unknown' for periods, and then
 * learned later. The requirement here is that all SIDs that can be known
 * are known by the second pass of the dissector (pinfo->visited != 0).
 *
 * There are two hash tables to map to an actual SID. The first goes
 * from sender information to SID ID. During the first pass multiple SID ID
 * may actually refer to the same SID, and so the system must be able to "patch"
 * these values as actual SIDs are learned. The second hash table goes from SID ID
 * to actual SID. This lookup is only known after a real SID has been learned.
 *
 * The hash tables are used in order to look up full SID information when only
 * partial information is known, and must support looking up in both directions
 * based on what is known from a particular PDU.
 */
static GHashTable *node_key_to_sid_id = NULL;
static GHashTable *sid_buffer_to_sid_id = NULL;
static GHashTable *sid_id_to_sid_buffer = NULL;

typedef struct _node_key_to_sid_id_key
{
    gint transport_id;
    gint transport_node_id;
    gint dof_id;
    gint dof_node_id;
    gint dof_session_id;
} node_key_to_sid_id_key;

static guint sender_key_hash_fn(gconstpointer key)
{
    const node_key_to_sid_id_key *sid_key_ptr = (const node_key_to_sid_id_key *)key;
    guint result = 0;

    result += g_int_hash(&(sid_key_ptr->transport_id));
    result += g_int_hash(&(sid_key_ptr->transport_node_id));
    result += g_int_hash(&(sid_key_ptr->dof_id));
    result += g_int_hash(&(sid_key_ptr->dof_node_id));
    result += g_int_hash(&(sid_key_ptr->dof_session_id));

    return result;
}

static guint sid_buffer_hash_fn(gconstpointer key)
{
    /* The sid buffer is a length byte followed by data. */
    guint hash = 5381;
    const guint8 *str = (const guint8 *)key;
    guint8 i;

    for (i = 0; i <= str[0]; i++)
        hash = ((hash << 5) + hash) + str[i]; /* hash * 33 + c */

    return hash;
}

static gboolean sender_key_equal_fn(gconstpointer key1, gconstpointer key2)
{
    const node_key_to_sid_id_key *sid_key_ptr1 = (const node_key_to_sid_id_key *)key1;
    const node_key_to_sid_id_key *sid_key_ptr2 = (const node_key_to_sid_id_key *)key2;

    if (sid_key_ptr1->transport_id != sid_key_ptr2->transport_id)
        return FALSE;

    if (sid_key_ptr1->transport_node_id != sid_key_ptr2->transport_node_id)
        return FALSE;

    if (sid_key_ptr1->dof_id != sid_key_ptr2->dof_id)
        return FALSE;

    if (sid_key_ptr1->dof_node_id != sid_key_ptr2->dof_node_id)
        return FALSE;

    if (sid_key_ptr1->dof_session_id != sid_key_ptr2->dof_session_id)
        return FALSE;

    return TRUE;
}

static gboolean sid_buffer_equal_fn(gconstpointer key1, gconstpointer key2)
{
    const guint8 *sb1 = (const guint8 *)key1;
    const guint8 *sb2 = (const guint8 *)key2;

    if (sb1[0] != sb2[0])
        return FALSE;

    return memcmp(sb1 + 1, sb2 + 1, sb1[0]) == 0;
}

static guint dpp_next_sid_id = 1;

/**
 * This routine is called for each reset (file load, capture) and is responsible
 * for allocating the SID support hash tables. Previous information is freed
 * if needed.
 */
static void dpp_reset_sid_support(void)
{
    dpp_next_sid_id = 1;

    if (node_key_to_sid_id != NULL)
    {
        g_hash_table_destroy(node_key_to_sid_id);
        node_key_to_sid_id = NULL;
    }

    if (sid_buffer_to_sid_id != NULL)
    {
        g_hash_table_destroy(sid_buffer_to_sid_id);
        sid_buffer_to_sid_id = NULL;
    }

    if (sid_id_to_sid_buffer != NULL)
    {
        g_hash_table_destroy(sid_id_to_sid_buffer);
        sid_id_to_sid_buffer = NULL;
    }

    /* The value is not allocated, so does not need to be freed. */
    node_key_to_sid_id = g_hash_table_new_full(sender_key_hash_fn, sender_key_equal_fn, g_free, NULL);
    sid_buffer_to_sid_id = g_hash_table_new_full(sid_buffer_hash_fn, sid_buffer_equal_fn, g_free, NULL);
    sid_id_to_sid_buffer = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
}

/**
 * OPERATION IDENTIFIER SUPPORT
 * Operation identifiers are an extension of a SID, and represent each separate
 * operation in the DOF. They are identified by a SID and an operation count.
 * Like SIDs, they are indepenent of version (at least in meaning, the formatting
 * may change).
 *
 * The hash is used to look up common operation information each time an operation
 * is seen in any packet.
 */
static GHashTable *dpp_opid_to_packet_data = NULL;

static guint dpp_opid_hash_fn(gconstpointer opid)
{
    const dof_2009_1_pdu_20_opid *ptr = (const dof_2009_1_pdu_20_opid *)opid;
    return g_int_hash(&ptr->op_sid_id) + g_int_hash(&ptr->op_cnt);
}

static gboolean dpp_opid_equal_fn(gconstpointer opid1, gconstpointer opid2)
{
    const dof_2009_1_pdu_20_opid *ptr1 = (const dof_2009_1_pdu_20_opid *)opid1;
    const dof_2009_1_pdu_20_opid *ptr2 = (const dof_2009_1_pdu_20_opid *)opid2;
    if (ptr1->op_cnt != ptr2->op_cnt)
        return FALSE;
    if (ptr1->op_sid_id != ptr2->op_sid_id)
        return FALSE;

    return TRUE;
}

static void dpp_reset_opid_support(void)
{
    if (dpp_opid_to_packet_data != NULL)
    {
        /* Clear it out. Note that this calls the destroy functions for each element. */
        g_hash_table_destroy(dpp_opid_to_packet_data);
        dpp_opid_to_packet_data = NULL;
    }

    dpp_opid_to_packet_data = g_hash_table_new_full(dpp_opid_hash_fn, dpp_opid_equal_fn, NULL, NULL);
}

/**
 * NON-SECURE SESSION LOOKUP SUPPORT
 */
static GHashTable *dof_ns_session_lookup = NULL;

/**
 * NON-SECURE DPS SESSION
 * This is defined by the transport session and the DNP port information.
 */
typedef struct _dof_ns_session_key
{
    guint transport_session_id;
    guint client;
    guint server;
    gboolean is_secure;
} dof_ns_session_key;

static dof_session_data* dof_ns_session_retrieve(guint transport_session_id, guint client, guint server)
{
    dof_ns_session_key lookup_key;
    dof_session_data *value;

    /* Build a (non-allocated) key to do the lookup. */
    lookup_key.transport_session_id = transport_session_id;
    lookup_key.client = client;
    lookup_key.server = server;

    value = (dof_session_data *)g_hash_table_lookup(dof_ns_session_lookup, &lookup_key);
    if (value)
    {
        /* We found a match. */
        return value;
    }

    return NULL;
}

static void dof_ns_session_define(guint transport_session_id, guint client, guint server, dof_session_data *session_data)
{
    dof_ns_session_key *key;

    /* No match, need to add a key. */
    key = g_new0(dof_ns_session_key, 1);
    key->transport_session_id = transport_session_id;
    key->client = client;
    key->server = server;

    /* Note, this is not multithread safe, but Wireshark isn't multithreaded. */
    g_hash_table_insert(dof_ns_session_lookup, key, session_data);
}

/* COMMON PDU DISSECTORS */

/* Security.1 */
static int hf_security_1_permission_type = -1;
static int hf_security_1_length = -1;
static int hf_security_1_data = -1;

static const value_string dof_2008_16_permission_type[] = {
    { 1, "Binding" },
    { 3, "IAM" },
    { 5, "ACTAS" },
    { 128, "Requestor" },
    { 130, "Provider" },
    { 131, "Define" },
    { 133, "Tunnel Domain" },
    { 0, NULL }
};

/* Security.2 */
static int hf_security_2_count = -1;
static int ett_security_2_permission = -1;
static int hf_security_2_permission = -1;

/* Security.3.1 */
static int hf_security_3_1_credential_type = -1;
static int hf_security_3_1_stage = -1;
static int ett_security_3_1_security_node_identifier = -1;
static int hf_security_3_1_security_node_identifier = -1;

/* Security.3.2 */
static int hf_security_3_2_credential_type = -1;
static int hf_security_3_2_stage = -1;
static int hf_security_3_2_length = -1;
static int hf_security_3_2_public_data = -1;

/* Security.4 */
static int hf_security_4_l = -1;
static int hf_security_4_f = -1;
static int hf_security_4_ln = -1;
static int ett_security_4_identity = -1;
static int hf_security_4_identity = -1;
static int hf_security_4_nonce = -1;
static int ett_security_4_permission_set = -1;
static int hf_security_4_permission_set = -1;

/* Security.5 */
static int hf_security_5_mac = -1;
static int hf_security_5_key = -1;

/* Security.6.1 */
static int hf_security_6_1_desired_duration = -1;
static int ett_security_6_1_desired_security_mode = -1;
static int hf_security_6_1_desired_security_mode = -1;
static int ett_security_6_1_initiator_request = -1;
static int hf_security_6_1_initiator_request = -1;

/* Security.6.2 */
static int ett_security_6_2_responder_request = -1;
static int hf_security_6_2_responder_request = -1;

/* Security.6.3 */
static int hf_security_6_3_granted_duration = -1;
static int ett_security_6_3_session_security_scope = -1;
static int hf_security_6_3_session_security_scope = -1;
static int ett_security_6_3_initiator_validation = -1;
static int hf_security_6_3_initiator_validation = -1;
static int ett_security_6_3_responder_validation = -1;
static int hf_security_6_3_responder_validation = -1;

/* Security.9 */
static int hf_security_9_length = -1;
static int hf_security_9_initial_state = -1;

/* Security.10 */
static int hf_security_10_count = -1;
static int hf_security_10_permission_group_identifier = -1;

/* Security.11 */
static int hf_security_11_count = -1;
static int ett_security_11_permission_security_scope = -1;
static int hf_security_11_permission_security_scope = -1;

/* Security.12 */
static int hf_security_12_m = -1;

static const value_string dof_2008_16_security_12_m[] = {
    { 0, "Reference" },
    { 1, "Relative" },
    { 2, "Absolute" },
    { 3, "Continued" },
    { 0, NULL }
};

static int hf_security_12_count = -1;
static int hf_security_12_permission_group_identifier = -1;


static int dissect_2008_1_dsp_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *parent = proto_tree_get_parent(tree);
    guint8 attribute_code = tvb_get_guint8(tvb, 0);
    guint16 attribute_data = tvb_get_ntohs(tvb, 1);
    guint8 option_length = tvb_get_guint8(tvb, 3);

    /* Add the generic representation of the fields. */
    proto_tree_add_item(tree, hf_2008_1_dsp_attribute_code, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(tree, hf_2008_1_dsp_attribute_data, tvb, 1, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_2008_1_dsp_value_length, tvb, 3, 1, ENC_NA);

    /* Append description to the parent. */
    proto_item_append_text(parent, " (Code=%s/Data=0x%04x)", val_to_str(attribute_code, strings_2008_1_dsp_attribute_codes, "%u"), attribute_data);

    if (option_length)
    {
        proto_tree_add_item(tree, hf_2008_1_dsp_value_data, tvb, 4, option_length, ENC_NA);

        /* call the next dissector */
        tvb_set_reported_length(tvb, option_length + 4);
        dissector_try_uint(dsp_option_dissectors, (attribute_code << 16) | attribute_data, tvb, pinfo, tree);
    }
    return option_length + 4;
}

/**
 * Security.1: Permission. This is the base type for
 * permissions, and supports extension.
 */
static int dissect_2008_16_security_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    gboolean has_length;
    guint16 length;

    /* Permission Type */
    {
        gint start = offset;
        guint16 value;
        gint val_len;
        proto_item *pi;
        offset = read_c2(tvb, offset, &value, &val_len);
        has_length = (gboolean)(value % 2);
        pi = proto_tree_add_uint(tree, hf_security_1_permission_type, tvb, start, offset - start, value);
        validate_c2(pinfo, pi, value, val_len);
    }

    if (!has_length)
        return offset;

    /* Length */
    {
        gint start = offset;
        guint16 value;
        gint value_len;
        proto_item *pi;
        offset = read_c2(tvb, offset, &value, &value_len);
        length = value;
        pi = proto_tree_add_uint(tree, hf_security_1_length, tvb, start, offset - start, value);
        validate_c2(pinfo, pi, value, value_len);
    }

    /* Data */
    proto_tree_add_item(tree, hf_security_1_data, tvb, offset, length, ENC_NA);
    offset += length;

    return offset;
}

/**
 * Security.2: Permission Request.
 */
static int dissect_2008_16_security_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    guint16 count;

    /* Count */
    {
        gint start = offset;
        guint16 value;
        gint length;
        proto_item *pi;
        offset = read_c2(tvb, offset, &value, &length);
        count = value;
        pi = proto_tree_add_uint(tree, hf_security_2_count, tvb, start, offset - start, value);
        validate_c2(pinfo, pi, value, length);
    }

    while (count--)
    {
        proto_item *ti = proto_tree_add_item(tree, hf_security_2_permission, tvb, offset, -1, ENC_NA);
        proto_tree *subtree = proto_item_add_subtree(ti, ett_security_2_permission);
        tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, -1, -1);
        gint len = dissect_2008_16_security_1(next_tvb, pinfo, subtree, NULL);
        proto_item_set_len(ti, len);
        offset += len;
    }

    return offset;
}

/**
 * Security.3.1: Base Credential Format.
 * Returns: dof_2008_16_security_3_1
 */
static int dissect_2008_16_security_3_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gint offset = 0;
    guint8 stage;
    proto_item *ti;
    dof_2008_16_security_3_1 *return_data = (dof_2008_16_security_3_1 *)data;

    /* Credential Type */
    {
        gint start = offset;
        guint16 value;
        gint length;
        proto_item *pi;
        offset = read_c2(tvb, offset, &value, &length);
        pi = proto_tree_add_uint(tree, hf_security_3_1_credential_type, tvb, start, offset - start, value);
        validate_c2(pinfo, pi, value, length);
    }

    /* Stage */
    stage = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_item(tree, hf_security_3_1_stage, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (stage != 0)
        expert_add_info(pinfo, ti, &ei_security_3_1_invalid_stage);

    /* Security Node Identifier */
    {
        int block_length;
        tvbuff_t *start = tvb_new_subset(tvb, offset, -1, -1);
        proto_tree *subtree;
        ti = proto_tree_add_item(tree, hf_security_3_1_security_node_identifier, tvb, offset, 0, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_security_3_1_security_node_identifier);
        block_length = dissect_2008_16_security_8(start, pinfo, subtree, NULL);
        proto_item_set_len(ti, block_length);
        offset += block_length;
        tvb_set_reported_length(start, block_length);
        if (return_data)
            return_data->identity = start;
    }

    return offset;
}

/**
 * Security.3.2: Identity Resolution.
 */
int dissect_2008_16_security_3_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    guint16 length;

    /* Credential Type */
    {
        gint start = offset;
        guint16 value;
        gint val_len;
        proto_item *pi;
        offset = read_c2(tvb, offset, &value, &val_len);
        pi = proto_tree_add_uint(tree, hf_security_3_2_credential_type, tvb, start, offset - start, value);
        validate_c2(pinfo, pi, value, val_len);
    }

    /* Stage */
    proto_tree_add_item(tree, hf_security_3_2_stage, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Length */
    {
        gint start = offset;
        guint16 value;
        gint value_len;
        proto_item *pi;
        offset = read_c2(tvb, offset, &value, &value_len);
        length = value;
        pi = proto_tree_add_uint(tree, hf_security_3_2_length, tvb, start, offset - start, value);
        validate_c2(pinfo, pi, value, value_len);
    }

    /* Public Data */
    proto_tree_add_item(tree, hf_security_3_2_public_data, tvb, offset, length, ENC_NA);
    offset += length;

    return offset;
}

/**
 * Security.4: Key Request. Returns: dof_2008_16_security_4
 */
static int dissect_2008_16_security_4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gint offset = 0;
    guint8 flag;
    dof_2008_16_security_4 *return_data = (dof_2008_16_security_4 *)data;

    flag = tvb_get_guint8(tvb, offset);
    if (flag & 0x30)
        expert_add_info(pinfo, tree, &ei_security_4_invalid_bit);

    proto_tree_add_item(tree, hf_security_4_l, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_security_4_f, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_security_4_ln, tvb, offset, 1, ENC_NA);
    offset += 1;

    {
        int block_length;
        tvbuff_t *start = tvb_new_subset(tvb, offset, -1, -1);
        proto_item *ti;
        proto_tree *subtree;
        dof_2008_16_security_3_1 return_3_1;

        ti = proto_tree_add_item(tree, hf_security_4_identity, tvb, offset, 0, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_security_4_identity);

        block_length = dissect_2008_16_security_3_1(start, pinfo, subtree, &return_3_1);
        proto_item_set_len(ti, block_length);
        offset += block_length;
        if (return_data)
        {
            return_data->identity = return_3_1.identity;
        }
    }

    {
        tvbuff_t *start = tvb_new_subset(tvb, offset, (flag & 0x0F) + 1, (flag & 0x0F) + 1);
        if (return_data)
            return_data->nonce = start;

        proto_tree_add_item(tree, hf_security_4_nonce, start, 0, (flag & 0x0F) + 1, ENC_NA);
        offset += (flag & 0x0F) + 1;
    }

    {
        int block_length;
        tvbuff_t *start = tvb_new_subset(tvb, offset, -1, -1);
        proto_item *ti;
        proto_tree *subtree;

        ti = proto_tree_add_item(tree, hf_security_4_permission_set, tvb, offset, 0, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_security_4_permission_set);
        block_length = dissect_2008_16_security_2(start, pinfo, subtree, NULL);
        proto_item_set_len(ti, block_length);
        offset += block_length;
    }

    return offset;
}

/**
 * Security.5: Key Grant.
 */
static int dissect_2008_16_security_5(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    gint offset = 0;

    proto_tree_add_item(tree, hf_security_5_mac, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(tree, hf_security_5_key, tvb, offset, 32, ENC_NA);
    offset += 32;

    return offset;
}

/**
 * Security.6.1: Session Initator Block.
 * Returns dof_2008_16_security_6_1
 */
static int dissect_2008_16_security_6_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gint offset = 0;

    /* Allocate the return structure. */
    dof_2008_16_security_6_1 *return_data = (dof_2008_16_security_6_1 *)data;

    /* Desired Duration */
    proto_tree_add_item(tree, hf_security_6_1_desired_duration, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Desired Security Mode */
    {
        int block_length;
        tvbuff_t *start = tvb_new_subset(tvb, offset, -1, -1);
        proto_item *ti;
        proto_tree *subtree;

        ti = proto_tree_add_item(tree, hf_security_6_1_desired_security_mode, tvb, offset, 0, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_security_6_1_desired_security_mode);

        block_length = dissect_2008_16_security_13(start, pinfo, subtree, NULL);
        offset += block_length;
        tvb_set_reported_length(start, block_length);
        proto_item_set_len(ti, block_length);

        if (return_data)
        {
            return_data->security_mode = tvb_get_ntohs(start, 1);
            return_data->security_mode_data_length = block_length - 4;
            return_data->security_mode_data = (guint8 *)tvb_memdup(wmem_file_scope(), start, 4, block_length - 4);
        }
    }

    /* Initiator Request */
    {
        int block_length;
        dof_2008_16_security_4 output;
        tvbuff_t *start = tvb_new_subset(tvb, offset, -1, -1);
        proto_item *ti;
        proto_tree *subtree;

        ti = proto_tree_add_item(tree, hf_security_6_1_initiator_request, tvb, offset, 0, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_security_6_1_initiator_request);

        block_length = dissect_2008_16_security_4(start, pinfo, subtree, &output);
        proto_item_set_len(ti, block_length);
        offset += block_length;
        if (return_data)
        {
            return_data->i_identity = output.identity;
            return_data->i_nonce = output.nonce;
        }
    }

    return offset;
}

/**
 * Security.6.2: Session Responder Block.
 * Returns dof_2008_16_security_6_2
 */
static int dissect_2008_16_security_6_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gint offset = 0;
    dof_2008_16_security_6_2 *return_data = (dof_2008_16_security_6_2 *)data;

    /* Responder Request */
    {
        int block_length;
        dof_2008_16_security_4 output;
        tvbuff_t *start = tvb_new_subset(tvb, offset, -1, -1);
        proto_item *ti;
        proto_tree *subtree;

        ti = proto_tree_add_item(tree, hf_security_6_2_responder_request, tvb, offset, 0, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_security_6_2_responder_request);

        block_length = dissect_2008_16_security_4(start, pinfo, subtree, &output);
        proto_item_set_len(ti, block_length);
        offset += block_length;
        if (return_data)
        {
            return_data->r_identity = output.identity;
            return_data->r_nonce = output.nonce;
        }
    }

    return offset;
}

/**
 * Security.6.3: Authentication Response Block.
 */
static int dissect_2008_16_security_6_3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;

    /* Granted Duration */
    proto_tree_add_item(tree, hf_security_6_3_granted_duration, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Session Security Scope */
    {
        int block_length;
        tvbuff_t *start = tvb_new_subset(tvb, offset, -1, -1);
        proto_item *ti;
        proto_tree *subtree;

        ti = proto_tree_add_item(tree, hf_security_6_3_session_security_scope, tvb, offset, 0, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_security_6_3_session_security_scope);
        block_length = dissect_2008_16_security_10(start, pinfo, subtree, NULL);
        proto_item_set_len(ti, block_length);
        offset += block_length;
    }

    /* Initiator Validation */
    {
        int block_length;
        tvbuff_t *start = tvb_new_subset(tvb, offset, -1, -1);
        proto_item *ti;
        proto_tree *subtree;

        ti = proto_tree_add_item(tree, hf_security_6_3_initiator_validation, tvb, offset, 0, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_security_6_3_initiator_validation);
        block_length = dissect_2008_16_security_11(start, pinfo, subtree, NULL);
        proto_item_set_len(ti, block_length);
        offset += block_length;
    }

    /* Responder Validation */
    {
        int block_length;
        tvbuff_t *start = tvb_new_subset(tvb, offset, -1, -1);
        proto_item *ti;
        proto_tree *subtree;

        ti = proto_tree_add_item(tree, hf_security_6_3_responder_validation, tvb, offset, 0, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_security_6_3_responder_validation);
        block_length = dissect_2008_16_security_11(start, pinfo, subtree, NULL);
        proto_item_set_len(ti, block_length);
        offset += block_length;
    }

    return offset;
}

/**
 * Security.7: Security Domain.
 */
static int dissect_2008_16_security_7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Parse the base type. */
    gint block_length;

    block_length = dissect_2009_11_type_4(tvb, pinfo, tree, NULL);

    return block_length;
}

/**
 * Security.8: Security Node Identifier.
 */
static int dissect_2008_16_security_8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Parse the base type. */
    gint block_length;

    block_length = dissect_2009_11_type_4(tvb, pinfo, tree, NULL);

    return block_length;
}

/**
 * Security.9: Security Mode of Operation Initialization.
 * If the packet info has knowledge of the active security mode
 * of operation then this datagram can be further decoded.
 */
static int dissect_2008_16_security_9(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    guint16 length;

    /* Length */
    {
        gint start = offset;
        guint16 value;
        gint value_len;
        proto_item *pi;
        offset = read_c2(tvb, offset, &value, &value_len);
        length = value;
        pi = proto_tree_add_uint(tree, hf_security_9_length, tvb, start, offset - start, value);
        validate_c2(pinfo, pi, value, value_len);
    }

    if (length > 0)
    {
        proto_tree_add_item(tree, hf_security_9_initial_state, tvb, offset, length, ENC_NA);
        offset += length;
    }

    return offset;
}

/**
 * Security.10: Security Scope.
 */
static int dissect_2008_16_security_10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    guint16 count;

    /* Count */
    {
        gint start = offset;
        guint16 value;
        gint length;
        proto_item *pi;
        offset = read_c2(tvb, offset, &value, &length);
        count = value;
        pi = proto_tree_add_uint(tree, hf_security_10_count, tvb, start, offset - start, value);
        validate_c2(pinfo, pi, value, length);
    }

    while (count--)
    {
        const char *def = "";

        gint start = offset;
        guint32 value;
        gint length;
        proto_item *pi;

        offset = read_c4(tvb, offset, &value, &length);

        switch (value)
        {
        case 0x3FFFFFFF:
            def = " (all scopes)";
            break;
        case 0x3FFFFFFE:
            def = " (doesn't mask)";
            break;
        case 0x3FFFFFFD:
            def = " (session scope)";
            break;
        }

        pi = proto_tree_add_uint_format_value(tree, hf_security_10_permission_group_identifier, tvb, start, offset - start, value, "%u%s", value, def);
        validate_c4(pinfo, pi, value, length);
    }

    return offset;
}

/**
 * Security.11: Permission Validation.
 */
static int dissect_2008_16_security_11(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    guint16 count;

    /* Count */
    {
        gint start = offset;
        guint16 value;
        gint length;
        proto_item *pi;
        offset = read_c2(tvb, offset, &value, &length);
        count = value;
        pi = proto_tree_add_uint(tree, hf_security_11_count, tvb, start, offset - start, value);
        validate_c2(pinfo, pi, value, length);
    }

    while (count--)
    {
        proto_item *ti = proto_tree_add_item(tree, hf_security_11_permission_security_scope, tvb, offset, -1, ENC_NA);
        proto_tree *subtree = proto_item_add_subtree(ti, ett_security_11_permission_security_scope);
        tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, -1, -1);
        gint len;
        len = dissect_2008_16_security_12(next_tvb, pinfo, subtree, NULL);
        proto_item_set_len(ti, len);
        offset += len;
    }

    return offset;
}

/**
 * Security.12: Permission Security Scope.
 */
static int dissect_2008_16_security_12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    guint8 m = tvb_get_guint8(tvb, offset) >> 6;
    guint16 count = tvb_get_guint8(tvb, offset) & 0x3F;
    proto_item *pi;

    proto_tree_add_item(tree, hf_security_12_m, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_security_12_count, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (m == 0)
        return offset;

    while (count--)
    {
        const char *def = "";

        gint start = offset;
        guint32 value;
        gint length;
        offset = read_c4(tvb, offset, &value, &length);

        switch (value)
        {
        case 0x3FFFFFFF:
            def = " (all scopes)";
            break;
        case 0x3FFFFFFE:
            def = " (doesn't mask)";
            break;
        case 0x3FFFFFFD:
            def = " (session scope)";
            break;
        }

        pi = proto_tree_add_uint_format_value(tree, hf_security_12_permission_group_identifier, tvb, start, offset - start, value, "%u%s", value, def);
        validate_c4(pinfo, pi, value, length);
    }

    return offset;
}

/**
 * Security.13: Security Mode of Operation Negotiation.
 */
static int dissect_2008_16_security_13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Parse the base type. */
    gint block_length;
    guint16 attribute_data;

    /* TODO: Skipping this first byte means that no other encryption modes can be supported. */
    attribute_data = tvb_get_ntohs(tvb, 1);
    if (attribute_data < 0x6000 || attribute_data >= 0x7000)
        expert_add_info(pinfo, tree, &ei_security_13_out_of_range);

    block_length = dissect_2008_1_dsp_1(tvb, pinfo, tree);

    return block_length;
}

/**
 * Dissects a buffer that is pointing at an OID.
 * Adds a subtree with detailed information about the fields of
 * the OID,
 * returns the length of the OID,
 * and appends text to the tree (really a tree item) that is
 * passed in that gives a more accurate description of the OID.
 * Note that the tree already shows the bytes of the OID, so if
 * no additional information can be displayed then it should not
 * be.
 *
 * If 'tree' is NULL then just return the length.
 */
static gint dissect_2009_11_type_4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    gint start_offset = 0;
    gint offset = 0;
    guint32 oid_class;
    gint oid_class_len;
    guint8 oid_len_byte;
    proto_tree *oid_tree = tree;
    proto_tree *header_tree;

    if (tree)
    {
        ti = proto_tree_get_parent(tree);
        proto_item_set_text(ti, "Object ID: %s", dof_oid_create_standard_string(tvb_reported_length(tvb), tvb_get_ptr(tvb, 0, tvb_reported_length(tvb))));
    }

    offset = read_c4(tvb, offset, &oid_class, &oid_class_len);
    ti = proto_tree_add_uint_format(oid_tree, hf_oid_class, tvb, start_offset, offset - start_offset, oid_class, "Class: %u", oid_class);
    validate_c4(pinfo, ti, oid_class, oid_class_len);

    oid_len_byte = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_uint_format(oid_tree, hf_oid_header, tvb,
                                    offset, 1, oid_len_byte, "Header: 0x%02x (%sLength=%d)", oid_len_byte, oid_len_byte & 0x80 ? "Attribute, " : "", oid_len_byte & 0x3F);

    header_tree = proto_item_add_subtree(ti, ett_oid_header);
    proto_tree_add_item(header_tree, hf_oid_attribute, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(header_tree, hf_oid_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Validate the flag byte */
    if (oid_len_byte & 0x40)
    {
        /* Type.4 Malformed (bit mandated zero). */
        expert_add_info(pinfo, ti, &ei_type_4_header_zero);
    }

    if ((oid_len_byte & 0x3F) > 0)
    {
        /* Add the raw data. */
        proto_tree_add_item(oid_tree, hf_oid_data, tvb, offset, oid_len_byte & 0x3F, ENC_NA);
        offset += oid_len_byte & 0x3F;
    }

    /* Check for attributes */
    if (oid_len_byte & 0x80)
    {
        /* Read attributes, adding them to oid_tree. */
        guint8 flag;

        do
        {
            tvbuff_t *packet = tvb_new_subset(tvb, offset, -1, -1);
            proto_tree *attribute_tree;
            gint attribute_length;

            ti = proto_tree_add_item(tree, hf_oid_all_attribute_data, tvb, offset, -1, ENC_NA);
            attribute_tree = proto_item_add_subtree(ti, ett_oid_attribute);
            flag = tvb_get_guint8(tvb, offset);
            attribute_length = dissect_2009_11_type_5(packet, pinfo, attribute_tree);
            proto_item_set_len(ti, (const gint)attribute_length);
            offset += attribute_length;
        }
        while (flag & 0x80);
    }

    if (tree)
    {
        ti = proto_tree_get_parent(tree);
        proto_item_set_len(ti, offset - start_offset);
    }

    /* TODO: Add the description. */
    /* proto_item_append_text( oid_tree, ": %s", "TODO" ); */
    return offset;
}

/**
 * Dissects a buffer that is pointing at an attribute.
 * Adds a subtree with detailed information about the fields of
 * the attribute,
 * returns the new offset,
 * and appends text to the tree (really a tree item) that is
 * passed in that gives a more accurate description of the
 * attribute.
 * Note that the tree already shows the bytes of the OID, so if
 * no additional information can be displayed then it should not
 * be.
 *
 * If 'tree' is NULL then just return the length.
 */
static int dissect_2009_11_type_5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    gint offset = 0;
    guint8 attribute_id_byte;
    guint8 attribute_length_byte;
    proto_tree *oid_tree = tree;
    proto_tree *header_tree;

    attribute_id_byte = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_uint_format(oid_tree, hf_oid_attribute_header, tvb,
                                    offset, 1, attribute_id_byte, "Header: 0x%02x (%sLength=%d)", attribute_id_byte, attribute_id_byte & 0x80 ? "Attribute, " : "", attribute_id_byte & 0x3F);

    header_tree = proto_item_add_subtree(ti, ett_oid_attribute_header);
    proto_tree_add_item(header_tree, hf_oid_attribute_attribute, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(header_tree, hf_oid_attribute_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    attribute_length_byte = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(oid_tree, hf_oid_attribute_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    switch (attribute_id_byte & 0x7F)
    {
    case 1:
        /* TODO: Check length */
        proto_tree_add_item(oid_tree, hf_oid_attribute_data, tvb, offset, attribute_length_byte, ENC_NA);
        offset += attribute_length_byte;
        break;

    case 0:
    case 2:
    {
        tvbuff_t *packet = tvb_new_subset(tvb, offset, attribute_length_byte, attribute_length_byte);
        proto_tree *attribute_tree;

        ti = proto_tree_add_item(tree, hf_oid_attribute_oid, tvb, offset, -1, ENC_NA);
        attribute_tree = proto_item_add_subtree(ti, ett_oid_attribute_oid);
        offset += dissect_2009_11_type_4(packet, pinfo, attribute_tree, NULL);
    }
        break;

    default:
        proto_tree_add_item(oid_tree, hf_oid_attribute_data, tvb, offset, attribute_length_byte, ENC_NA);
        offset += attribute_length_byte;
    }

    return offset;
}


/* Transport Session ID */
static dof_globals globals;

/* Static Methods. */

static dof_packet_data* create_packet_data(packet_info *pinfo);
static int dof_dissect_dnp_length(tvbuff_t *tvb, packet_info *pinfo, guint8 version, gint *offset);
static void encryptInPlace(guint protocol_id, void *cipher_state, guint8 *ptct, guint8 ptct_len);

#define VALIDHEX(c) ( ((c) >= '0' && (c) <= '9') || ((c) >= 'A' && (c) <= 'F') || ((c) >= 'a' && (c) <= 'f') )


/* Configuration structures. These tables allow for security
 * mode templates, security keys, and secrets to be configured.
 */

static gboolean decrypt_all_packets = FALSE;
static gboolean track_operations = FALSE;
static guint track_operations_window = 5;
static guint32 next_dof_frame = 1;

/* Structure for security mode of operation templates. */
typedef struct _secmode_field_t {
    gchar *domain;
    gchar *identity;
    gchar *kek;
} secmode_field_t;

static secmode_field_t *secmode_list = NULL;
static guint num_secmode_list = 0;

/* Structure for security keys. */
typedef struct _seckey_field_t {
    gchar *key;
} seckey_field_t;

/* Structure for secrets (for identities) */
typedef struct _identsecret_field_t {
    gchar *domain;
    gchar *identity;
    gchar *secret;
} identsecret_field_t;

typedef struct _tcp_ignore_data
{
    guint32 sequence;
    gboolean ignore;
    struct _tcp_ignore_data *next;
} tcp_ignore_data;

typedef struct _tcp_dof_packet_ref
{
    /* A single TCP frame can contain multiple packets. We must
     * be able to keep track of them all.
     */
    dof_api_data api_data;

    guint16 start_offset;
    dof_transport_packet transport_packet;
    struct _tcp_dof_packet_ref *next;
} tcp_dof_packet_ref;

/**
 * This structure exists for TCP packets and allows matching Wireshark frames to
 * DPS packets.
 */
typedef struct _tcp_packet_data
{
    /* Packets are ignored based on the starting TCP SEQ (sequence of first byte). */
    tcp_ignore_data *from_client_ignore_list;
    tcp_ignore_data *from_server_ignore_list;

    /* DPS packet structures contained within a TCP frame. */
    tcp_dof_packet_ref *dof_packets;
} tcp_packet_data;

/**
 * This structure exists for UDP sessions and allows for advanced stream handling
 * and matching Wireshark frames to DPS packets.
 */
typedef struct _udp_session_data
{
    /* This must be the first structure, as a pointer to this type is stored in each DPS packet. */
    dof_transport_session common;

    /* For the associated TCP conversation, this tracks the client and server
     * addresses.
     */
    ws_node server;
} udp_session_data;

/* This structure exists for TCP sessions and allows for advanced stream handling
 * and matching Wireshark frames to DPS packets.
 */
typedef struct _tcp_session_data
{
    /* This must be the first structure, as a pointer to this type is stored in each DPS packet. */
    dof_transport_session common;

    /* This flag is used to determine that an entire TCP session is NOT OpenDOF.
     * Because of TCP/IP negotation in the DPS it is easy to confuse arbitrary
     * protocols as OpenDOF. Once it is determined that it is not then this
     * flag can be set, which will turn off all the OpenDOF dissectors.
     */
    gboolean not_dps;

    /* For the associated TCP conversation, this tracks the client and server
     * addresses.
     */
    ws_node client, server;

    /* TCP sequence numbers, used to detect retransmissions. These are only valid
     * during the first pass through the packets.
     */
    guint32 from_client_seq;
    guint32 from_server_seq;

} tcp_session_data;

static dof_security_data global_security;

static guint8 count_hex_bytes(gchar *str);

/* Global DPS data structures for security keys. */
static seckey_field_t *seckey_list = NULL;
static guint num_seckey_list = 0;

/* Global DPS data structures for identity secrets. */
static identsecret_field_t *identsecret_list = NULL;
static guint num_identsecret_list = 0;


/* Callbacks for Configuration security templates. */
UAT_CSTRING_CB_DEF(secmode_list, domain, secmode_field_t)
UAT_CSTRING_CB_DEF(secmode_list, identity, secmode_field_t)
UAT_CSTRING_CB_DEF(secmode_list, kek, secmode_field_t)

static void secmode_list_post_update_cb(void)
{
}

static gboolean secmode_list_update_cb(void *r, char **err)
{
    secmode_field_t *rec = (secmode_field_t *)r;
    guint32 size;

    *err = NULL;

    size = (guint32)strlen(rec->domain);
    if (!VALIDHEX(rec->domain[0]) && !dof_oid_create_internal(rec->domain, &size, NULL))
    {
        *err = g_strdup("Invalid domain [must be valid OID].");
        return FALSE;
    }
    else if (!count_hex_bytes(rec->domain))
    {
        *err = g_strdup("Invalid domain [must be valid OID].");
        return FALSE;
    }

    size = (guint32)strlen(rec->identity);
    if (!VALIDHEX(rec->identity[0]) && !dof_oid_create_internal(rec->identity, &size, NULL))
    {
        *err = g_strdup("Invalid identity [must be valid OID].");
        return FALSE;
    }
    else if (!count_hex_bytes(rec->identity))
    {
        *err = g_strdup("Invalid identity [must be valid OID].");
        return FALSE;
    }

    if (count_hex_bytes(rec->kek) != 32)
    {
        *err = g_strdup("Invalid KEK [must be 32 byte key].");
        return FALSE;
    }
    return TRUE;
}

static void* secmode_list_copy_cb(void *n, const void *o, size_t siz _U_)
{
    secmode_field_t *new_rec = (secmode_field_t *)n;
    const secmode_field_t *old_rec = (const secmode_field_t *)o;

    if (old_rec->domain)
    {
        new_rec->domain = g_strdup(old_rec->domain);
    }
    else
    {
        new_rec->domain = NULL;
    }

    if (old_rec->identity)
    {
        new_rec->identity = g_strdup(old_rec->identity);
    }
    else
    {
        new_rec->identity = NULL;
    }

    if (old_rec->kek)
    {
        new_rec->kek = g_strdup(old_rec->kek);
    }
    else
    {
        new_rec->kek = NULL;
    }

    return new_rec;
}

static void secmode_list_free_cb(void *r)
{
    secmode_field_t *rec = (secmode_field_t *)r;

    if (rec->domain)
        g_free(rec->domain);
    if (rec->identity)
        g_free(rec->identity);
    if (rec->kek)
        g_free(rec->kek);
}


/* Callbacks for security keys. */
UAT_CSTRING_CB_DEF(seckey_list, key, seckey_field_t)

static void seckey_list_post_update_cb(void)
{
}

static gboolean seckey_list_update_cb(void *r, char **err)
{
    seckey_field_t *rec = (seckey_field_t *)r;

    *err = NULL;
    if (count_hex_bytes(rec->key) != 32)
    {
        *err = g_strdup("Invalid secret [must be 32 bytes].");
        return FALSE;
    }
    return TRUE;
}

static void* seckey_list_copy_cb(void *n, const void *o, size_t siz _U_)
{
    seckey_field_t *new_rec = (seckey_field_t *)n;
    const seckey_field_t *old_rec = (const seckey_field_t *)o;

    if (old_rec->key)
    {
        new_rec->key = g_strdup(old_rec->key);
    }
    else
    {
        new_rec->key = NULL;
    }

    return new_rec;
}

static void seckey_list_free_cb(void *r)
{
    seckey_field_t *rec = (seckey_field_t *)r;

    if (rec->key)
        g_free(rec->key);
}


/* Callbacks for identity secrets. */
UAT_CSTRING_CB_DEF(identsecret_list, domain, identsecret_field_t)
UAT_CSTRING_CB_DEF(identsecret_list, identity, identsecret_field_t)
UAT_CSTRING_CB_DEF(identsecret_list, secret, identsecret_field_t)

static void identsecret_list_post_update_cb(void)
{
}

static gboolean identsecret_list_update_cb(void *r, char **err)
{
    identsecret_field_t *rec = (identsecret_field_t *)r;
    guint32 size;

    *err = NULL;

    size = (guint32)strlen(rec->domain);
    if (!VALIDHEX(rec->domain[0]))
    {
        if (dof_oid_create_internal(rec->domain, &size, NULL))
        {
            *err = g_strdup("Invalid domain [must be valid OID].");
            return FALSE;
        }
    }
    else if (!count_hex_bytes(rec->domain))
    {
        *err = g_strdup("Invalid domain [must be valid OID].");
        return FALSE;
    }

    size = (guint32)strlen(rec->identity);
    if (!VALIDHEX(rec->identity[0]))
    {
        if (dof_oid_create_internal(rec->identity, &size, NULL))
        {
            *err = g_strdup("Invalid identity [must be valid OID].");
            return FALSE;
        }
    }
    else if (!count_hex_bytes(rec->identity))
    {
        *err = g_strdup("Invalid identity [must be valid OID].");
        return FALSE;
    }

    if (count_hex_bytes(rec->secret) != 32)
    {
        *err = g_strdup("Invalid secret [must be 32 byte key].");
        return FALSE;
    }
    return TRUE;
}

static void* identsecret_list_copy_cb(void *n, const void *o, size_t siz _U_)
{
    identsecret_field_t *new_rec = (identsecret_field_t *)n;
    const identsecret_field_t *old_rec = (const identsecret_field_t *)o;

    if (old_rec->domain)
    {
        new_rec->domain = g_strdup(old_rec->domain);
    }
    else
    {
        new_rec->domain = NULL;
    }

    if (old_rec->identity)
    {
        new_rec->identity = g_strdup(old_rec->identity);
    }
    else
    {
        new_rec->identity = NULL;
    }

    if (old_rec->secret)
    {
        new_rec->secret = g_strdup(old_rec->secret);
    }
    else
    {
        new_rec->secret = NULL;
    }

    return new_rec;
}

static void identsecret_list_free_cb(void *r)
{
    identsecret_field_t *rec = (identsecret_field_t *)r;

    if (rec->domain)
        g_free(rec->domain);
    if (rec->identity)
        g_free(rec->identity);
    if (rec->secret)
        g_free(rec->secret);
}

static void init_addr_port_tables(void);

/* The IP transport protocols need to assign SENDER ID based on the
 * transport address. This requires a hash lookup from address/port to ID.
 */

static GHashTable *addr_port_to_id = NULL;

typedef struct _addr_port_key
{
    address addr;
    guint16 port;
} addr_port_key;

static guint addr_port_key_hash_fn(gconstpointer key)
{
    const addr_port_key *addr_key = (const addr_port_key *)key;
    guint result = 0;
    guint port_as_int = addr_key->port;
    guint type_as_int = addr_key->addr.type;

    result += g_int_hash(&port_as_int);
    result += g_int_hash(&type_as_int);

    {
        guint hash = 5381;
        const guint8 *str = (const guint8 *)addr_key->addr.data;
        guint8 i;

        for (i = 0; i < addr_key->addr.len; i++)
            hash = ((hash << 5) + hash) + str[i]; /* hash * 33 + c */

        result += hash;
    }

    return result;
}

static gboolean addr_port_key_equal_fn(gconstpointer key1, gconstpointer key2)
{
    const addr_port_key *addr_key_ptr1 = (const addr_port_key *)key1;
    const addr_port_key *addr_key_ptr2 = (const addr_port_key *)key2;

    if (addr_key_ptr1->port != addr_key_ptr2->port)
        return FALSE;

    return addresses_equal(&addr_key_ptr1->addr, &addr_key_ptr2->addr);
}

static void addr_port_key_free_fn(gpointer key)
{
    addr_port_key *addr_port = (addr_port_key *)key;
    g_free(addr_port->addr.priv);
    g_free(addr_port);
}

static void init_addr_port_tables(void)
{
    /* This routine is called each time the system is reset (file load, capture)
     * and so it should take care of freeing any of our persistent stuff.
     */
    if (addr_port_to_id != NULL)
    {
        /* Clear it out. Note that this calls the destroy functions for each element. */
        g_hash_table_destroy(addr_port_to_id);
        addr_port_to_id = NULL;
    }

    /* The value is not allocated, so does not need to be freed. */
    addr_port_to_id = g_hash_table_new_full(addr_port_key_hash_fn, addr_port_key_equal_fn, addr_port_key_free_fn, NULL);
}

static guint next_addr_port_id = 1;

#define EP_COPY_ADDRESS(to, from) { \
    guint8 *EP_COPY_ADDRESS_data; \
    (to)->type = (from)->type; \
    (to)->len = (from)->len; \
    EP_COPY_ADDRESS_data = (guint8*) wmem_alloc(wmem_packet_scope(),(from)->len); \
    memcpy(EP_COPY_ADDRESS_data, (from)->data, (from)->len); \
    (to)->priv = EP_COPY_ADDRESS_data; \
    (to)->data = (to)->priv; \
    }

/* Return the transport ID, a unique number for each transport sender.
 */
static guint assign_addr_port_id(address *addr, guint16 port)
{
    addr_port_key lookup_key;
    addr_port_key *key;
    guint value;

    /* Build a (non-allocated) key to do the lookup. */

    EP_COPY_ADDRESS(&lookup_key.addr, addr);
    lookup_key.port = port;

    value = GPOINTER_TO_UINT(g_hash_table_lookup(addr_port_to_id, &lookup_key));
    if (value)
    {
        /* We found a match. */
        return value;
    }

    /* No match, need to add a key. */
    key = g_new0(addr_port_key, 1);
    copy_address(&key->addr, addr);
    key->port = port;

    /* Note, this is not multithread safe, but Wireshark isn't multithreaded. */
    g_hash_table_insert(addr_port_to_id, key, GUINT_TO_POINTER(next_addr_port_id));
    return next_addr_port_id++;
}

/* Wireshark Configuration Dialog Routines*/

static gboolean identsecret_chk_cb(void *r _U_, const char *p _U_, unsigned len _U_, const void *u1 _U_, const void *u2 _U_, char **err _U_)
{
#if 0
    gchar** protos;
    gchar* line = ep_strndup(p, len);
    guint num_protos, i;

    g_strstrip(line);
    ascii_strdown_inplace(line);

    protos = ep_strsplit(line, ":", 0);

    for (num_protos = 0; protos[num_protos]; num_protos++)
    g_strstrip(protos[num_protos]);

    if (!num_protos)
    {
        *err = g_strdup("No protocols given");
        return FALSE;
    }

    for (i = 0; i < num_protos; i++)
    {
        if (!find_dissector(protos[i]))
        {
            *err = g_strdup("Could not find dissector for: '%s'", protos[i]);
            return FALSE;
        }
    }
#endif
    return TRUE;
}

/* Utility Methods */

static guint8 count_hex_bytes(gchar *str)
{
    guint8 total = 0;

    while (str != NULL && *str != '\0' && *str != '#')
    {
        if (!g_ascii_isxdigit(*str))
        {
            str += 1;
            continue;
        }

        if (!g_ascii_isxdigit(str[1]))
            return 0;

        total += 1;
        str += 2;
    }

    return total;
}

static void parse_hex_string(gchar *str, guint8 **ptr, guint8 *len)
{
    guint8 j = 0;
    *len = count_hex_bytes(str);
    *ptr = (guint8 *)g_malloc0(*len);

    while (j < *len)
    {
        int high, low;

        if (!g_ascii_isxdigit(*str))
        {
            str += 1;
            continue;
        }

        high = ws_xton(str[0]);
        low = ws_xton(str[1]);
        (*ptr)[j++] = (high << 4) | low;
        str += 2;
    }
}

/* OID and IID Parsing */

static const guint8 OALString_HexChar[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

#define IS_PRINTABLE(c)         ( ((guint8)c) >= 32U && ((guint8)c) < 127U )
#define IS_ESCAPED(c)           ( (c) == '(' || (c) == ')' || (c) == '[' || (c) == ']' || (c) == '{' || (c) == '}' || (c) == '\\' || (c) == '|' )
#define DOFOBJECTID_MAX_CLASS_SIZE (4)
#define MAX_OID_DATA_SIZE                 (63)
#define OID_DATA_LEN_MASK                 (MAX_OID_DATA_SIZE)

#define ObjectID_DataToStringLength( data, dataSize ) ObjectID_DataToString( (data), (dataSize), NULL )
#define OALString_HexDigitToChar(c)     (OALString_HexChar[(c)])
#define DOFObjectIDAttribute_IsValid( attribute ) ((attribute).id < DOFOBJECTIDATTRIBUTE_INVALID)
#define DOFOBJECTID_HEADER_SIZE     (offsetof( DOFObjectID_t, oid ))
#define DOFObjectIDAttribute_GetValueSize( attribute ) ((attribute).dataSize)
#define DOFObjectIDAttribute_GetValue( attribute ) ((attribute).data)
#define DOFObjectIDAttribute_GetType( attribute ) ((DOFObjectIDAttributeType)(attribute).id)

typedef enum DOFObjectIDAttributeID_t
{
    /**
    * Provider attribute. This attribute identifies an object as being
    * provided by a specific service provider. The associated data must
    * be an object identifier.
    */
    DOFOBJECTIDATTRIBUTE_PROVIDER = 0,

    /**
    * Session attribute. This attribute associates the object with the
    * specified session. The associated data must be exactly 16 bytes long.
    */
    DOFOBJECTIDATTRIBUTE_SESSION = 1,

    /**
    * Group attribute. This attribute is normally used in association
    * with the BROADCAST object identifier. It defines a target that is
    * a multicast group in the DOF network (as opposed to the transport).
    * The associated data must be an object identifier.
    */
    DOFOBJECTIDATTRIBUTE_GROUP = 2,

    /**
    * Invalid, used to signal that an error has occurred.
    */
    DOFOBJECTIDATTRIBUTE_INVALID = 128
} DOFObjectIDAttributeType;
typedef guint32                        DOFObjectIDClass;

typedef struct DOFObjectID_t
{
    guint32 refCount;
    guint16 len;                /* Actual length of oid's wire representation. Max is 32707: 4 + 1 + 63 + (127 * 257). */
    guint8  oid[1];             /* Extends beyond end of this defined structure, so oid MUST be last structure member! */
} DOFObjectID_t;

typedef DOFObjectID_t *DOFObjectID;

typedef guint8                         DOFObjectIDAttributeDataSize;

typedef struct DOFObjectIDAttribute_t
{
    guint8                          id;         /**< Attribute Identifier.  Intentionally defined as @ref uint8 for size, but holds all valid values for @ref DOFObjectIDAttributeType.  **/
    DOFObjectIDAttributeDataSize   dataSize;    /**< Size of the attribute data. **/
    const guint8 *data;                         /**< Attribute data. **/
} DOFObjectIDAttribute;

static guint32 OALMarshal_UncompressValue(guint8 maxSize, guint32 *bufLength, const guint8 *buffer)
{
    guint32 value = 0;
    guint8 used = 0;
    guint8 size = maxSize;
    guint8 mask;

    switch (buffer[0] >> 6)
    {
    case 0x02:
        /* Two Bytes */
        if (maxSize > 2)
            mask = 0x3F;
        else
            mask = 0x7F;
        size = 2;
        break;

    case 0x03:
        /* Three/Four Bytes */
        if (maxSize > 2)
            mask = 0x3F;
        else
            mask = 0x7F;
        break;

    default:
        /* One Byte */
        size = 1;
        mask = 0x7F;
        break;
    }

    value = buffer[used++] & mask;
    while (used < size)
        value = (value << 8) | buffer[used++];

    *bufLength = used;
    return (value);
}

static guint32 DOFObjectID_GetClassSize_Bytes(const guint8 *pBytes)
{
    guint32 size = 4;

    (void)OALMarshal_UncompressValue(DOFOBJECTID_MAX_CLASS_SIZE, &size, pBytes);

    return size;
}

static guint32 DOFObjectID_GetClassSize(DOFObjectID self)
{
    return DOFObjectID_GetClassSize_Bytes(self->oid);
}

static guint32 DOFObjectID_GetDataSize(const DOFObjectID self)
{
    return ((*((const guint8 *)self->oid + DOFObjectID_GetClassSize(self))) & OID_DATA_LEN_MASK);
}

static guint32 ObjectID_DataToString(const guint8 *data, guint32 dataSize, char *pBuf)
{
    guint32 len = 0, i, nonprintable, escaped;

    /* Determine if the data is printable... */
    for (i = 0, nonprintable = 0, escaped = 0; i < dataSize; i++)
    {
        if (!IS_PRINTABLE(data[i]))
            nonprintable++;
        else if (IS_ESCAPED(data[i]))
            escaped++;
    }
    if (nonprintable == 0)
    {
        /* Printable, so copy as a string, escaping where necessary. */
        if (pBuf)
        {
            for (i = 0; i < dataSize; i++)
            {
                if (IS_ESCAPED(data[i]))
                {
                    pBuf[len++] = '\\';
                    pBuf[len++] = data[i];
                }
                else
                    pBuf[len++] = data[i];
            }
        }
        else
        {
            len = dataSize + escaped; /* Count escaped characters twice. */
        }
    }
    else
    {
        /* Non-printable, so format as hex string. */
        if (pBuf)
        {
            pBuf[len++] = '{';
            for (i = 0; i < dataSize; i++)
            {
                pBuf[len++] = OALString_HexDigitToChar((data[i] >> 4) & 0x0F);
                pBuf[len++] = OALString_HexDigitToChar((data[i]) & 0x0F);
            }
            pBuf[len++] = '}';
        }
        else
        {
            len = dataSize * 2 + 2;
        }
    }
    return len;
}

static const guint8* DOFObjectID_GetData(const DOFObjectID self)
{
    if (DOFObjectID_GetDataSize(self) > 0)
        return (const guint8 *)self->oid + DOFObjectID_GetClassSize(self) + 1;          /* 1: length of length byte. */

    return NULL;
}

static guint32 DOFObjectID_GetIDClass(const DOFObjectID self)
{
    guint32 size = 4;

    return OALMarshal_UncompressValue(DOFOBJECTID_MAX_CLASS_SIZE, &size, self->oid);
}

static gboolean DOFObjectID_HasAttributes(const DOFObjectID self)
{
    if (!self)
        return FALSE;

    /* bit 7: next attribute flag. */
    return (gboolean)(((*(const guint8 *)((const guint8 *)(self->oid) + DOFObjectID_GetClassSize(self))) & 0x80) != 0);
}

static guint8 DOFObjectID_GetBaseSize(const DOFObjectID oid)
{
    return DOFObjectID_GetClassSize(oid) + 1 + DOFObjectID_GetDataSize(oid);
}

static guint8 DOFObjectID_GetAttributeCount(const DOFObjectID self)
{
    guint8 retVal = 0;

    /* Note: No OID can duplicate an attribute ID. Legal attribute IDs can be from 0-126. So max count fits in uint8. */
    if (self && DOFObjectID_HasAttributes(self))
    {
        const guint8 *pNextAttribute = (const guint8 *)self->oid + DOFObjectID_GetBaseSize(self);

        ++retVal;
        while (*pNextAttribute & 0x80)                                         /* bit 7: next attribute present flag. */
        {
            ++retVal;
            pNextAttribute += (2 + *((const guint8 *)pNextAttribute + 1));      /* 2: attribute marshalling overhead. */
        }
    }

    return retVal;
}

static DOFObjectIDAttribute DOFObjectID_GetAttributeAtIndex(const DOFObjectID self, guint8 attribute_index)
{
    DOFObjectIDAttribute retAttributeDescriptor = { DOFOBJECTIDATTRIBUTE_INVALID, 0, NULL };

    /* Note: No OID can duplicate an attribute ID. Legal attribute IDs can be from 0-127. So max index fits in uint8. */
    if (self && attribute_index < DOFOBJECTIDATTRIBUTE_INVALID)
    {
        if (DOFObjectID_HasAttributes(self))
        {
            guint8         count = 0;
            const guint8 *pNextAttribute = (const guint8 *)self->oid + DOFObjectID_GetBaseSize(self);

            while (1)                                           /* Parse through the N Attributes. */
            {
                if (attribute_index == count++)
                {
                    retAttributeDescriptor.id = *pNextAttribute & 0x7F;
                    retAttributeDescriptor.dataSize = (DOFObjectIDAttributeDataSize) * ((const guint8 *)pNextAttribute + 1);
                    retAttributeDescriptor.data = (const guint8 *)pNextAttribute + 2; /* 2: attr marshalling overhead. */
                    break;                                      /* Success. */
                }
                if (!(*pNextAttribute & 0x80))
                    break;                                      /* Fail: no more Attributes */
                pNextAttribute += (2 + *((const guint8 *)pNextAttribute + 1));
            }
        }
    }

    return retAttributeDescriptor;
}

static void DOFObjectID_Destroy(DOFObjectID self _U_)
{
    /* Ephemeral memory doesn't need to be freed. */
}

static void DOFObjectID_InitStruct(DOFObjectID newObjID, guint32 dataLen)
{
    newObjID->refCount = 1;
    newObjID->len = dataLen;
}

static DOFObjectID DOFObjectID_Create_Unmarshal(guint32 *length, const guint8 *buffer)
{
    guint32  len = *length;

    /* Legal OID described at buffer must have at least 2 bytes. */
    if (buffer && len >= 2)
    {
        guint32 classSize = len;
        guint32 classv = OALMarshal_UncompressValue(DOFOBJECTID_MAX_CLASS_SIZE, &classSize, buffer);

        /* Legal OID described at buffer must have its class representation be correctly compressed. */
        if (1)
        {
            guint32 computedSize;

            /* Above call won't return 3 because DOFOBJECTID_MAX_CLASS_SIZE (4) was passed in. */
            computedSize = classSize + 1;                              /* 1: length of length byte. */
            /* Legal OID described at buffer must have enough bytes to describe its OID class. */
            if (len >= computedSize)
            {
                guint8 lenByte = buffer[classSize];

                /* Legal OID described at buffer must have its length byte bit 6 be 0. */
                if (!(lenByte & 0x40))
                {
                    gboolean hasAttr;
                    guint8   dataLen = lenByte & OID_DATA_LEN_MASK;

                    /* Legal broadcast OID described at buffer must have no base data, though it can have attribute(s)*/
                    if ((classv == 0) && (dataLen > 0))
                        goto notvalid;
                    computedSize += dataLen;
                    hasAttr = lenByte & 0x80;                       /* Valid OID base; check attributes. */
                    while (hasAttr)
                    {
                        /* Legal OID described at buffer must have enough bytes to hold each new found attribute. */
                        if (len >= computedSize + 2)                /* 2: attribute marshalling overhead. */
                        {
                            hasAttr = buffer[computedSize] & 0x80;  /* bit 7: next attribute present flag. */
                            computedSize += (2 + buffer[computedSize + 1]);
                        }
                        else
                            goto notvalid;
                    }
                    /* Legal OID described at buffer must have enough buffer bytes, final check. */
                    if (len >= computedSize)
                    {
                        DOFObjectID newObjID = (DOFObjectID)wmem_alloc0(wmem_packet_scope(), DOFOBJECTID_HEADER_SIZE + computedSize + 1);
                        /* Adds space for null-terminator, just in case. */

                        *length = computedSize;
                        if (newObjID)
                        {
                            DOFObjectID_InitStruct(newObjID, computedSize);
                            memcpy(newObjID->oid, buffer, computedSize);
                            newObjID->oid[computedSize] = 0;
                            return newObjID;                    /* Success. */
                        }
                        /* buffer describes valid OID, but due to alloc failure we cannot return the newly created OID*/
                        goto allocErrorOut;
                    }
                }
            }
        }
    }
notvalid:
    /* buffer does not describe a valid OID, but do not log a message. The caller may have called us to find out if the
    buffer does or does not obey the rules of a valid OID. He learns that by our NULL return. */
allocErrorOut :
    *length = 0;

    return NULL;
}

static DOFObjectID DOFObjectID_Create_Bytes(guint32 bufferSize, const guint8 *pOIDBuffer)
{
    guint32      len = bufferSize;
    DOFObjectID rval = DOFObjectID_Create_Unmarshal(&len, pOIDBuffer);

    if (rval)
    {
        if (len != bufferSize)
        {
            DOFObjectID_Destroy(rval);
            rval = NULL;
        }
    }
    return rval;
}

static guint32 ObjectID_ToStringLength(const DOFObjectID oid)
{
    guint32 len = 0;

    /* Note: All these string functions can be exercised with objectid_test.c, which outputs the string to console. */
    len = 7 /* [{xx}: and trailing ] */ + ObjectID_DataToStringLength(DOFObjectID_GetData(oid),
                                                                      DOFObjectID_GetDataSize(oid));
    if (DOFObjectID_GetIDClass(oid) & 0xFF000000)
        len += 6;                                           /* Six more hex digits. */
    else if (DOFObjectID_GetIDClass(oid) & 0xFF0000)
        len += 4;                                           /* Four more hex digits. */
    else if (DOFObjectID_GetIDClass(oid) & 0xFF00)
        len += 2;                                           /* Two more hex digits. */
    /* Handle Attributes, if any. */
    if (DOFObjectID_HasAttributes(oid))
    {
        guint8 i;                                            /* Max attribute count is under uint8. */
        guint8 attributeCount = DOFObjectID_GetAttributeCount(oid);

        len += 2;                                           /* surrounding ( ) */
        for (i = 0; i < attributeCount; i++)
        {
            DOFObjectID embedOID;
            DOFObjectIDAttribute avpDescriptor = DOFObjectID_GetAttributeAtIndex(oid, i);

            if (!DOFObjectIDAttribute_IsValid(avpDescriptor))
                break;  /* Done with Attributes. If here, some error took place. */

            if (i)
                len++;
            len += 5;  /* {xx}: */
            /* Handle embedded Object IDs. */
            embedOID = DOFObjectID_Create_Bytes(DOFObjectIDAttribute_GetValueSize(avpDescriptor),
                                                DOFObjectIDAttribute_GetValue(avpDescriptor));
            if (embedOID)
            {
                len += ObjectID_ToStringLength(embedOID); /* Recurse to compute string rep length of found OID. */
                DOFObjectID_Destroy(embedOID);
            }
            else
            {
                /* Hex Data. */
                len += ObjectID_DataToStringLength(DOFObjectIDAttribute_GetValue(avpDescriptor),
                                                   DOFObjectIDAttribute_GetValueSize(avpDescriptor));
            }
        } /* end for(). */
    }

    return len;
}

static guint32 InterfaceID_ToString(const guint8 *iid, char *pBuf)
{
    guint32           len = 0;
    guint iid_len = iid[0] & 0x03;
    guint i;

    if (iid_len == 3)
        iid_len = 4;

    pBuf[len++] = '[';
    pBuf[len++] = '{';

    pBuf[len++] = OALString_HexDigitToChar((iid[0] >> 6) & 0x0F);
    pBuf[len++] = OALString_HexDigitToChar((iid[0] >> 2) & 0x0F);

    pBuf[len++] = '}';
    pBuf[len++] = ':';
    pBuf[len++] = '{';

    /* Data */
    for (i = 0; i < iid_len; i++)
    {
        pBuf[len++] = OALString_HexDigitToChar((iid[i + 1] >> 4) & 0x0F);
        pBuf[len++] = OALString_HexDigitToChar(iid[i + 1] & 0x0F);
    }

    pBuf[len++] = '}';
    pBuf[len++] = ']';

    return len;
}

static guint32 ObjectID_ToString(const DOFObjectID oid, char *pBuf)
{
    DOFObjectIDClass oidClass;
    guint32           len = 0;

    pBuf[len++] = '[';
    pBuf[len++] = '{';
    /* Class */
    oidClass = DOFObjectID_GetIDClass(oid);
    if (oidClass & 0xFF000000)
    {
        pBuf[len++] = OALString_HexDigitToChar((oidClass >> 28) & 0x0F);
        pBuf[len++] = OALString_HexDigitToChar((oidClass >> 24) & 0x0F);
    }
    if (oidClass & 0xFFFF0000)
    {
        pBuf[len++] = OALString_HexDigitToChar((oidClass >> 20) & 0x0F);
        pBuf[len++] = OALString_HexDigitToChar((oidClass >> 16) & 0x0F);
    }
    if (oidClass & 0xFFFFFF00)
    {
        pBuf[len++] = OALString_HexDigitToChar((oidClass >> 12) & 0x0F);
        pBuf[len++] = OALString_HexDigitToChar((oidClass >> 8) & 0x0F);
    }
    pBuf[len++] = OALString_HexDigitToChar((oidClass >> 4) & 0x0F);
    pBuf[len++] = OALString_HexDigitToChar((oidClass) & 0x0F);
    pBuf[len++] = '}';
    pBuf[len++] = ':';
    /* Data */
    len += ObjectID_DataToString(DOFObjectID_GetData(oid), DOFObjectID_GetDataSize(oid), &pBuf[len]);
    /* Handle Attributes, if any. */
    if (DOFObjectID_HasAttributes(oid))
    {
        guint8 i;
        guint8 attributeCount = DOFObjectID_GetAttributeCount(oid);

        pBuf[len++] = '(';
        for (i = 0; i < attributeCount; i++)
        {
            DOFObjectID embedOID;
            DOFObjectIDAttribute avpDescriptor = DOFObjectID_GetAttributeAtIndex(oid, i);

            if (!DOFObjectIDAttribute_IsValid(avpDescriptor))
                break;  /* Done with Attributes. If here, some error took place. */

            if (i)
                pBuf[len++] = '|';
            pBuf[len++] = '{';
            pBuf[len++] = OALString_HexDigitToChar((DOFObjectIDAttribute_GetType(avpDescriptor) >> 4) & 0x0F);
            pBuf[len++] = OALString_HexDigitToChar((DOFObjectIDAttribute_GetType(avpDescriptor)) & 0x0F);
            pBuf[len++] = '}';
            pBuf[len++] = ':';

            /* Handle embedded Object IDs. */
            embedOID = DOFObjectID_Create_Bytes(DOFObjectIDAttribute_GetValueSize(avpDescriptor),
                                                DOFObjectIDAttribute_GetValue(avpDescriptor));
            if (embedOID)
            {
                len += ObjectID_ToString(embedOID, &pBuf[len]); /* Recurse to output string rep of found OID. */
                DOFObjectID_Destroy(embedOID);
            }
            else
            {
                /* Hex Data. */
                len += ObjectID_DataToString(DOFObjectIDAttribute_GetValue(avpDescriptor),
                                             DOFObjectIDAttribute_GetValueSize(avpDescriptor), &pBuf[len]);
            }
        } /* end for(). */
        pBuf[len++] = ')';
    }
    pBuf[len++] = ']';

    return len;
}

static const gchar* dof_iid_create_standard_string(guint32 bufferSize, const guint8 *pIIDBuffer)
{
    gchar *pRetval;
    guint len = 9 + (bufferSize - 1) * 2;   /* Alias is always [{AA}:{01234567}] */

    pRetval = (gchar *)wmem_alloc(wmem_packet_scope(), len + 1);
    if (pRetval)
    {
        InterfaceID_ToString(pIIDBuffer, pRetval);
        pRetval[len] = 0;
    }

    return pRetval;
}

static const gchar* dof_oid_create_standard_string(guint32 bufferSize, const guint8 *pOIDBuffer)
{
    DOFObjectID oid;
    gchar *pRetval;
    guint32 len = bufferSize;

    oid = DOFObjectID_Create_Unmarshal(&len, pOIDBuffer);
    if (!oid)
        return "Illegal OID";

    len = ObjectID_ToStringLength(oid);
    /* Use PCRMem_Alloc() and not DOFMem_Alloc() because app caller will be freeing memory with PCRMem_Destroy(). */
    pRetval = (gchar *)wmem_alloc(wmem_packet_scope(), len + 1);
    if (pRetval)
    {
        ObjectID_ToString(oid, pRetval);
        pRetval[len] = 0;
    }

    return pRetval;
}

struct parseCtx
{
    const char *oid;
    guint8 *buffer;
    guint32 buffLen;
    guint32 oidLen;
    guint32 currOidPos;
    guint32 currBufferPos;
}parseCtx;

/* Operations on OID string */
#define PARSECTX_PEEK_CHAR_OID(ctx) ( (ctx)->oid[(ctx)->currOidPos] )
#define PARSECTX_PEEK_NEXT_CHAR_OID(ctx) ( (ctx)->oid[(ctx)->currOidPos+1] )
#define PARSECTX_READ_CHAR_OID(ctx) ( (ctx)->oid[(ctx)->currOidPos++] )
#define PARSECTX_GET_CURRENT_POS_OID(ctx) ( (ctx)->oid+(ctx)->currOidPos )
#define PARSECTX_STEP_OID(ctx, count)((ctx)->currOidPos+=(count))

/* Operations on DOFObjectID buffer */
#define PARSECTX_GET_CURRENT_POS_BUF(ctx)( ((ctx)->buffer)? (ctx)->buffer+(ctx)->currBufferPos: NULL )
#define PARSECTX_STEP_BUF(ctx, count)( (ctx)->currBufferPos+=(count))
#define PARSECTX_WRITE_AT_POS_BUF(ctx, pos, value) do{ if((ctx)->buffer) *(pos) = (value); } while(0)
#define PARSECTX_OR_AT_POS_BUF(ctx, pos, value) do{ if((ctx)->buffer) *(pos) |= (value); } while(0)
#define PARSECTX_WRITE_BUF(ctx, value)( ((ctx)->buffer)? (ctx)->buffer[(ctx)->currBufferPos++] = (value): (ctx)->currBufferPos++ )
#define PARSECTX_CHECK_LEN(ctx, len) (((ctx)->buffer)? (((ctx)->currBufferPos+len <= (ctx)->buffLen)? 0: 1): 0)

/* Operation to read from OID straight to buffer */
#define PARSECTX_WRITE_BUF_FROM_OID(ctx) (((ctx)->buffer)? (ctx)->buffer[(ctx)->currBufferPos++] = (ctx)->oid[(ctx)->currOidPos]: ((ctx)->currBufferPos++),((ctx)->currOidPos++))

#define IS_DIGIT(c) (((c) >= '0' && (c) <= '9'))
#define DIGIT2VALUE(c) (c-48)

#define HEX2VALUE(c) ( (IS_DIGIT(c))? DIGIT2VALUE(c) : ((c) >= 'A' && (c) <= 'F')? (c-55): (c-87) )
#define VALIDHEXSEP(c) ( (c) == ' ' || (c) == ':' || (c) == '-' )
#define VALIDHEX(c) ( ((c) >= '0' && (c) <= '9') || ((c) >= 'A' && (c) <= 'F') || ((c) >= 'a' && (c) <= 'f') )
#define VALIDHEXBYTE(s) ( VALIDHEX((s)[0]) && VALIDHEX((s)[1]) )
#define VALIDNUMBER(c) ((c) >= '0' && (c) <= '9')

#define VALIDASCIICHAR(c) (((guint8)c) >= 32 && ((guint8)c) <= 126 )

#define IS_ESCAPED(c) ( (c) == '(' || (c) == ')' || (c) == '[' || (c) == ']' || (c) == '{' || (c) == '}' || (c) == '\\' || (c) == '|' )

static guint8 parseFormatOID(struct parseCtx *ctx);

static guint8 parseHexField(struct parseCtx *ctx)
{
    /* Hex fields start with { and end with } can contain space, dash and colon*/
    if (PARSECTX_READ_CHAR_OID(ctx) == '{' && PARSECTX_PEEK_CHAR_OID(ctx) != '}')
    {
        while (PARSECTX_PEEK_CHAR_OID(ctx) != '}')
        {
            if (VALIDHEXBYTE(PARSECTX_GET_CURRENT_POS_OID(ctx)))
            {
                if (PARSECTX_CHECK_LEN(ctx, 1) == 0)
                {
                    PARSECTX_WRITE_BUF(ctx, HEX2VALUE(PARSECTX_PEEK_CHAR_OID(ctx)) << 4 | HEX2VALUE(PARSECTX_PEEK_NEXT_CHAR_OID(ctx)));
                    PARSECTX_STEP_OID(ctx, 2);

                    if (VALIDHEXSEP(PARSECTX_PEEK_CHAR_OID(ctx)))
                    {
                        if (PARSECTX_PEEK_NEXT_CHAR_OID(ctx) == '}')
                        {
                            /* no seperator after byte block */
                            return 1;
                        }
                        PARSECTX_STEP_OID(ctx, 1);
                    }
                }
                else
                {
                    return 1;
                }
            }
            else
            {
                return 1;
            }
        }
        PARSECTX_STEP_OID(ctx, 1);
        return 0;
    }
    return 1;
}

static guint8 parseStringField(struct parseCtx *ctx)
{
    /* Copy into buffer until end or */
    while (ctx->currOidPos < (ctx->oidLen - 1))
    {
        char curr = PARSECTX_PEEK_CHAR_OID(ctx);
        if (curr == ']' || curr == '(')
        {
            break; /* End of string field */
        }
        else if (curr == '\\')
        {
            /* Handle escaped char */
            PARSECTX_STEP_OID(ctx, 1);
            if (!IS_ESCAPED(PARSECTX_PEEK_CHAR_OID(ctx)) || PARSECTX_CHECK_LEN(ctx, 1) != 0)
                return 1;
            PARSECTX_WRITE_BUF_FROM_OID(ctx);
        }
        else
        {
            if (VALIDASCIICHAR(curr) && PARSECTX_CHECK_LEN(ctx, 1) == 0)
                PARSECTX_WRITE_BUF_FROM_OID(ctx);
            else
                return 1;
        }
    }
    return 0;
}

static guint8 OALMarshal_GetCompressedValueSize(guint8 maxSize, guint32 value)
{
    guint8 lenbytes = (1 + (value > 0x7F) + (value > 0x3FFF));
    if (lenbytes > 2)
        return (maxSize);
    return (lenbytes);
}

static guint32 OALMarshal_CompressValue(guint8 maxSize, guint32 value, guint32 bufLength, guint8 *buffer)
{
    guint8 lenSize = OALMarshal_GetCompressedValueSize(maxSize, value);

    if (bufLength < lenSize)
        return 0;
    switch (lenSize)
    {
    case 4:
        *(buffer++) = (guint8)((value >> 24) & 0x3F) | 0xC0;
        *(buffer++) = (guint8)((value >> 16) & 0xFF);
        *(buffer++) = (guint8)((value >> 8) & 0xFF);
        *(buffer++) = (guint8)(value & 0xFF);
        break;

    case 3:
        *(buffer++) = (guint8)((value >> 16) & 0x3F) | 0xC0;
        *(buffer++) = (guint8)((value >> 8) & 0xFF);
        *(buffer++) = (guint8)(value & 0xFF);
        break;

    case 2:
        if (maxSize == 2)
        {
            *(buffer++) = (guint8)((value >> 8) & 0x7F) | 0x80;
        }
        else
        {
            *(buffer++) = (guint8)((value >> 8) & 0x3F) | 0x80;
        }
        *(buffer++) = (guint8)(value & 0xFF);
        break;

    case 1:
        *(buffer++) = (guint8)(value & 0x7F);
        break;

    default:
        /* Invalid computed size! */
        break;
    }
    return (lenSize);
}

static guint8 parseOIDClass(struct parseCtx *ctx)
{
    if (PARSECTX_PEEK_CHAR_OID(ctx) == '{' && PARSECTX_PEEK_NEXT_CHAR_OID(ctx) != '}')
    {
        /* Hex */
        guint8 classSize = 0;
        guint32 oidClass = 0;
        PARSECTX_STEP_OID(ctx, 1);
        while (PARSECTX_PEEK_CHAR_OID(ctx) != '}')
        {
            if (VALIDHEXBYTE(PARSECTX_GET_CURRENT_POS_OID(ctx)))
            {
                oidClass <<= 8;
                oidClass += (HEX2VALUE(PARSECTX_PEEK_CHAR_OID(ctx)) << 4 | HEX2VALUE(PARSECTX_PEEK_NEXT_CHAR_OID(ctx)));
                PARSECTX_STEP_OID(ctx, 2);

                if (VALIDHEXSEP(PARSECTX_PEEK_CHAR_OID(ctx)))
                {
                    if (PARSECTX_PEEK_NEXT_CHAR_OID(ctx) == '}')
                    {
                        /* no seperator after byte block */
                        return 1;
                    }
                    PARSECTX_STEP_OID(ctx, 1);
                }
            }
            else
            {
                return 1;
            }
        }
        PARSECTX_STEP_OID(ctx, 1);

        classSize = OALMarshal_GetCompressedValueSize(4, oidClass);
        if (PARSECTX_CHECK_LEN(ctx, classSize) == 0)
        {
            if (PARSECTX_GET_CURRENT_POS_BUF(ctx))
                classSize = OALMarshal_CompressValue(4, oidClass, classSize, PARSECTX_GET_CURRENT_POS_BUF(ctx));

            PARSECTX_STEP_BUF(ctx, classSize);
        }

        return 0;
    }
    else
    {
        /* Number */
        guint8 classSize = 0;
        guint32 oidClass = 0;
        while (IS_DIGIT(PARSECTX_PEEK_CHAR_OID(ctx)))
        {
            oidClass *= 10;
            oidClass += DIGIT2VALUE(PARSECTX_PEEK_CHAR_OID(ctx));
            PARSECTX_STEP_OID(ctx, 1);
        }

        classSize = OALMarshal_GetCompressedValueSize(4, oidClass);
        if (PARSECTX_CHECK_LEN(ctx, classSize) == 0)
        {
            if (PARSECTX_GET_CURRENT_POS_BUF(ctx))
                classSize = OALMarshal_CompressValue(4, oidClass, classSize, PARSECTX_GET_CURRENT_POS_BUF(ctx));

            PARSECTX_STEP_BUF(ctx, classSize);
        }

        return 0;
    }
}

static guint8 parseAttributeID(struct parseCtx *ctx)
{
    if (PARSECTX_PEEK_CHAR_OID(ctx) == '{')
    {
        return parseHexField(ctx);
    }
    else
    {
        guint8 avpid = 0;
        while (IS_DIGIT(PARSECTX_PEEK_CHAR_OID(ctx)))
        {
            avpid *= 10;
            avpid += DIGIT2VALUE(PARSECTX_PEEK_CHAR_OID(ctx));
            PARSECTX_STEP_OID(ctx, 1);
        }

        if (PARSECTX_CHECK_LEN(ctx, 1) == 0)
        {
            PARSECTX_WRITE_BUF(ctx, avpid);
            return 0;
        }
    }
    return 1;
}

static guint8 parseAttributeData(struct parseCtx *ctx)
{
    if (PARSECTX_PEEK_CHAR_OID(ctx) == '[')
    {
        return parseFormatOID(ctx);
    }
    else if (PARSECTX_PEEK_CHAR_OID(ctx) == '{')
    {
        return parseHexField(ctx);
    }
    else
    {
        return parseStringField(ctx);
    }
}

static guint8 parseAttribute(struct parseCtx *ctx)
{
    if (parseAttributeID(ctx) == 0)
    {
        /* seperated by ':' */
        if (PARSECTX_READ_CHAR_OID(ctx) == ':' && PARSECTX_CHECK_LEN(ctx, 1) == 0)
        {
            guint8 *length = PARSECTX_GET_CURRENT_POS_BUF(ctx);
            if (length == NULL)
                return 0;

            PARSECTX_STEP_BUF(ctx, 1);

            if (parseAttributeData(ctx) == 0)
            {
                PARSECTX_WRITE_AT_POS_BUF(ctx, length, (guint8)(PARSECTX_GET_CURRENT_POS_BUF(ctx) - (length + 1)));
                return 0;
            }
        }
    }
    return 1;
}

static guint8 parseAttributes(struct parseCtx *ctx)
{
    /* AVPs surrounded by '(' ')' but needs at least an avp */
    if (PARSECTX_READ_CHAR_OID(ctx) == '(' &&  PARSECTX_PEEK_CHAR_OID(ctx) != ')')
    {
        while (PARSECTX_PEEK_CHAR_OID(ctx) != ')')
        {
            guint8 *avpID = PARSECTX_GET_CURRENT_POS_BUF(ctx);
            if (avpID == NULL)
                return 0;

            if (parseAttribute(ctx) != 0)
                return 1;

            /* multiple seperated by '|' */
            if (PARSECTX_PEEK_CHAR_OID(ctx) == '|' && PARSECTX_PEEK_NEXT_CHAR_OID(ctx) != ')')
            {
                PARSECTX_OR_AT_POS_BUF(ctx, avpID, 0x80); /* set that there is a next attribute */
                PARSECTX_STEP_OID(ctx, 1);
            }
        }
        PARSECTX_STEP_OID(ctx, 1);
        return 0;
    }
    return 1;
}

static guint8 parseFormatOID(struct parseCtx *ctx)
{
    /* oid must start with '[' */
    if (PARSECTX_PEEK_CHAR_OID(ctx) == '[')
    {
        PARSECTX_STEP_OID(ctx, 1);
        /* Get class id */
        if (parseOIDClass(ctx) == 0)
        {
            /* seperated by ':' */
            if (PARSECTX_READ_CHAR_OID(ctx) == ':' && PARSECTX_CHECK_LEN(ctx, 1) == 0)
            {
                guint8 *length = PARSECTX_GET_CURRENT_POS_BUF(ctx);
                PARSECTX_STEP_BUF(ctx, 1);

                /* Get data */
                if (PARSECTX_PEEK_CHAR_OID(ctx) == '{')
                {
                    /* hex data */
                    if (parseHexField(ctx) != 0)
                        return 1;
                }
                else
                {
                    /* string data */
                    if (parseStringField(ctx) != 0)
                        return 1;
                }

                /* Write length */
                if (length == NULL)
                    return 0;
                PARSECTX_WRITE_AT_POS_BUF(ctx, length, (guint8)(PARSECTX_GET_CURRENT_POS_BUF(ctx) - (length + 1)));

                /* Check if attributes exist */
                if (PARSECTX_PEEK_CHAR_OID(ctx) == '(')
                {
                    PARSECTX_OR_AT_POS_BUF(ctx, length, 0x80); /* set that there are attributes */
                    if (parseAttributes(ctx) != 0)
                        return 1;
                }

                /* Ends with ] */
                if (PARSECTX_READ_CHAR_OID(ctx) == ']')
                {
                    return 0;
                }
            }
        }
    }
    return 1;
}

static guint8 dof_oid_create_internal(const char *oid, guint32 *size, guint8 *buffer)
{
    struct parseCtx ctx;

    ctx.oid = oid;
    ctx.buffer = buffer;
    ctx.currOidPos = 0;
    ctx.currBufferPos = 0;

    if (oid)
    {
        if (size)
        {
            ctx.buffLen = (*size);
            ctx.oidLen = (guint32)strlen(oid);
            if (PARSECTX_PEEK_CHAR_OID(&ctx) == '[')
            {
                /* Format OID */
                if (parseFormatOID(&ctx) == 0)
                {
                    (*size) = ctx.currBufferPos;
                    return 0;
                }
            }
            else if (PARSECTX_PEEK_CHAR_OID(&ctx) == '{')
            {
                /* HEX OID */
                if (parseHexField(&ctx) == 0)
                {
                    (*size) = ctx.currBufferPos;
                    return 0;
                }
            }
            (*size) = 0;
        }
    }
    return 1;
}

static void dof_oid_new_standard_string(const char *data, guint32 *rsize, guint8 **oid)
{
    if (data)
    {
        guint8 err;
        guint32 size = 0;

        /* Call parseInternal to find out how big the buffer needs to be. */
        err = dof_oid_create_internal(data, &size, NULL);

        if (err == 0)
        {
            /* Create the DOFObjectID using the size that was just computed. */
            *oid = (guint8 *)g_malloc(size + 1); /* Adds space for null-terminator, just in case. */

            if (*oid)
            {
                /* Now that the size is computed and the DOFObjectID is created, call parseInternal again to fill the oid buffer. */
                err = dof_oid_create_internal(data, &size, *oid);

                if (err == 0)
                {
                    *rsize = size;
                    return;
                }

                g_free(*oid);
            }
        }
    }

    *rsize = 0;
    *oid = NULL;
}

/* Binary Parsing Support */

/**
 * Read a compressed 32-bit quantity (PDU Type.3).
 * Since the value is variable length, the new offset is
 * returned. The value can also be returned, along with the size, although
 * NULL is allowed for those parameters.
 */
static gint read_c4(tvbuff_t *tvb, gint offset, guint32 *v, gint *L)
{
    guint32 val = 0;
    guint8 len = 0;
    guint8 b = tvb_get_guint8(tvb, offset++);
    int i;

    if ((b & 0x80) == 0)
    {
        len = 1;
        b = b & 0x7F;
    }
    else if ((b & 0x40) == 0)
    {
        len = 2;
        b = b & 0x3F;
    }
    else
    {
        len = 4;
        b = b & 0x3F;
    }

    val = b;
    for (i = 1; i < len; i++)
        val = (val << 8) | tvb_get_guint8(tvb, offset++);

    if (L)
        *L = len;
    if (v)
        *v = val;
    return offset;
}

/**
 * Validate PDU Type.3
 * Validaes the encoding.
 * Add Expert Info if format invalid
 * This also validates Spec Type.3.1.
 */
static void validate_c4(packet_info *pinfo, proto_item *pi, guint32 val, gint len)
{
    if (len > 1 && val < 0x80)
    {
        /* SPEC Type.3.1 Violation. */
        expert_add_info_format(pinfo, pi, &ei_c2_c3_c4_format, "DOF Violation: Type.3.1: Compressed 32-bit Compression Manditory.");
    }

    if (len > 2 && val < 0x4000)
    {
        /* SPEC Type.3.1 Violation. */
        expert_add_info_format(pinfo, pi, &ei_c2_c3_c4_format, "DOF Violation: Type.3.1: Compressed 32-bit Compression Manditory.");
    }
}

/**
 * Reads a compressed 24-bit quantity (PDU Type.2).
 * Since the value is variable length, the new offset is
 * returned.
 * The value can also be returned, along with the size, although
 * NULL is allowed for those parameters.
 */
static gint read_c3(tvbuff_t *tvb, gint offset, guint32 *v, gint *L)
{
    guint32 val = 0;
    guint8 len = 0;
    guint8 b = tvb_get_guint8(tvb, offset++);
    int i;

    if ((b & 0x80) == 0)
    {
        len = 1;
        b = b & 0x7F;
    }
    else if ((b & 0x40) == 0)
    {
        len = 2;
        b = b & 0x3F;
    }
    else
    {
        len = 3;
        b = b & 0x3F;
    }

    val = b;
    for (i = 1; i < len; i++)
        val = (val << 8) | tvb_get_guint8(tvb, offset++);

    if (L)
        *L = len;
    if (v)
        *v = val;
    return offset;
}

/**
 * Validate PDU Type.2
 * Validaes the encoding.
 * Adds Expert Info if format invalid
 * This also validates Spec Type.2.1.
 */
static void validate_c3(packet_info *pinfo, proto_item *pi, guint32 val, gint len)
{
    if (len > 1 && val < 0x80)
    {
        /* SPEC Type.2.1 Violation. */
        expert_add_info_format(pinfo, pi, &ei_c2_c3_c4_format, "DOF Violation: Type.2.1: Compressed 24-bit Compression Manditory." );
    }

    if (len > 2 && val < 0x4000)
    {
        /* SPEC Type.2.1 Violation. */
        expert_add_info_format(pinfo, pi, &ei_c2_c3_c4_format, "DOF Violation: Type.2.1: Compressed 24-bit Compression Manditory.");
    }
}

/**
 * Reads a compressed 16-bit quantity (PDU Type.1).
 * Since the value is variable length, the new offset is
 * returned. The value can also be returned, along with the size, although
 * NULL is allowed for those parameters.
 */
static gint read_c2(tvbuff_t *tvb, gint offset, guint16 *v, gint *L)
{
    guint16 val = 0;
    guint8 b = tvb_get_guint8(tvb, offset++);
    if (b & 0x80)
    {
        b = b & 0x7F;
        val = (b << 8) | tvb_get_guint8(tvb, offset++);
        if (L)
            *L = 2;
    }
    else
    {
        val = b;
        if (L)
            *L = 1;
    }

    if (v)
        *v = val;
    return offset;
}

/**
 * Validates PDU Type.1
 * Validaes the encoding.
 * Adds Expert Info if format invalid
 * This also validates Spec Type.1.1.
 */
static void validate_c2(packet_info *pinfo, proto_item *pi, guint16 val, gint len)
{
    if (len > 1 && val < 0x80)
    {
        /* SPEC Type.1.1 Violation. */
        expert_add_info_format(pinfo, pi, &ei_c2_c3_c4_format, "DOF Violation: Type.1.1: Compressed 16-bit Compression Manditory." );
    }
}

/**
 * Given a packet data, and assuming that all of the prerequisite information is known,
 * assign a SID ID to the packet if not already assigned.
 * A SID ID is the *possibility* of a unique SID, but until the SID is learned the
 * association is not made. Further, multiple SID ID may end up referring to the
 * same SID, in which case the assignment must be repaired.
 */
static void assign_sid_id(dof_api_data *api_data)
{
    node_key_to_sid_id_key lookup_key;
    node_key_to_sid_id_key *key;
    dof_session_data *session;
    dof_packet_data *packet;
    guint value;

    /* Validate input. These represent dissector misuse, not decoding problems. */
    /* TODO: Diagnostic/programmer message. */
    if (!api_data || !api_data->packet || !api_data->session)
        return;

    session = api_data->session;
    packet = (dof_packet_data *)api_data->packet;


    /* Check if the sender_sid_id is already assigned, if so we are done. */
    if (!packet->sender_sid_id)
    {
        /* Build a (non-allocated) key to do the lookup. */
        lookup_key.transport_id = api_data->transport_session->transport_id;
        lookup_key.transport_node_id = api_data->transport_packet->sender_id;
        lookup_key.dof_id = session->dof_id;
        lookup_key.dof_node_id = packet->sender_id;
        lookup_key.dof_session_id = session->session_id;

        value = GPOINTER_TO_UINT(g_hash_table_lookup(node_key_to_sid_id, &lookup_key));
        if (value)
        {
            gpointer sid_id_key = GUINT_TO_POINTER(value);
            gpointer sid_buffer;

            /* We found a match. */
            packet->sender_sid_id = value;

            /* If we know the SID, we must get it now. */
            sid_buffer = g_hash_table_lookup(sid_id_to_sid_buffer, sid_id_key);
            if (sid_buffer)
            {
                /* We found a match. */
                packet->sender_sid = (dof_2009_1_pdu_19_sid)sid_buffer;
            }
        }
        else
        {
            /* No match, need to add a key. */
            key = g_new0(node_key_to_sid_id_key, 1);
            memcpy(key, &lookup_key, sizeof(node_key_to_sid_id_key));

            /* Note, this is not multithread safe, but Wireshark isn't multithreaded. */
            g_hash_table_insert(node_key_to_sid_id, key, GUINT_TO_POINTER(dpp_next_sid_id));
            packet->sender_sid_id = dpp_next_sid_id++;
        }
    }

    /* Check if the receiver_sid_id is already assigned, if so we are done. */
    if (!packet->receiver_sid_id)
    {
        /* Build a (non-allocated) key to do the lookup. */
        lookup_key.transport_id = api_data->transport_session->transport_id;
        lookup_key.transport_node_id = api_data->transport_packet->receiver_id;
        lookup_key.dof_id = session->dof_id;
        lookup_key.dof_node_id = packet->receiver_id;
        lookup_key.dof_session_id = session->session_id;

        value = GPOINTER_TO_UINT(g_hash_table_lookup(node_key_to_sid_id, &lookup_key));
        if (value)
        {
            gpointer sid_id_key = GUINT_TO_POINTER(value);
            gpointer sid_buffer;

            /* We found a match. */
            packet->receiver_sid_id = value;

            /* If we know the SID, we must get it now. */
            sid_buffer = g_hash_table_lookup(sid_id_to_sid_buffer, sid_id_key);
            if (sid_buffer)
            {
                /* We found a match. */
                packet->receiver_sid = (dof_2009_1_pdu_19_sid)sid_buffer;
            }
        }
        else
        {
            /* No match, need to add a key. */
            key = g_new0(node_key_to_sid_id_key, 1);
            memcpy(key, &lookup_key, sizeof(node_key_to_sid_id_key));

            /* Note, this is not multithread safe, but Wireshark isn't multithreaded. */
            g_hash_table_insert(node_key_to_sid_id, key, GUINT_TO_POINTER(dpp_next_sid_id));
            packet->receiver_sid_id = dpp_next_sid_id++;
        }
    }

}

/**
 * Declare that the sender of the packet is known to have a SID
 * that is identified by the specified buffer. There are a few
 * cases here:
 *  1. The sid of the sender is already assigned. This is a NOP.
 *  2. The sid has never been seen. This associates the SID with the sender SID ID.
 *  3. The sid has been seen, and matches the SID ID of the sender. This just sets the sid field.
 *  4. The sid has been seen, but with a different SID ID than ours. Patch up all the packets.
 */
static void learn_sender_sid(dof_api_data *api_data, guint8 length, const guint8 *sid)
{
    dof_packet_data *packet;
    guint8 lookup_key[256];
    guint8 *key;
    gpointer value;

    /* Validate input. */
    if (!api_data)
    {
        /* TODO: Print error. */
        return;
    }

    if (!api_data->packet)
    {
        /* TODO: Print error. */
        return;
    }

    packet = (dof_packet_data *)api_data->packet;
    if (!packet->sender_sid_id)
        return;

    /* Check for sender SID already known. */
    if (packet->sender_sid)
        return;

    /* Check for SID already known (has assigned SID ID) */
    /* Build a (non-allocated) key to do the lookup. */
    lookup_key[0] = length;
    memcpy(lookup_key + 1, sid, length);

    if (g_hash_table_lookup_extended(sid_buffer_to_sid_id, &lookup_key, (gpointer *)&key, &value))
    {
        guint sid_id = GPOINTER_TO_UINT(value);

        /* We found a match. */
        if (packet->sender_sid_id == sid_id)
        {
            /* It matches our SID ID. Set the sid field. */
            packet->sender_sid = key;
            return;
        }
        else
        {
            /* There is a mis-match between SID and SID ID. We have to go through
            * all the packets that have SID ID (ours) and update them to SID ID (sid).
            */
            guint sid_id_correct = sid_id;
            guint sid_id_incorrect = packet->sender_sid_id;
            dof_packet_data *ptr = globals.dof_packet_head;

            while (ptr)
            {
                if (ptr->sender_sid_id == sid_id_incorrect)
                    ptr->sender_sid_id = sid_id_correct;

                if (ptr->receiver_sid_id == sid_id_incorrect)
                    ptr->receiver_sid_id = sid_id_correct;

                if (ptr->op.op_sid_id == sid_id_incorrect)
                    ptr->op.op_sid_id = sid_id_correct;

                if (ptr->ref_op.op_sid_id == sid_id_incorrect)
                    ptr->ref_op.op_sid_id = sid_id_correct;

                ptr = ptr->next;
            }
        }

        return;
    }

    /* The SID has never been seen. Associate with the SID ID. */
    key = (dof_2009_1_pdu_19_sid)g_malloc0(length + 1);
    memcpy(key, lookup_key, length + 1);

    /* Note, this is not multithread safe, but Wireshark isn't multithreaded. */
    g_hash_table_insert(sid_buffer_to_sid_id, key, GUINT_TO_POINTER(packet->sender_sid_id));
    g_hash_table_insert(sid_id_to_sid_buffer, GUINT_TO_POINTER(packet->sender_sid_id), key);

    /* NOTE: We are storing a reference to the SID in the packet data. This memory
    * will be freed by the dissector init routine when the SID hash table is destroyed.
    * Nothing else should free this SID.
    */
    packet->sender_sid = (dof_2009_1_pdu_19_sid)key;

    /* We have learned the "correct" sid and sid_id, so we can set the sid of
    * any packets that have this sid_id (saves hash lookups in the future).
    */
    {
        dof_packet_data *ptr = globals.dof_packet_head;

        while (ptr)
        {
            if (ptr->sender_sid_id == packet->sender_sid_id)
                ptr->sender_sid = key;

            if (ptr->receiver_sid_id == packet->sender_sid_id)
                ptr->receiver_sid = key;

            ptr = ptr->next;
        }
    }
}

/**
 * Learn a SID from an explict operation. This only defines sids and sid ids.
 */
static void learn_operation_sid(dof_2009_1_pdu_20_opid *opid, guint8 length, const guint8 *sid)
{
    guint8 lookup_key[256];
    guint8 *key;
    gpointer value;

    /* Check for sender SID already known. */
    if (opid->op_sid)
        return;

    /* Check for SID already known (has assigned SID ID) */
    /* Build a (non-allocated) key to do the lookup. */
    lookup_key[0] = length;
    memcpy(lookup_key + 1, sid, length);

    if (g_hash_table_lookup_extended(sid_buffer_to_sid_id, &lookup_key, (gpointer *)&key, &value))
    {
        guint sid_id = GPOINTER_TO_UINT(value);

        opid->op_sid_id = sid_id;
        opid->op_sid = key;
        return;
    }

    /* The SID has never been seen. Associate with the SID ID. */
    key = (dof_2009_1_pdu_19_sid)g_malloc0(length + 1);
    memcpy(key, lookup_key, length + 1);

    /* Assign the op_sid_id. */
    opid->op_sid_id = dpp_next_sid_id++;

    /* Note, this is not multithread safe, but Wireshark isn't multithreaded. */
    g_hash_table_insert(sid_buffer_to_sid_id, key, GUINT_TO_POINTER(opid->op_sid_id));
    g_hash_table_insert(sid_id_to_sid_buffer, GUINT_TO_POINTER(opid->op_sid_id), key);

    /* NOTE: We are storing a reference to the SID in the packet data. This memory
    * will be freed by the dissector init routine when the SID hash table is destroyed.
    * Nothing else should free this SID.
    */
    opid->op_sid = (dof_2009_1_pdu_19_sid)key;
}

static void encryptInPlace(guint protocol_id, void *cipher_state, guint8 *ptct, guint8 ptct_len)
{
    switch (protocol_id)
    {
    case DOF_PROTOCOL_CCM: /* Encrypt is AES */
    {
        rijndael_ctx *ctx = (rijndael_ctx *)cipher_state;
        guint8 ct[16];

        if (ptct_len != 16)
        {
            memset(ptct, 0, ptct_len);
            return;
        }

        rijndael_encrypt(ctx, ptct, ct);
        memcpy(ptct, ct, sizeof(ct));
    }
        break;

    case DOF_PROTOCOL_TEP: /* Encrypt is AES */
    {
        rijndael_ctx *ctx = (rijndael_ctx *)cipher_state;
        guint8 ct[16];

        if (ptct_len != 16)
        {
            memset(ptct, 0, ptct_len);
            return;
        }

        rijndael_encrypt(ctx, ptct, ct);
        memcpy(ptct, ct, sizeof(ct));
    }
        break;

    default: /* Unsupported, zero the mac. */
        memset(ptct, 0, ptct_len);
        return;
    }
}

static void generateMac(guint protocol_id, void *cipher_state, guint8 *nonce, const guint8 *epp, gint a_len, guint8 *data, gint len, guint8 *mac, gint mac_len)
{
    guint16 i;
    guint16 cnt;

    /* a_len = 1, t = mac_len, q = 4: (t-2)/2 : (q-1) -> 4B */
    mac[0] = 0x43 | (((mac_len - 2) / 2) << 3);
    memcpy(mac + 1, nonce, 11);
    memset(mac + 12, 0, 4);
    mac[14] = len >> 8;
    mac[15] = len & 0xFF;

    encryptInPlace(protocol_id, cipher_state, mac, 16);

    mac[0] ^= (a_len >> 8);
    mac[1] ^= (a_len);
    i = 2;

    for (cnt = 0; cnt < a_len; cnt++, i++)
    {
        if (i % 16 == 0)
            encryptInPlace(protocol_id, cipher_state, mac, 16);

        mac[i % 16] ^= epp[cnt];
    }

    i = 0;
    for (cnt = 0; cnt < len; cnt++, i++)
    {
        if (i % 16 == 0)
            encryptInPlace(protocol_id, cipher_state, mac, 16);

        mac[i % 16] ^= data[cnt];
    }

    encryptInPlace(protocol_id, cipher_state, mac, 16);
}

static int decrypt(ccm_session_data *session, ccm_packet_data *pdata, guint8 *nonce, const guint8 *epp, gint a_len, guint8 *data, gint len)
{
    unsigned short i;

    unsigned char ctr[16];
    unsigned char encrypted_ctr[16];
    unsigned char mac[16];
    unsigned char computed_mac[16];
    unsigned int skip;
    guint8 *ekey;

    if (data == NULL || len == 0)
        return 0;

    /* Check the mac length. */
    if (session->mac_len < 4 || session->mac_len > 16)
        return 0;

    if (pdata->period == 0)
        ekey = (guint8 *)session->cipher_data;
    else
        ekey = (guint8 *)g_hash_table_lookup(session->cipher_data_table, GUINT_TO_POINTER(pdata->period));

    if (!ekey)
        return 0;

    /* Determine how many blocks are skipped. */
#if 0 /* seems to be dead code... check this! */
    skip = a_len + 2;
    skip /= 16;
    if ((a_len + 2) % 16)
        skip += 1;
#endif
    skip = 0;

    /* This is hard-coded for q=4. This can only change with a protocol revision.
    Note the value is stored as (q-1). */
    ctr[0] = 0x03;
    memcpy(ctr + 1, nonce, 11);
    ctr[12] = 0;
    ctr[13] = 0;
    ctr[14] = 0;
    ctr[15] = skip; /* Preincremented below. */


    for (i = 0; i < len - session->mac_len; i++)
    {
        if (i % 16 == 0)
        {
            if (ctr[15] == 255)
                ctr[14] += 1;
            ctr[15] += 1;
            memcpy(encrypted_ctr, ctr, 16);
            encryptInPlace(session->protocol_id, session->cipher_data, encrypted_ctr, 16);
        }

        data[i] ^= encrypted_ctr[i % 16];
    }

    memcpy(mac, data + i, session->mac_len);

    ctr[12] = 0;
    ctr[13] = 0;
    ctr[14] = 0;
    ctr[15] = 0;
    memcpy(encrypted_ctr, ctr, 16);
    encryptInPlace(session->protocol_id, session->cipher_data, encrypted_ctr, 16);

    for (i = 0; i < session->mac_len; i++)
        mac[i] ^= encrypted_ctr[i];

    /* Now we have to generate the MAC... */
    generateMac(session->protocol_id, session->cipher_data, nonce, epp, a_len, data, (gint)(len - session->mac_len), computed_mac, session->mac_len);
    if (!memcmp(mac, computed_mac, session->mac_len))
        return 1;

    /* Failure */
    return 0;
}

/* Master Protocol Layer Handlers */

/**
 * This dissector is handed a DPP packet of any version. It is responsible for decoding
 * the common header fields and then passing off to the specific DPP dissector
 */
static int dissect_app_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    col_clear(pinfo->cinfo, COL_INFO);

    /* Compute the APP control information. This is the version and the flags byte.
    * The flags byte is either present, or is based on the version (and can be defaulted).
    */
    {
        guint16 app;
        gint app_len;

        read_c2(tvb, 0, &app, &app_len);

        col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "APP(%u)", app);

        /* call the next dissector */
        if (dissector_try_uint_new(app_dissectors, app, tvb, pinfo, tree, TRUE, data))
        {
            col_set_fence(pinfo->cinfo, COL_PROTOCOL);
            col_set_fence(pinfo->cinfo, COL_INFO);

            return tvb_reported_length(tvb);
        }
        else
        {
            proto_tree_add_protocol_format(tree, proto_2008_1_app, tvb, 0, app_len,
                                           DOF_APPLICATION_PROTOCOL ", Version: %u", app);
        }
    }

    return 0;
}

/**
 * This dissector is handed a DPP packet of any version. It is responsible for decoding
 * the common header fields and then passing off to the specific DPP dissector
 */
static int dof_dissect_dpp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dof_api_data *api_data = (dof_api_data *)data;
    guint offset = 0;

    DISSECTOR_ASSERT(api_data != NULL);

    col_clear(pinfo->cinfo, COL_INFO);

    /* Compute the DPP control information. This is the version and the flags byte.
    * The flags byte is either present, or is based on the version (and can be defaulted).
    */
    {
        guint8 header = tvb_get_guint8(tvb, offset);
        guint8 dpp_version = header & 0x7F;
        guint8 dpp_flags_included = header & 0x80;
        proto_item *hi;
        proto_tree * dpp_root,*dpp_tree;

        col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "DPPv%u", dpp_version);


        hi = proto_tree_add_protocol_format(tree, proto_2008_1_dpp, tvb, offset, 0,
                                            DOF_PRESENTATION_PROTOCOL " Version %u, Flags: %s", dpp_version, dpp_flags_included ? "Included" : "Default");

        dpp_root = proto_item_add_subtree(hi, ett_2008_1_dpp);

        dpp_tree = proto_tree_add_subtree(dpp_root, tvb, offset, 1, ett_2008_1_dpp_1_header, NULL, "Header");


        /* Version and Flag bit */
        proto_tree_add_item(dpp_tree, hf_2008_1_dpp_1_flag, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(dpp_tree, hf_2008_1_dpp_1_version, tvb, offset, 1, ENC_NA);
        offset += 1;

        /* This may, in some cases, be the end of the packet. This is only valid in some
        * situations, which are checked here.
        */
        if (offset == tvb_reported_length(tvb))
        {
            /* TODO: Complete this logic. */

            proto_item_set_len(hi, offset);

            if (!api_data)
                return offset;

            if (api_data->transport_session->is_streaming)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "DNP/DPP Negotiation");

                if (pinfo->fd->flags.visited &&
                    api_data->transport_session->negotiation_required &&
                    ((api_data->transport_session->negotiation_complete_at == 0) || (api_data->transport_session->negotiation_complete_at_ts.secs - api_data->transport_session->session_start_ts.secs > 10)))
                {
                    /* This is the second pass, so we can check for timeouts. */
                    expert_add_info(pinfo, hi, &ei_dof_6_timeout);
                }

                return offset;
            }
        }

        /* call the next dissector */
        if (dissector_try_uint_new(dof_dpp_dissectors, dpp_version, tvb, pinfo, dpp_root, FALSE, data))
        {
            col_set_fence(pinfo->cinfo, COL_PROTOCOL);
            col_set_fence(pinfo->cinfo, COL_INFO);

            return tvb_reported_length(tvb);
        }
    }

    return 0;
}

/**
 * This dissector is handed a DNP packet of any version. It is responsible for decoding
 * the common header fields and then passing off to the specific DNP dissector
 */
static int dof_dissect_dnp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dof_api_data *api_data, gint offset)
{
    guint8 header = tvb_get_guint8(tvb, offset);
    guint8 dnp_version = header & 0x7F;
    guint8 dnp_flags_included = header & 0x80;
    proto_item *main_ti;
    proto_tree * dnp_root,*dnp_tree;

    col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "DNPv%u", dnp_version);

    main_ti = proto_tree_add_protocol_format(tree, proto_2008_1_dnp, tvb, offset, 0,
                                             DOF_NETWORK_PROTOCOL " Version %u, Flags: %s", dnp_version, dnp_flags_included ? "Included" : "Default");

    dnp_root = proto_item_add_subtree(main_ti, ett_2008_1_dnp);

    dnp_tree = proto_tree_add_subtree(dnp_root, tvb, offset, 1, ett_2008_1_dnp_header, NULL, "Header");

    /* Version and Flag bit */
    proto_tree_add_item(dnp_tree, hf_2008_1_dnp_1_flag, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(dnp_tree, hf_2008_1_dnp_1_version, tvb, offset, 1, ENC_NA);

    /* call the next dissector */
    if (dissector_try_uint_new(dnp_dissectors, dnp_version, tvb, pinfo, dnp_root, FALSE, api_data))
    {
        /* Since the transport may have additional packets in this frame, protect our work. */
        col_set_fence(pinfo->cinfo, COL_PROTOCOL);
        col_set_fence(pinfo->cinfo, COL_INFO);
    }
    else
    {
        proto_item_set_end(main_ti, tvb, 1);

        /* During negotiation, we can move past DNP even if it is not known. */
        if (((header & 0x80) == 0) && api_data->transport_session->negotiation_required && ((pinfo->fd->num < api_data->transport_session->negotiation_complete_at) || (api_data->transport_session->negotiation_complete_at == 0)))
        {
            offset += dof_dissect_dpp_common(tvb_new_subset_remaining(tvb, offset + 1), pinfo, tree, api_data);
        }
    }

    if (dnp_flags_included && !api_data->transport_session->negotiation_complete_at)
    {
        api_data->transport_session->negotiation_complete_at = pinfo->fd->num;
        api_data->transport_session->negotiation_complete_at_ts = pinfo->fd->abs_ts;
    }

    return offset;
}

/**
 * This dissector is called for each DPS packet. It assumes that the first layer is
 * DNP, but it does not know anything about versioning. Further, it only worries
 * about decoding DNP (DNP will decode DPP, and so on).
 *
 * This routine is given the DPS packet for the first packet, but doesn't know anything
 * about DPS sessions. It may understand transport sessions, but these are surprisingly
 * worthless for DPS.
 */
static int dissect_dof_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dof_api_data *api_data = (dof_api_data *)data;
    proto_tree *dof_root;
    dof_packet_data *packet;

    DISSECTOR_ASSERT(api_data != NULL);
    DISSECTOR_ASSERT(api_data->transport_session != NULL);
    DISSECTOR_ASSERT(api_data->transport_packet != NULL);

    packet = (dof_packet_data *)api_data->packet;

    /* Create the packet if it doesn't exist. */
    if (packet == NULL)
    {
        api_data->packet = packet = create_packet_data(pinfo);
        DISSECTOR_ASSERT(packet != NULL);

        /* TODO: This is not correct for reversed sessions. */
        packet->is_sent_by_initiator = api_data->transport_packet->is_sent_by_client;
    }

    /* Assign the transport sequence if it does not exist. */
    if (api_data->transport_session->transport_session_id == 0)
        api_data->transport_session->transport_session_id = globals.next_transport_session++;

    /* Compute the DPS information. This is a master holder for general information. */
    {
        proto_item *ti;

        ti = proto_tree_add_protocol_format(tree, proto_2008_1_dof, tvb, 0, tvb_reported_length(tvb), DOF_PROTOCOL_STACK);
        dof_root = proto_item_add_subtree(ti, ett_2008_1_dof);

        /* Add the general packet information. */
        {
            ti = proto_tree_add_uint(dof_root, hf_2008_1_dof_session_transport, tvb, 0, 0, api_data->transport_session->transport_session_id);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_boolean(dof_root, hf_2008_1_dof_is_2_node, tvb, 0, 0, api_data->transport_session->is_2_node);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_boolean(dof_root, hf_2008_1_dof_is_streaming, tvb, 0, 0, api_data->transport_session->is_streaming);
            PROTO_ITEM_SET_GENERATED(ti);

            if (api_data->session)
            {
                ti = proto_tree_add_uint(dof_root, hf_2008_1_dof_session, tvb, 0, 0, api_data->session->session_id);
                PROTO_ITEM_SET_GENERATED(ti);
            }

            if (api_data->secure_session)
            {
                ti = proto_tree_add_uint_format(dof_root, hf_2008_1_dof_session, tvb, 0, 0, api_data->secure_session->original_session_id, "DPS Session (Non-secure): %d", api_data->secure_session->original_session_id);
                PROTO_ITEM_SET_GENERATED(ti);
            }

            ti = proto_tree_add_uint(dof_root, hf_2008_1_dof_frame, tvb, 0, 0, packet->dof_frame);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_boolean(dof_root, hf_2008_1_dof_is_from_client, tvb, 0, 0, api_data->transport_packet->is_sent_by_client);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }

    dof_dissect_dnp_common(tvb, pinfo, tree, api_data, 0);

    packet->processed = TRUE;
    return tvb_reported_length(tvb);
}

/**
 * This dissector is called for each DPS packet. It assumes that the first layer is
 * ENP, but it does not know anything about versioning. Further, it only worries
 * about decoding ENP (ENP will decode EPP, and so on).
 *
 * This routine is given the DPS packet for the first packet, but doesn't know anything
 * about DPS sessions. It may understand transport sessions, but these are surprisingly
 * worthless for DPS.
 */
static int dissect_tunnel_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* The packet data is the private_data, and must exist. */
    tcp_dof_packet_ref *ref = (tcp_dof_packet_ref *)data;
    gint offset = 0;

    offset = 0;

    /* Compute the APP control information. This is the version and the length bytes.
    * The flags byte is either present, or is based on the version (and can be defaulted).
    */
    {
        guint8 version = tvb_get_guint8(tvb, offset);
        guint8 opcode;
        proto_item *ti;
        proto_tree *app_root;

        col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "TUNv%u", version);

        ti = proto_tree_add_protocol_format(tree, proto_2012_1_tunnel, tvb, offset, 0,
                                            "DOF Tunnel Protocol, Version: %u", version);

        app_root = proto_item_add_subtree(ti, ett_2012_1_tunnel);
        proto_tree_add_item(app_root, hf_2012_1_tunnel_1_version, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(app_root, hf_2012_1_tunnel_1_length, tvb, offset + 1, 2, ENC_BIG_ENDIAN);

        opcode = tvb_get_guint8(tvb, offset + 3);
        if (opcode == 3)
        {
            tvbuff_t *next_tvb = tvb_new_subset(tvb, offset + 5, -1, -1);

            dissect_dof_common(next_tvb, pinfo, tree, &ref->api_data);
        }
    }

    return tvb_captured_length(tvb);
}

static int dissect_tun_app_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_clear(pinfo->cinfo, COL_INFO);

    /* Compute the APP control information. This is the version and the flags byte.
    * The flags byte is either present, or is based on the version (and can be defaulted).
    */
    {
        guint16 app;
        gint app_len;


        app = tvb_get_guint8(tvb, 0);
        app_len = 1;

        col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "APP(%u)", app);

        /* call the next dissector */
        if (dissector_try_uint(dof_tun_app_dissectors, app, tvb, pinfo, tree))
        {
            col_set_fence(pinfo->cinfo, COL_PROTOCOL);
            col_set_fence(pinfo->cinfo, COL_INFO);

            return tvb_captured_length(tvb);
        }
        else
        {
            proto_tree_add_protocol_format(tree, proto_2012_1_tunnel, tvb, 0, app_len,
                                                DOF_APPLICATION_PROTOCOL ", Version: %u", app);
        }
    }

    return 0;
}

/* Packet and Session Data Creation */

static udp_session_data* create_udp_session_data(packet_info *pinfo, conversation_t *conversation _U_)
{
    udp_session_data *packet = wmem_new0(wmem_file_scope(), udp_session_data);

    /* TODO: Determine if this is valid or not. */
    /* WMEM_COPY_ADDRESS( wmem_file_scope(), &packet->server.address, &conversation->key_ptr->addr1 );
    packet->server.port = conversation->key_ptr->port1; */
    copy_address_wmem(wmem_file_scope(), &packet->server.addr, &pinfo->dst);
    packet->server.port = pinfo->destport;

    packet->common.transport_id = proto_2008_1_dof_udp;

    {
        const guint8 *addr = (const guint8 *)packet->server.addr.data;
        if ((packet->server.addr.type == AT_IPv4) && (addr != NULL) && (addr[0] != 224))
            packet->common.is_2_node = TRUE;
        else
            packet->common.is_2_node = FALSE;
    }

    packet->common.is_streaming = FALSE;
    packet->common.session_start_ts = pinfo->fd->abs_ts;
    packet->common.negotiation_required = FALSE;
    packet->common.negotiation_complete_at = 0;

    return packet;
}

static tcp_session_data* create_tcp_session_data(packet_info *pinfo, conversation_t *conversation)
{
    tcp_session_data *packet = wmem_new0(wmem_file_scope(), tcp_session_data);

    copy_address_wmem(wmem_file_scope(), &packet->client.addr, &conversation->key_ptr->addr1);
    packet->client.port = conversation->key_ptr->port1;
    copy_address_wmem(wmem_file_scope(), &packet->server.addr, &conversation->key_ptr->addr2);
    packet->server.port = conversation->key_ptr->port2;

    packet->not_dps = FALSE;

    packet->common.transport_id = proto_2008_1_dof_tcp;
    packet->common.is_2_node = TRUE;
    packet->common.is_streaming = TRUE;
    packet->common.session_start_ts = pinfo->fd->abs_ts;
    packet->common.negotiation_required = TRUE;
    packet->common.negotiation_complete_at = 0;

    return packet;
}

static dof_packet_data* create_packet_data(packet_info *pinfo)
{
    /* Create the packet data. */
    dof_packet_data *packet = wmem_new0(wmem_file_scope(), dof_packet_data);

    packet->frame = pinfo->fd->num;
    packet->dof_frame = next_dof_frame++;

    /* Add the packet into the list of packets. */
    if (!globals.dof_packet_head)
    {
        globals.dof_packet_head = packet;
        globals.dof_packet_tail = packet;
    }
    else
    {
        globals.dof_packet_tail->next = packet;
        globals.dof_packet_tail = packet;
    }

    return packet;
}

/* Dissectors for Transports (UDP/TCP) */

/**
 * Dissect a UDP packet. The parent protocol is UDP. No assumptions about DPS
 * data structures are made on input, but before calling common they must
 * be set up.
 * This dissector is registered with the UDP protocol on the standard DPS port.
 * It will be used for anything that involves that port (source or destination).
 */
static int dissect_dof_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    dof_api_data *api_data = (dof_api_data *)p_get_proto_data(NULL, pinfo, proto_2008_1_dof_udp, 0);
    if (api_data == NULL)
    {
        conversation_t *conversation;
        udp_session_data *transport_session;
        dof_transport_packet *transport_packet;
        /* gboolean mcast = FALSE; */

        /* {
            guint8* addr = (guint8*) pinfo->dst.data;
            if ( (pinfo->dst.type == AT_IPv4) && (addr != NULL) && (addr[0] != 224) )
                mcast = TRUE;
        } */

        /* Register the source address as being DPS for the sender UDP port. */
        conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, NO_ADDR_B | NO_PORT_B);
        if (!conversation)
        {
            conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, NO_ADDR_B | NO_PORT_B);
            conversation_set_dissector(conversation, dof_udp_handle);
        }

        /* Find or create the conversation for this transport session. For UDP, the transport session is determined entirely by the
         * server port. This assumes that the first packet seen is from a client to the server.
         */
        conversation = find_conversation(pinfo->fd->num, &pinfo->dst, &pinfo->src, PT_UDP, pinfo->destport, pinfo->srcport, NO_ADDR_B | NO_PORT_B);
        if (conversation)
        {
            /* TODO: Determine if this is valid or not. */
            /*if ( conversation->key_ptr->port1 != pinfo->destport || ! addresses_equal( &conversation->key_ptr->addr1, &pinfo->dst ) )
                conversation = NULL; */
        }

        if (!conversation)
            conversation = conversation_new(pinfo->fd->num, &pinfo->dst, &pinfo->src, PT_UDP, pinfo->destport, pinfo->srcport, NO_ADDR2 | NO_PORT2 | CONVERSATION_TEMPLATE);

        transport_session = (udp_session_data *)conversation_get_proto_data(conversation, proto_2008_1_dof_udp);
        if (transport_session == NULL)
        {
            transport_session = create_udp_session_data(pinfo, conversation);
            conversation_add_proto_data(conversation, proto_2008_1_dof_udp, transport_session);
        }

        /* UDP has no framing or retransmission issues, so the dof_api_data is stored directly on the frame. */
        api_data = wmem_new0(wmem_file_scope(), dof_api_data);
        if (api_data == NULL)
            return 0;

        transport_packet = wmem_new0(wmem_file_scope(), dof_transport_packet);
        if (transport_packet == NULL)
            return 0;

        transport_packet->is_sent_by_client = TRUE;
        if (addresses_equal(&transport_session->server.addr, &pinfo->src) && (transport_session->server.port == pinfo->srcport))
            transport_packet->is_sent_by_client = FALSE;

        transport_packet->sender_id = assign_addr_port_id(&pinfo->src, pinfo->srcport);
        transport_packet->receiver_id = assign_addr_port_id(&pinfo->dst, pinfo->destport);

        api_data->transport_session = &transport_session->common;
        api_data->transport_packet = transport_packet;
        p_add_proto_data(NULL, pinfo, proto_2008_1_dof_udp, 0, api_data);
    }

    return dissect_dof_common(tvb, pinfo, tree, api_data);
}

/**
 * Determine if the current offset has already been processed.
 * This is specific to the TCP dissector.
 */
static gboolean is_retransmission(packet_info *pinfo, tcp_session_data *session, tcp_packet_data *packet, struct tcpinfo *tcpinfo)
{
    /* TODO: Determine why we get big numbers sometimes... */
    /* if ( tcpinfo->seq != 0 && tcpinfo->seq < 1000000) */
    {
        tcp_ignore_data *id;
        guint32 sequence = tcpinfo->seq;

        if (addresses_equal(&pinfo->src, &session->client.addr) && (pinfo->srcport == session->client.port))
        {
            id = packet->from_client_ignore_list;
        }
        else
        {
            id = packet->from_server_ignore_list;
        }

        while (id != NULL && id->sequence != sequence)
        {
            id = id->next;
        }

        if (id == NULL)
            return FALSE;

        return id->ignore;
    }

    return FALSE;
}

/**
 * We have found and processed packets starting at offset, so
 * don't allow the same (or previous) packets.
 * This only applies to TCP dissector conversations.
 */
static void remember_offset(packet_info *pinfo, tcp_session_data *session, tcp_packet_data *packet, struct tcpinfo *tcpinfo)
{
    gboolean ignore = FALSE;

    /* TODO: Determine why we get big numbers sometimes... */
    /* if ( tcpinfo->seq != 0 && tcpinfo->seq < 1000000) */
    {
        tcp_ignore_data **last;
        tcp_ignore_data *id;
        guint32 sequence;
        guint32 *seqptr = NULL;

        if (addresses_equal(&pinfo->src, &session->client.addr) && (pinfo->srcport == session->client.port))
        {
            last = &(packet->from_client_ignore_list);
            id = packet->from_client_ignore_list;
            sequence = tcpinfo->seq;
            seqptr = &session->from_client_seq;

            if (LE_SEQ(tcpinfo->seq, session->from_client_seq))
                ignore = TRUE;
        }
        else
        {
            last = &(packet->from_server_ignore_list);
            id = packet->from_server_ignore_list;
            sequence = tcpinfo->seq;
            seqptr = &session->from_server_seq;

            if (LE_SEQ(tcpinfo->seq, session->from_server_seq))
                ignore = TRUE;
        }

        while (id != NULL && id->sequence != tcpinfo->seq)
        {
            last = &(id->next);
            id = id->next;
        }

        *seqptr = sequence;
        if (id == NULL)
        {
            *last = (tcp_ignore_data *)wmem_alloc0(wmem_file_scope(), sizeof(tcp_ignore_data));
            id = *last;
            id->ignore = ignore;
            id->sequence = tcpinfo->seq;
        }
    }
}

/**
 * This dissector is registered with TCP using the standard port. It uses registered
 * protocols to determine framing, and those dissectors will call into the base
 * DPS dissector for each packet.
 */
static int dissect_dof_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t *conversation;
    tcp_session_data *session;
    tcp_packet_data *packet;
    struct tcpinfo *tcpinfo = (struct tcpinfo *)data;
    guint8 header;

    /* Get the TCP conversation. TCP creates a new conversation for each TCP connection,12
     * so we can "mirror" that by attaching our own data to that conversation. If our
     * data cannot be found, then it is a new connection (to us).
     */
    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
    {
        /* This should be impossible - the TCP dissector requires this conversation.
         * Bail...
         */
        DISSECTOR_ASSERT(conversation != NULL);
    }


    /* This requires explanation. TCP will call this dissector, and we know
     * that the first byte (offset 0 of this tvb) is the first byte of an
     * DPS packet. The TCP dissector ensures this.
     *
     * We do *not* know that this is the only packet, and
     * so the dissector that we call below must handle framing. All of
     * this state must be stored, and so we store it in a transport
     * data structure. DPS packet data is created later and associated
     * differently.
     *
     * Further, this routine MAY be called MULTIPLE times for the SAME
     * frame with DIFFERENT sequence numbers. This makes handling
     * retransmissions very difficult - we must track each call to this
     * routine with its associated offset and ignore flag. However, due
     * to the way that Wireshark handles asking for more data we cannot
     * mark an offset as "duplicate" until after it has been processed.
     */

    /* TCP packet data is only associated with TCP frames that hold DPS packets. */
    session = (tcp_session_data *)conversation_get_proto_data(conversation, proto_2008_1_dof_tcp);
    if (session == NULL)
    {
        session = create_tcp_session_data(pinfo, conversation);
        if (!session)
        {
            fprintf(stderr, "! session");
            return 0;
        }

        conversation_add_proto_data(conversation, proto_2008_1_dof_tcp, session);
    }

    if (session->not_dps)
        return 0;

    packet = (tcp_packet_data *)p_get_proto_data(NULL, pinfo, proto_2008_1_dof_tcp, 0);
    if (packet == NULL)
    {
        packet = (tcp_packet_data *)wmem_alloc0(wmem_file_scope(), sizeof(tcp_packet_data));
        if (!packet)
        {
            fprintf(stderr, "! packet");
            return 0;
        }

        p_add_proto_data(NULL, pinfo, proto_2008_1_dof_tcp, 0, packet);
    }

    if (is_retransmission(pinfo, session, packet, tcpinfo))
        return 0;

    /* Loop, checking all the packets in this frame and communicating with the TCP
     * desegmenter. The framing dissector entry is used to determine the size
     * of the current frame.
     */
    {
        /* Note that we must handle fragmentation on TCP... */
        gint offset = 0;

        while (offset < (gint)tvb_reported_length(tvb))
        {
            gint available = tvb_ensure_captured_length_remaining(tvb, offset);
            int packet_length;

            header = tvb_get_guint8(tvb, offset);

            /* If we are negotiating, then we do not need the framing dissector
             * as we know the packet length is two. Note that for the first byte
             * of a TCP session there are only two cases, both handled here. An error
             * of not understanding the first byte will trigger that this is not
             * a DPS session.
             */
            if (((header & 0x80) == 0) && session->common.negotiation_required && ((pinfo->fd->num < session->common.negotiation_complete_at) || (session->common.negotiation_complete_at == 0)))
            {
                packet_length = 2;
                if (header > DNP_MAX_VERSION)
                {
                    session->not_dps = TRUE;
                    return 0;
                }
            }
            else
            {
                packet_length = dof_dissect_dnp_length(tvb, pinfo, header & 0x7F, &offset);
                if (packet_length < 0)
                {
                    session->not_dps = TRUE;
                    return offset;
                }
            }

            if (packet_length == 0)
            {
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return offset;
            }

            if (available < packet_length)
            {
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = packet_length - available;
                return offset;
            }

            remember_offset(pinfo, session, packet, tcpinfo);
            if (is_retransmission(pinfo, session, packet, tcpinfo))
                return 0;

            /* We have a packet. We have to store the dof_packet_data in a list, as there may be
             * multiple DPS packets in a single Wireshark frame.
             */
            {
                tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, packet_length, packet_length);
                tcp_dof_packet_ref *ref;
                gint raw_offset = tvb_raw_offset(tvb) + offset;
                gboolean ref_is_new = FALSE;

                /* Get the packet data. This is a list in increasing sequence order. */
                if (packet->dof_packets == NULL)
                {
                    ref_is_new = TRUE;
                    ref = (tcp_dof_packet_ref *)wmem_alloc0(wmem_file_scope(), sizeof(tcp_dof_packet_ref));
                    ref->transport_packet.sender_id = assign_addr_port_id(&pinfo->src, pinfo->srcport);
                    ref->transport_packet.receiver_id = assign_addr_port_id(&pinfo->dst, pinfo->destport);
                    packet->dof_packets = ref;
                    ref->start_offset = raw_offset;
                }
                else
                    ref = packet->dof_packets;

                /* Find the entry for our offset. */
                while (ref->start_offset != raw_offset)
                {
                    if (ref->next)
                    {
                        ref = ref->next;
                        continue;
                    }

                    {
                        tcp_dof_packet_ref *last = ref;

                        /* This is the default state, NULL and 0. */
                        ref_is_new = TRUE;
                        ref = wmem_new0(wmem_file_scope(), tcp_dof_packet_ref);
                        if (!ref)
                        {
                            fprintf(stderr, "! ref");
                            return offset;
                        }

                        ref->transport_packet.sender_id = last->transport_packet.sender_id;
                        ref->transport_packet.receiver_id = last->transport_packet.receiver_id;
                        ref->start_offset = raw_offset;
                        last->next = ref;
                    }
                }

                if (ref_is_new)
                {
                    dof_transport_packet *tp = &(ref->transport_packet);

                    tp->is_sent_by_client = FALSE;
                    if (addresses_equal(&session->client.addr, &pinfo->src) &&
                        (session->client.port == pinfo->srcport))
                        tp->is_sent_by_client = TRUE;

                    ref->api_data.transport_session = (dof_transport_session *)&(session->common);
                    ref->api_data.transport_packet = tp;
                }


                dissect_dof_common(next_tvb, pinfo, tree, &ref->api_data);
            }

            offset += packet_length;
        }

        return offset;
    }
}

#if 0 /* TODO not used yet */
/**
 * This dissector is registered with the UDP protocol on the standard DPS port.
 * It will be used for anything that involves that port (source or destination).
 */
#if 0
static int dissect_tunnel_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    conversation_t *conversation;
    dof_packet_data *packet;

    /* Initialize the default transport session structure. */
    if (!udp_transport_session)
    udp_transport_session = se_alloc0(sizeof(*udp_transport_session));

    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP, pinfo->srcport, pinfo->destport, 0);
    if (!conversation)
    {
        conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP, pinfo->srcport, pinfo->destport, 0);
    }

    /* Add the packet data. */
    packet = p_get_proto_data(pinfo->fd, proto_2012_1_tunnel, 0);
    if (!packet)
    {
        packet = se_alloc0(sizeof(dof_packet_data));
        packet->frame = pinfo->fd->num;
        packet->next = NULL;
        packet->start_offset = 0;
        packet->session_counter = &session_counter;
        packet->transport_session = udp_transport_session;
        p_add_proto_data(pinfo->fd, proto_2012_1_tunnel, 0, packet);
    }

    pinfo->private_data = packet;
    return dissect_tunnel_common(tvb, pinfo, tree);
#else
static int dissect_tunnel_udp(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
#endif
    return 0;
}
#endif


/**
 * This dissector is registered with TCP using the standard port. It uses registered
 * protocols to determine framing, and those dissectors will call into the base
 * DPS dissector for each packet.
 */
static int dissect_tunnel_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t *conversation;
    tcp_session_data *session;
    tcp_packet_data *packet;
    struct tcpinfo *tcpinfo = (struct tcpinfo *)data;

    /* Get the TCP conversation. TCP creates a new conversation for each TCP connection,
    * so we can "mirror" that by attaching our own data to that conversation. If our
    * data cannot be found, then it is a new connection (to us).
    */
    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
    {
        /* This should be impossible - the TCP dissector requires this conversation.
        * Bail...
        */
        DISSECTOR_ASSERT(conversation != NULL);
    }


    /* This requires explanation. TCP will call this dissector, and we know
    * that the first byte (offset 0 of this tvb) is the first byte of an
    * DPS packet. The TCP dissector ensures this.
    *
    * We do *not* know that this is the only packet, and
    * so the dissector that we call below must handle framing. All of
    * this state must be stored, and so we store it in a transport
    * data structure. DPS packet data is created later and associated
    * differently.
    *
    * Further, this routine MAY be called MULTIPLE times for the SAME
    * frame with DIFFERENT sequence numbers. This makes handling
    * retransmissions very difficult - we must track each call to this
    * routine with its associated offset and ignore flag. However, due
    * to the way that Wireshark handles asking for more data we cannot
    * mark an offset as "duplicate" until after it has been processed.
    */

    /* TCP packet data is only associated with TCP frames that hold DPS packets. */
    session = (tcp_session_data *)conversation_get_proto_data(conversation, proto_2012_1_tunnel);
    if (session == NULL)
    {
        session = create_tcp_session_data(pinfo, conversation);
        if (!session)
        {
            fprintf(stderr, "! session");
            return 0;
        }

        conversation_add_proto_data(conversation, proto_2012_1_tunnel, session);
    }

    packet = (tcp_packet_data *)p_get_proto_data(NULL, pinfo, proto_2012_1_tunnel, 0);
    if (packet == NULL)
    {
        packet = (tcp_packet_data *)wmem_alloc0(wmem_file_scope(), sizeof(tcp_packet_data));
        if (!packet)
        {
            fprintf(stderr, "! packet");
            return 0;
        }

        p_add_proto_data(NULL, pinfo, proto_2012_1_tunnel, 0, packet);
    }

    if (is_retransmission(pinfo, session, packet, tcpinfo))
        return 0;

    /* Loop, checking all the packets in this TCP frame.
    */
    {
        /* Note that we must handle fragmentation on TCP... */
        gint offset = 0;

        while (offset < (gint)tvb_reported_length(tvb))
        {
            gint available = tvb_reported_length_remaining(tvb, offset);
            int packet_length;
            int header_length;
            int i;

            if (available < 3)
            {
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return offset + available;
            }

            packet_length = 0;
            header_length = 3;

            for (i = 0; i < 2; i++)
                packet_length = packet_length * 256 + tvb_get_guint8(tvb, offset + 1 + i);

            packet_length += header_length;

            if (available < packet_length)
            {
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = packet_length - available;
                return offset + available;
            }

            /* We have a packet. We have to store the dof_packet_data in a list, as there may be
            * multiple DPS packets in a single Wireshark frame.
            */
            {
                tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, packet_length, packet_length);
                tcp_dof_packet_ref *ref;
                gint raw_offset = tvb_raw_offset(tvb) + offset;
                gboolean ref_is_new = FALSE;

                /* Get the packet data. This is a list in increasing sequence order. */
                if (packet->dof_packets == NULL)
                {
                    ref_is_new = TRUE;
                    ref = (tcp_dof_packet_ref *)wmem_alloc0(wmem_file_scope(), sizeof(tcp_dof_packet_ref));
                    ref->transport_packet.sender_id = assign_addr_port_id(&pinfo->src, pinfo->srcport);
                    ref->transport_packet.receiver_id = assign_addr_port_id(&pinfo->dst, pinfo->destport);
                    packet->dof_packets = ref;
                    ref->start_offset = raw_offset;
                }
                else
                    ref = packet->dof_packets;

                /* Find the entry for our offset. */
                while (ref->start_offset != raw_offset)
                {
                    if (ref->next)
                    {
                        ref = ref->next;
                        continue;
                    }

                    {
                        tcp_dof_packet_ref *last = ref;

                        /* This is the default state, NULL and 0. */
                        ref_is_new = TRUE;
                        ref = (tcp_dof_packet_ref *)wmem_alloc0(wmem_file_scope(), sizeof(tcp_dof_packet_ref));
                        if (!ref)
                        {
                            fprintf(stderr, "! ref");
                            return offset;
                        }

                        ref->transport_packet.sender_id = last->transport_packet.sender_id;
                        ref->transport_packet.receiver_id = last->transport_packet.receiver_id;
                        ref->start_offset = raw_offset;
                        last->next = ref;
                    }
                }

                if (ref_is_new)
                {
                    dof_transport_packet *tp = &(ref->transport_packet);

                    tp->is_sent_by_client = FALSE;
                    if (addresses_equal(&session->client.addr, &pinfo->src) &&
                        (session->client.port == pinfo->srcport))
                        tp->is_sent_by_client = TRUE;

                    ref->api_data.transport_session = (dof_transport_session *)&(session->common);
                    ref->api_data.transport_packet = tp;
                }

                /* Manage the private data, restoring the existing value. Call the common dissector. */
                {
                    dissect_tunnel_common(next_tvb, pinfo, tree, ref);
                }
            }

            offset += packet_length;
        }

        return tvb_captured_length(tvb);
    }
}

/* Dissectors */

static int dissect_dnp_0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint offset = 0;

    guint8 dnp_flags_included = 0;

    offset = 0;
    col_clear(pinfo->cinfo, COL_INFO);

    /* Compute the DNP control information. This is the version and the flags byte.
    * The flags byte is either present, or is based on the version (and can be defaulted).
    */
    {
        guint8 header = tvb_get_guint8(tvb, offset);

        dnp_flags_included = (header & 0x80) != 0;

        offset += 1;

        {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "DNPv0 ");

            if (dnp_flags_included)
            {
                /* TODO: Protocol violation. */
            }

            if (tvb_reported_length(tvb) == offset)
                col_set_str(pinfo->cinfo, COL_INFO, "Query");
            else
            {
                guint8 first = tvb_get_guint8(tvb, offset);
                if (first == 0)
                {
                    /* Query with padding. */
                    col_set_str(pinfo->cinfo, COL_INFO, "Query");
                    proto_tree_add_item(tree, hf_2008_1_dnp_0_1_1_padding, tvb, offset, -1, ENC_NA);
                }
                else
                {
                    /* Response. */
                    col_set_str(pinfo->cinfo, COL_INFO, "Query Response");
                    while (first)
                    {
                        proto_tree_add_item(tree, hf_2008_1_dnp_0_1_1_version, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        if (offset == tvb_reported_length(tvb))
                            break;

                        first = tvb_get_guint8(tvb, offset);
                    }

                    if (offset < tvb_reported_length(tvb))
                        proto_tree_add_item(tree, hf_2008_1_dnp_0_1_1_padding, tvb, offset, -1, ENC_NA);
                }
            }
        }
    }

    col_set_fence(pinfo->cinfo, COL_PROTOCOL);
    col_set_fence(pinfo->cinfo, COL_INFO);
    return tvb_reported_length(tvb);
}

/**
 * Determine the length of the packet in tvb, starting at an offset that is passed as a
 * pointer in private_data.
 * Return 0 if the length cannot be determined because there is not enough data in
 * the buffer, otherwise return the length of the packet.
 */
static int determine_packet_length_1(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data)
{
    /* Note that we must handle fragmentation on TCP... */
    gint offset = *((gint *)data);

    {
        gint available = tvb_ensure_captured_length_remaining(tvb, offset);
        guint8 header, flags;
        guint8 size;
        guint8 i;
        gint data_len, header_len;

        if (available < 2)
            return 0;

        header = tvb_get_guint8(tvb, offset);
        data_len = 0;

        if ((header & 0x80) == 0)
        {
            /* The length is fixed in this case... */
            data_len = 0;
            header_len = 2;
            size = 0;
        }
        else
        {
            flags = tvb_get_guint8(tvb, offset + 1);
            size = flags & 0x03;
            header_len = 2 + size;
        }

        if (available < header_len)
            return 0;

        for (i = 0; i < size; i++)
            data_len = data_len * 256 + tvb_get_guint8(tvb, offset + 2 + i);

        return header_len + data_len;
    }
}

static int dissect_dnp_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gint offset = 0;
    dof_api_data *api_data = (dof_api_data *)data;
    dof_packet_data *packet;

    gint8 dnp_version = -1;
    guint8 dnp_flags_included = 0;
    guint8 dnp_length_length = 0;
    guint32 dnp_flags = 0;

    guint length = 0;
    guint encapsulated_length = 0;

    int i;

    proto_tree *dnp_tree = tree;

    if (!api_data)
    {
        /* TODO: Print error */
        return 0;
    }

    if (!api_data->packet)
    {
        /* TODO: Print error */
        return 0;
    }

    packet = api_data->packet;

    offset = 0;
    col_clear(pinfo->cinfo, COL_INFO);

    /* Compute the DNP control information. This is the version and the flags byte.
    * The flags byte is either present, or is based on the version (and can be defaulted).
    */
    {
        guint8 header = tvb_get_guint8(tvb, offset);
        guint32 dnp_src_port = 0;
        guint32 dnp_dst_port = 0;

        dnp_version = header & 0x7F;
        dnp_flags_included = (header & 0x80) != 0;


        offset += 1;

        {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "DNPv1 ");

            if (dnp_flags_included)
            {
                /* Including flags always terminates negotiation. */
                /* packet->negotiated = TRUE; */

                dnp_flags = tvb_get_guint8(tvb, offset);
                if ((dnp_flags & 0xF0) != 0)
                    expert_add_info(pinfo, NULL, &ei_dof_10_flags_zero);

                proto_tree_add_bitmask(dnp_tree, tvb, offset, hf_2009_9_dnp_1_flags, ett_2009_9_dnp_1_flags, bitmask_2009_9_dnp_1_flags, ENC_BIG_ENDIAN);

                offset += 1;
            }
            else
                dnp_flags = DNP_V1_DEFAULT_FLAGS;

            /* Determine the size of the length field. */
            dnp_length_length = dnp_flags & 0x03;
            if (dnp_length_length)
                proto_tree_add_item(dnp_tree, hf_2009_9_dnp_1_length, tvb, offset, dnp_length_length, ENC_BIG_ENDIAN);

            /* Read the length. */
            length = 0;
            for (i = 0; i < dnp_length_length; i++)
                length = (length << 8) | tvb_get_guint8(tvb, offset + i);

            /* Validate the length. */
#if 0
            if ( (length == 0) && packet->negotiated && session && ! session->connectionless )
            {
            expert_add_info( pinfo, NULL, &ei_dof_13_length_specified );
            }
#endif

            offset += dnp_length_length;

            /* If there isn't a length specified then use the packet size. */
            if (dnp_length_length == 0)
                length = tvb_reported_length(tvb) - offset;

            encapsulated_length = length;

            /* Read the srcport */
            if (dnp_flags & 0x04)
            {
                gint s_offset = offset;
                proto_item *item;
                gint dnp_src_port_len;

                offset = read_c3(tvb, offset, &dnp_src_port, &dnp_src_port_len);
                item = proto_tree_add_uint_format(dnp_tree, hf_2009_9_dnp_1_srcport, tvb, s_offset, offset - s_offset, dnp_src_port, "Source Address: %u", dnp_src_port);
                validate_c3(pinfo, item, dnp_src_port, dnp_src_port_len);
                encapsulated_length -= (offset - s_offset);
            }
            else
            {
                proto_item *item = proto_tree_add_uint_format(dnp_tree, hf_2009_9_dnp_1_srcport, tvb, 0, 0, 0, "Source Address: %u", 0);
                PROTO_ITEM_SET_GENERATED(item);
            }

            /* Read the dstport */
            if (dnp_flags & 0x08)
            {
                gint s_offset = offset;
                gint dnp_dst_port_len;
                proto_item *item;

                offset = read_c3(tvb, offset, &dnp_dst_port, &dnp_dst_port_len);
                item = proto_tree_add_uint_format(dnp_tree, hf_2009_9_dnp_1_dstport, tvb, s_offset, offset - s_offset, dnp_dst_port, "Destination Address: %u", dnp_dst_port);
                validate_c3(pinfo, item, dnp_dst_port, dnp_dst_port_len);
                encapsulated_length -= (offset - s_offset);
            }
            else
            {
                proto_item *item = proto_tree_add_uint_format(dnp_tree, hf_2009_9_dnp_1_dstport, tvb, 0, 0, 0, "Destination Address: %u", 0);
                PROTO_ITEM_SET_GENERATED(item);
            }
        }

        proto_item_set_end(tree, tvb, offset);

        /* Given the transport session and the DPS port information, determine the DPS session. */
        if (api_data->session == NULL)
        {
            guint32 client;
            guint32 server;

            if (api_data->transport_packet->is_sent_by_client)
            {
                client = dnp_src_port;
                server = dnp_dst_port;
            }
            else
            {
                client = dnp_dst_port;
                server = dnp_src_port;
            }

            api_data->session = dof_ns_session_retrieve(api_data->transport_session->transport_session_id, client, server);
            if (api_data->session == NULL)
            {
                dof_session_data *sdata = (dof_session_data *)wmem_alloc0(wmem_file_scope(), sizeof(dof_session_data));
                dof_ns_session_define(api_data->transport_session->transport_session_id, client, server, sdata);
                sdata->session_id = globals.next_session++;
                sdata->dof_id = dnp_version;
                api_data->session = sdata;
            }
        }

        packet->sender_id = dnp_src_port;
        packet->receiver_id = dnp_dst_port;

        /* Assuming there is more, it must be DPP. */

        /* We have a packet. */
        {
            tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, encapsulated_length, tvb_reported_length(tvb) - offset);
            offset += dof_dissect_dpp_common(next_tvb, pinfo, proto_item_get_parent(tree), data);
        }
    }

    col_set_fence(pinfo->cinfo, COL_PROTOCOL);
    col_set_fence(pinfo->cinfo, COL_INFO);
    return offset;
}

static int dissect_dpp_0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint offset = 0;

    guint8 dpp_flags_included = 0;

    offset = 0;
    col_clear(pinfo->cinfo, COL_INFO);

    /* Compute the DPP control information. This is the version and the flags byte.
    * The flags byte is either present, or is based on the version (and can be defaulted).
    */
    {
        guint8 header = tvb_get_guint8(tvb, offset);

        dpp_flags_included = (header & 0x80) != 0;

        offset += 1;

        {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "DPPv0 ");

            if (dpp_flags_included)
            {
                /* TODO: Protocol violation. */
            }

            if (tvb_reported_length(tvb) == offset)
                col_set_str(pinfo->cinfo, COL_INFO, "Query");
            else
            {
                guint8 first = tvb_get_guint8(tvb, offset);
                /* Response. */
                col_set_str(pinfo->cinfo, COL_INFO, "Query Response");
                while (first)
                {
                    proto_tree_add_item(tree, hf_2008_1_dpp_0_1_1_version, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    if (offset == tvb_reported_length(tvb))
                        break;

                    first = tvb_get_guint8(tvb, offset);
                }
            }
        }
    }

    col_set_fence(pinfo->cinfo, COL_PROTOCOL);
    col_set_fence(pinfo->cinfo, COL_INFO);
    return tvb_reported_length(tvb);
}

static int dissect_dpp_v2_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dof_api_data *api_data = (dof_api_data *)data;
    dof_packet_data *packet_data;
    gint offset = 0;
    guint8 opcode;
    guint16 app;
    gint app_len;
    proto_item *ti;
    proto_tree *dpps_tree;
    proto_tree *opid_tree;

    if (api_data == NULL)
    {
        /* TODO: Output error. */
        return 0;
    }

    packet_data = api_data->packet;
    if (packet_data == NULL)
    {
        /* TODO: Output error. */
        return 0;
    }

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DPPs ");

    /* Create the protocol tree. */
    offset = 0;
    ti = proto_tree_add_item(tree, proto_2009_12_dpp_common, tvb, offset, -1, ENC_NA);
    dpps_tree = proto_item_add_subtree(ti, ett_2009_12_dpp_common);

    /* Add the APPID. */
    offset = read_c2(tvb, offset, &app, &app_len);
    ti = proto_tree_add_uint(dpps_tree, hf_2008_1_app_version, tvb, 0, app_len, app);
    validate_c2(pinfo, ti, app, app_len);


    /* Retrieve the opcode. */
    opcode = tvb_get_guint8(tvb, offset);
    if (!packet_data->is_command)
        opcode |= OP_2009_12_RESPONSE_FLAG;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(opcode, strings_2009_12_dpp_common_opcodes, "Unknown Opcode (%d)"));

    /* Opcode */
    proto_tree_add_uint_format(dpps_tree, hf_2009_12_dpp_2_14_opcode, tvb, offset, 1, opcode & 0x3F, "Opcode: %s (%u)", val_to_str(opcode, strings_2009_12_dpp_common_opcodes, "Unknown Opcode (%d)"), opcode & 0x3F);
    offset += 1;

    switch (opcode)
    {
    case OP_2009_12_SOURCE_LOST_CMD:
    case OP_2009_12_SOURCE_FOUND_CMD:
    case OP_2009_12_RENAME_CMD:
        packet_data->has_referenced_opid = TRUE;

        /* FALL THROUGH */

    case OP_2009_12_CANCEL_ALL_CMD:
    case OP_2009_12_NODE_DOWN_CMD:
    case OP_2009_12_QUERY_RSP:
        /* SID */
    {
        proto_tree *oid_tree;
        gint opid_len;
        tvbuff_t *next_tvb;

        if (packet_data->has_referenced_opid)
        {
            opid_tree = proto_tree_add_subtree(dpps_tree, tvb, offset, 0, ett_2009_12_dpp_2_opid, NULL, "Operation Identifier");
        }
        else
        {
            opid_tree = dpps_tree;
        }

        oid_tree = proto_tree_add_subtree(opid_tree, tvb, offset, 0, ett_2009_12_dpp_2_opid, NULL, "Source Identifier");

        next_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb) - offset);
        opid_len = call_dissector_only(dof_oid_handle, next_tvb, pinfo, oid_tree, NULL);

        learn_sender_sid(api_data, opid_len, tvb_get_ptr(next_tvb, 0, opid_len));
        if (packet_data->has_referenced_opid)
            learn_operation_sid(&packet_data->ref_op, opid_len, tvb_get_ptr(next_tvb, 0, opid_len));

        offset += opid_len;
    }

        if (packet_data->has_referenced_opid)
        {
            guint32 opcnt;
            gint opcnt_len;
            proto_item *pi;

            read_c4(tvb, offset, &opcnt, &opcnt_len);
            pi = proto_tree_add_uint_format(opid_tree, hf_2009_12_dpp_2_1_opcnt, tvb, offset, opcnt_len, opcnt, "Operation Count: %u", opcnt);
            validate_c4(pinfo, pi, opcnt, opcnt_len);
            offset += opcnt_len;

            packet_data->ref_op.op_cnt = opcnt;
        }

        break;
    }
    return offset;
}

static int dissect_dpp_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dof_api_data *api_data = (dof_api_data *)data;
    dof_packet_data *packet_data;

    proto_item *ti = NULL;
    proto_item *tf = NULL;
    proto_item *opid = NULL;

    gint opid_start = -1;
    guint8 dpp_flags_included = 0;
    guint32 dpp_flags = 0;
    guint8 dpp_opid_keytype = 0;

    proto_tree *dpp_flags_tree;
    proto_tree *opid_tree = NULL;


    gint offset = 0;

    proto_tree *dpp_tree = tree;

    if (api_data == NULL)
    {
        /* TODO: Output error. */
        return 0;
    }

    packet_data = api_data->packet;
    if (packet_data == NULL)
    {
        /* TODO: Output error. */
        return 0;
    }

    /* We should have everything required for determining the SID ID. */
    assign_sid_id(api_data);

    offset = 0;
    col_clear(pinfo->cinfo, COL_INFO);

    /* Compute the DPP control information. This is the version and the flags byte.
    * The flags byte is either present, or is based on the version (and can be defaulted).
    */
    {
        guint8 header = tvb_get_guint8(tvb, offset);
        dpp_flags_included = (header & 0x80) != 0;
        offset += 1;

        {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "DPPv2 ");

            ti = proto_tree_add_uint_format(tree, hf_2008_1_dpp_sid_num, tvb,
                                            0, 0, packet_data->sender_sid_id, "SID ID: %d", packet_data->sender_sid_id);
            PROTO_ITEM_SET_GENERATED(ti);

            if (packet_data->sender_sid)
            {
                const gchar *SID = dof_oid_create_standard_string(packet_data->sender_sid[0], packet_data->sender_sid + 1);
                ti = proto_tree_add_bytes_format_value(tree, hf_2008_1_dpp_sid_str, tvb, 0, 0, packet_data->sender_sid, "%s", SID);
                PROTO_ITEM_SET_GENERATED(ti);
            }

            ti = proto_tree_add_uint_format(tree, hf_2008_1_dpp_rid_num, tvb,
                                            0, 0, packet_data->receiver_sid_id, "RID ID: %d", packet_data->receiver_sid_id);
            PROTO_ITEM_SET_GENERATED(ti);

            if (packet_data->receiver_sid)
            {
                const gchar *SID = dof_oid_create_standard_string(packet_data->receiver_sid[0], packet_data->receiver_sid + 1);
                ti = proto_tree_add_bytes_format_value(tree, hf_2008_1_dpp_rid_str, tvb, 0, 0, packet_data->receiver_sid, "%s", SID);
                PROTO_ITEM_SET_GENERATED(ti);
            }

            if (dpp_flags_included)
            {
                dpp_flags = tvb_get_guint8(tvb, offset);
                if (((dpp_flags & 0x10) != 0) && ((dpp_flags & 0x0F) != 0))
                    expert_add_info(pinfo, NULL, &ei_dpp2_dof_10_flags_zero);
                if (((dpp_flags & 0x10) == 0) && ((dpp_flags & 0x09) != 0))
                    expert_add_info(pinfo, NULL, &ei_dpp2_dof_10_flags_zero);

                tf = proto_tree_add_uint_format(dpp_tree, hf_2009_12_dpp_2_1_flags, tvb,
                                                offset, 1, dpp_flags, "Flags: 0x%02x", dpp_flags);

                dpp_flags_tree = proto_item_add_subtree(tf, ett_2009_12_dpp_2_1_flags);

                if (dpp_flags == DPP_V2_DEFAULT_FLAGS)
                    expert_add_info(pinfo, dpp_flags_tree, &ei_dpp_default_flags);

                proto_tree_add_item(dpp_flags_tree, hf_2009_12_dpp_2_1_flag_security, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(dpp_flags_tree, hf_2009_12_dpp_2_1_flag_opid, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(dpp_flags_tree, hf_2009_12_dpp_2_1_flag_cmdrsp, tvb, offset, 1, ENC_NA);
                if ((dpp_flags & 0x10) == 0)
                {
                    proto_tree_add_item(dpp_flags_tree, hf_2009_12_dpp_2_1_flag_seq, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(dpp_flags_tree, hf_2009_12_dpp_2_1_flag_retry, tvb, offset, 1, ENC_NA);
                }

                offset += 1;
            }
            else
                dpp_flags = DPP_V2_DEFAULT_FLAGS;

            packet_data->is_command = (dpp_flags & 0x10) == 0;

            /* We are allowed to be complete here if still negotiating. */
            /*if ( ! packet->negotiated && (offset == tvb_reported_length(tvb)) )
            {
            col_set_str( pinfo->cinfo, COL_INFO, "DPS Negotiation" );
            return 1;
            }*/

            dpp_opid_keytype = (dpp_flags & 0x60) >> 5;
            switch (dpp_opid_keytype)
            {
            case 0: /* No OPID */
                packet_data->has_opid = FALSE;
                break;

            case 1: /* Implied sender. */
                packet_data->has_opid = TRUE;
                packet_data->op.op_sid_id = packet_data->sender_sid_id;
                packet_data->op.op_sid = packet_data->sender_sid;
                break;

            case 2: /* Implied receiver. */
                packet_data->has_opid = TRUE;
                packet_data->op.op_sid_id = packet_data->receiver_sid_id;
                packet_data->op.op_sid = packet_data->receiver_sid;
                break;

            case 3: /* Explicit. */
                packet_data->has_opid = TRUE;
                break;
            }

            if (dpp_opid_keytype != 0)
            {
                opid_start = offset;
                opid_tree = proto_tree_add_subtree(dpp_tree, tvb, offset, 0, ett_2009_12_dpp_2_opid, NULL, "Operation Identifier");
            }

            switch (dpp_opid_keytype)
            {
            case 0: /* We have no opid. */
                break;

            case 3: /* Explicit. */
            {
                proto_tree *oid_tree;
                tvbuff_t *next_tvb;
                gint opid_len;

                oid_tree = proto_tree_add_subtree(opid_tree, tvb, offset, 0, ett_2009_12_dpp_2_opid, NULL, "Source Identifier");

                next_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb) - offset);
                opid_len = call_dissector_only(dof_oid_handle, next_tvb, pinfo, oid_tree, NULL);
                proto_item_set_len(oid_tree, opid_len);

                learn_operation_sid(&packet_data->op, opid_len, tvb_get_ptr(next_tvb, 0, opid_len));

                /* Warn if Explicit SID could be optimized. */
                if (packet_data->op.op_sid_id == packet_data->sender_sid_id)
                    expert_add_info(pinfo, ti, &ei_dpp_explicit_sender_sid_included);
                if (packet_data->op.op_sid_id == packet_data->receiver_sid_id)
                    expert_add_info(pinfo, ti, &ei_dpp_explicit_receiver_sid_included);

                offset += opid_len;
            }

                /* FALL THROUGH */

            case 1: /* Implied sender. */
            case 2: /* Implied receiver. */
            {
                guint32 opcnt;
                gint opcnt_len;
                proto_item *pi;

                /* Display the SID if known. */
                if ((dpp_opid_keytype != 3) && packet_data->op.op_sid)
                {
                    proto_tree *oid_tree;

                    tvbuff_t *next_tvb = tvb_new_child_real_data(tvb, packet_data->op.op_sid + 1, packet_data->op.op_sid[0], packet_data->op.op_sid[0]);
                    oid_tree = proto_tree_add_subtree(opid_tree, tvb, 0, 0, ett_2009_12_dpp_2_opid, NULL, "Source Identifier");

                    call_dissector_only(dof_oid_handle, next_tvb, pinfo, oid_tree, NULL);

                    PROTO_ITEM_SET_GENERATED(ti);
                }

                read_c4(tvb, offset, &opcnt, &opcnt_len);
                pi = proto_tree_add_uint_format(opid_tree, hf_2009_12_dpp_2_1_opcnt, tvb, offset, opcnt_len, opcnt, "Operation Count: %u", opcnt);
                validate_c4(pinfo, pi, opcnt, opcnt_len);
                offset += opcnt_len;

                proto_item_set_len(opid, offset - opid_start);

                packet_data->op.op_cnt = opcnt;

                /* At this point we have a packet with an operation identifier. We need to
                * update the master list of operation identifiers, and do any checking that
                * we can in order to validate things.
                */
                if (packet_data->has_opid && !packet_data->opid_first)
                {
                    dof_packet_data *first = (dof_packet_data *)g_hash_table_lookup(dpp_opid_to_packet_data, (gconstpointer) & packet_data->op);
                    if (first == NULL)
                    {
                        /* First reference to this operation. */
                        g_hash_table_insert(dpp_opid_to_packet_data, (gpointer) & packet_data->op, (gpointer)packet_data);
                        packet_data->opid_first = packet_data;
                        packet_data->opid_last = packet_data;

                        /* The first opid must be a command. */
                    }
                    else
                    {
                        /* Operation exists, time to patch things in. */
                        packet_data->opid_first = first;
                        first->opid_last->opid_next = packet_data;
                        first->opid_last = packet_data;

                        if (!packet_data->is_command)
                        {
                            if (!first->opid_first_response)
                            {
                                first->opid_first_response = packet_data;
                                first->opid_last_response = packet_data;
                            }
                            else
                            {
                                first->opid_last_response->opid_next_response = packet_data;
                                first->opid_last_response = packet_data;
                            }
                        }
                    }
                }


                /* Add all the reference information to the tree. */
                if (globals.track_operations && tree)
                {
                    proto_tree *ophistory_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_2009_12_dpp_2_opid_history, NULL, "Operation History");

                    dof_packet_data *ptr = packet_data->opid_first;

                    if (ptr)
                        proto_tree_add_uint_format(ophistory_tree, hf_2008_1_dpp_first_command,
                                                   tvb, 0, 0, ptr->frame,
                                                   "First Operation: %u",
                                                   ptr->frame);

                    if (ptr->opid_last && ptr->opid_last != ptr)
                        proto_tree_add_uint_format(ophistory_tree, hf_2008_1_dpp_last_command,
                                                   tvb, 0, 0, ptr->opid_last->frame,
                                                   "Last Operation: %u",
                                                   ptr->opid_last->frame);

                    if (ptr->opid_first_response)
                        proto_tree_add_uint_format(ophistory_tree, hf_2008_1_dpp_first_response,
                                                   tvb, 0, 0, ptr->opid_first_response->frame,
                                                   "First Response: %u",
                                                   ptr->opid_first_response->frame);

                    if (ptr->opid_last_response && ptr->opid_last_response != ptr->opid_first_response)
                        proto_tree_add_uint_format(ophistory_tree, hf_2008_1_dpp_last_response,
                                                   tvb, 0, 0, ptr->opid_last_response->frame,
                                                   "Last Response: %u",
                                                   ptr->opid_last_response->frame);

                    /* Determine the window start, then output the number of packets. Output the number of skipped packets before
                    * and after.
                    */
                    {
                        dof_packet_data *start = packet_data->opid_first;
                        guint diff = 0;
                        while (ptr)
                        {
                            if (ptr == packet_data)
                                break;

                            ptr = ptr->opid_next;
                            diff += 1;

                            if (diff > globals.track_operations_window)
                            {
                                start = start->opid_next;
                                diff -= 1;
                            }
                        }

                        ptr = start;
                        diff = 0;

                        while (ptr)
                        {
                            const char *THIS = "";

                            if (ptr == packet_data)
                            {
                                THIS = "this ";
                                diff = globals.track_operations_window + 1;
                            }

                            /* (DPS Frame) [ws WS Frame]: (SID)->(RID): (THIS) (SUMMARY) */
                            proto_tree_add_uint_format(ophistory_tree, hf_2008_1_dpp_related_frame,
                                                       tvb, 0, 0, ptr->frame,
                                                       "%u[ws %u]: %u->%u: %s%s",
                                                       ptr->dof_frame, ptr->frame,
                                                       ptr->sender_sid_id, ptr->receiver_sid_id,
                                                       THIS,
                                                       ptr->summary ? ptr->summary : "");

                            ptr = ptr->opid_next;
                            if (diff && !--diff)
                                break;
                        }
                    }
                }
            }
                break;
            }

            proto_item_set_len(opid_tree, offset - opid_start);

            {
                if ((dpp_flags & 0x10) == 0)
                {
                    guint8 dpp_seq = 0;
                    guint8 dpp_retry = 0;
                    guint16 dpp_delay = 0;

                    /* Extract SEQ */
                    if (dpp_flags & 0x04)
                    {
                        dpp_seq = tvb_get_guint8(tvb, offset);
                        proto_tree_add_uint_format(dpp_tree, hf_2009_12_dpp_2_1_seq, tvb, offset, 1, dpp_seq, "Sequence: %u", dpp_seq);
                        offset += 1;
                    }

                    /* Extract Retry */
                    if (dpp_flags & 0x02)
                    {
                        dpp_retry = tvb_get_guint8(tvb, offset);
                        proto_tree_add_uint_format(dpp_tree, hf_2009_12_dpp_2_1_retry, tvb, offset, 1, dpp_retry, "Retry: %u", dpp_retry);
                        offset += 1;
                    }

                    /* Extract Delay */
                    {
                        dpp_delay = tvb_get_guint8(tvb, offset);
                        if (dpp_delay > 128)
                            dpp_delay = 128 + ((dpp_delay - 128) * 32);

                        proto_tree_add_uint_format(dpp_tree, hf_2009_12_dpp_2_1_delay, tvb, offset, 1, dpp_delay, "Delay: %u seconds", dpp_delay);
                        offset += 1;
                    }

                    packet_data->summary = wmem_strdup_printf(wmem_file_scope(), "command seq %u, retry %u, delay %u", dpp_seq, dpp_retry, dpp_delay);
                }
                else
                    packet_data->summary = "response";
            }

            /* Extract session information. */
            if (dpp_flags & 0x80)
            {
                guint32 sec_offset = offset;
                guint8 sh_flags;
                guint32 ssid;
                proto_tree *security_tree;
                proto_tree *sec_flags_tree;
                proto_item *item;

                security_tree = proto_tree_add_subtree(dpp_tree, tvb, offset, -1, ett_2009_12_dpp_2_3_security, NULL, "Security Header");

                sh_flags = tvb_get_guint8(tvb, offset);
                item = proto_tree_add_uint_format(security_tree, hf_2009_12_dpp_2_3_sec_flags, tvb,
                                                  offset, 1, sh_flags, "Flags: 0x%02x", sh_flags);

                sec_flags_tree = proto_item_add_subtree(item, ett_2009_12_dpp_2_3_sec_flags);
                proto_tree_add_item(sec_flags_tree, hf_2009_12_dpp_2_3_sec_flag_secure, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sec_flags_tree, hf_2009_12_dpp_2_3_sec_flag_rdid, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sec_flags_tree, hf_2009_12_dpp_2_3_sec_flag_partition, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sec_flags_tree, hf_2009_12_dpp_2_3_sec_flag_as, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(sec_flags_tree, hf_2009_12_dpp_2_3_sec_flag_ssid, tvb, offset, 1, ENC_NA);
                offset += 1;

                ssid = 0;
                if (sh_flags & DPP_V2_SEC_FLAG_S)
                {
                    gint s_offset = offset;
                    gint ssid_len;
                    proto_item *pi;
                    offset = read_c4(tvb, offset, &ssid, &ssid_len);
                    pi = proto_tree_add_uint_format(security_tree, hf_2009_12_dpp_2_3_sec_ssid, tvb, s_offset, offset - s_offset, ssid, "Security State Identifier: %u (0x%x)", ssid, ssid);
                    validate_c4(pinfo, pi, ssid, ssid_len);
                }

                /* At this point we know the transport information, DNP port information, and the
                * SSID. This means that we can isolate the session that this communication belongs
                * to. Note that all uses of an SSID are scoped by the transport.
                */
                if (sh_flags & DPP_V2_SEC_FLAG_A)
                    ssid |= AS_ASSIGNED_SSID;

                if (api_data->session && !api_data->secure_session)
                {
                    dof_secure_session_data *search = api_data->session->secure_sessions;
                    while (search)
                    {
                        if (ssid == search->ssid)
                            break;

                        search = search->next;
                    }

                    if (search)
                    {
                        api_data->session = search->parent;
                        api_data->secure_session = search;
                    }
                }

                if (sh_flags & DPP_V2_SEC_FLAG_D)
                {
                    gint s_offset = offset;
                    guint32 rdid;
                    gint rdid_len;
                    proto_item *pi;
                    offset = read_c4(tvb, offset, &rdid, &rdid_len);
                    pi = proto_tree_add_uint_format(security_tree, hf_2009_12_dpp_2_3_sec_rdid, tvb, s_offset, offset - s_offset, rdid, "Remote Domain Identifier: %u (0x%x)", rdid, rdid);
                    validate_c4(pinfo, pi, rdid, rdid_len);

                    offset = dof_dissect_pdu_as_field(dissect_2008_16_security_10, tvb, pinfo, security_tree,
                                                      offset, hf_2009_12_dpp_2_3_sec_remote_partition, ett_2009_12_dpp_2_3_sec_remote_partition, NULL);
                }

                if (sh_flags & DPP_V2_SEC_FLAG_P)
                {
                    offset = dof_dissect_pdu_as_field(dissect_2008_16_security_10, tvb, pinfo, security_tree,
                                                      offset, hf_2009_12_dpp_2_3_sec_partition, ett_2009_12_dpp_2_3_sec_partition, NULL);
                }

                if (sh_flags & DPP_V2_SEC_FLAG_E)
                {
                    /* If we get here without success, then we can only bail. */
                    if (packet_data->security_session_error)
                    {
                        col_set_str(pinfo->cinfo, COL_INFO, packet_data->security_session_error);
                        proto_item_set_end(tree, tvb, offset);
                        expert_add_info(pinfo, security_tree, &ei_dpp_no_security_context);
                        {
                            tvbuff_t *data_tvb = tvb_new_subset_remaining(tvb, offset);
                            call_dissector(undissected_data_handle, data_tvb, pinfo, tree);
                        }
                        proto_item_set_len(security_tree, offset - sec_offset);
                        return offset;
                    }

                    if (!api_data->secure_session)
                    {
                        packet_data->security_session_error = "[Encrypted - No Session Available]";
                        proto_item_set_len(security_tree, offset - sec_offset);
                        return offset;
                    }

                    /* Security has not failed, and we have a security session. */
                    {
                        dissector_table_t sec_header = find_dissector_table("dof.secmode");
                        /* TODO: CCM is hardcoded. We should try all of the sessions, which could mean multiple security modes. */
                        dissector_handle_t dp = dissector_get_uint_handle(sec_header, 0x6001); /* packet_data->security_session->security_mode); */
                        if (dp)
                        {
                            dof_secmode_api_data sdata;

                            sdata.context = HEADER;
                            sdata.security_mode_offset = offset;
                            sdata.dof_api = api_data;
                            sdata.secure_session = api_data->secure_session;
                            sdata.session_key_data = NULL;

                            offset += call_dissector_only(dp, tvb, pinfo, security_tree, &sdata);

                            if (!packet_data->decrypted_buffer)
                            {
                                proto_item_set_end(tree, tvb, offset);
                                proto_item_set_len(security_tree, offset - sec_offset);
                                return offset;
                            }
                        }
                    }
                }
                proto_item_set_len(security_tree, offset - sec_offset);
            }

            /* The end of the packet must be called in the original tvb or chaos ensues... */
            proto_item_set_end(tree, tvb, offset);
        }


        if (packet_data->decrypted_tvb)
        {
            tvb = packet_data->decrypted_tvb;
            offset = packet_data->decrypted_offset;
        }

        /* Assuming there is more, it must be DPP. */
        /* We have a packet. We must handle the special case of this being *our* application
        * protocol (0x7FFF). If it is, then *we* are the dissector...
        */
        {
            guint16 app;
            tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb) - offset);

            read_c2(tvb, offset, &app, NULL);
            if (app == 0x7FFF)
            {
                offset += dissect_dpp_v2_common(next_tvb, pinfo, proto_item_get_parent(tree), data);
            }
            else
            {
                offset += dissect_app_common(next_tvb, pinfo, proto_item_get_parent(tree), data);
            }
        }
    }

    col_set_fence(pinfo->cinfo, COL_PROTOCOL);
    col_set_fence(pinfo->cinfo, COL_INFO);
    return offset;
}

static int dissect_options(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    while (offset < (gint)tvb_captured_length(tvb))
    {
        proto_tree *subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_2008_1_dsp_12_option, NULL, "Option");
        tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, -1, -1);
        gint len = dissect_2008_1_dsp_1(next_tvb, pinfo, subtree);
        proto_item_set_len(proto_tree_get_parent(subtree), len);
        offset += len;
    }

    return offset;
}

static int dissect_dsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dof_api_data *api_data = (dof_api_data *)data;
    dof_packet_data *packet_data;
    guint offset = 0;
    guint8 opcode;
    guint16 app;
    gint app_len;
    proto_item *ti;
    proto_tree *dsp_tree;
    proto_tree *options_tree;

    if (api_data == NULL)
    {
        /* TODO: Output error. */
        return 0;
    }

    packet_data = api_data->packet;
    if (packet_data == NULL)
    {
        /* TODO: Output error. */
        return 0;
    }

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DSPv2 ");

    /* Create the protocol tree. */
    offset = 0;
    ti = proto_tree_add_item(tree, proto_2008_1_dsp, tvb, offset, -1, ENC_NA);
    dsp_tree = proto_item_add_subtree(ti, ett_2008_1_dsp_12);

    /* Add the APPID. */
    offset = read_c2(tvb, offset, &app, &app_len);
    ti = proto_tree_add_uint(dsp_tree, hf_2008_1_app_version, tvb, 0, app_len, app);
    validate_c2(pinfo, ti, app, app_len);

#if 0
    if (!packet->is_streaming)
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "DSPv2 ");

        if (tvb_captured_length(tvb) == offset)
        col_set_str(pinfo->cinfo, COL_INFO, "Query");
        else
        {
            col_set_str(pinfo->cinfo, COL_INFO, "Query Response");
            while (offset < tvb_captured_length(tvb))
            {
                guint16 app;
                gint start = offset;
                offset = read_c2(tvb, offset, &app, NULL);
                proto_tree_add_uint(dsp_tree, hf_2008_1_app_version, tvb, start, offset - start, app);
            }
        }

        return offset;
    }
#endif

    if (offset == tvb_captured_length(tvb))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "DSP [nop]");
        expert_add_info(pinfo, dsp_tree, &ei_implicit_no_op);

        return offset;
    }

    /* Determine the ESP opcode. */
    opcode = tvb_get_guint8(tvb, offset);

    if (!packet_data->is_command)
        opcode |= OP_2008_1_RSP;

    proto_tree_add_uint_format(dsp_tree, hf_2008_1_dsp_12_opcode, tvb, offset, 1, opcode, "Opcode: %s (%u)", val_to_str(opcode, strings_2008_1_dsp_opcodes, "Unknown Opcode (%d)"), opcode & 0x7F);
    offset += 1;
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, "/", "%s", val_to_str(opcode, strings_2008_1_dsp_opcodes, "Unknown Opcode (%d)"));

    switch (opcode)
    {
    case OP_2008_1_OPEN_CMD: /* 2008.1 DSP.14.1 */
        break;

    case OP_2008_1_OPEN_RSP: /* 2008.1 DSP.14.2 */
    case OP_2008_1_OPEN_SECURE_RSP: /* 2008.1 DSP.14.3 */
    {
        while (offset < tvb_captured_length(tvb))
        {
            guint16 ap;
            gint length;
            proto_item *pi;
            gint start = offset;
            offset = read_c2(tvb, offset, &ap, &length);
            pi = proto_tree_add_uint(dsp_tree, hf_2008_1_app_version, tvb, start, offset - start, ap);
            validate_c2(pinfo, pi, ap, length);
        }
    }
        break;

    case OP_2008_1_QUERY_CMD:
        break;

    case OP_2008_1_QUERY_RSP:
        break;

    case OP_2008_1_CONFIG_ACK:
        break;

    case OP_2008_1_CONFIG_REQ:
        /* This will start a session if not existing... */
        /* FALL THROUGH */

    case OP_2008_1_CONFIG_NAK:
    {
        gint length = tvb_captured_length(tvb) - offset;

        options_tree = proto_tree_add_subtree_format(dsp_tree, tvb, offset, length, ett_2008_1_dsp_12_options, NULL,
                                                     "DSP Options: (%d byte%s)", length, plurality(length, "", "s"));
        offset = dissect_options(tvb, offset, pinfo, options_tree, NULL);
    }
        break;

    case OP_2008_1_CONFIG_REJ:
        /* TODO: Handle reject. */
        break;

    case OP_2008_1_TERMINATE_CMD:
    case OP_2008_1_TERMINATE_RSP:
        /* Nothing */
        break;
    }

    return offset;
}

static int dissect_ccm_dsp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    /* We are handed a buffer that starts with an option and our protocol id. Any options follow that. */
    gint offset = 0;
    proto_item *parent = proto_tree_get_parent(tree);
    guint8 len, strength_count, i;
    proto_item *ti;
    proto_tree *ccm_tree;

    /* Append description to the parent. */
    proto_item_append_text(parent, " (CCM)");

    /* Compute the version and flags, masking off other bits. */
    offset += 3; /* Skip the type and protocol. */
    len = tvb_get_guint8(tvb, offset++);

    ti = proto_tree_add_item(tree, hf_ccm_dsp_option, tvb, offset, len, ENC_NA);
    ccm_tree = proto_item_add_subtree(ti, ett_ccm_dsp_option);

    strength_count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(ccm_tree, hf_ccm_dsp_strength_count, tvb, offset++, 1, ENC_NA);

    for (i = 0; i < strength_count; i++)
        proto_tree_add_item(ccm_tree, hf_ccm_dsp_strength, tvb, offset++, 1, ENC_NA);

    proto_tree_add_item(ccm_tree, hf_ccm_dsp_e_flag, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ccm_tree, hf_ccm_dsp_m_flag, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ccm_tree, hf_ccm_dsp_tmax, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ccm_tree, hf_ccm_dsp_tmin, tvb, offset, 1, ENC_NA);

    offset += 1;
    return offset;
}

/**
 * This is the main entry point for the CCM dissector. It is always called from an DPS
 * dissector, and is always passed the dof_secmode_data structure.
 */
static int dissect_ccm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dof_secmode_api_data *secmode_api_data;
    dof_session_key_exchange_data *key_data;

    secmode_api_data = (dof_secmode_api_data *)data;
    if (secmode_api_data == NULL)
    {
        fprintf(stderr, "secmode_api_data == NULL");
        return 0;
    }

    key_data = secmode_api_data->session_key_data;

    /* Based on the context of the request, handle the work. */
    switch (secmode_api_data->context)
    {
    case INITIALIZE:
        /* Parse off the initialization fields, and if necessary create the security mode state
        * that is being initialized. This is passed the DPS data, DPS session data, and Key Exchange Data.
        */
    {
        ccm_session_data *ccm_data = (ccm_session_data *)key_data->security_mode_key_data;
        gint offset = 0;
        guint8 header;
        guint16 length;

        if (!ccm_data)
        {
            /* We need to parse the initialization data. */
            ccm_data = (ccm_session_data *)wmem_alloc0(wmem_file_scope(), sizeof(ccm_session_data));
            if (!ccm_data)
                return 0;

            key_data->security_mode_key_data = ccm_data;

            if (!key_data->security_mode_data || key_data->security_mode_data_length < 3)
                return 0;

            /* TODO: Not sure that these are all right. */
            ccm_data->protocol_id = DOF_PROTOCOL_CCM;
            ccm_data->cipher = key_data->security_mode_data[1];
            ccm_data->encrypted = key_data->security_mode_data[key_data->security_mode_data_length - 1] & 0x80;
            ccm_data->mac_len = (key_data->security_mode_data[key_data->security_mode_data_length - 1] & 0x07) * 2 + 2;
            ccm_data->client_datagram_number = 0;
            ccm_data->server_datagram_number = 0;

            switch (ccm_data->protocol_id)
            {
            case DOF_PROTOCOL_CCM:
                ccm_data->cipher_data = wmem_alloc0(wmem_file_scope(), sizeof(rijndael_ctx));
                break;

            default:
                return 0;
            }
        }

        if (secmode_api_data->dof_api->transport_session->is_2_node)
        {
            switch (ccm_data->protocol_id)
            {
            case DOF_PROTOCOL_CCM:
                rijndael_set_key((rijndael_ctx *)ccm_data->cipher_data, key_data->session_key, 256);
                break;

            default:
                return 0;
            }

            /* This mode has a fixed size, so we can return here without parsing further. */
            return 2;
        }

        offset = read_c2(tvb, offset, &length, NULL);
        /* TODO validate C2 */
        header = tvb_get_guint8(tvb, offset);
        offset += 1;

        /* Determine the period, and store the key. */
        {
            guint8 period = (header & 0x70) >> 4;
            if (ccm_data->cipher_data_table == NULL)
            {
                guint8 *ekey = (guint8 *)wmem_alloc0(wmem_file_scope(), sizeof(rijndael_ctx));

                /* TODO: This needs to be freed. */
                ccm_data->cipher_data_table = g_hash_table_new(g_direct_hash, g_direct_equal);
                ccm_data->period = 1;
                ccm_data->periods[period] = ccm_data->period;

                switch (ccm_data->protocol_id)
                {
                case DOF_PROTOCOL_CCM:
                    rijndael_set_key((rijndael_ctx *)ekey, key_data->session_key, 256);
                    break;

                default:
                    return 0;
                }

                g_hash_table_insert(ccm_data->cipher_data_table, GUINT_TO_POINTER(ccm_data->period), ekey);
            }
            else
            {
                guint32 lookup = ccm_data->periods[period];

                if (!lookup)
                {
                    guint8 *ekey = (guint8 *)wmem_alloc0(wmem_file_scope(), sizeof(rijndael_ctx));
                    switch (ccm_data->protocol_id)
                    {
                    case DOF_PROTOCOL_CCM:
                        rijndael_set_key((rijndael_ctx *)ekey, key_data->session_key, 256);
                        break;

                    default:
                        return 0;
                    }

                    ccm_data->period += 1;
                    ccm_data->periods[period] = ccm_data->period;
                    g_hash_table_insert(ccm_data->cipher_data_table, GUINT_TO_POINTER(ccm_data->period), ekey);
                }
                else
                {
                    guint8 *in_table = (guint8 *)g_hash_table_lookup(ccm_data->cipher_data_table, GUINT_TO_POINTER(lookup));
                    if (memcmp(key_data->session_key, in_table, 32) != 0)
                    {
                        guint8 *ekey = (guint8 *)wmem_alloc0(wmem_file_scope(), sizeof(rijndael_ctx));
                        switch (ccm_data->protocol_id)
                        {
                        case DOF_PROTOCOL_CCM:
                            rijndael_set_key((rijndael_ctx *)ekey, key_data->session_key, 256);
                            break;

                        default:
                            return 0;
                        }

                        ccm_data->period += 1;
                        ccm_data->periods[period] = ccm_data->period;
                        g_hash_table_insert(ccm_data->cipher_data_table, GUINT_TO_POINTER(ccm_data->period), ekey);
                    }
                }
            }
        }

        return offset + length - 1;
    }

    case HEADER:
    {
        ccm_session_data *session;
        dof_transport_session *transport_session = (dof_transport_session *)secmode_api_data->dof_api->transport_session;
        dof_secure_session_data *secure_session = secmode_api_data->secure_session;
        dof_session_key_exchange_data *security_data = NULL;
        dof_packet_data *dof_packet = secmode_api_data->dof_api->packet;
        guint8 ccm_flags;
        guint32 nid;
        guint16 slot = 0;
        guint32 pn = 0;
        gboolean pn_present = FALSE;
        guint32 tnid;
        guint32 nnid;
        proto_tree *ccm_flags_tree;
        proto_tree *header_tree;
        proto_item * item,*header;
        ccm_packet_data *pdata;
        gint offset = 0;

        if (!dof_packet->security_session)
        {
            if (transport_session->is_streaming)
            {
                /* Find the first security data that is applicable - they are in order of packet sequence. */
                security_data = secure_session->session_security_data;
                while (security_data)
                {
                    if (dof_packet->is_sent_by_initiator && (dof_packet->dof_frame > security_data->i_valid))
                        break;

                    if (!dof_packet->is_sent_by_initiator && (dof_packet->dof_frame > security_data->r_valid))
                        break;

                    security_data = security_data->next;
                }

                if (security_data)
                    dof_packet->security_session = security_data;
                else
                {
                    dof_packet->security_session_error = "[Encrypted - No Session Available]";
                    return offset;
                }
            }
            else
            {
                dof_packet->security_session = secure_session->session_security_data;
                security_data = dof_packet->security_session;
            }
        }
        else
        {
            security_data = dof_packet->security_session;
        }

        if (!security_data || !security_data->session_key || !security_data->security_mode_key_data)
        {
            dof_packet->security_session_error = "[Encrypted - No Session Available]";
            return offset;
        }

        session = (ccm_session_data *)security_data->security_mode_key_data;
        offset = secmode_api_data->security_mode_offset;

        /* Add a master header for this protocol. */
        header = proto_tree_add_protocol_format(tree, proto_ccm, tvb, offset, 0,
                                                "CCM Security Mode, Version: 1");
        header_tree = proto_item_add_subtree(header, ett_header);
        tree = header_tree;

        ccm_flags = tvb_get_guint8(tvb, offset);
        item = proto_tree_add_uint_format(tree, hf_epp_v1_ccm_flags, tvb,
                                          offset, 1, ccm_flags, "Flags: 0x%02x", ccm_flags);

        ccm_flags_tree = proto_item_add_subtree(item, ett_epp_v1_ccm_flags);
        proto_tree_add_item(ccm_flags_tree, hf_epp_v1_ccm_flags_manager, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(ccm_flags_tree, hf_epp_v1_ccm_flags_period, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(ccm_flags_tree, hf_epp_v1_ccm_flags_target, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(ccm_flags_tree, hf_epp_v1_ccm_flags_next_nid, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(ccm_flags_tree, hf_epp_v1_ccm_flags_packet, tvb, offset, 1, ENC_NA);
        offset += 1;

        if (ccm_flags & 0x01)
            pn_present = TRUE;

        pdata = (ccm_packet_data *)dof_packet->security_packet;
        if (!pdata)
        {
            pdata = (ccm_packet_data *)wmem_alloc0(wmem_file_scope(), sizeof(ccm_packet_data));
            if (pdata)
            {
                dof_packet->security_packet = pdata;

                if (transport_session->is_2_node)
                {
                    if (dof_packet->is_sent_by_initiator)
                    {
                        pdata->nid = 0;
                        if (pn_present == FALSE)
                            pdata->dn = ++session->client_datagram_number;
                        else
                            pdata->dn = pn;
                    }
                    else
                    {
                        pdata->nid = 1;
                        if (pn_present == 0)
                            pdata->dn = ++session->server_datagram_number;
                        else
                            pdata->dn = pn;
                    }
                }
                else
                {
                    guint8 packet_period = (ccm_flags & 0x70) >> 4;
                    pdata->period = session->periods[packet_period];
                }
            }
        }

        if (!pdata)
            return offset - secmode_api_data->security_mode_offset;

        if (!secure_session->is_2_node)
        {
            gint nid_len;
            proto_item *pi;
            read_c4(tvb, offset, &nid, &nid_len);
            /* TODO: Do this right, as offset from BNID. */
            nid /= 2;
            pdata->nid = nid;
            pi = proto_tree_add_uint_format(tree, hf_epp_v1_ccm_nid, tvb, offset, nid_len, nid, "Node ID: %u", nid);
            validate_c4(pinfo, pi, nid, nid_len);
            offset += nid_len;
        }
        else
        {
            item = proto_tree_add_uint_format(tree, hf_epp_v1_ccm_nid, tvb, 0, 0, pdata->nid, "Node ID: %u", pdata->nid);
            PROTO_ITEM_SET_GENERATED(item);
        }

        if (!secure_session->is_2_node)
        {
            gint slot_len;
            proto_item *pi;
            read_c2(tvb, offset, &slot, &slot_len);
            pi = proto_tree_add_uint_format(tree, hf_epp_v1_ccm_slot, tvb, offset, slot_len, slot, "Slot: %hu", slot);
            validate_c2(pinfo, pi, slot, slot_len);
            offset += slot_len;
        }
        else
        {
            item = proto_tree_add_uint_format(tree, hf_epp_v1_ccm_slot, tvb, 0, 0, 0, "Slot: %u", 0);
            PROTO_ITEM_SET_GENERATED(item);
        }

        if (ccm_flags & 0x01)
        {
            gint pn_len;
            proto_item *pi;
            read_c4(tvb, offset, &pn, &pn_len);
            pi = proto_tree_add_uint_format(tree, hf_epp_v1_ccm_pn, tvb, offset, pn_len, pn, "Packet Number: %u", pn);
            validate_c4(pinfo, pi, pn, pn_len);
            pdata->dn = pn;
            offset += pn_len;
        }
        else
        {
            item = proto_tree_add_uint_format(tree, hf_epp_v1_ccm_pn, tvb, 0, 0, pdata->dn, "Packet Number: %u", pdata->dn);
            PROTO_ITEM_SET_GENERATED(item);
        }

        if (ccm_flags & 0x08)
        {
            gint tnid_len;
            proto_item *pi;
            read_c4(tvb, offset, &tnid, &tnid_len);
            pi = proto_tree_add_uint_format(tree, hf_epp_v1_ccm_tnid, tvb, offset, tnid_len, tnid, "Target Node ID: %u", tnid);
            validate_c4(pinfo, pi, tnid, tnid_len);
            offset += tnid_len;
        }

        if (ccm_flags & 0x02)
        {
            gint nnid_len;
            proto_item *pi;
            read_c4(tvb, offset, &nnid, &nnid_len);
            pi = proto_tree_add_uint_format(tree, hf_epp_v1_ccm_nnid, tvb, offset, nnid_len, nnid, "Next Node ID: %u", nnid);
            validate_c4(pinfo, pi, nnid, nnid_len);
            offset += nnid_len;
        }

        proto_item_set_len(header, offset - secmode_api_data->security_mode_offset);

        if (dof_packet->decrypted_buffer_error)
        {
            col_set_str(pinfo->cinfo, COL_INFO, dof_packet->decrypted_buffer_error);
            expert_add_info(pinfo, tree, &ei_decode_failure);
            return offset - secmode_api_data->security_mode_offset;
        }

        /* We have reached the encryption boundary. At this point the rest of the packet
        * is encrypted, and we may or may not be able to decrypt it.
        *
        * If we can decrypt it (which for now means that it uses a Session Key of [0]
        * the we switch to decoding the decrypted PDU. Otherwise we create an entry
        * for the encrypted bytes and move on...
        */

        {
            gint e_len = tvb_captured_length(tvb) - offset;
            const guint8 *epp_buf = tvb_get_ptr(tvb, 0, -1);
            guint a_len = offset;
            guint16 e_off;
            guint8 *buf = (guint8 *)g_malloc(e_len);
            tvbuff_t *app;

            /* The default nonce is a function of whether or not this is the server
            * or the client and the packet count. The packet count either comes from
            * the PDU or is a function of the previous value (of the sending node).
            */
            guint8 nonce[] = { 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
                0x00,
                0x00, 0x00, 0x00, 0x00 };

            nonce[0] = (pdata->nid) >> 24;
            nonce[1] = (pdata->nid) >> 16;
            nonce[2] = (pdata->nid) >> 8;
            nonce[3] = (guint8)(pdata->nid);
            nonce[4] = slot >> 8;
            nonce[5] = (guint8)slot;
            nonce[7] = (pdata->dn) >> 24;
            nonce[8] = (pdata->dn) >> 16;
            nonce[9] = (pdata->dn) >> 8;
            nonce[10] = (guint8)(pdata->dn);

            /* Now the hard part. We need to determine the current packet number.
            * This is a function of the sending node, the previous state and the
            * current PDU.
            */
            for (e_off = 0; e_off < e_len; e_off++)
                buf[e_off] = tvb_get_guint8(tvb, offset + e_off);

            app = NULL;

            proto_item_set_end(tree, tvb, offset);
            if (!session->encrypted)
            {
                /* There is still a MAC involved, and even though we don't need a new
                * buffer we need to adjust the length of the existing buffer.
                */
                g_free(buf);
                app = tvb_new_subset(tvb, offset, e_len - session->mac_len, e_len - session->mac_len);
                dof_packet->decrypted_tvb = app;
                dof_packet->decrypted_offset = 0;
            }
            else
            {
                if (dof_packet->decrypted_buffer)
                {
                    /* No need to decrypt, but still need to create buffer. */
                    app = tvb_new_real_data((const guint8 *)dof_packet->decrypted_buffer, e_len - session->mac_len, e_len - session->mac_len);
                    tvb_set_child_real_data_tvbuff(tvb, app);
                    add_new_data_source(pinfo, app, "Decrypted DOF");
                    dof_packet->decrypted_tvb = app;
                    dof_packet->decrypted_offset = 0;
                }
                else
                {
                    if (decrypt(session, pdata, nonce, epp_buf, a_len, buf, e_len))
                    {
                        guint8 *cache = (guint8 *)wmem_alloc0(wmem_file_scope(), e_len - session->mac_len);
                        memcpy(cache, buf, e_len - session->mac_len);
                        app = tvb_new_real_data(cache, e_len - session->mac_len, e_len - session->mac_len);
                        tvb_set_child_real_data_tvbuff(tvb, app);
                        add_new_data_source(pinfo, app, "Decrypted DOF");
                        dof_packet->decrypted_buffer = cache;
                        dof_packet->decrypted_offset = 0;
                        dof_packet->decrypted_tvb = app;

                        g_free(buf);
                    }
                    else
                    {
                        /* Failure to decrypt or validate the MAC.
                        * The packet is secure, so there is nothing we can do!
                        */
                        dof_packet->decrypted_buffer_error = "[Encrypted packet - decryption failure]";

                        g_free(buf);
                    }
                }
            }
        }

        return offset - secmode_api_data->security_mode_offset;
    }
        break;

    case TRAILER:
       /* TODO check this case */
        break;

    }

    return 0;
}

static int dissect_ccm_app(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    guint8 opcode = 0;
    guint16 app;
    gint app_len;

    proto_item *ti;
    proto_tree *ccm_tree;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CCM ");

    /* Create the protocol tree. */
    offset = 0;
    ti = proto_tree_add_item(tree, proto_ccm_app, tvb, offset, -1, ENC_NA);
    ccm_tree = proto_item_add_subtree(ti, ett_ccm);

    /* Add the APPID. */
    offset = read_c2(tvb, offset, &app, &app_len);
    ti = proto_tree_add_uint(ccm_tree, hf_2008_1_app_version, tvb, 0, app_len, app);
    validate_c2(pinfo, ti, app, app_len);

    /* Retrieve the opcode. */
    opcode = tvb_get_guint8(tvb, offset);

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(opcode, ccm_opcode_strings, "Unknown Opcode (%d)"));

    if (tree)
    {
        /* Opcode */
        proto_tree_add_item(ccm_tree, hf_ccm_opcode, tvb, offset, 1, ENC_NA);
#if 0  /* this needs completion */
        offset += 1;

        switch (opcode)
        {
        case CCM_PDU_PROBE:
        {
        }
            break;

        }
#endif
    }

    return 1;
}

#if 0 /* TODO not used yet */
static int dissect_ccm_validate(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    dof_api_data *api_data = (dof_api_data *)data;
    dof_packet_data *packet;
    ccm_session_data *session;
    gint offset;
    guint8 ccm_flags;
    guint32 nid;
    guint16 slot;
    guint32 pn;
    guint32 tnid;

    if (api_data == NULL)
    {
        fprintf(stderr, "api_data is NULL.");
        return 0;
    }

    packet = api_data->packet;
    if (packet == NULL)
    {
        fprintf(stderr, "api_data->packet is NULL.");
        return 0;
    }

    if (!packet->security_session)
    {
        fprintf(stderr, "packet->security_session is NULL");
        return 0;
    }

    if (packet->security_session->security_mode != DOF_PROTOCOL_CCM)
    {
        fprintf(stderr, "packet->security_session->security_mode != DOF_PROTOCOL_CCM");
        return 0;
    }

    session = (ccm_session_data *)packet->security_session->security_mode_key_data;

    /* The buffer we have been passed includes the entire EPP frame. The packet
    * structure gives us the offset to our header.
    */
    offset = 0;

    ccm_flags = tvb_get_guint8(tvb, offset);
    offset += 1;

    /* TODO validate the C2 and C4 fields below? */
    if (ccm_flags & 0x04)
        offset = read_c4(tvb, offset, &nid, NULL);

    if (ccm_flags & 0x02)
        offset = read_c2(tvb, offset, &slot, NULL);

    if (ccm_flags & 0x01)
        offset = read_c4(tvb, offset, &pn, NULL);

    if (ccm_flags & 0x08)
        offset = read_c4(tvb, offset, &tnid, NULL);


    /* We have reached the encryption boundary. At this point the rest of the packet
    * is encrypted, and we may or may not be able to decrypt it.
    *
    * If we can decrypt it (which for now means that it uses a Session Key of [0]
    * the we switch to decoding the decrypted PDU. Otherwise we create an entry
    * for the encrypted bytes and move on...
    */

    {
        gint e_len = tvb_captured_length(tvb) - offset;
        const guint8 *epp_buf = tvb_get_ptr(tvb, 0, -1);
        guint a_len = offset - 0;
        guint16 e_off;
        guint8 *buf = (guint8 *)g_malloc(e_len);

        /* The default nonce is a function of whether or not this is the server
        * or the client and the packet count. The packet count either comes from
        * the PDU or is a function of the previous value (of the sending node).
        */
        guint8 nonce[] = { 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00,
            0x00,
            0x00, 0x00, 0x00, 0x00 };

        nonce[0] = nid >> 24;
        nonce[1] = nid >> 16;
        nonce[2] = nid >> 8;
        nonce[3] = (guint8)nid;
        nonce[4] = slot >> 8;
        nonce[5] = (guint8)slot;
        nonce[7] = pn >> 24;
        nonce[8] = pn >> 16;
        nonce[9] = pn >> 8;
        nonce[10] = (guint8)pn;

        /* Now the hard part. We need to determine the current packet number.
        * This is a function of the sending node, the previous state and the
        * current PDU.
        */
        for (e_off = 0; e_off < e_len; e_off++)
            buf[e_off] = tvb_get_guint8(tvb, offset + e_off);

        /* TODO: This is hardcoded for a 4-byte MAC */

        proto_item_set_end(tree, tvb, offset);
        if (decrypt(session, (ccm_packet_data *)packet->security_packet, nonce, epp_buf, a_len, buf, e_len))
        {
            g_free(buf);
            return 1;
        }
        else
        {
            /* Failure to decrypt or validate the MAC.
            * The packet is secure, so there is nothing we can do!
            */
            g_free(buf);
            return 1;
        }
    }
}
#endif

static int dissect_oap_dsp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    /* We are handed a buffer that starts with our protocol id. Any options follow that. */
    gint offset = 0;

    /* We don't care except for the treeview. */
    if (!tree)
        return 0;

    /* Compute the version and flags, masking off other bits. */
    offset += 4; /* Skip the type and protocol. */

    proto_tree_add_item(tree, hf_oap_1_dsp_option, tvb, 0, -1, ENC_NA);
    return offset;
}

static int dissect_oap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dof_api_data *api_data = (dof_api_data *)data;
    dof_packet_data *packet_data;

    gint offset = 0;
    guint8 opcode = 0;
    guint8 flags = 0;
    guint16 item_id = 0;
    guint16 app;
    guint app_len;

    oap_1_packet_data *oap_packet = NULL;

    proto_item *ti;
    proto_tree *oap_tree;

    if (api_data == NULL)
    {
        fprintf(stderr, "api_data == NULL");
        return 0;
    }

    packet_data = api_data->packet;
    if (packet_data == NULL)
    {
        fprintf(stderr, "packet_data == NULL");
        return 0;
    }


    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OAPv1 ");

    /* Create the protocol tree. */
    offset = 0;
    ti = proto_tree_add_item(tree, proto_oap_1, tvb, offset, -1, ENC_NA);
    oap_tree = proto_item_add_subtree(ti, ett_oap_1);

    /* Add the APPID. */
    offset = read_c2(tvb, offset, &app, &app_len);
    ti = proto_tree_add_uint(oap_tree, hf_2008_1_app_version, tvb, 0, app_len, app);
    validate_c2(pinfo, ti, app, app_len);

    if (app_len == tvb_captured_length(tvb))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "OAP [nop]");
        expert_add_info(pinfo, oap_tree, &ei_implicit_no_op);

        return app_len;
    }

    oap_packet = (oap_1_packet_data *)dof_packet_get_proto_data(packet_data, proto_oap_1);
    if (!oap_packet)
    {
        oap_packet = (oap_1_packet_data *)wmem_alloc0(wmem_file_scope(), sizeof(oap_1_packet_data));
        dof_packet_add_proto_data(packet_data, proto_oap_1, oap_packet);
    }

    /* Compute the version and flags, masking off other bits. */
    opcode = tvb_get_guint8(tvb, offset) & 0x1F;
    if (!packet_data->is_command)
        opcode |= OAP_1_RESPONSE;

    flags = tvb_get_guint8(tvb, offset) & 0xE0;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(opcode, oap_opcode_strings, "Unknown Opcode (%d)"));


    /* Opcode */
    {
        guint8 mask = 0x10;
        char str[20];
        guint8 no_of_bits = 5;
        guint8 i;
        guint8 bit = 3;
        g_strlcpy(str, "...", 20);

        /* read the bits for the int */
        for (i = 0; i < no_of_bits; i++)
        {
            if (bit && (!(bit % 4)))
                g_strlcat(str, " ", 20);

            bit++;

            if (opcode & mask)
                g_strlcat(str, "1", 20);
            else
                g_strlcat(str, "0", 20);

            mask = mask >> 1;
        }

        proto_tree_add_uint_format(oap_tree, hf_oap_1_opcode, tvb, offset, 1, opcode & 0x1F, "%s = Opcode: %s (%u)", str, val_to_str(opcode, oap_opcode_strings, "Unknown Opcode (%d)"), opcode & 0x1F);
    }


    /* Flags, based on opcode.
    * Each opcode needs to define the flags, however, the fall into major categories...
    */
    switch (opcode)
    {
        /* Both alias and a flag that equals command control. */
    case OAP_1_CMD_ACTIVATE:
    case OAP_1_CMD_CONNECT:
    case OAP_1_CMD_FULL_CONNECT:
    case OAP_1_CMD_GET:
    case OAP_1_CMD_INVOKE:
    case OAP_1_CMD_REGISTER:
    case OAP_1_CMD_SET:
    case OAP_1_CMD_SUBSCRIBE:
    case OAP_1_CMD_WATCH:
        proto_tree_add_item(oap_tree, hf_oap_1_alias_size, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(oap_tree, hf_oap_1_flags, tvb, offset, 1, ENC_NA);
        if (flags & 0x20)
        {
            offset += 1;
            offset = oap_1_tree_add_cmdcontrol(pinfo, oap_tree, tvb, offset);
        }
        else
            offset += 1;

        break;

        /* No alias, but flags for command control. */
    case OAP_1_CMD_ADVERTISE:
        /* TODO: Expert info on top two bits.*/
        proto_tree_add_item(oap_tree, hf_oap_1_flags, tvb, offset, 1, ENC_NA);
        if (flags & 0x20)
        {
            offset = oap_1_tree_add_cmdcontrol(pinfo, oap_tree, tvb, ENC_BIG_ENDIAN);
        }
        else
            offset += 1;

        break;

        /* No alias, but flag for provider. */
    case OAP_1_RSP_GET:
    case OAP_1_RSP_INVOKE:
    case OAP_1_RSP_REGISTER:
    case OAP_1_RSP_SET:
    case OAP_1_RSP_SUBSCRIBE:
        /* TODO: Expert info on top two bits.*/
        proto_tree_add_item(oap_tree, hf_oap_1_flags, tvb, offset, 1, ENC_NA);
        if (flags & 0x20)
        {
            offset += 1;
            offset = dof_dissect_pdu_as_field(dissect_2009_11_type_4, tvb, pinfo, oap_tree,
                                              offset, hf_oap_1_providerid, ett_oap_1_1_providerid, NULL);
        }
        else
            offset += 1;
        if ((opcode == OAP_1_RSP_GET) || (opcode == OAP_1_RSP_INVOKE))
        {
            proto_tree_add_item(oap_tree, hf_oap_1_value_list, tvb, offset, -1, ENC_NA);
            offset += tvb_reported_length_remaining(tvb, offset);
        }

        break;

        /* Alias, but no flags. */
    case OAP_1_CMD_CHANGE:
    case OAP_1_CMD_OPEN:
    case OAP_1_CMD_PROVIDE:
    case OAP_1_CMD_SIGNAL:
        proto_tree_add_item(oap_tree, hf_oap_1_alias_size, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;

        /* Special flags. */
    case OAP_1_RSP_EXCEPTION:
        proto_tree_add_item(oap_tree, hf_oap_1_exception_internal_flag, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(oap_tree, hf_oap_1_exception_final_flag, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(oap_tree, hf_oap_1_exception_provider_flag, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;

        /* No flags. */
    case OAP_1_CMD_DEFINE:
    case OAP_1_RSP_DEFINE:
    case OAP_1_RSP_OPEN:
        /* TODO: Non-zero not allowed.*/
        offset += 1;
        break;

    default:
        /* TODO: Illegal opcode.*/
        return offset;
    }

    /* Parse off arguments based on opcodes. */
    switch (opcode)
    {
    case OAP_1_CMD_SUBSCRIBE:
    {
        guint8 alias_len = (flags & 0xC0) >> 6;
        if (alias_len == 3)
            alias_len = 4;

        /* The item identifier comes first, but it is compressed. */
        {
            gint item_id_len;
            proto_item *pi;

            read_c2(tvb, offset, &item_id, &item_id_len);
            pi = proto_tree_add_uint_format(oap_tree, hf_oap_1_itemid, tvb, offset, item_id_len, item_id, "Item ID: %u", item_id);
            validate_c2(pinfo, pi, item_id, item_id_len);
            offset += item_id_len;
        }

        if (alias_len > 0)
        {
            if (api_data->session == NULL)
            {
                expert_add_info(pinfo, ti, &ei_oap_no_session);
                return offset;
            }
            offset = oap_1_tree_add_alias(api_data, oap_packet, packet_data, oap_tree, tvb, offset, alias_len, TRUE);
        }
        else
            offset = oap_1_tree_add_binding(oap_tree, pinfo, tvb, offset);

        /* Read the miniumum delta. */
        {
            gint delta_len;
            guint16 delta;
            proto_item *pi;

            read_c2(tvb, offset, &delta, &delta_len);
            pi = proto_tree_add_uint_format(oap_tree, hf_oap_1_subscription_delta, tvb, offset, delta_len, delta, "Minimum Delta: %u", delta);
            validate_c2(pinfo, pi, delta, delta_len);
            offset += delta_len;
        }
    }
        break;

    case OAP_1_CMD_REGISTER:
    {
        guint8 alias_len = (flags & 0xC0) >> 6;
        if (alias_len == 3)
            alias_len = 4;

        /* The item identifier comes first, but it is compressed. */
        {
            gint item_id_len;
            proto_item *pi;

            read_c2(tvb, offset, &item_id, &item_id_len);
            pi = proto_tree_add_uint_format(oap_tree, hf_oap_1_itemid, tvb, offset, item_id_len, item_id, "Item ID: %u", item_id);
            validate_c2(pinfo, pi, item_id, item_id_len);
            offset += item_id_len;
        }

        if (alias_len > 0)
        {
            if (api_data->session == NULL)
            {
                expert_add_info(pinfo, ti, &ei_oap_no_session);
                return offset;
            }
            offset = oap_1_tree_add_alias(api_data, oap_packet, packet_data, oap_tree, tvb, offset, alias_len, TRUE);
        }
        else
            offset = oap_1_tree_add_binding(oap_tree, pinfo, tvb, offset);
    }
        break;

    case OAP_1_RSP_REGISTER:
    {
        if (flags & 0x20)
        {
            /* offset = add_oid( tvb, offset, NULL, oap_tree ); */
        }

        /* Sequence is next. */
        proto_tree_add_item(oap_tree, hf_oap_1_update_sequence, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
        break;

    case OAP_1_CMD_WATCH:
    case OAP_1_CMD_ACTIVATE:
    case OAP_1_CMD_CONNECT:
    case OAP_1_CMD_FULL_CONNECT:
    {
        guint8 alias_len = (flags & 0xC0) >> 6;
        if (alias_len == 3)
            alias_len = 4;

        if (alias_len > 0)
        {
            if (api_data->session == NULL)
            {
                expert_add_info(pinfo, ti, &ei_oap_no_session);
                return offset;
            }
            offset = oap_1_tree_add_alias(api_data, oap_packet, packet_data, oap_tree, tvb, offset, alias_len, TRUE);
        }
        else
            offset = oap_1_tree_add_binding(oap_tree, pinfo, tvb, offset);
    }
        break;

    case OAP_1_CMD_ADVERTISE:
        offset = oap_1_tree_add_binding(oap_tree, pinfo, tvb, offset);
        break;

    case OAP_1_CMD_GET:
    case OAP_1_CMD_INVOKE:
    case OAP_1_CMD_SET:
    {
        guint8 alias_len = (flags & 0xC0) >> 6;
        if (alias_len == 3)
            alias_len = 4;

        /* The item identifier comes first, but it is compressed. */
        {
            gint item_id_len;
            proto_item *pi;

            read_c2(tvb, offset, &item_id, &item_id_len);
            pi = proto_tree_add_uint_format(oap_tree, hf_oap_1_itemid, tvb, offset, item_id_len, item_id, "Item ID: %u", item_id);
            validate_c2(pinfo, pi, item_id, item_id_len);
            offset += item_id_len;
        }

        if (alias_len > 0)
        {
            if (api_data->session == NULL)
            {
                expert_add_info(pinfo, ti, &ei_oap_no_session);
                return offset;
            }
            offset = oap_1_tree_add_alias(api_data, oap_packet, packet_data, oap_tree, tvb, offset, alias_len, TRUE);
        }
        else
            offset = oap_1_tree_add_binding(oap_tree, pinfo, tvb, offset);

        if ((opcode == OAP_1_CMD_SET) || (opcode == OAP_1_CMD_INVOKE))
        {
            proto_tree_add_item(oap_tree, hf_oap_1_value_list, tvb, offset, -1, ENC_NA);
            offset += tvb_reported_length_remaining(tvb, offset);
        }
    }
        break;

    case OAP_1_CMD_OPEN:
    {
        guint8 alias_len = (flags & 0xC0) >> 6;
        if (alias_len == 3)
            alias_len = 4;

        if (alias_len > 0)
        {
            if (api_data->session == NULL)
            {
                expert_add_info(pinfo, ti, &ei_oap_no_session);
                return offset;
            }
            offset = oap_1_tree_add_alias(api_data, oap_packet, packet_data, oap_tree, tvb, offset, alias_len, TRUE);
        }
        else
            offset = oap_1_tree_add_binding(oap_tree, pinfo, tvb, offset);

        offset = oap_1_tree_add_interface(oap_tree, tvb, offset);

        offset = dof_dissect_pdu_as_field(dissect_2009_11_type_4, tvb, pinfo, oap_tree,
                                          offset, hf_oap_1_objectid, ett_oap_1_objectid, NULL);
    }
        break;

    case OAP_1_CMD_PROVIDE:
    {
        guint8 alias_length = flags >> 6;
        gint alias_offset;
        gint iid_offset;
        gint oid_offset;

        if (alias_length == 3)
            alias_length = 4;

        alias_offset = offset;
        if (alias_length == 0)
        {
            expert_add_info_format(pinfo, ti, &ei_malformed, "alias_length == 0");
            return offset;
        }
        if (api_data->session == NULL)
        {
            expert_add_info(pinfo, ti, &ei_oap_no_session);
            return offset;
        }
        offset = oap_1_tree_add_alias(api_data, oap_packet, packet_data, oap_tree, tvb, offset, alias_length, FALSE);

        iid_offset = offset;
        offset = oap_1_tree_add_interface(oap_tree, tvb, offset);

        oid_offset = offset;
        offset = dof_dissect_pdu_as_field(dissect_2009_11_type_4, tvb, pinfo, oap_tree,
                                          offset, hf_oap_1_objectid, ett_oap_1_objectid, NULL);

        if (alias_length && !packet_data->processed)
        {
            guint32 alias;
            oap_1_binding *binding = (oap_1_binding *)wmem_alloc0(wmem_file_scope(), sizeof(oap_1_binding));
            int i;

            alias = 0;
            for (i = 0; i < alias_length; i++)
                alias = (alias << 8) | tvb_get_guint8(tvb, alias_offset + i);

            binding->iid_length = oid_offset - iid_offset;
            binding->iid = (guint8 *)wmem_alloc0(wmem_file_scope(), binding->iid_length);
            tvb_memcpy(tvb, binding->iid, iid_offset, binding->iid_length);

            binding->oid_length = offset - oid_offset;
            binding->oid = (guint8 *)wmem_alloc0(wmem_file_scope(), binding->oid_length);
            tvb_memcpy(tvb, binding->oid, oid_offset, binding->oid_length);

            binding->frame = pinfo->fd->num;
            oap_1_define_alias(api_data, alias, binding);
        }
    }
        break;

    case OAP_1_CMD_CHANGE:
    case OAP_1_CMD_SIGNAL:
    {
        guint8 alias_len = (flags & 0xC0) >> 6;
        if (alias_len == 3)
            alias_len = 4;

        /* The item identifier comes first, but it is compressed. */
        {
            gint item_id_len;
            proto_item *pi;

            read_c2(tvb, offset, &item_id, &item_id_len);
            pi = proto_tree_add_uint_format(oap_tree, hf_oap_1_itemid, tvb, offset, item_id_len, item_id, "Item ID: %u", item_id);
            validate_c2(pinfo, pi, item_id, item_id_len);
            offset += item_id_len;
        }

        if (alias_len > 0)
        {
            if (api_data->session == NULL)
            {
                expert_add_info(pinfo, ti, &ei_oap_no_session);
                return offset;
            }
            offset = oap_1_tree_add_alias(api_data, oap_packet, packet_data, oap_tree, tvb, offset, alias_len, TRUE);
        }
        else
            offset = oap_1_tree_add_binding(oap_tree, pinfo, tvb, offset);

        /* Sequence is next. */
        proto_tree_add_item(oap_tree, hf_oap_1_update_sequence, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(oap_tree, hf_oap_1_value_list, tvb, offset, -1, ENC_NA);
        offset += tvb_reported_length_remaining(tvb, offset);
    }
        break;

    case OAP_1_RSP_EXCEPTION:
    {
        if (flags & 0x20)
        {
            /* offset = add_oid( tvb, offset, NULL, oap_tree );*/
        }

        /* The response code, compressed. */
        {
            gint rsp_len;
            guint16 rsp;

            /* TODO: Validate*/
            read_c2(tvb, offset, &rsp, &rsp_len);
            /* TODO: Add to tree with error codes. */
            offset += rsp_len;
        }
        proto_tree_add_item(oap_tree, hf_oap_1_value_list, tvb, offset, -1, ENC_NA);
        offset += tvb_reported_length_remaining(tvb, offset);
    }
        break;

    default:
        /* TODO: Bad opcode!*/
        break;
    }

    return offset;
}

static int dissect_sgmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dof_api_data *api_data = (dof_api_data *)data;
    dof_packet_data *packet_data;
    guint offset = 0;
    guint8 opcode;
    guint16 app;
    gint app_len;
    proto_item *ti;
    proto_tree *sgmp_tree;

    if (api_data == NULL)
    {
        /* TODO: Output error. */
        return 0;
    }

    packet_data = api_data->packet;
    if (packet_data == NULL)
    {
        /* TODO: Output error. */
        return 0;
    }

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SGMPv1 ");

    /* Create the protocol tree. */
    offset = 0;
    ti = proto_tree_add_item(tree, proto_sgmp, tvb, offset, -1, ENC_NA);
    sgmp_tree = proto_item_add_subtree(ti, ett_sgmp);

    /* Add the APPID. */
    offset = read_c2(tvb, offset, &app, &app_len);
    ti = proto_tree_add_uint(sgmp_tree, hf_2008_1_app_version, tvb, 0, app_len, app);
    validate_c2(pinfo, ti, app, app_len);

    if (offset == tvb_captured_length(tvb))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "SGMP [nop]");
        expert_add_info(pinfo, sgmp_tree, &ei_implicit_no_op);

        return offset;
    }


    /* Retrieve the opcode. */
    opcode = tvb_get_guint8(tvb, offset);
    if (!packet_data->is_command)
        opcode |= SGMP_RESPONSE;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(opcode, sgmp_opcode_strings, "Unknown Opcode (%d)"));

    /* Opcode */
    proto_tree_add_item(sgmp_tree, hf_opcode, tvb, offset, 1, ENC_NA);
    offset += 1;

    switch (opcode)
    {
    case SGMP_CMD_EPOCH_CHANGED:
    {
        /* TMIN - 2 bytes */
        {
            proto_tree_add_item(sgmp_tree, hf_sgmp_tmin, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }

        /* EPOCH - 2 bytes */
        {
            proto_tree_add_item(sgmp_tree, hf_sgmp_epoch, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }
        break;

    case SGMP_CMD_HEARTBEAT:
    {
        gint start_offset;

        /* Latest SGMP Version - Type.1 */
        {
            guint16 version;
            gint length;
            proto_item *pi;

            start_offset = offset;
            offset = read_c2(tvb, offset, &version, &length);
            pi = proto_tree_add_uint(sgmp_tree, hf_latest_version, tvb, start_offset, offset - start_offset, version);
            validate_c2(pinfo, pi, version, length);
        }

        /* Desire - 1 byte */
        {
            proto_tree_add_item(sgmp_tree, hf_desire, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        /* Tie Breaker - 4 bytes */
        {
            proto_tree_add_item(sgmp_tree, hf_tie_breaker, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
    }
        break;

    case SGMP_CMD_REKEY:
    case SGMP_CMD_REKEY_EPOCH:
    case SGMP_CMD_REKEY_MERGE:
    {
#if 0 /*TODO check this */
        gint start_offset;
        tvbuff_t *initial_state;
#endif
        guint8 key[32];

        /* Delay - one byte */
        if (opcode != SGMP_CMD_REKEY_MERGE)
        {
            proto_tree_add_item(sgmp_tree, hf_delay, tvb, offset, 1, ENC_NA);
            offset += 1;
        }

        /* Initial State - Security.9 (not REKEY_MERGE) */
        {
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_9, tvb, pinfo, sgmp_tree,
                                              offset, hf_initial_state, ett_initial_state, NULL);
#if 0 /*TODO check this */
            initial_state = tvb_new_subset(tvb, start_offset, offset - start_offset, offset - start_offset);
#endif
        }

        /* Epoch - 2 bytes (only REKEY_EPOCH) */
        if (opcode == SGMP_CMD_REKEY_EPOCH)
        {
            proto_tree_add_item(sgmp_tree, hf_sgmp_epoch, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }

        /* Kgm - 32 bytes */
        {
            proto_tree_add_item(sgmp_tree, hf_key, tvb, offset, 32, ENC_NA);
            tvb_memcpy(tvb, key, offset, 32);
            offset += 32;
        }

        /* Handle the initialization block. */
        if (!packet_data->processed && api_data->session)
        {
            /*dof_session_data* session = (dof_session_data*)api_data->session;*/

            /* Look up the field-dissector table, and determine if it is registered. */
            dissector_table_t field_dissector = find_dissector_table("dof.secmode");
            if (field_dissector != NULL)
            {
#if 0
                dissector_handle_t field_handle = dissector_get_port_handle(field_dissector, packet_data->security_mode);
                if (field_handle != NULL)
                {
                    void *saved_private = pinfo->private_data;
                    dof_secmode_api_data setup_data;
                    gint block_length;

                    setup_data.version = DOF_API_VERSION;
                    setup_data.context = INITIALIZE;
                    setup_data.dof_api = api_data;
                    setup_data.secure_session = rekey_data->security_session;
                    /* TODO FIX THIS setup_data.session_key = session_key; */
                    pinfo->private_data = &setup_data;
                    block_length = call_dissector_only(field_handle, NULL, pinfo, NULL);
                    pinfo->private_data = saved_private;
                }
#endif
            }
        }
    }
        break;

    case SGMP_CMD_REQUEST_GROUP:
    {
        guint8 *domain_buf = NULL;
        guint8 domain_length = 0;
        gint start_offset;
        guint I_offset = offset;
        sgmp_packet_data *sgmp_data = NULL;
        guint16 epoch;

        /* START OF I BLOCK */
        /* Domain - Security.7 */
        {
            start_offset = offset;
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_7, tvb, pinfo, sgmp_tree,
                                              offset, hf_sgmp_domain, ett_sgmp_domain, NULL);
            if (!packet_data->processed)
            {
                domain_length = offset - start_offset;
                domain_buf = (guint8 *)wmem_alloc0(wmem_packet_scope(), domain_length);
                tvb_memcpy(tvb, domain_buf, start_offset, domain_length);
            }
        }

        /* Epoch - 2 bytes */
        {
            epoch = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(sgmp_tree, hf_sgmp_epoch, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }

        /* Initiator Block - SGMP.6.3 */
        {
            /* SGMP Key Request - Security.4 */
            {
                dof_2008_16_security_4 response;
                offset = dof_dissect_pdu_as_field(dissect_2008_16_security_4, tvb, pinfo, sgmp_tree,
                                                  offset, hf_initiator_block, ett_initiator_block, &response);
                if (!packet_data->processed)
                {
                    tvbuff_t *identity = response.identity;
                    guint8 identity_length = tvb_reported_length(identity);
                    guint8 *identity_buf = (guint8 *)wmem_alloc0(wmem_file_scope(), identity_length);

                    /* Get the buffer. */
                    tvb_memcpy(identity, identity_buf, 0, identity_length);

                    {
                        sgmp_data = (sgmp_packet_data *)wmem_alloc0(wmem_file_scope(), sizeof(sgmp_packet_data));
                        dof_packet_add_proto_data(packet_data, proto_sgmp, sgmp_data);

                        sgmp_data->domain_length = domain_length;
                        sgmp_data->domain = (guint8 *)wmem_alloc0(wmem_file_scope(), domain_length);
                        memcpy(sgmp_data->domain, domain_buf, domain_length);

                        sgmp_data->group_length = identity_length;
                        sgmp_data->group = (guint8 *)wmem_alloc0(wmem_file_scope(), identity_length);
                        memcpy(sgmp_data->group, identity_buf, identity_length);

                        sgmp_data->epoch = epoch;
                        sgmp_data->request_session = api_data->session;
                    }
                }
            }
        }

        /* Security Scope - Security.10 */
        {
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_10, tvb, pinfo, sgmp_tree,
                                              offset, hf_sgmp_security_scope, ett_sgmp_security_scope, NULL);
        }

        /* END OF I BLOCK */
        if (sgmp_data && !sgmp_data->I)
        {
            sgmp_data->I_length = offset - I_offset;
            sgmp_data->I = (guint8 *)wmem_alloc0(wmem_file_scope(), sgmp_data->I_length);
            tvb_memcpy(tvb, sgmp_data->I, I_offset, sgmp_data->I_length);
        }
    }
        break;

    case SGMP_RSP_REQUEST_GROUP:
    {
        gint start_offset;
#if 0 /*TODO check this */
        guint A_offset;
        tvbuff_t *initial_state;
        guint A_end;
#endif

        /* START OF A BLOCK */
        /* Initial State - SGMP.6.2.1 */
        {
         /*   A_offset = offset;*/

            /* Initial State - Security.9 */
            {
                offset = dof_dissect_pdu_as_field(dissect_2008_16_security_9, tvb, pinfo, sgmp_tree,
                                                  offset, hf_initial_state, ett_initial_state, NULL);
#if 0 /*TODO check this */
                initial_state = tvb_new_subset(tvb, start_offset, offset - start_offset, offset - start_offset);
#endif
            }

            /* Latest SGMP Version - Type.1 */
            {
                guint16 version;
                gint length;
                proto_item *pi;

                start_offset = offset;
                offset = read_c2(tvb, offset, &version, &length);
                pi = proto_tree_add_uint(sgmp_tree, hf_latest_version, tvb, start_offset, offset - start_offset, version);
                validate_c2(pinfo, pi, version, length);
            }

            /* Desire - 1 byte */
            {
                proto_tree_add_item(sgmp_tree, hf_desire, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
        }

        /* END OF A BLOCK */
        /* A block data handled in first part of the next block. */
#if 0 /*TODO check this */
        A_end = offset;
#endif

        /* Ticket - Security.5 */
        {
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_5, tvb, pinfo, sgmp_tree,
                                              offset, hf_ticket, ett_ticket, NULL);
        }

        /* Try to match up the information learned here with any groups that exist.
        * Note that we do not know the SSID, and so we can only match based on the
        * domain and group identifier. We will learn the SSID based on a successful
        * match to a secure session.
        */
        if (packet_data->opid_first && !api_data->secure_session)
        {
#if 0
            sgmp_packet_data* cmd_data = (sgmp_packet_data*)dof_packet_get_proto_data(packet_data->opid_first, proto_sgmp);
            extern struct BlockCipher BlockCipher_AES_256;
            struct BlockCipher* cipher = &BlockCipher_AES_256;
            guint8* ekey = (guint8*)ep_alloc(cipher->keyStateSize);

            if (cmd_data && !cmd_data->A)
            {
                cmd_data->A_length = A_end - A_offset;
                cmd_data->A = (guint8*)wmem_alloc0(wmem_file_scope(), cmd_data->A_length);
                tvb_memcpy(tvb, cmd_data->A, A_offset, cmd_data->A_length);
            }

            /* Search through the appropriate keks to find a match. */
            {
                dof_learned_group_data* group = globals.learned_group_data;
                struct list;
                struct list
                { dof_learned_group_data *group;
                    struct list *next; };
                struct list *to_try = NULL;
                guint8 confirmation[32];
                guint8* discovered_kek = NULL;
                dof_learned_group_auth_data *auth = NULL;

                tvb_memcpy(tvb, confirmation, start_offset, 32);

                while (group)
                {
                    if ((cmd_data->domain_length == group->domain_length) &&
                        (memcmp(cmd_data->domain, group->domain, group->domain_length) == 0) &&
                        (cmd_data->group_length == group->group_length) &&
                        (memcmp(cmd_data->group, group->group, group->group_length) == 0))
                    {
                        struct list *n = (struct list *) ep_alloc0(sizeof(struct list));
                        n->group = group;
                        n->next = to_try;
                        to_try = n;
                    }

                    group = group->next;
                }

                /* At this point we may be able to learn the session key. */
                while (to_try && !discovered_kek)
                {
                    group = to_try->group;

                    auth = group->keys;

                    while (auth && !discovered_kek)
                    {
                        guint8 mac[32];
                        guint8 key[32];
                        int j;

                        /* It only makes sense to check matching epochs. */
                        if (auth->epoch == cmd_data->epoch)
                        {
                            tvb_memcpy(tvb, mac, start_offset, 32);
                            tvb_memcpy(tvb, key, start_offset + 32, 32);

                            if (cipher != NULL)
                            {
                                cipher->GenerateKeyState(ekey, auth->kek);
                                cipher->Encrypt(ekey, mac);
                                cipher->Encrypt(ekey, mac + 16);
                            }

                            for (j = 0; j < 32; j++)
                            key[j] ^= mac[j];

                            if (sgmp_validate_session_key(cmd_data, confirmation, auth->kek, key))
                            {
                                discovered_kek = (guint8*)se_alloc0(32);
                                memcpy(discovered_kek, key, 32);
                                break;
                            }
                        }

                        auth = auth->next;
                    }

                    to_try = to_try->next;
                }

                /* Determine if there is already a secure session for this information. If there is, then
                * EPP will find it to decode any packets. If there is not, then we must create a secure
                * session and initialize it so that future packets can be decoded.
                * NOTE: None of the actual decoding is done here, because this packet is not encrypted
                * in the session that it defines.
                * NOTE: SGMP secure sessions are always attached to the DPS session, which is always
                * associated with the transport session (server address).
                */
                if (discovered_kek)
                {
                    dissector_table_t field_dissector;
                    dissector_handle_t field_handle;
                    dof_session_key_exchange_data *key_exchange = NULL;

                    dof_secure_session_data *dof_secure_session = cmd_data->request_session->secure_sessions;
                    while (dof_secure_session)
                    {
                        if ((dof_secure_session->ssid == group->ssid) &&
                            (dof_secure_session->domain_length == group->domain_length) &&
                            (memcmp(dof_secure_session->domain, group->domain, group->domain_length) == 0))
                        break;

                        dof_secure_session = dof_secure_session->next;
                    }

                    if (!dof_secure_session)
                    {
                        dof_session_data *dof_session = wmem_alloc0(wmem_file_scope(), sizeof(dof_session_data));
                        dof_session->session_id = globals.next_session++;
                        dof_session->dof_id = api_data->session->dof_id;

                        dof_secure_session = wmem_alloc0(wmem_file_scope(), sizeof(dof_secure_session_data));
                        dof_secure_session->ssid = group->ssid;
                        dof_secure_session->domain_length = group->domain_length;
                        dof_secure_session->domain = group->domain;
                        dof_secure_session->original_session_id = cmd_data->request_session->session_id;
                        dof_secure_session->parent = dof_session;
                        dof_secure_session->is_2_node = FALSE;
                        dof_secure_session->next = cmd_data->request_session->secure_sessions;
                        cmd_data->request_session->secure_sessions = dof_secure_session;
                    }

                    /* This packet represents a new key exchange, and so a new key exchange data
                    * structure needs to be created.
                    */
                    {
                        key_exchange = wmem_alloc0(wmem_file_scope(), sizeof(dof_session_key_exchange_data));
                        if (!key_exchange)
                        return offset;

                        key_exchange->i_valid = packet_data->opid_first->dof_frame;
                        key_exchange->r_valid = packet_data->dof_frame;
                        key_exchange->security_mode = auth->security_mode;
                        key_exchange->security_mode_data = auth->mode;
                        key_exchange->security_mode_data_length = auth->mode_length;
                        key_exchange->session_key = discovered_kek;

                        /* Insert the new key information at the front of the list. */
                        if (!dof_secure_session->session_security_data_last)
                        dof_secure_session->session_security_data = key_exchange;
                        else
                        dof_secure_session->session_security_data_last->next = key_exchange;

                        dof_secure_session->session_security_data_last = key_exchange;
                    }

                    /* Look up the field-dissector table, and determine if it is registered. */
                    field_dissector = find_dissector_table("dps.secmode");
                    if (field_dissector != NULL)
                    {
                        field_handle = dissector_get_uint_handle(field_dissector, auth->security_mode);
                        if (field_handle != NULL)
                        {
                            dof_secmode_api_data setup_data;
                            gint block_length;
                            tvbuff_t *ntvb = tvb_new_subset(tvb, A_offset, -1, -1);

                            setup_data.context = INITIALIZE;
                            setup_data.security_mode_offset = 0;
                            setup_data.dof_api = api_data;
                            setup_data.secure_session = dof_secure_session;
                            setup_data.session_key_data = key_exchange;
                            block_length = call_dissector_only(field_handle, ntvb, pinfo, tree, &setup_data);
                        }
                    }
                }
            }
#endif
        }
    }
        break;

    default:
        break;
    }

    return offset;
}

#ifdef LIBGCRYPT_OK
static gboolean validate_session_key(tep_rekey_data *rekey, guint S_length, guint8 *S, guint8 *confirmation, guint8 *key)
{
    guint8 pad[16];
    gcry_mac_hd_t hmac;
    gcry_error_t result;

    memset(pad, 0, sizeof(pad));
    result = gcry_mac_open(&hmac, GCRY_MAC_HMAC_SHA256, 0, NULL);
    if (result != 0)
        return FALSE;

    gcry_mac_setkey(hmac, key, 32);
    gcry_mac_write(hmac, pad, 16 - rekey->i_nonce_length);
    gcry_mac_write(hmac, rekey->i_nonce, rekey->i_nonce_length);
    gcry_mac_write(hmac, pad, 16 - rekey->r_nonce_length);
    gcry_mac_write(hmac, rekey->r_nonce, rekey->r_nonce_length);
    gcry_mac_write(hmac, S, S_length);
    gcry_mac_write(hmac, rekey->r_identity, rekey->r_identity_length);
    result = gcry_mac_verify(hmac, confirmation, 32);
    return result == 0;
}
#else
static gboolean validate_session_key(tep_rekey_data *rekey _U_, guint S_length _U_, guint8 *S _U_, guint8 *confirmation _U_, guint8 *key _U_)
{
   return FALSE;
}
#endif

static int dissect_tep_dsp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    /* We are handed a buffer that starts with our protocol id. Any options follow that. */
    gint offset = 0;

    /* We don't care except for the treeview. */
    if (!tree)
        return 0;

    /* Compute the version and flags, masking off other bits. */
    offset += 4; /* Skip the type and protocol. */

    proto_tree_add_item(tree, hf_dsp_option, tvb, 0, -1, ENC_NA);
    return offset;
}

static int dissect_2008_4_tep_2_2_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 *ssid, void *data)
{
    gint offset = 0;
    proto_item *ti;
    dof_api_data *api_data = (dof_api_data *)data;
    dof_packet_data *packet_data;

    if (api_data == NULL)
    {
        /* TODO: Output error. */
        return 0;
    }

    packet_data = api_data->packet;
    if (packet_data == NULL)
    {
        /* TODO: Output error. */
        return 0;
    }

    /* State Identifier - Only if Unsecured */
    if (packet_data->decrypted_buffer == NULL)
    {
        proto_item *pi;
        gint ssid_len;
        gint start = offset;
        offset = read_c4(tvb, offset, ssid, &ssid_len);
        pi = proto_tree_add_uint(tree, hf_tep_2_2_1_state_identifier, tvb, start, offset - start, *ssid);
        validate_c4(pinfo, pi, *ssid, ssid_len);
    }

    /* Initial State */
    {
        int block_length;
        tvbuff_t *start = tvb_new_subset(tvb, offset, -1, -1);
        ti = proto_tree_add_item(tree, hf_tep_2_2_1_initial_state, tvb, offset, 0, ENC_NA);
        ti = proto_item_add_subtree(ti, ett_tep_2_2_1_initial_state);
        block_length = dof_dissect_pdu(dissect_2008_16_security_9, start, pinfo, ti, NULL);
        proto_item_set_len(ti, block_length);
        offset += block_length;
    }

    return offset;
}

/**
 * This is the main entry point for the CCM dissector.
 * TEP operations create security periods.
 * They can also create sessions when used with "None" sessions.
 * In any case, these PDUs need to pass information between
 * them.
 * They also must maintain state for each rekey request, some of
 * which modify the session key, some of which create new
 * sessions, and others that determine new session information
 * like permission sets.
 *
 * In order to store information appropriately, the following structures are
 * used:
 *   1. api_data (dof_api_data*) source for all other state.
 *   2. packet (dof_packet_data*) dps packet information.
 *   3. rekey_data (tep_rekey_data*) tep information for rekey/accept/confirm.
 */
static int dissect_tep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dof_api_data *api_data = (dof_api_data *)data;
    dof_packet_data *packet;
    tep_rekey_data *rekey_data;

    guint offset = 0;
    guint8 operation;
    guint16 app;
    gint app_len;
    proto_item *ti;
    proto_tree *tep_tree, *operation_tree;

    if (api_data == NULL)
    {
        /* TODO: Output error. */
        return 0;
    }

    packet = api_data->packet;
    if (packet == NULL)
    {
        /* TODO: Output error. */
        return 0;
    }

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TEPv1 ");

    /* Create the protocol tree. */
    offset = 0;
    ti = proto_tree_add_item(tree, proto_tep, tvb, offset, -1, ENC_NA);
    tep_tree = proto_item_add_subtree(ti, ett_tep);

    /* Add the APPID. */
    offset = read_c2(tvb, offset, &app, &app_len);
    ti = proto_tree_add_uint(tep_tree, hf_2008_1_app_version, tvb, 0, app_len, app);
    validate_c2(pinfo,ti, app, app_len);

    /* Check for empty packet. */
    if (offset == tvb_captured_length(tvb))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "TEP [nop]");
        expert_add_info(pinfo, tep_tree, &ei_implicit_no_op);

        return offset;
    }

    /* Retrieve the opcode. */
    operation = tvb_get_guint8(tvb, offset);
    if (!packet->is_command)
        operation |= TEP_OPCODE_RSP;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(operation, tep_opcode_strings, "Unknown Opcode (%d)"));

    ti = proto_tree_add_uint_format(tep_tree, hf_tep_operation, tvb, offset, 1, operation, "Operation: %s (%u)", val_to_str(operation, tep_opcode_strings, "Unknown Opcode (%d)"), operation);

    operation_tree = proto_item_add_subtree(ti, ett_tep_operation);
    ti = proto_tree_add_boolean(operation_tree, hf_tep_operation_type, tvb, offset, 0, operation);
    PROTO_ITEM_SET_GENERATED(ti);

    /* The flags are reserved except for OPCODE=1 & COMMAND */
    if ((operation & 0x8F) == 0x01)
    {
        proto_tree_add_item(operation_tree, hf_tep_c, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(operation_tree, hf_tep_k, tvb, offset, 1, ENC_NA);
    }

    proto_tree_add_item(operation_tree, hf_tep_opcode, tvb, offset, 1, ENC_NA);
    offset += 1;

    switch (operation)
    {
    case TEP_PDU_REQUEST_KEY:
        /* The K bit must be set, so there is a domain ONLY IF NOT SECURED. */

        /* Remember the current request. */
        rekey_data = (tep_rekey_data *)packet->opid_data;
        if (!rekey_data)
        {
            packet->opid_data = rekey_data = (tep_rekey_data *)wmem_alloc0(wmem_file_scope(), sizeof(tep_rekey_data));
        }

        rekey_data->key_data = (dof_session_key_exchange_data *)wmem_alloc0(wmem_file_scope(), sizeof(dof_session_key_exchange_data));
        rekey_data->is_rekey = TRUE;

        /* The K bit must be set, so there is a domain ONLY IF NOT SECURED. */
        if (packet->decrypted_buffer == NULL)
        {
            gint start_offset = offset;

            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_7, tvb, pinfo, tep_tree,
                                              offset, hf_tep_2_1_domain, ett_tep_2_1_domain, NULL);

            if (!rekey_data->domain)
            {
                rekey_data->domain_length = offset - start_offset;
                rekey_data->domain = (guint8 *)wmem_alloc0(wmem_file_scope(), rekey_data->domain_length);

                /* Get the buffer. */
                tvb_memcpy(tvb, rekey_data->domain, start_offset, rekey_data->domain_length);
            }
        }
        else
        {
            /* The domain is not present, but this is a secure packet and so the domain can be obtained
            * through the session.
            */
            if (!rekey_data->domain)
            {
                rekey_data->domain_length = api_data->secure_session->domain_length;
                rekey_data->domain = api_data->secure_session->domain;
            }
        }

        /* FALL THROUGH TO REQUEST */

    case TEP_PDU_REQUEST:

        /* Remember the current request. */
        rekey_data = (tep_rekey_data *)packet->opid_data;
        if (!rekey_data)
        {
            if (api_data->secure_session == NULL)
            {
                /* TODO: Output error. */
                return 0;
            }
            packet->opid_data = rekey_data = (tep_rekey_data *)wmem_alloc0(wmem_file_scope(), sizeof(tep_rekey_data));
            rekey_data->domain_length = api_data->secure_session->domain_length;
            rekey_data->domain = api_data->secure_session->domain;
        }

        /* The C bit must be clear, so there is an Initiator Block. */
        {
            dof_2008_16_security_6_1 response;
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_6_1, tvb, pinfo, tep_tree,
                                              offset, hf_tep_2_1_initiator_block, ett_tep_2_1_initiator_block, &response);
            if (!packet->processed)
            {
                tvbuff_t *inonce = response.i_nonce;
                tvbuff_t *iidentity = response.i_identity;

                rekey_data->i_nonce_length = tvb_reported_length(inonce);
                rekey_data->i_nonce = (guint8 *)wmem_alloc0(wmem_file_scope(), rekey_data->i_nonce_length);
                tvb_memcpy(inonce, rekey_data->i_nonce, 0, rekey_data->i_nonce_length);

                rekey_data->i_identity_length = tvb_reported_length(iidentity);
                rekey_data->i_identity = (guint8 *)wmem_alloc0(wmem_file_scope(), rekey_data->i_identity_length);
                tvb_memcpy(iidentity, rekey_data->i_identity, 0, rekey_data->i_identity_length);

                rekey_data->security_mode = response.security_mode;
                rekey_data->security_mode_data_length = response.security_mode_data_length;
                rekey_data->security_mode_data = response.security_mode_data;
            }
        }
        break;

    case TEP_PDU_ACCEPT:
    {
        guint32 ssid = 0;
        guint8 *S = NULL;
        guint8 S_length = 0;
        guint8 confirmation[32];
        typedef struct identity_key
        {
            guint8 *session_key;
            struct identity_key *next;
        } identity_key;
        identity_key *identity_key_list = NULL;
        dof_secure_session_data *dof_secure_session = NULL;

        if (!packet->opid_first)
        {
            /* TODO: Print error */
            return 0;
        }

        rekey_data = (tep_rekey_data *)packet->opid_first->opid_data;
        if (!rekey_data)
            return tvb_captured_length(tvb);

        /* Initiator Ticket */
        {
            gint start_offset;
            guint8 ticket[64];

            start_offset = offset;
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_5, tvb, pinfo, tep_tree,
                                              offset, hf_tep_2_2_initiator_ticket, ett_tep_2_2_initiator_ticket, NULL);

            if (!packet->processed && rekey_data)
            {
                rijndael_ctx cipher_state;
                int i;

                /* Produce a (possibly empty) list of potential keys based on our
                * initiator secrets based on identity. These will be validated
                * later on.
                */
                for (i = 0; i < globals.global_security->identity_data_count; i++)
                {
                    dof_identity_data *identity = globals.global_security->identity_data + i;
                    int j;

                    if (identity->domain_length != rekey_data->domain_length)
                        continue;
                    if (memcmp(identity->domain, rekey_data->domain, identity->domain_length) != 0)
                        continue;
                    if (identity->identity_length != rekey_data->i_identity_length)
                        continue;
                    if (memcmp(identity->identity, rekey_data->i_identity, identity->identity_length) != 0)
                        continue;

                    tvb_memcpy(tvb, ticket, start_offset, 64);

                    rijndael_set_key(&cipher_state, identity->secret, 256);
                    encryptInPlace(DOF_PROTOCOL_TEP, &cipher_state, ticket, 16);
                    encryptInPlace(DOF_PROTOCOL_TEP, &cipher_state, ticket + 16, 16);

                    for (j = 0; j < 32; j++)
                        ticket[j + 32] = ticket[j + 32] ^ ticket[j];

                    /* Add the key to the list - ep memory. */
                    {
                        identity_key *key = (identity_key *)wmem_alloc0(wmem_file_scope(), sizeof(*key));
                        key->session_key = (guint8 *)wmem_alloc0(wmem_file_scope(), 32);
                        memcpy(key->session_key, ticket + 32, 32);
                        key->next = identity_key_list;
                        identity_key_list = key;
                    }
                }
            }
        }

        /* Ticket Confirmation */
        {
            if (!packet->processed)
                tvb_memcpy(tvb, confirmation, offset, sizeof(confirmation));
            proto_tree_add_item(tep_tree, hf_tep_2_2_ticket_confirmation, tvb, offset, 32, ENC_NA);
            offset += 32;
        }

        /* Add a field to show the session key that has been learned. */
        if (rekey_data->key_data && rekey_data->key_data->session_key && tep_tree)
        {
            const gchar *SID = bytestring_to_str(NULL, rekey_data->key_data->session_key, 32, ':');
            ti = proto_tree_add_bytes_format_value(tree, hf_tep_session_key, tvb, 0, 0, rekey_data->key_data->session_key, "%s", SID);
            PROTO_ITEM_SET_GENERATED(ti);
        }

        /* Responder Initialization - present based on whether the command was a rekey */
        {

            if (rekey_data && rekey_data->is_rekey)
            {
                int block_length;
                tvbuff_t *start = tvb_new_subset(tvb, offset, -1, -1);
                ti = proto_tree_add_item(tep_tree, hf_tep_2_2_responder_initialization, tvb, offset, 0, ENC_NA);
                ti = proto_item_add_subtree(ti, ett_tep_2_2_responder_initialization);
                block_length = dissect_2008_4_tep_2_2_1(start, pinfo, ti, &ssid, data);
                proto_item_set_len(ti, block_length);
                offset += block_length;

                if (!packet->processed)
                {
                    S_length = block_length;
                    S = (guint8 *)wmem_alloc0(wmem_file_scope(), S_length);
                    tvb_memcpy(start, S, 0, S_length);
                }

                /* TEP can create new sessions when not used inside an existing secure
                * session. Each session can use an SSID, present in TEP.2.2.1.
                * Note that in this case there may be no existing session, and so
                * we need to "backpedal" and create one.
                */
                if (packet->decrypted_buffer == NULL && !packet->processed)
                {
#if 0
                    if (api_data->session)
                    tep_session = (tep_session_data*)dof_session_get_proto_data((dof_session_data*)api_data->session, proto_tep);
                    if (!tep_session && api_data->session)
                    {
                        tep_session = (tep_session_data*)se_alloc0(sizeof(*tep_session));
                        dof_session_add_proto_data((dof_session_data*)api_data->session, proto_tep, tep_session);
                    }

                    tep_session->pending_rekey = cmd;
                    tep_session->pending_confirm = packet;
#endif
                }
            }
        }

        /* Responder Block */
        {
            dof_2008_16_security_6_2 response;
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_6_2, tvb, pinfo, tep_tree,
                                              offset, hf_tep_2_2_responder_block, ett_tep_2_2_responder_block, &response);
            if (!packet->processed)
            {
                tvbuff_t *rnonce = response.r_nonce;
                tvbuff_t *ridentity = response.r_identity;

                rekey_data->r_nonce_length = tvb_reported_length(rnonce);
                rekey_data->r_nonce = (guint8 *)wmem_alloc0(wmem_file_scope(), rekey_data->r_nonce_length);
                tvb_memcpy(rnonce, rekey_data->r_nonce, 0, rekey_data->r_nonce_length);

                rekey_data->r_identity_length = tvb_reported_length(ridentity);
                rekey_data->r_identity = (guint8 *)wmem_alloc0(wmem_file_scope(), rekey_data->r_identity_length);
                tvb_memcpy(ridentity, rekey_data->r_identity, 0, rekey_data->r_identity_length);
            }
        }

        /* Authentication Initialization */
        {
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_6_3, tvb, pinfo, tep_tree,
                                              offset, hf_tep_2_2_authenticator_initialization, ett_tep_2_2_authenticator_initialization, NULL);
        }


        /* The request was accepted, and so a new secure session exists. We define the session,
        * add it to the list of secure sessions for the unsecure session, and EPP will do the
        * rest.
        */
        if (packet->decrypted_buffer == NULL)
        {
            /* This triggers the creation of the corresponding secure DPS session if it is not already
            * created. This allows information to be stored in that session even though no packets
            * have used it yet. There is a problem, however, because at this point we do not know
            * the SSID that (may) be associated with this session.
            */
            {
                dof_session_data *dof_session = api_data->session;

                dof_secure_session = dof_session->secure_sessions;
                while (dof_secure_session != NULL)
                {
                    /* Determine matching session. The session list already is scoped by transport and DPS
                    * session, so the only thing remaining is the domain and secure session ID.
                    */
                    if ((dof_secure_session->ssid == ssid) &&
                        (dof_secure_session->domain_length == rekey_data->domain_length) &&
                        (memcmp(dof_secure_session->domain, rekey_data->domain, rekey_data->domain_length) == 0))
                        break;

                    dof_secure_session = dof_secure_session->next;
                }

                if (!dof_secure_session)
                {
                    dof_session = (dof_session_data *)wmem_alloc0(wmem_file_scope(), sizeof(dof_session_data));
                    dof_session->session_id = globals.next_session++;
                    dof_session->dof_id = api_data->session->dof_id;

                    dof_secure_session = (dof_secure_session_data *)wmem_alloc0(wmem_file_scope(), sizeof(dof_secure_session_data));
                    dof_secure_session->ssid = ssid;
                    dof_secure_session->domain_length = rekey_data->domain_length;
                    dof_secure_session->domain = rekey_data->domain;
                    dof_secure_session->original_session_id = api_data->session->session_id;
                    dof_secure_session->parent = dof_session;
                    dof_secure_session->is_2_node = TRUE;
                    dof_secure_session->next = api_data->session->secure_sessions;
                    api_data->session->secure_sessions = dof_secure_session;

                    if (!dof_secure_session->session_security_data_last)
                        dof_secure_session->session_security_data = rekey_data->key_data;
                    else
                        dof_secure_session->session_security_data_last->next = rekey_data->key_data;

                    dof_secure_session->session_security_data_last = rekey_data->key_data;
                }
            }
        }

        /* This PDU indicates the beginning of security for the responder. The next PDU
        * sent will be encrypted with these settings. This means that we must determine
        * the security settings and set them in the session.
        */
        if (!packet->processed && rekey_data->is_rekey)
        {
            int i;
            guint8 *session_key = NULL;

            /* We have everything that we need. Determine the session secret if we can. */

            /* Check any keys determined above by initiator identity. */
            while (session_key == NULL && identity_key_list)
            {
                if (validate_session_key(rekey_data, S_length, S, confirmation, identity_key_list->session_key))
                {
                    session_key = (guint8 *)wmem_alloc0(wmem_file_scope(), 32);
                    memcpy(session_key, identity_key_list->session_key, 32);
                }

                identity_key_list = identity_key_list->next;
            }

            /* For each key in the global configuration, see if we can validate the confirmation. */
            for (i = 0; session_key == NULL && i < globals.global_security->session_key_count; i++)
            {
                if (validate_session_key(rekey_data, S_length, S, confirmation, globals.global_security->session_key[i].session_key))
                    session_key = globals.global_security->session_key[i].session_key;
            }


            /* Whether or not this can be decrypted, the security mode infomation
            * should be kept with the session.
            */
            {
                rekey_data->key_data->r_valid = packet->dof_frame;
                rekey_data->key_data->i_valid = G_MAXUINT32;
                rekey_data->key_data->session_key = session_key;
                rekey_data->key_data->security_mode = rekey_data->security_mode;
                rekey_data->key_data->security_mode_data_length = rekey_data->security_mode_data_length;
                rekey_data->key_data->security_mode_data = rekey_data->security_mode_data;

                if (session_key && dof_secure_session)
                {
                    /* Look up the field-dissector table, and determine if it is registered. */
                    dissector_table_t field_dissector = find_dissector_table("dof.secmode");
                    if (field_dissector != NULL)
                    {
                        dissector_handle_t field_handle = dissector_get_uint_handle(field_dissector, rekey_data->key_data->security_mode);
                        if (field_handle != NULL)
                        {
                            dof_secmode_api_data setup_data;

                            setup_data.context = INITIALIZE;
                            setup_data.security_mode_offset = 0;
                            setup_data.dof_api = api_data;
                            setup_data.secure_session = dof_secure_session;
                            setup_data.session_key_data = rekey_data->key_data;

                            call_dissector_only(field_handle, NULL, pinfo, NULL, &setup_data);
                        }
                    }
                }
            }
        }
    }
        break;

    case TEP_PDU_CONFIRM:
    {
        /* C is set, K is clear. */
        /* Ticket Confirmation */
        proto_tree_add_item(tep_tree, hf_tep_2_1_ticket_confirmation, tvb, offset, 32, ENC_NA);
        offset += 32;

        if (!packet->processed && api_data->session && packet->opid_first && packet->opid_first->opid_data)
        {
            dof_session_key_exchange_data *sk_data;

            rekey_data = (tep_rekey_data *)packet->opid_first->opid_data;
            sk_data = rekey_data->key_data;

            /* TODO: Error if not found or if already set. */
            if (sk_data)
                sk_data->i_valid = packet->dof_frame;
        }
    }
        break;

    case TEP_PDU_END_SESSION:
    case TEP_PDU_SESSION_ENDING:
        break;

    case TEP_PDU_REJECT:
    {
        /* Error Code */
        proto_tree_add_item(tep_tree, hf_tep_reject_code, tvb, offset, 1, ENC_NA);
        offset += 1;

        /* Error Description */
        if (tvb_captured_length(tvb) > offset)
            proto_tree_add_item(tep_tree, hf_tep_reject_data, tvb, offset, -1, ENC_NA);
    }
        break;

    default:
        break;
    }
    return offset;
}

static int dissect_trp_dsp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    /* We are handed a buffer that starts with our protocol id. Any options follow that. */
    gint offset = 0;

    /* We don't care except for the treeview. */
    if (!tree)
        return 0;

    /* Compute the version and flags, masking off other bits. */
    offset += 4; /* Skip the type and protocol. */

    proto_tree_add_item(tree, hf_trp_dsp_option, tvb, 0, -1, ENC_NA);
    return offset;
}

static int dissect_trp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dof_api_data *api_data = (dof_api_data *)data;
    dof_packet_data *packet_data;
    guint offset = 0;
    guint8 opcode;
    guint16 app;
    gint app_len;
    proto_item *ti;
    proto_tree *trp_tree;
    trp_packet_data *trp_data;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TRP ");

    /* Create the protocol tree. */
    offset = 0;
    ti = proto_tree_add_item(tree, proto_trp, tvb, offset, -1, ENC_NA);
    trp_tree = proto_item_add_subtree(ti, ett_trp);

    /* Add the APPID. */
    offset = read_c2(tvb, offset, &app, &app_len);
    ti = proto_tree_add_uint(trp_tree, hf_2008_1_app_version, tvb, 0, app_len, app);
    validate_c2(pinfo, ti, app, app_len);

    if (api_data == NULL)
    {
        expert_add_info_format(pinfo, ti, &ei_malformed, "api_data == NULL");
        return offset;
    }

    packet_data = api_data->packet;
    if (packet_data == NULL)
    {
        expert_add_info_format(pinfo, ti, &ei_malformed, "api_data == NULL");
        return offset;
    }

    trp_data = (trp_packet_data *)dof_packet_get_proto_data(packet_data, proto_trp);

    if (offset == tvb_captured_length(tvb))
    {
        col_append_str(pinfo->cinfo, COL_INFO, "TRP [nop]");
        expert_add_info(pinfo, trp_tree, &ei_implicit_no_op);

        return offset;
    }

    /* Retrieve the opcode. */
    opcode = tvb_get_guint8(tvb, offset);
    if (!packet_data->is_command)
        opcode |= TRP_RESPONSE;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(opcode, trp_opcode_strings, "Unknown Opcode (%d)"));

    /* Opcode */
    ti = proto_tree_add_uint_format(trp_tree, hf_trp_opcode, tvb, offset, 1, opcode & 0x7F, "Opcode: %s (%u)", val_to_str(opcode, trp_opcode_strings, "Unknown Opcode (%d)"), opcode & 0x7F);
    offset += 1;

    switch (opcode)
    {
    case TRP_RSP_REJECT:
    {
        /* Error Code */
        proto_tree_add_item(trp_tree, hf_trp_errorcode, tvb, offset, 1, ENC_NA);
        offset += 1;
    }
        break;

    case TRP_CMD_REQUEST_KEK:
    {
        guint8 *domain_buf = NULL;
        guint8 domain_length = 0;
        gint start_offset;

        if (trp_data && trp_data->identity_length)
        {
            expert_add_info(pinfo, ti, &ei_trp_initiator_id_known);
        }

        /* Domain - Security.7 */
        start_offset = offset;
        offset = dof_dissect_pdu_as_field(dissect_2008_16_security_7, tvb, pinfo, trp_tree, offset, hf_domain, ett_domain, NULL);
        if (!packet_data->processed)
        {
            domain_length = offset - start_offset;
            domain_buf = (guint8 *)wmem_alloc0(wmem_file_scope(), domain_length);
            tvb_memcpy(tvb, domain_buf, start_offset, domain_length);
        }

        /* Initiator Block - TRP.4.1.1 */
        {
            dof_2008_16_security_4 response;
            trp_packet_data *trp_pkt_data = NULL;

            start_offset = offset;

            /* Initiator Key Request - Security.4 */
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_4, tvb, pinfo, trp_tree,
                                              offset, hf_initiator_request, ett_initiator_request, &response);
            if (!packet_data->processed)
            {
                tvbuff_t *identity = response.identity;
                guint8 identity_length = tvb_reported_length(identity);
                guint8 *identity_buf = (guint8 *)wmem_alloc0(wmem_packet_scope(), identity_length);
                int i;

                /* Get the buffer. */
                tvb_memcpy(identity, identity_buf, 0, identity_length);

                /* Check to see if there is a matching identity. */
                for (i = 0; i < globals.global_security->identity_data_count; i++)
                {
                    dof_identity_data *gidentity = globals.global_security->identity_data + i;

                    if (domain_length != gidentity->domain_length ||
                        memcmp(domain_buf, gidentity->domain, domain_length) != 0)
                        continue;

                    if (identity_length == gidentity->identity_length &&
                        memcmp(identity_buf, gidentity->identity, identity_length) == 0)
                    {
                        trp_pkt_data = (trp_packet_data *)wmem_alloc0(wmem_file_scope(), sizeof(trp_packet_data));
                        dof_packet_add_proto_data(packet_data, proto_trp, trp_pkt_data);

                        trp_pkt_data->domain_length = domain_length;
                        trp_pkt_data->domain = (guint8 *)wmem_alloc0(wmem_file_scope(), domain_length);
                        memcpy(trp_pkt_data->domain, domain_buf, domain_length);

                        trp_pkt_data->identity_length = identity_length;
                        trp_pkt_data->identity = (guint8 *)wmem_alloc0(wmem_file_scope(), identity_length);
                        memcpy(trp_pkt_data->identity, identity_buf, identity_length);

                        trp_pkt_data->secret = gidentity->secret;
                    }
                }
            }

            /* Group Identifier - Security.8 */
            {
                gint gid_start = offset;
                offset = dof_dissect_pdu_as_field(dissect_2008_16_security_8, tvb, pinfo, trp_tree,
                                                  offset, hf_group_identifier, ett_group_identifier, NULL);

                if (trp_pkt_data)
                {
                    trp_pkt_data->group_length = offset - gid_start;
                    trp_pkt_data->group = (guint8 *)wmem_alloc0(wmem_file_scope(), trp_pkt_data->group_length);
                    tvb_memcpy(tvb, trp_pkt_data->group, gid_start, trp_pkt_data->group_length);
                }
            }

            if (trp_pkt_data)
            {
                /* We need to store the entire block_I for later use. */
                trp_pkt_data->block_I_length = offset - start_offset;
                trp_pkt_data->block_I = (guint8 *)wmem_alloc0(wmem_file_scope(), trp_pkt_data->block_I_length);
                tvb_memcpy(tvb, trp_pkt_data->block_I, start_offset, trp_pkt_data->block_I_length);
            }
        }
    }
        break;

    case TRP_RSP_REQUEST_KEK:
    {
        gint start_offset;
        guint32 ssid;
        guint8 *mode;
        guint8 mode_length;
        guint8 *block_A;
        guint8 block_A_length;

        if (trp_data && trp_data->kek_known)
        {
            expert_add_info(pinfo, ti, &ei_trp_kek_discovered);
        }

        /* Initiator Ticket - Security.5 */
        offset = dof_dissect_pdu_as_field(dissect_2008_16_security_5, tvb, pinfo, trp_tree,
                                          offset, hf_initiator_ticket, ett_initiator_ticket, NULL);

        /* Initialization Block - TRP.4.2.1 */
        /* A BLOCK */
        {
            start_offset = offset;

            /* THB */
            {
                proto_tree_add_item(trp_tree, hf_thb, tvb, offset, 1, ENC_NA);
                offset += 1;
            }

            /* TMIN */
            {
                proto_tree_add_item(trp_tree, hf_tmin, tvb, offset, 1, ENC_NA);
                offset += 1;
            }

            /* TMAX */
            {
                proto_tree_add_item(trp_tree, hf_tmax, tvb, offset, 1, ENC_NA);
                offset += 1;
            }

            /* Epoch */
            {
                proto_tree_add_item(trp_tree, hf_trp_epoch, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }

            /* SIDg - Type.4 */
            {
                offset = dof_dissect_pdu_as_field(dissect_2009_11_type_4, tvb, pinfo, trp_tree,
                                                  offset, hf_sidg, ett_sidg, NULL);
            }

            /* Initiator Node Security Scope - Security.10 */
            {
                offset = dof_dissect_pdu_as_field(dissect_2008_16_security_10, tvb, pinfo, trp_tree,
                                                  offset, hf_security_scope, ett_security_scope, NULL);
            }

            /* Security Mode - Security.13 */
            {
                gint mode_start = offset;
                offset = dof_dissect_pdu_as_field(dissect_2008_16_security_13, tvb, pinfo, trp_tree,
                                                  offset, hf_security_mode, ett_security_mode, NULL);
                if (!packet_data->processed)
                {
                    mode_length = offset - mode_start;
                    mode = (guint8 *)wmem_alloc0(wmem_packet_scope(), mode_length);
                    tvb_memcpy(tvb, mode, mode_start, mode_length);
                }
            }

            /* State Identifier - Type.3 */
            {
                gint s_offset = offset;
                gint ssid_len;
                proto_item *pi;
                offset = read_c4(tvb, offset, &ssid, &ssid_len);
                ssid |= AS_ASSIGNED_SSID;   /* TRP SSID are *always* assigned by the AS. */
                pi = proto_tree_add_uint_format(trp_tree, hf_ssid, tvb, s_offset, offset - s_offset, ssid, "SSID: %u", ssid);
                validate_c4(pinfo, pi, ssid, ssid_len);
            }

            /* PG - Security.2 */
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_2, tvb, pinfo, trp_tree,
                                              offset, hf_responder_pg, ett_responder_pg, NULL);

            /* Group Validation - Security.11 */
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_11, tvb, pinfo, trp_tree,
                                              offset, hf_responder_validation, ett_responder_validation, NULL);

            /* Initiator Validation - Security.11 */
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_11, tvb, pinfo, trp_tree,
                                              offset, hf_initiator_validation, ett_initiator_validation, NULL);

            block_A_length = offset - start_offset;
            block_A = (guint8 *)wmem_alloc0(wmem_packet_scope(), block_A_length);
            tvb_memcpy(tvb, block_A, start_offset, block_A_length);
        }

        /* Determine the KEK, if possible. This requires that either the initiator node's secret
        * is known or that the group has been configured. In either case this requires knowledge
        * from the matching command, including the domain, identity, and group information.
        */
        if (packet_data->opid_first && !packet_data->processed)
        {
#if 0
            trp_packet_data* cmd_data = (trp_packet_data*)dof_packet_get_proto_data(packet_data->opid_first, proto_trp);
            guint8 mac[32];
            extern struct BlockCipher BlockCipher_AES_256;
            struct BlockCipher* cipher = &BlockCipher_AES_256;
            guint8* ekey = (guint8*)ep_alloc(cipher->keyStateSize);

            int i;

            if (cmd_data)
            {
                guint8 kek[32];

                tvb_memcpy(tvb, mac, mac_offset, 32);
                tvb_memcpy(tvb, kek, mac_offset + 32, 32);

                if (cipher != NULL)
                {
                    cipher->GenerateKeyState(ekey, cmd_data->secret);
                    cipher->Encrypt(ekey, mac);
                    cipher->Encrypt(ekey, mac + 16);
                }

                for (i = 0; i < 32; i++)
                kek[i] ^= mac[i];

                {
                    OALSecureHMACContext ctx;
                    OALSecureHMACDigest digest;

                    OALSecureHMAC_Start(&ctx, cmd_data->secret);
                    OALSecureHMAC_Digest(&ctx, cmd_data->domain_length, cmd_data->domain);
                    OALSecureHMAC_Digest(&ctx, cmd_data->block_I_length, cmd_data->block_I);
                    OALSecureHMAC_Digest(&ctx, block_A_length, block_A);
                    OALSecureHMAC_Digest(&ctx, 32, kek);
                    OALSecureHMAC_Finish(&ctx, digest);

                    tvb_memcpy(tvb, mac, mac_offset, 32);
                    if (memcmp(mac, digest, 32) == 0)
                    {
                        dof_learned_group_data* group = globals.learned_group_data;
                        dof_learned_group_auth_data *auth = NULL;

                        /* The KEK has been discovered, flag this for output on the PDU. */
                        if (!trp_data)
                        {
                            trp_data = wmem_alloc0(wmem_file_scope(), sizeof(trp_packet_data));
                            dof_packet_add_proto_data(packet_data, proto_trp, trp_data);
                        }

                        trp_data->kek_known = TRUE;

                        while (group)
                        {
                            if ((cmd_data->domain_length == group->domain_length) &&
                                (memcmp(cmd_data->domain, group->domain, group->domain_length) == 0) &&
                                (cmd_data->group_length == group->group_length) &&
                                (memcmp(cmd_data->group, group->group, group->group_length) == 0) &&
                                (ssid == group->ssid))
                            break;

                            group = group->next;
                        }

                        if (group == NULL)
                        {
                            group = wmem_alloc0(wmem_file_scope, sizeof(dof_learned_group_data));
                            group->domain_length = cmd_data->domain_length;
                            group->domain = cmd_data->domain;
                            group->group_length = cmd_data->group_length;
                            group->group = cmd_data->group;
                            group->ssid = ssid;
                            group->next = globals.learned_group_data;
                            globals.learned_group_data = group;
                        }

                        auth = group->keys;

                        while (auth)
                        {
                            if (epoch == auth->epoch)
                            break;

                            auth = auth->next;
                        }

                        if (auth == NULL)
                        {
                            auth = wmem_alloc0(wmem_file_scope(), sizeof(dof_learned_group_auth_data));
                            auth->epoch = epoch;
                            auth->next = group->keys;
                            group->keys = auth;

                            auth->kek = (guint8*)wmem_alloc0(wmem_file_scope(), 32);
                            memcpy(auth->kek, kek, 32);

                            auth->mode_length = mode_length;
                            auth->mode = (guint8*)wmem_alloc0(wmem_file_scope(), mode_length);
                            memcpy(auth->mode, mode, mode_length);

                            auth->security_mode = (mode[1] * 256) | mode[2];
                            auth->parent = group;
                        }
                    }
                }
            }
#endif
        }
    }
        break;

    case TRP_CMD_REQUEST_RANDOM:
    {
        guint8 *domain_buf = NULL;
        guint8 domain_length = 0;
        gint start_offset;

        if (trp_data && trp_data->identity_length)
        {
            expert_add_info(pinfo, ti, &ei_trp_initiator_id_known);
        }

        /* Domain - Security.7 */
        start_offset = offset;
        offset = dof_dissect_pdu_as_field(dissect_2008_16_security_7, tvb, pinfo, trp_tree,
                                          offset, hf_domain, ett_domain, NULL);
        if (!packet_data->processed)
        {
            domain_length = offset - start_offset;
            domain_buf = (guint8 *)wmem_alloc0(wmem_packet_scope(), domain_length);
            tvb_memcpy(tvb, domain_buf, start_offset, domain_length);
        }

        /* Initiator Block - TRP.6.1.1 */
        {
            dof_2008_16_security_4 response;
            trp_packet_data *trp_pkt_data = NULL;

            start_offset = offset;

            /* Initiator Key Request - Security.4 */
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_4, tvb, pinfo, trp_tree,
                                              offset, hf_initiator_request, ett_initiator_request, &response);
            if (!packet_data->processed)
            {
                tvbuff_t *identity = response.identity;
                guint8 identity_length = tvb_reported_length(identity);
                guint8 *identity_buf = (guint8 *)wmem_alloc0(wmem_packet_scope(), identity_length);
                int i;

                /* Get the buffer. */
                tvb_memcpy(identity, identity_buf, 0, identity_length);

                /* Check to see if there is a matching identity. */
                for (i = 0; i < globals.global_security->identity_data_count; i++)
                {
                    dof_identity_data *gidentity = globals.global_security->identity_data + i;

                    if (domain_length != gidentity->domain_length ||
                        memcmp(domain_buf, gidentity->domain, domain_length) != 0)
                        continue;

                    if (identity_length == gidentity->identity_length &&
                        memcmp(identity_buf, gidentity->identity, identity_length) == 0)
                    {
                        trp_pkt_data = (trp_packet_data *)wmem_alloc0(wmem_file_scope(), sizeof(trp_packet_data));
                        dof_packet_add_proto_data(packet_data, proto_trp, trp_pkt_data);

                        trp_pkt_data->domain_length = domain_length;
                        trp_pkt_data->domain = (guint8 *)wmem_alloc0(wmem_file_scope(), domain_length);
                        memcpy(trp_pkt_data->domain, domain_buf, domain_length);

                        trp_pkt_data->identity_length = identity_length;
                        trp_pkt_data->identity = (guint8 *)wmem_alloc0(wmem_file_scope(), identity_length);
                        memcpy(trp_pkt_data->identity, identity_buf, identity_length);

                        trp_pkt_data->secret = gidentity->secret;
                    }
                }
            }

            if (trp_pkt_data)
            {
                /* We need to store the entire block_I for later use. */
                trp_pkt_data->block_I_length = offset - start_offset;
                trp_pkt_data->block_I = (guint8 *)wmem_alloc0(wmem_file_scope(), trp_pkt_data->block_I_length);
                tvb_memcpy(tvb, trp_pkt_data->block_I, start_offset, trp_pkt_data->block_I_length);
            }
        }
    }
        break;

    case TRP_RSP_REQUEST_RANDOM:
    {
        /* Initiator Ticket - Security.5 */
        offset = dof_dissect_pdu_as_field(dissect_2008_16_security_5, tvb, pinfo, trp_tree,
                                          offset, hf_initiator_ticket, ett_initiator_ticket, NULL);
    }
        break;

    case TRP_CMD_REQUEST_SECURITY_SCOPES:
    {
        guint8 *domain_buf = NULL;
        guint8 domain_length = 0;
        gint start_offset;

        if (trp_data && trp_data->identity_length)
        {
            expert_add_info(pinfo, ti, &ei_trp_initiator_id_known);
        }

        /* Domain - Security.7 */
        start_offset = offset;
        offset = dof_dissect_pdu_as_field(dissect_2008_16_security_7, tvb, pinfo, trp_tree,
                                          offset, hf_domain, ett_domain, NULL);
        if (!packet_data->processed)
        {
            domain_length = offset - start_offset;
            domain_buf = (guint8 *)wmem_alloc0(wmem_packet_scope(), domain_length);
            tvb_memcpy(tvb, domain_buf, start_offset, domain_length);
        }

        /* Initiator Block - TRP.5.1.1 */
        {
            dof_2008_16_security_4 response;
            trp_packet_data *trp_pk_data = NULL;

            start_offset = offset;

            /* Initiator Duration Request */
            proto_tree_add_item(trp_tree, hf_trp_duration, tvb, offset, 1, ENC_NA);
            offset += 1;

            /* Initiator Key Request - Security.4 */
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_4, tvb, pinfo, trp_tree,
                                              offset, hf_initiator_request, ett_initiator_request, &response);
            if (!packet_data->processed)
            {
                tvbuff_t *identity = response.identity;
                guint8 identity_length = tvb_reported_length(identity);
                guint8 *identity_buf = (guint8 *)wmem_alloc0(wmem_packet_scope(), identity_length);
                int i;

                /* Get the buffer. */
                tvb_memcpy(identity, identity_buf, 0, identity_length);

                /* Check to see if there is a matching identity. */
                for (i = 0; i < globals.global_security->identity_data_count; i++)
                {
                    dof_identity_data *gidentity = globals.global_security->identity_data + i;

                    if (domain_length != gidentity->domain_length ||
                        memcmp(domain_buf, gidentity->domain, domain_length) != 0)
                        continue;

                    if (identity_length == gidentity->identity_length &&
                        memcmp(identity_buf, gidentity->identity, identity_length) == 0)
                    {
                        trp_pk_data = (trp_packet_data *)wmem_alloc0(wmem_file_scope(), sizeof(trp_packet_data));
                        dof_packet_add_proto_data(packet_data, proto_trp, trp_pk_data);

                        trp_pk_data->domain_length = domain_length;
                        trp_pk_data->domain = (guint8 *)wmem_alloc0(wmem_file_scope(), domain_length);
                        memcpy(trp_pk_data->domain, domain_buf, domain_length);

                        trp_pk_data->identity_length = identity_length;
                        trp_pk_data->identity = (guint8 *)wmem_alloc0(wmem_file_scope(), identity_length);
                        memcpy(trp_pk_data->identity, identity_buf, identity_length);

                        trp_pk_data->secret = gidentity->secret;
                    }
                }
            }

            /* Node - Security.8 */
            {
                gint gid_start = offset;
                offset = dof_dissect_pdu_as_field(dissect_2008_16_security_8, tvb, pinfo, trp_tree,
                                                  offset, hf_node_identifier, ett_node_identifier, NULL);

                if (trp_pk_data)
                {
                    trp_pk_data->group_length = offset - gid_start;
                    trp_pk_data->group = (guint8 *)wmem_alloc0(wmem_file_scope(), trp_pk_data->group_length);
                    tvb_memcpy(tvb, trp_pk_data->group, gid_start, trp_pk_data->group_length);
                }
            }

            if (trp_pk_data)
            {
                /* We need to store the entire block_I for later use. */
                trp_pk_data->block_I_length = offset - start_offset;
                trp_pk_data->block_I = (guint8 *)wmem_alloc0(wmem_file_scope(), trp_pk_data->block_I_length);
                tvb_memcpy(tvb, trp_pk_data->block_I, start_offset, trp_pk_data->block_I_length);
            }
        }
    }
        break;

    case TRP_RSP_REQUEST_SECURITY_SCOPES:
    {
        gint start_offset;
        guint8 *block_A;
        guint8 block_A_length;

        /* Initiator Ticket - Security.5 */
        offset = dof_dissect_pdu_as_field(dissect_2008_16_security_5, tvb, pinfo, trp_tree,
                                          offset, hf_initiator_ticket, ett_initiator_ticket, NULL);

        /* Initialization Block - TRP.5.2.1 */
        /* A BLOCK */
        {
            start_offset = offset;

            /* Initiator Duration Request */
            proto_tree_add_item(trp_tree, hf_trp_duration, tvb, offset, 1, ENC_NA);
            offset += 1;

            /* Initiator Node Security Scope - Security.10 */
            {
                offset = dof_dissect_pdu_as_field(dissect_2008_16_security_10, tvb, pinfo, trp_tree,
                                                  offset, hf_security_scope, ett_security_scope, NULL);
            }

            /* Validation - Security.11 */
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_11, tvb, pinfo, trp_tree,
                                              offset, hf_initiator_validation, ett_initiator_validation, NULL);

            block_A_length = offset - start_offset;
            block_A = (guint8 *)wmem_alloc0(wmem_packet_scope(), block_A_length);
            tvb_memcpy(tvb, block_A, start_offset, block_A_length);
        }
    }
        break;

    case TRP_CMD_RESOLVE_CREDENTIAL:
    {
        guint8 *domain_buf = NULL;
        guint8 domain_length = 0;
        gint start_offset;

        /* Domain - Security.7 */
        start_offset = offset;
        offset = dof_dissect_pdu_as_field(dissect_2008_16_security_7, tvb, pinfo, trp_tree,
                                          offset, hf_domain, ett_domain, NULL);
        if (!packet_data->processed)
        {
            domain_length = offset - start_offset;
            domain_buf = (guint8 *)wmem_alloc0(wmem_packet_scope(), domain_length);
            tvb_memcpy(tvb, domain_buf, start_offset, domain_length);
        }

        /* Identity Resolution - Security.3.2 */
        offset = dof_dissect_pdu_as_field(dissect_2008_16_security_3_2, tvb, pinfo, trp_tree,
                                          offset, hf_identity_resolution, ett_identity_resolution, NULL);
    }
        break;

    case TRP_RSP_RESOLVE_CREDENTIAL:
    {
        /* Identity Resolution - Security.3.2 */
        offset = dof_dissect_pdu_as_field(dissect_2008_16_security_3_2, tvb, pinfo, trp_tree,
                                          offset, hf_identity_resolution, ett_identity_resolution, NULL);
    }
        break;

    case TRP_CMD_REQUEST_SESSION:
    {
        guint8 *domain_buf = NULL;
        guint8 domain_length = 0;
        gint start_offset;

        if (trp_data && trp_data->identity_length)
        {
            expert_add_info(pinfo, ti, &ei_trp_initiator_id_known);
        }

        /* Domain - Security.7 */
        start_offset = offset;
        offset = dof_dissect_pdu_as_field(dissect_2008_16_security_7, tvb, pinfo, trp_tree,
                                          offset, hf_domain, ett_domain, NULL);
        if (!packet_data->processed)
        {
            domain_length = offset - start_offset;
            domain_buf = (guint8 *)wmem_alloc0(wmem_packet_scope(), domain_length);
            tvb_memcpy(tvb, domain_buf, start_offset, domain_length);
        }

        /* Responder Block - Security.6.2 */
        offset = dof_dissect_pdu_as_field(dissect_2008_16_security_6_2, tvb, pinfo, trp_tree,
                                          offset, hf_responder_request, ett_responder_request, NULL);

        /* Initiator Block - Security.6.1 */
        offset = dof_dissect_pdu_as_field(dissect_2008_16_security_6_1, tvb, pinfo, trp_tree,
                                          offset, hf_initiator_request, ett_initiator_request, NULL);
    }
        break;

    case TRP_RSP_REQUEST_SESSION:
    {
        gint start_offset;
        guint8 *block_A;
        guint8 block_A_length;

        /* Responder Ticket - Security.5 */
        offset = dof_dissect_pdu_as_field(dissect_2008_16_security_5, tvb, pinfo, trp_tree,
                                          offset, hf_responder_ticket, ett_responder_ticket, NULL);

        /* Initiator Ticket - Security.5 */
        offset = dof_dissect_pdu_as_field(dissect_2008_16_security_5, tvb, pinfo, trp_tree,
                                          offset, hf_initiator_ticket, ett_initiator_ticket, NULL);


        /* Initialization Block - Security.6.3 */
        /* A BLOCK */
        {
            start_offset = offset;

            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_6_3, tvb, pinfo, trp_tree,
                                              offset, hf_authentication_block, ett_authentication_block, NULL);

            block_A_length = offset - start_offset;
            block_A = (guint8 *)wmem_alloc0(wmem_packet_scope(), block_A_length);
            tvb_memcpy(tvb, block_A, start_offset, block_A_length);
        }
    }
        break;

    case TRP_CMD_VALIDATE_CREDENTIAL:
        {
            tvbuff_t *data_tvb;

            /* Domain - Security.7 */
            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_7, tvb, pinfo, trp_tree,
                                              offset, hf_domain, ett_domain, NULL);

            offset = dof_dissect_pdu_as_field(dissect_2008_16_security_3_1, tvb, pinfo, trp_tree,
                                              offset, hf_identity_resolution, ett_identity_resolution, NULL);
            data_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(undissected_data_handle, data_tvb, pinfo, trp_tree);
        }
        break;

    case TRP_RSP_VALIDATE_CREDENTIAL:
    {
        tvbuff_t *data_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(undissected_data_handle, data_tvb, pinfo, trp_tree);
    }
       break;
    }

    return offset;
}

/* Initialize Core Tunnel Functionality */
static void dof_tun_register(void)
{
    static hf_register_info hf[] =
    {
        { &hf_2012_1_tunnel_1_version,
            { "Version", "dof.2012_1.tunnel_1.version", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_2012_1_tunnel_1_length,
            { "Length", "dof.2012_1.tunnel_1.length", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_2012_1_tunnel,
    };

    proto_2012_1_tunnel = proto_register_protocol(TUNNEL_PROTOCOL_STACK, "DTPS", "dtps");
    proto_register_field_array(proto_2008_1_app, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector(TUNNEL_PROTOCOL_STACK, dissect_tunnel_common, proto_2012_1_tunnel);
    dof_tun_app_dissectors = register_dissector_table("dof.tunnel.app", "DOF Tunnel Version", proto_2012_1_tunnel, FT_UINT8, BASE_DEC);
}

static void dof_tun_reset(void)
{
}

static void dof_tun_cleanup(void)
{
}

/* The registration hand-off routine */
static void dof_tun_handoff(void)
{
    static dissector_handle_t tcp_handle;

    register_dissector(TUNNEL_APPLICATION_PROTOCOL, dissect_tun_app_common, proto_2008_1_app);

    tcp_handle = create_dissector_handle(dissect_tunnel_tcp, proto_2012_1_tunnel);

    dissector_add_uint("tcp.port", DOF_TUN_NON_SEC_TCP_PORT, tcp_handle);
}

/* Main DOF Registration Support */

static void dof_reset(void)
{
    globals.next_session = 1;
    globals.next_transport_session = 1;
    globals.dof_packet_head = globals.dof_packet_tail = NULL;
    globals.global_security = &global_security;
    globals.learned_group_data = NULL;
    globals.decrypt_all_packets = decrypt_all_packets;
    globals.track_operations = track_operations;
    globals.track_operations_window = track_operations_window;

    init_addr_port_tables();

    /* Reset the packet counter. */
    next_dof_frame = 1;

    /* Load the template values for different groups. */
    {
        secmode_field_t *list = secmode_list;
        guint i;

        global_security.group_data = g_new0(dof_group_data, num_secmode_list);
        global_security.group_data_count = num_secmode_list;
        for (i = 0; i < num_secmode_list; i++)
        {
            guint8 kek_len;
            dof_group_data *group_data = global_security.group_data + i;
            parse_hex_string(list[i].domain, &(group_data->domain), &(group_data->domain_length));
            parse_hex_string(list[i].identity, &(group_data->identity), &(group_data->identity_length));
            parse_hex_string(list[i].kek, &(group_data->kek), &kek_len);
        }
    }

    /* Load the template values for different secrets. */
    {
        seckey_field_t *list = seckey_list;
        guint i;

        /* Clear existing. */
        for (i = 0; i < global_security.session_key_count; i++)
        {
            dof_session_key_data *session_data = &global_security.session_key[i];
            g_free(session_data->session_key);
        }

        g_free(global_security.session_key);
        global_security.session_key = NULL;
        global_security.session_key_count = 0;

        global_security.session_key = g_new0(dof_session_key_data, num_seckey_list);
        global_security.session_key_count = num_seckey_list;
        for (i = 0; i < num_seckey_list; i++)
        {
            guint8 key_len;
            dof_session_key_data *session_data = global_security.session_key + i;
            parse_hex_string(list[i].key, &(session_data->session_key), &key_len);
        }
    }

    /* Load the template values for different identities. */
    {
        identsecret_field_t *list = identsecret_list;
        guint i;

        /* Clear existing. */
        for (i = 0; i < global_security.identity_data_count; i++)
        {
            dof_identity_data *identity_data = &global_security.identity_data[i];
            g_free(identity_data->domain);
            g_free(identity_data->identity);
            g_free(identity_data->secret);
        }

        g_free(global_security.identity_data);
        global_security.identity_data = NULL;
        global_security.identity_data_count = 0;

        global_security.identity_data = g_new0(dof_identity_data, num_identsecret_list);
        global_security.identity_data_count = num_identsecret_list;
        for (i = 0; i < num_identsecret_list; i++)
        {
            guint8 key_len;
            guint32 size;

            dof_identity_data *identity_data = global_security.identity_data + i;
            if (VALIDHEX(list[i].domain[0]))
            {
                parse_hex_string(list[i].domain, &(identity_data->domain), &(identity_data->domain_length));
            }
            else
            {
                size = (guint32)strlen(list[i].domain);
                dof_oid_new_standard_string(list[i].domain, &size, &(identity_data->domain));
                identity_data->domain_length = size;
            }

            if (VALIDHEX(list[i].identity[0]))
            {
                parse_hex_string(list[i].identity, &(identity_data->identity), &(identity_data->identity_length));
            }
            else
            {
                size = (guint32)strlen(list[i].identity);
                dof_oid_new_standard_string(list[i].identity, &size, &(identity_data->identity));
                identity_data->identity_length = size;
            }

            parse_hex_string(list[i].secret, &(identity_data->secret), &key_len);
        }
    }
}

static void dof_cleanup(void)
{
    guint i;

    /* Clear existing. */
    for (i = 0; i < global_security.group_data_count; i++)
    {
        dof_group_data *group_data = &global_security.group_data[i];
        g_free(group_data->domain);
        g_free(group_data->identity);
        g_free(group_data->kek);
    }

    g_free(global_security.group_data);
    global_security.group_data = NULL;
    global_security.group_data_count = 0;

}

/**
 * Initialize Core DPS Functionality
 */
static void dof_register(void)
{
    static hf_register_info hf[] =
    {
        { &hf_security_1_permission_type,
            { "Permission Type", "dof.2008.16.security.1.desired-duration", FT_UINT16, BASE_DEC, VALS(dof_2008_16_permission_type), 0, NULL, HFILL } },

        { &hf_security_1_length,
            { "Length", "dof.2008.16.security.1.length", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },

        { &hf_security_1_data,
            { "Data", "dof.2008.16.security.1.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Security.2 */
        { &hf_security_2_count,
            { "Count", "dof.2008.16.security.2.count", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },

        { &hf_security_2_permission,
            { "Permission", "dof.2008.16.security.2.permission", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Security.3.1 */
        { &hf_security_3_1_credential_type,
            { "Credential Type", "dof.2008.16.security.3.1.credential_type", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },

        { &hf_security_3_1_stage,
            { "Stage", "dof.2008.16.security.3.1.stage", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },

        { &hf_security_3_1_security_node_identifier,
            { "Security Node Identifier", "dof.2008.16.security.3.1.security_node_identifier", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Security 3.2 */
        { &hf_security_3_2_credential_type,
            { "Credential Type", "dof.2008.16.security.3.2.credential_type", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },

        { &hf_security_3_2_stage,
            { "Stage", "dof.2008.16.security.3.2.stage", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },

        { &hf_security_3_2_length,
            { "Length", "dof.2008.16.security.3.2.length", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },

        { &hf_security_3_2_public_data,
            { "Public Data", "dof.2008.16.security.3.2.public_data", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Security.4 */
        { &hf_security_4_l,
            { "L", "dof.2008.16.security.4.l", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL } },

        { &hf_security_4_f,
            { "F", "dof.2008.16.security.4.f", FT_UINT8, BASE_DEC, NULL, 0x40, NULL, HFILL } },

        { &hf_security_4_ln,
            { "Ln", "dof.2008.16.security.4.ln", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL } },

        { &hf_security_4_identity,
            { "Identity", "dof.2008.16.security.4.identity", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_security_4_nonce,
            { "Nonce", "dof.2008.16.security.4.nonce", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_security_4_permission_set,
            { "Permission Set", "dof.2008.16.security.4.permission_set", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Security.5 */
        { &hf_security_5_mac,
            { "MAC", "dof.2008.16.security.5.mac", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_security_5_key,
            { "KEY", "dof.2008.16.security.5.key", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Security.6.1 */
        { &hf_security_6_1_desired_duration,
            { "Desired Duration", "dof.2008.16.security.6.1.desired_duration", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },

        { &hf_security_6_1_desired_security_mode,
            { "Desired Security Mode", "dof.2008.16.security.6.1.desired_security_mode", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_security_6_1_initiator_request,
            { "Initiator Request", "dof.2008.16.security.6.1.initiator_request", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Security.6.2 */
        { &hf_security_6_2_responder_request,
            { "Responder Request", "dof.2008.16.security.6.2.responder_request", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Security.6.3 */
        { &hf_security_6_3_granted_duration,
            { "Granted Duration", "dof.2008.16.security.6.3.granted_duration", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },

        { &hf_security_6_3_session_security_scope,
            { "Session Security Scope", "dof.2008.16.security.6.3.session_security_scope", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_security_6_3_initiator_validation,
            { "Initiator Validation", "dof.2008.16.security.6.3.initiator_validation", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_security_6_3_responder_validation,
            { "Responder Validation", "dof.2008.16.security.6.3.responder_validation", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Security.9 */
        { &hf_security_9_length,
            { "Length", "dof.2008.16.security.9.length", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },

        { &hf_security_9_initial_state,
            { "Initial State", "dof.2008.16.security.9.initial_state", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Security.10 */
        { &hf_security_10_count,
            { "Count", "dof.2008.16.security.10.count", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL } },

        { &hf_security_10_permission_group_identifier,
            { "Permission Group Identifier", "dof.2008.16.security.10.permission_group_identifier", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },

        /* Security.11 */
        { &hf_security_11_count,
            { "Count", "dof.2008.16.security.11.count", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },

        { &hf_security_11_permission_security_scope,
            { "Permission Security Scope", "dof.2008.16.security.11.permission_security_scope", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },

        /* Security.12 */
        { &hf_security_12_m,
            { "M", "dof.2008.16.security.12.m", FT_UINT8, BASE_DEC, VALS(dof_2008_16_security_12_m), 0xC0, NULL, HFILL } },

        { &hf_security_12_count,
            { "Count", "dof.2008.16.security.12.count", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL } },

        { &hf_security_12_permission_group_identifier,
            { "Permission Group Identifier", "dof.2008.16.security.12.permission_group_identifier", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },

        { &hf_2008_1_dof_session_transport,
            { "Transport Session", "dof.transport_session", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_2008_1_dof_session,
            { "DPS Session", "dof.session", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_2008_1_dof_frame,
            { "DPS Frame", "dof.frame", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_2008_1_dof_is_2_node,
            { "DPS Is 2 Node", "dof.is_2_node", FT_BOOLEAN, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_2008_1_dof_is_streaming,
            { "DPS Is Streaming", "dof.is_streaming", FT_BOOLEAN, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_2008_1_dof_is_from_client,
            { "DPS Is From Client", "dof.is_from_client", FT_BOOLEAN, BASE_DEC, NULL, 0x00, NULL, HFILL }
        }
    };

    static gint *ett[] = {
        /* Security.2 */
        &ett_security_2_permission,
        &ett_security_3_1_security_node_identifier,

        /* Security.11 */
        &ett_security_11_permission_security_scope,

        &ett_security_6_1_desired_security_mode,
        &ett_security_6_1_initiator_request,

        &ett_security_6_2_responder_request,
        &ett_security_6_3_session_security_scope,
        &ett_security_6_3_initiator_validation,
        &ett_security_6_3_responder_validation,

        &ett_security_4_identity,
        &ett_security_4_permission_set,

        &ett_2008_1_dof,
    };

    static ei_register_info ei[] =
    {
#if 0
        { &ei_undecoded, { "dof.undecoded", PI_UNDECODED, PI_WARN, "DOF: Some protocol octets were not decoded", EXPFILL } },
#endif
        { &ei_malformed, { "dof.malformed", PI_MALFORMED, PI_ERROR, "Malformed:", EXPFILL } },
        { &ei_implicit_no_op, { "dof.implicit_no_op", PI_PROTOCOL, PI_COMMENT, "Implicit No-op", EXPFILL } },
        { &ei_c2_c3_c4_format, { "dof.c2_c3_c4_format", PI_MALFORMED, PI_WARN, "DOF: Cx IE format", EXPFILL } },
        { &ei_security_3_1_invalid_stage, { "dof.security.3.1.invalid_stage", PI_MALFORMED, PI_ERROR, "DPS: Security.3.1: Stage invalid.", EXPFILL } },
        { &ei_security_4_invalid_bit, { "dof.security.4.invalid_bit", PI_MALFORMED, PI_WARN, "DPS: Security.4: Reserved bit set.", EXPFILL } },
        { &ei_security_13_out_of_range, { "dof.security.13.out_of_range", PI_MALFORMED, PI_ERROR, "DPS: Security.13: Attribute Data out of range.", EXPFILL } },
    };

    /* Security mode of operation templates. */
    static uat_field_t secmode_uat_fields[] = {
        UAT_FLD_CSTRING(secmode_list, domain, "Domain", "The domain, coded as hex digits of PDU Security.7."),
        UAT_FLD_CSTRING(secmode_list, identity, "Group ID", "The group identifer, coded as hex digits of PDU Security.8."),
        UAT_FLD_CSTRING(secmode_list, kek, "KEK", "The KEK, coded as hex digits representing the KEK (256-bit)."),
        UAT_END_FIELDS
    };

    /* Security keys. */
    static uat_field_t seckey_uat_fields[] = {
        UAT_FLD_CSTRING(seckey_list, key, "Session Key", "The session key to try to use, coded as hex digits representing the key (256-bit)."),
        UAT_END_FIELDS
    };

    /* Identity secrets. */
    static uat_field_t identsecret_uat_fields[] = {
        UAT_FLD_CSTRING(identsecret_list, domain, "Domain", "The domain, coded as hex digits of PDU Security.7."),
        UAT_FLD_CSTRING(identsecret_list, identity, "Identity", "The group identifer, coded as hex digits of PDU Security.8."),
        UAT_FLD_CSTRING_OTHER(identsecret_list, secret, "Secret", identsecret_chk_cb, "The resolved secret for a given identity, coded as hex digits representing the secret (256-bit)."),
        UAT_END_FIELDS
    };

    module_t *dof_module;
    uat_t *secmode_uat;
    uat_t *seckey_uat;
    uat_t *identsecret_uat;
    char *uat_load_err;
    expert_module_t *expert_security;

    dsp_option_dissectors = register_dissector_table("dof.dsp.options", "DSP Protocol Options", proto_2008_1_dsp, FT_UINT32, BASE_DEC);
    dof_sec_dissectors = register_dissector_table("dof.secmode", "DOF Security Mode of Operation", proto_2008_1_dof, FT_UINT16, BASE_DEC);
    register_dissector_table("dof.2008.1", "DOF Common PDU", proto_2008_1_dof, FT_STRING, BASE_DEC);

    proto_2008_1_dof = proto_register_protocol(DOF_PROTOCOL_STACK, "DOF", "dof");

    proto_2008_1_dof_tcp = proto_register_protocol(DOF_PROTOCOL_STACK" TCP", "DOF-TCP", "dof-tcp");
    proto_2008_1_dof_udp = proto_register_protocol(DOF_PROTOCOL_STACK" UDP", "DOF-UDP", "dof-udp");

    proto_register_field_array(proto_2008_1_dof, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_security = expert_register_protocol(proto_2008_1_dof);
    expert_register_field_array(expert_security, ei, array_length(ei));

    dof_module = prefs_register_protocol(proto_2008_1_dof, dof_reset);
    secmode_uat = uat_new("DPS Security Mode Templates",
                          sizeof(secmode_field_t),
                          "custom_dof_secmode_list",
                          TRUE,
                          &secmode_list,
                          &num_secmode_list,
                          (UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS),
                          NULL,
                          secmode_list_copy_cb,
                          secmode_list_update_cb,
                          secmode_list_free_cb,
                          secmode_list_post_update_cb,
                          secmode_uat_fields
                          );

    seckey_uat = uat_new("DPS Session Keys",
                         sizeof(seckey_field_t),
                         "custom_dof_seckey_list",
                         TRUE,
                         &seckey_list,
                         &num_seckey_list,
                         (UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS),
                         NULL,
                         seckey_list_copy_cb,
                         seckey_list_update_cb,
                         seckey_list_free_cb,
                         seckey_list_post_update_cb,
                         seckey_uat_fields
                         );

    identsecret_uat = uat_new("DPS Identity Secrets",
                              sizeof(identsecret_field_t),
                              "custom_dof_identsecret_list",
                              TRUE,
                              &identsecret_list,
                              &num_identsecret_list,
                              (UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS),
                              NULL,
                              identsecret_list_copy_cb,
                              identsecret_list_update_cb,
                              identsecret_list_free_cb,
                              identsecret_list_post_update_cb,
                              identsecret_uat_fields
                              );

    prefs_register_bool_preference(dof_module, "custom_dof_decrypt_all",
                                   "Attempt to decrypt all packets",
                                   "Specifies that decryption should be attempted on all packets, even if the session initialization wasn't captured.",
                                   &decrypt_all_packets);

    prefs_register_bool_preference(dof_module, "custom_dof_track_operations",
                                   "Track DPS operations",
                                   "Specifies that operations should be tracked across multiple packets, providing summary lists. This takes time and memory.",
                                   &track_operations);

    prefs_register_uint_preference(dof_module, "custom_dof_track_operations_window",
                                   "Track DPS window",
                                   "Limits the number of operations shown before and after the current operations",
                                   10, &track_operations_window);

    prefs_register_static_text_preference(dof_module, "name4567", "The following are tables not preferences.", "These tables are not controlled by OK, Apply, and Cancel of this dialog.");

    prefs_register_uat_preference(dof_module, "custom_dof_secmode_list", "DPS Security Mode Templates",
                                  "A table of security modes and initialization data that will be tried if no security mode is found.",
                                  secmode_uat);

    prefs_register_uat_preference(dof_module, "custom_dof_seckey_list", "DPS Session Keys",
                                  "A table of session keys to attempt if none is known.",
                                  seckey_uat);

    prefs_register_uat_preference(dof_module, "custom_dof_identsecret_list", "DPS Identity Secrets",
                                  "A table of secrets for different identities.",
                                  identsecret_uat);

    uat_load(secmode_uat, &uat_load_err);
    uat_load(seckey_uat, &uat_load_err);
    uat_load(identsecret_uat, &uat_load_err);
}

static void dof_handoff(void)
{
    static dissector_handle_t tcp_handle;

    dof_oid_handle = register_dissector(DOF_OBJECT_IDENTIFIER, dissect_2009_11_type_4, oid_proto);

    tcp_handle = create_dissector_handle(dissect_dof_tcp, proto_2008_1_dof);
    dof_udp_handle = create_dissector_handle(dissect_dof_udp, proto_2008_1_dof);

    undissected_data_handle = find_dissector("data");

    dissector_add_uint("tcp.port", DOF_P2P_NEG_SEC_TCP_PORT, tcp_handle);
    dissector_add_uint("udp.port", DOF_P2P_NEG_SEC_UDP_PORT, dof_udp_handle);
    dissector_add_uint("udp.port", DOF_MCAST_NEG_SEC_UDP_PORT, dof_udp_handle);
}

/* OID Registration Support */

static void oid_reset(void)
{
}

static void oid_cleanup(void)
{
}

/* Initialize OID */
static void oid_register(void)
{
    static hf_register_info hf[] = {
        { &hf_oid_class,
            { "Class", "dof.oid.class", FT_UINT32, BASE_DEC, NULL, 0, "DPS Object Identifier Class", HFILL }
        },
        { &hf_oid_header,
            { "Header", "dof.oid.header", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_oid_attribute,
            { "Attribute", "dof.oid.attribute", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }
        },
        { &hf_oid_length,
            { "Length", "dof.oid.length", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }
        },
        { &hf_oid_data,
            { "Data", "dof.oid.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_oid_all_attribute_data,
            { "Attribute Data", "dof.oid.attribute-data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_oid_attribute_header,
            { "Header", "dof.attribute.header", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_oid_attribute_attribute,
            { "Attribute", "dof.attribute.attribute", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }
        },
        { &hf_oid_attribute_id,
            { "ID", "dof.attribute.id", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }
        },
        { &hf_oid_attribute_length,
            { "Length", "dof.attribute.length", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_oid_attribute_data,
            { "Data", "dof.attribute.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_oid_attribute_oid,
            { "OID", "dof.attribute.oid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_oid,
        &ett_oid_header,
        &ett_oid_attribute,
        &ett_oid_attribute_header,
        &ett_oid_attribute_oid,
    };

    static ei_register_info ei[] =
    {
        { &ei_type_4_header_zero, { "dof.oid.header_zero", PI_MALFORMED, PI_ERROR, "DOF Violation: Type.4: Header bit mandated 0.", EXPFILL } },
    };

    if (oid_proto == -1)
    {
        expert_module_t *expert_oid;

        oid_proto = proto_register_protocol(DOF_OBJECT_IDENTIFIER, "DPS.OID", "dof.oid");
        proto_register_field_array(oid_proto, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
        expert_oid = expert_register_protocol(oid_proto);
        expert_register_field_array(expert_oid, ei, array_length(ei));
    }
}

static void oid_handoff(void)
{
}

/* DNP Registration Support */

static guint dof_ns_session_key_hash_fn(gconstpointer key)
{
    const dof_ns_session_key *session_key = (const dof_ns_session_key *)key;
    guint result = 0;

    result += g_int_hash(&session_key->transport_session_id);
    result += g_int_hash(&session_key->client);
    result += g_int_hash(&session_key->server);

    return result;
}

static gboolean dof_ns_session_key_equal_fn(gconstpointer key1, gconstpointer key2)
{
    const dof_ns_session_key *session_key_ptr1 = (const dof_ns_session_key *)key1;
    const dof_ns_session_key *session_key_ptr2 = (const dof_ns_session_key *)key2;

    if (session_key_ptr1->transport_session_id != session_key_ptr2->transport_session_id)
        return FALSE;

    if (session_key_ptr1->client != session_key_ptr2->client)
        return FALSE;

    if (session_key_ptr1->server != session_key_ptr2->server)
        return FALSE;

    return TRUE;
}

static void dof_dnp_reset(void)
{
    dof_ns_session_lookup = g_hash_table_new_full(dof_ns_session_key_hash_fn, dof_ns_session_key_equal_fn, g_free, NULL);
}

static void dof_dnp_cleanup(void)
{
    g_hash_table_destroy(dof_ns_session_lookup);
    dof_ns_session_lookup = NULL;
}

static void dof_register_dnp_0(void)
{
    static hf_register_info hf[] =
    {
        { &hf_2008_1_dnp_0_1_1_padding,
            { "Padding", "dof.dnp.v0.padding", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_2008_1_dnp_0_1_1_version,
            { "Version", "dof.dnp.v0.version", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
    };

    if (proto_2008_1_dnp_0 == -1)
    {
        proto_2008_1_dnp_0 = proto_register_protocol(DOF_NETWORK_PROTOCOL " V0", "DPS.DNP.V0", "dof.dnp.v0");

        proto_register_field_array(proto_2008_1_dnp_0, hf, array_length(hf));
    }
}

/**
 * The registration hand-off routine
 */
static void dof_reg_handoff_dnp_0(void)
{
    dissector_handle_t dnp_handle;
    dnp_handle = create_dissector_handle(dissect_dnp_0, proto_2008_1_dnp_0);

    dissector_add_uint("dof.dnp", 0, dnp_handle);
}

static void dof_register_dnp_1(void)
{
    expert_module_t *expert_dnp;

    static hf_register_info hf[] =
    {
        { &hf_2009_9_dnp_1_flags,
            { "Flags", "dof.2009_9.dnp_1.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_2009_9_dnp_1_flag_length,
            { "Length Size", "dof.2009_9.dnp_1.flags.lengthsize", FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL }
        },
        { &hf_2009_9_dnp_1_flag_srcport,
            { "Source Port", "dof.2009_9.dnp_1.flags.srcport", FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL }
        },
        { &hf_2009_9_dnp_1_flag_dstport,
            { "Destination Port", "dof.2009_9.dnp_1.flags.dstport", FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL }
        },

        { &hf_2009_9_dnp_1_length,
            { "Length", "dof.2009_9.dnp_1.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_2009_9_dnp_1_srcport,
            { "Source Port", "dof.2009_9.dnp_1.srcport", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_2009_9_dnp_1_dstport,
            { "Destination Port", "dof.2009_9.dnp_1.dstport", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
    };

    static gint *ett[] =
    {
        &ett_2009_9_dnp_1_flags,
    };

    static ei_register_info ei[] =
    {
        { &ei_dof_10_flags_zero, { "dof.dnp.v1.flags_zero", PI_UNDECODED, PI_ERROR, "DPS-10: Reserved flag bits must be zero.", EXPFILL } },
#if 0
        { &ei_dof_13_length_specified, { "dof.dnp.v1.length_specified", PI_UNDECODED, PI_ERROR, "DPS-13: Length must be specified on a connection.", EXPFILL } },
#endif
    };

    if (proto_2009_9_dnp_1 == -1)
    {
        proto_2009_9_dnp_1 = proto_register_protocol(DOF_NETWORK_PROTOCOL " V1", "DOF.DNP.V1", "dof.dnp.v1");

        proto_register_field_array(proto_2009_9_dnp_1, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

        expert_dnp = expert_register_protocol(proto_2009_9_dnp_1);
        expert_register_field_array(expert_dnp, ei, array_length(ei));
    }
}

/**
 * The registration hand-off routine
 */
static void dof_reg_handoff_dnp_1(void)
{
    dissector_handle_t dnp_handle, dnp_frame_handle;
    dnp_handle = create_dissector_handle(dissect_dnp_1, proto_2009_9_dnp_1);
    dnp_frame_handle = create_dissector_handle(determine_packet_length_1, proto_2009_9_dnp_1);

    dissector_add_uint("dof.dnp", 1, dnp_handle);
    dissector_add_uint("dof.dnp.frame", 1, dnp_frame_handle);
}

static void dof_dnp_handoff(void)
{
    dof_reg_handoff_dnp_0();
    dof_reg_handoff_dnp_1();
}

/**
 * Initialize Core DNP Functionality
 */
static void dof_dnp_register(void)
{
    static hf_register_info hf[] =
    {
        { &hf_2008_1_dnp_1_flag,
            { "Flag", "dof.2008_1.dnp_1.flag", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x80, NULL, HFILL }
        },
        { &hf_2008_1_dnp_1_version,
            { "Version", "dof.2008_1.dnp_1.version", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }
        },
    };

    static gint *ett[] =
    {
        &ett_2008_1_dnp,
        &ett_2008_1_dnp_header,
    };

    proto_2008_1_dnp = proto_register_protocol(DOF_NETWORK_PROTOCOL, "DPS.DNP", "dof.dnp");

    proto_register_field_array(proto_2008_1_dnp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    dnp_dissectors = register_dissector_table("dof.dnp", "DOF DNP Version", proto_2008_1_dnp, FT_UINT8, BASE_DEC);
    dnp_framing_dissectors = register_dissector_table("dof.dnp.frame", "DOF DNP Framing", proto_2008_1_dnp, FT_UINT8, BASE_DEC);

    dof_register_dnp_0();
    dof_register_dnp_1();
}

/* DPP Registration Support */

/**
 * This routine is called each time the system is reset (file load, capture)
 * and so it should take care of freeing any of our persistent stuff.
 */
static void dof_dpp_reset(void)
{
    dpp_reset_opid_support();
    dpp_reset_sid_support();
}

static void dof_dpp_cleanup(void)
{
}

static void dof_register_dpp_0(void)
{
    static hf_register_info hf[] =
    {
        { &hf_2008_1_dpp_0_1_1_version,
            { "Version", "dof.dpp.v0.version", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
    };

    if (proto_2008_1_dpp_0 == -1)
    {
        proto_2008_1_dpp_0 = proto_register_protocol(DOF_PRESENTATION_PROTOCOL " V0", "DPS.DPP.V0", "dof.dpp.v0");

        proto_register_field_array(proto_2008_1_dpp_0, hf, array_length(hf));
    }
}

/**
 * The registration hand-off routine
 */
static void dof_reg_handoff_dpp_0(void)
{
    dissector_handle_t dpp_handle;
    dpp_handle = create_dissector_handle(dissect_dpp_0, proto_2008_1_dpp_0);

    dissector_add_uint("dof.dpp", 0, dpp_handle);
}

static void dof_register_dpp_2(void)
{
    expert_module_t *expert_dpp;

    static hf_register_info hf[] =
    {
        { &hf_2009_12_dpp_2_1_flags,
            { "Flags", "dof.dpp.v2.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_2009_12_dpp_2_1_flag_security,
            { "Secure", "dof.dpp.v2.flags.security", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        { &hf_2009_12_dpp_2_1_flag_opid,
            { "Operation ID Type", "dof.dpp.v2.flags.opidtype", FT_UINT8, BASE_DEC, VALS(strings_2009_12_dpp_opid_types), 0x60, NULL, HFILL } },
        { &hf_2009_12_dpp_2_1_flag_cmdrsp,
            { "Command/Response", "dof.dpp.v2.flags.cmdrsp", FT_BOOLEAN, 8, TFS(&tfs_response_command), 0x10, NULL, HFILL } },
        { &hf_2009_12_dpp_2_1_flag_seq,
            { "Sequence", "dof.dpp.v2.flags.sequence", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04, NULL, HFILL } },
        { &hf_2009_12_dpp_2_1_flag_retry,
            { "Retry", "dof.dpp.v2.flags.retry", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02, NULL, HFILL } },

        { &hf_2009_12_dpp_2_3_sec_flags,
            { "Flags", "dof.dpp.v2.security.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_2009_12_dpp_2_3_sec_flag_secure,
            { "Security Mode Header", "dof.dpp.v2.security.flags.securitymodeheader", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL } },
        { &hf_2009_12_dpp_2_3_sec_flag_rdid,
            { "Remote Domain ID", "dof.dpp.v2.security.flags.rdid", FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL } },
        { &hf_2009_12_dpp_2_3_sec_flag_partition,
            { "Partition Present", "dof.dpp.v2.security.flags.partition", FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL } },
        { &hf_2009_12_dpp_2_3_sec_flag_ssid,
            { "SSID Present", "dof.dpp.v2.security.flags.ssid", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL } },
        { &hf_2009_12_dpp_2_3_sec_flag_as,
            { "AS Present", "dof.dpp.v2.security.flags.as", FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL } },
        { &hf_2009_12_dpp_2_3_sec_ssid,
            { "Security State Identifier", "dof.dpp.v2.security.ssid", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_2009_12_dpp_2_3_sec_rdid,
            { "Remote Domain Identifier", "dof.dpp.v2.security.rdid", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_2009_12_dpp_2_3_sec_remote_partition,
            { "Remote Security Scope", "dof.dpp.v2.security.remote-scope", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_2009_12_dpp_2_3_sec_partition,
            { "Security Scope", "dof.dpp.v2.security.scope", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_2009_12_dpp_2_1_opcnt,
            { "Operation Count", "dof.dpp.v2.opcnt", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_2009_12_dpp_2_1_seq,
            { "Sequence", "dof.dpp.v2.sequence", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_2009_12_dpp_2_1_retry,
            { "Retry", "dof.dpp.v2.retry", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_2009_12_dpp_2_1_delay,
            { "Delay", "dof.dpp.v2.delay", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    };

    static hf_register_info shf[] =
    {
        { &hf_2009_12_dpp_2_14_opcode,
            { "Opcode", "dof.dpp.v2s.opcode", FT_UINT8, BASE_DEC, VALS(strings_2009_12_dpp_common_opcodes), 0x0, NULL, HFILL } },
    };

    static gint *ett[] =
    {
        &ett_2009_12_dpp_2_1_flags,
        &ett_2009_12_dpp_2_opid,
        &ett_2009_12_dpp_2_opid_history,
        &ett_2009_12_dpp_2_3_security,
        &ett_2009_12_dpp_2_3_sec_flags,
        &ett_2009_12_dpp_2_3_sec_remote_partition,
        &ett_2009_12_dpp_2_3_sec_partition,
    };

    static ei_register_info ei[] =
    {
        { &ei_dpp2_dof_10_flags_zero, { "dof.dpp.v2.flags_zero", PI_UNDECODED, PI_ERROR, "DPS-10: Reserved flag bits must be zero.", EXPFILL } },
        { &ei_dpp_default_flags, { "dof.dpp.v2.flags_included", PI_COMMENTS_GROUP, PI_NOTE, "Default flag value is included explicitly.", EXPFILL } },
        { &ei_dpp_explicit_sender_sid_included, { "dof.dpp.v2.sender_sid_included", PI_COMMENT, PI_NOTE, "Explicit SID could be optimized, same as sender.", EXPFILL } },
        { &ei_dpp_explicit_receiver_sid_included, { "dof.dpp.v2.receiver_sid_included", PI_COMMENT, PI_NOTE, "Explicit SID could be optimized, same as receiver.", EXPFILL } },
#ifdef LIBGCRYPT_OK
        { &ei_dpp_no_security_context, { "dof.dpp.v2.no_context", PI_UNDECODED, PI_WARN, "No security context to enable packet decryption.", EXPFILL } },
#else
        { &ei_dpp_no_security_context, { "dof.dpp.v2.no_context", PI_UNDECODED, PI_WARN, "This version of wireshark was built without DOF decryption capability", EXPFILL } },
#endif
    };

    static gint *sett[] =
    {
        &ett_2009_12_dpp_common,
    };

    if (proto_2009_12_dpp == -1)
    {
        proto_2009_12_dpp = proto_register_protocol(DOF_PRESENTATION_PROTOCOL " V2", "DPS.DPP.V2", "dof.dpp.v2");
        proto_register_field_array(proto_2009_12_dpp, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
    }

    if (proto_2009_12_dpp_common == -1)
    {
        proto_2009_12_dpp_common = proto_register_protocol(DOF_PRESENTATION_PROTOCOL " V2 Support", "DPS.DPP.V2S", "dof.dpp.v2s");

        proto_register_field_array(proto_2009_12_dpp, shf, array_length(shf));
        proto_register_subtree_array(sett, array_length(sett));

        expert_dpp = expert_register_protocol(proto_2009_12_dpp);
        expert_register_field_array(expert_dpp, ei, array_length(ei));
    }
}

/**
 * The registration hand-off routine
 */
static void dof_reg_handoff_dpp_2(void)
{
    dissector_handle_t dpp_handle;
    dpp_handle = create_dissector_handle(dissect_dpp_2, proto_2009_12_dpp);
    dissector_add_uint("dof.dpp", 2, dpp_handle);
}

/**
 * Initialize Core DPP Functionality
 */
static void dof_dpp_register(void)
{
    static hf_register_info hf[] =
    {
        { &hf_2008_1_dpp_sid_num,
            { "SID ID", "dof.dpp.v2.sid-id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_2008_1_dpp_sid_str,
            { "SID", "dof.dpp.v2.sid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_2008_1_dpp_rid_num,
            { "RID ID", "dof.dpp.v2.rid-id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_2008_1_dpp_rid_str,
            { "RID", "dof.dpp.v2.rid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_2008_1_dpp_first_command,
            { "First Operation", "dof.dpp.v2.first-operation", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_2008_1_dpp_last_command,
            { "Last Operation", "dof.dpp.v2.last-operation", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_2008_1_dpp_first_response,
            { "First Response", "dof.dpp.v2.first-response", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_2008_1_dpp_last_response,
            { "Last Response", "dof.dpp.v2.last-response", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_2008_1_dpp_related_frame,
            { "Related Frame", "dof.dpp.v2.related-frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_2008_1_dpp_1_flag,
            { "Flags", "dof.dpp.flag", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x80, NULL, HFILL }
        },
        { &hf_2008_1_dpp_1_version,
            { "Version", "dof.dpp.version", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }
        },
    };

    static gint *ett[] =
    {
        &ett_2008_1_dpp,
        &ett_2008_1_dpp_1_header,
    };

    static ei_register_info ei[] =
    {
        { &ei_dof_6_timeout, { "dof.dpp.timeout", PI_PROTOCOL, PI_ERROR, "DOF Violation: DPS.6: Negotiation not complete within 10 seconds.", EXPFILL } },
    };

    if (proto_2008_1_dpp == -1)
    {
        expert_module_t *expert_dpp;

        proto_2008_1_dpp = proto_register_protocol(DOF_PRESENTATION_PROTOCOL, "DPS.DPP", "dof.dpp");

        proto_register_field_array(proto_2008_1_dpp, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
        dof_dpp_dissectors = register_dissector_table("dof.dpp", "DOF DPP Version", proto_2008_1_dpp, FT_UINT8, BASE_DEC);

        expert_dpp = expert_register_protocol(proto_2008_1_dpp);
        expert_register_field_array(expert_dpp, ei, array_length(ei));
    }

    dof_register_dpp_0();
    dof_register_dpp_2();
}

static void dof_dpp_handoff(void)
{
    dof_reg_handoff_dpp_0();
    dof_reg_handoff_dpp_2();
}

/* General Application Registration Support */

static void app_reset(void)
{
}

static void app_cleanup(void)
{
}

/**
 * Initialize Core DPP Functionality
 */
static void app_register(void)
{
    if (proto_2008_1_app == -1)
    {
        proto_2008_1_app = proto_register_protocol(DOF_APPLICATION_PROTOCOL, "DPS.APP", "dof.app");
        app_dissectors = register_dissector_table("dof.app", "DOF APP Version", proto_2008_1_app, FT_UINT16, BASE_DEC);
    }
}

static void app_handoff(void)
{
}

/* DSP Registration Support */

static void dof_dsp_reset(void)
{
}

static void dof_dsp_cleanup(void)
{
}

static void dof_register_dsp_0(void)
{
    static hf_register_info hf[] =
    {
        { &hf_2008_1_app_version,
            { "APPID", "dof.app.v0.appid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        { &hf_2008_1_dsp_12_opcode,
            { "Opcode", "dof.dsp.opcode", FT_UINT8, BASE_DEC, VALS(strings_2008_1_dsp_opcodes), 0x0, NULL, HFILL } },

        { &hf_2008_1_dsp_attribute_code,
            { "Attribute Code", "dof.dsp.avp.attribute-code", FT_UINT8, BASE_DEC, VALS(strings_2008_1_dsp_attribute_codes), 0x00, NULL, HFILL } },

        { &hf_2008_1_dsp_attribute_data,
            { "Attribute Data", "dof.dsp.avp.attribute-data", FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL } },

        { &hf_2008_1_dsp_value_length,
            { "Value Length", "dof.dsp.avp.value-length", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL } },

        { &hf_2008_1_dsp_value_data,
            { "Value Data", "dof.dsp.avp.value-data", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    };

    static gint *ett[] =
    {
        &ett_2008_1_dsp_12,
        &ett_2008_1_dsp_12_options,
        &ett_2008_1_dsp_12_option,
    };

    proto_2008_1_dsp = proto_register_protocol("DOF Session Protocol", "DOF.ESP", "dof.esp");

    proto_register_field_array(proto_2008_1_dsp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/**
 * The registration hand-off routine
 */
static void dof_reg_handoff_dsp_0(void)
{
    dissector_handle_t dsp_handle = create_dissector_handle(dissect_dsp, proto_2008_1_dsp);
    dissector_add_uint("dof.app", 0, dsp_handle);
}

static void dof_dsp_register(void)
{
    dof_register_dsp_0();
}

static void dof_dsp_handoff(void)
{
    dof_reg_handoff_dsp_0();
}

/* CCM Registration Support */

static void dof_ccm_reset(void)
{
}

static void dof_ccm_cleanup(void)
{
}

static void dof_register_ccm_24577(void)
{
    expert_module_t *expert_ccm;

    static hf_register_info hfdsp[] =
    {
        { &hf_ccm_dsp_option,
            { "CCM Security Mode", "dof.ccm.dsp_opt", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ccm_dsp_strength_count,
            { "CCM Strength Count", "dof.ccm.strength-count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ccm_dsp_strength,
            { "CCM Strength", "dof.ccm.strength", FT_UINT8, BASE_DEC, VALS(ccm_strengths), 0x0, NULL, HFILL } },
        { &hf_ccm_dsp_e_flag,
            { "CCM Minimum Encrypt", "dof.ccm.encrypt.min", FT_BOOLEAN, 8, TFS(&tfs_encrypt_do_not_encrypt), 0x80, NULL, HFILL } },
        { &hf_ccm_dsp_m_flag,
            { "CCM Maximum Encrypt", "dof.ccm.encrypt.max", FT_BOOLEAN, 8, TFS(&tfs_encrypt_do_not_encrypt), 0x40, NULL, HFILL } },
        { &hf_ccm_dsp_tmax,
            { "CCM Maximum MAC", "dof.ccm.mac.max", FT_UINT8, BASE_DEC, NULL, 0x38, NULL, HFILL } },
        { &hf_ccm_dsp_tmin,
            { "CCM Minimum MAC", "dof.ccm.mac.min", FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL } },
    };

    static hf_register_info hf[] =
    {
        { &hf_ccm_opcode,
            { "Opcode", "dof.ccm.opcode", FT_UINT8, BASE_DEC, VALS(ccm_opcode_strings), 0x0, NULL, HFILL } },
    };

    static gint *ett[] =
    {
        &ett_ccm_dsp_option,
        &ett_ccm_dsp,
        &ett_ccm,
    };

    static hf_register_info hfheader[] =
    {
        { &hf_epp_v1_ccm_flags,
            { "Flags", "dof.epp.v1.ccm.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_epp_v1_ccm_flags_manager,
            { "Manager", "dof.epp.v1.ccm.flags.manager", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL } },
        { &hf_epp_v1_ccm_flags_period,
            { "Period", "dof.epp.v1.ccm.flags.period", FT_UINT8, BASE_DEC, NULL, 0x70, NULL, HFILL } },
        { &hf_epp_v1_ccm_flags_target,
            { "Target", "dof.epp.v1.ccm.flags.target", FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL } },
        { &hf_epp_v1_ccm_flags_next_nid,
            { "Next Node Identifier", "dof.epp.v1.ccm.flags.next-nid", FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL } },
        { &hf_epp_v1_ccm_flags_packet,
            { "Packet", "dof.epp.v1.ccm.flags.packet", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL } },
        { &hf_epp_v1_ccm_nid,
            { "Node ID", "dof.epp.v1.ccm.nodeid", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_epp_v1_ccm_slot,
            { "Slot", "dof.epp.v1.ccm.slot", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_epp_v1_ccm_pn,
            { "Packet", "dof.epp.v1.ccm.packet", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_epp_v1_ccm_tnid,
            { "Target Node ID", "dof.epp.v1.ccm.target", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_epp_v1_ccm_nnid,
            { "Next Node ID", "dof.epp.v1.ccm.nnid", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    };

    static gint *ettheader[] =
    {
        &ett_epp_v1_ccm_flags,
        &ett_header,
    };

    static ei_register_info ei[] =
    {
        { &ei_decode_failure, { "dof.ccm.decode_failure", PI_UNDECODED, PI_WARN, "Failure to decrypt packet.", EXPFILL } },
    };

    /* No Configuration options to register? */

    proto_ccm_app = proto_register_protocol("DOF CCM Security Mode App", "DOF.CCM.APP", "dof.ccm.app");
    proto_ccm = proto_register_protocol("DOF CCM Security Mode of Operation", "DOF.CCM", "dof.ccm");
    proto_ccm_dsp = proto_register_protocol("DOF CCM Security Mode DSP Options", "DOF.CCM.DSP", "dof.ccm.dsp");

    proto_register_field_array(proto_ccm_app, hf, array_length(hf));
    proto_register_field_array(proto_ccm_dsp, hfdsp, array_length(hfdsp));
    proto_register_subtree_array(ett, array_length(ett));

    proto_register_field_array(proto_ccm, hfheader, array_length(hfheader));
    proto_register_subtree_array(ettheader, array_length(ettheader));

    expert_ccm = expert_register_protocol(proto_ccm);
    expert_register_field_array(expert_ccm, ei, array_length(ei));
}

/**
 * The registration hand-off routine
 */
static void dof_reg_handoff_ccm_24577(void)
{
    static dissector_handle_t ccm_app_handle;
    static dissector_handle_t dsp_handle;
    static dissector_handle_t ccm_handle;

    ccm_app_handle = create_dissector_handle(dissect_ccm_app, proto_ccm_app);
    dsp_handle = create_dissector_handle(dissect_ccm_dsp, proto_ccm_dsp);
    ccm_handle = create_dissector_handle(dissect_ccm, proto_ccm);

    dissector_add_uint("dof.app", DOF_PROTOCOL_CCM, ccm_app_handle);
    dissector_add_uint("dof.dsp.options", DSP_CCM_FAMILY | DOF_PROTOCOL_CCM, dsp_handle);
    dissector_add_uint("dof.secmode", DOF_PROTOCOL_CCM, ccm_handle);
}

static void dof_ccm_register(void)
{
    dof_register_ccm_24577();
}

static void dof_ccm_handoff(void)
{
    dof_reg_handoff_ccm_24577();
}

/* OAP Registration Support */

static void dof_oap_reset(void)
{
    /* The value is not allocated, so does not need to be freed. */
    oap_1_alias_to_binding = g_hash_table_new_full(oap_1_alias_hash_func, oap_1_alias_equal_func, NULL, NULL);
}

static void dof_oap_cleanup(void)
{
    g_hash_table_destroy(oap_1_alias_to_binding);
    oap_1_alias_to_binding = NULL;
}

static void dof_register_oap_1(void)
{
    expert_module_t *expert_oap;

    static hf_register_info hfdsp[] =
    {
        { &hf_oap_1_dsp_option,
            { "Object Access Protocol", "dof.oap.dsp_opt", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    static hf_register_info hf[] =
    {
        { &hf_oap_1_opcode,
            { "Opcode", "dof.oap.opcode", FT_UINT8, BASE_DEC, VALS(oap_opcode_strings), 0x1F, NULL, HFILL } },

        { &hf_oap_1_alias_size,
            { "Alias Length", "dof.oap.aliaslen", FT_UINT8, BASE_DEC, NULL, 0xC0, NULL, HFILL } },

        { &hf_oap_1_flags,
            { "Flags", "dof.oap.flags", FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL } },

        { &hf_oap_1_exception_internal_flag,
            { "Internal Exception", "dof.oap.exception.internal", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL } },

        { &hf_oap_1_exception_final_flag,
            { "Final Exception", "dof.oap.exception.final", FT_UINT8, BASE_DEC, NULL, 0x40, NULL, HFILL } },

        { &hf_oap_1_exception_provider_flag,
            { "Exception Provider", "dof.oap.exception.provider", FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL } },

        { &hf_oap_1_cmdcontrol,
            { "Command Control", "dof.oap.cmdcontrol", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_oap_1_cmdcontrol_cache_flag,
            { "Cache Delay Flag", "dof.oap.cmdcontrol.flag.cache", FT_UINT8, BASE_HEX, NULL, 0x40, NULL, HFILL } },

        { &hf_oap_1_cmdcontrol_cache,
            { "Cache Delay", "dof.oap.cmdcontrol.cache", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },

        { &hf_oap_1_cmdcontrol_verbosity_flag,
            { "Verbosity Flag", "dof.oap.cmdcontrol.flag.verbosity", FT_UINT8, BASE_HEX, NULL, 0x30, NULL, HFILL } },

        { &hf_oap_1_cmdcontrol_noexecute_flag,
            { "No Execute Flag", "dof.oap.cmdcontrol.flag.noexecute", FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL } },

        { &hf_oap_1_cmdcontrol_ack_flag,
            { "Ack List Flag", "dof.oap.cmdcontrol.flag.ack", FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL } },

        { &hf_oap_1_cmdcontrol_ackcnt,
            { "Ack List Count", "dof.oap.cmdcontrol.ackcnt", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },

        { &hf_oap_1_cmdcontrol_ack,
            { "Ack", "dof.oap.cmdcontrol.ack", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        { &hf_oap_1_cmdcontrol_delay_flag,
            { "Execution Delay Flag", "dof.oap.cmdcontrol.flag.delay", FT_UINT8, BASE_HEX, NULL, 0x02, NULL, HFILL } },

        { &hf_oap_1_cmdcontrol_heuristic_flag,
            { "Heuristic Flag", "dof.oap.cmdcontrol.flag.heuristic", FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL } },

        { &hf_oap_1_cmdcontrol_heuristic,
            { "Heuristic", "dof.oap.cmdcontrol.heuristic", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },

        { &hf_oap_1_providerid,
            { "Provider ID", "dof.oap.provider-id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_oap_1_objectid,
            { "Object ID", "dof.oap.object-id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_oap_1_interfaceid,
            { "Interface ID", "dof.oap.interface-id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_oap_1_itemid,
            { "Item ID", "dof.oap.item-id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

#if 0 /* not used yet */
        { &hf_oap_1_distance,
            { "Distance", "dof.oap.distance", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
#endif

        { &hf_oap_1_alias,
            { "Alias", "dof.oap.alias", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_oap_1_alias_frame,
            { "Alias Frame", "dof.oap.alias-frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },

#if 0 /* not used yet */
        { &hf_oap_1_opinfo_start_frame,
            { "Command Frame", "dof.oap.command-frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_oap_1_opinfo_end_frame,
            { "Response Frame", "dof.oap.response-frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_oap_1_opinfo_timeout,
            { "Operation Timeout", "dof.oap.opid.timeout", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL } },
#endif

        { &hf_oap_1_subscription_delta,
            { "Minimum Delta", "dof.oap.subscription.min-delta", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_oap_1_update_sequence,
            { "Sequence", "dof.oap.sequence", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_oap_1_value_list,
            { "OAP Value List", "dof.oap.value_list", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    static gint *ett[] =
    {
        &ett_oap_1_dsp,
        &ett_oap_1_dsp_options,
        &ett_oap_1,
        &ett_oap_1_opinfo,
        &ett_oap_1_cmdcontrol,
        &ett_oap_1_cmdcontrol_flags,
        &ett_oap_1_cmdcontrol_ack,
        &ett_oap_1_alias,
        &ett_oap_1_objectid,
        &ett_oap_1_1_providerid,
    };

    static ei_register_info ei[] =
    {
        { &ei_oap_no_session, { "dof.oap.no_session", PI_PROTOCOL, PI_ERROR, "Session not found", EXPFILL } },
    };

    proto_oap_1 = proto_register_protocol("DOF Object Access Protocol", "DOF.OAP", "dof.oap");
    proto_oap_1_dsp = proto_register_protocol("DOF Object Access Protocol DSP Options", "DOF.OAP.DSP", "dof.oap.dsp");

    proto_register_field_array(proto_oap_1, hf, array_length(hf));
    proto_register_field_array(proto_oap_1_dsp, hfdsp, array_length(hfdsp));
    proto_register_subtree_array(ett, array_length(ett));

    expert_oap = expert_register_protocol(proto_oap_1);
    expert_register_field_array(expert_oap, ei, array_length(ei));
}

/**
 * The registration hand-off routine
 */
static void dof_reg_handoff_oap_1(void)
{
    dissector_handle_t oap_handle = create_dissector_handle(dissect_oap, proto_oap_1);
    dissector_handle_t dsp_handle = create_dissector_handle(dissect_oap_dsp, proto_oap_1_dsp);

    dissector_add_uint("dof.app", DOF_PROTOCOL_OAP_1, oap_handle);
    dissector_add_uint("dof.dsp.options", DSP_OAP_FAMILY | DOF_PROTOCOL_OAP_1, dsp_handle);
}

static void dof_oap_register(void)
{
    dof_register_oap_1();
}

static void dof_oap_handoff(void)
{
    dof_reg_handoff_oap_1();
}

/* SGMP Registration Support */

void dof_register_sgmp_130(void);
void dof_reg_handoff_sgmp_130(void);

static void dof_sgmp_reset(void)
{
}

static void dof_sgmp_cleanup(void)
{
}

void dof_register_sgmp_130(void)
{
    static hf_register_info hf[] =
    {
        { &hf_opcode,
            { "Opcode", "dof.sgmp.v1.opcode", FT_UINT8, BASE_DEC, VALS(sgmp_opcode_strings), 0x0, NULL, HFILL } },

        { &hf_sgmp_domain,
            { "Domain", "dof.sgmp.v1.domain", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_sgmp_epoch,
            { "Epoch", "dof.sgmp.v1.epoch", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },

        { &hf_initiator_block,
            { "Initiator Block", "dof.sgmp.v1.initiator-block", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_sgmp_security_scope,
            { "Security Scope", "dof.sgmp.v1.security-scope", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_initial_state,
            { "Initial State", "dof.sgmp.v1.initial-state", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_latest_version,
            { "Latest SGMP Version", "dof.sgmp.v1.latest-sgmp-version", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },

        { &hf_desire,
            { "Desire", "dof.sgmp.v1.desire", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },

        { &hf_ticket,
            { "Ticket", "dof.sgmp.v1.ticket", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_sgmp_tmin,
            { "TMIN", "dof.sgmp.v1.tmin", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },

        { &hf_tie_breaker,
            { "Tie Breaker", "dof.sgmp.v1.tie-breaker", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },

        { &hf_delay,
            { "Delay", "dof.sgmp.v1.delay", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },

        { &hf_key,
            { "Key", "dof.sgmp.v1.key", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
    };

    static gint *ett[] =
    {
        &ett_sgmp,
        &ett_sgmp_domain,
        &ett_initiator_block,
        &ett_sgmp_security_scope,
        &ett_initial_state,
        &ett_ticket,
    };

    proto_sgmp = proto_register_protocol("DOF Secure Group Management Protocol", "DOF.SGMP", "dof.sgmp");

    proto_register_field_array(proto_sgmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/**
 * The registration hand-off routine
 */
void dof_reg_handoff_sgmp_130(void)
{
    dissector_handle_t sgmp_handle = create_dissector_handle(dissect_sgmp, proto_sgmp);

    dissector_add_uint("dof.app", DOF_PROTOCOL_SGMP, sgmp_handle);
}

static void dof_sgmp_register(void)
{
    dof_register_sgmp_130();
}

static void dof_sgmp_handoff(void)
{
    dof_reg_handoff_sgmp_130();
}

/* TEP Registration Support */

static void dof_tep_reset(void)
{
}

static void dof_tep_cleanup(void)
{
}

static void dof_register_tep_128(void)
{
    static hf_register_info hfdsp[] =
    {
        { &hf_dsp_option,
            { "Ticket Exchange Protocol Version 1", "dof.tep1.dsp_opt", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    static hf_register_info hf[] =
    {
        { &hf_tep_operation,
            { "Operation", "dof.tep1.operation", FT_UINT8, BASE_DEC, VALS(tep_opcode_strings), 0x00, NULL, HFILL } },

        { &hf_tep_operation_type,
            { "Operation Type", "dof.tep1.operation_type", FT_BOOLEAN, 8, TFS(&tep_optype_vals), TEP_OPCODE_RSP, NULL, HFILL } },

        { &hf_tep_opcode,
            { "Opcode", "dof.tep1.opcode", FT_UINT8, BASE_DEC, VALS(tep_opcode_strings), 0x0F, NULL, HFILL } },

        { &hf_tep_k,
            { "K", "dof.tep1.k", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL } },

        { &hf_tep_c,
            { "C", "dof.tep1.c", FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL } },

        { &hf_tep_reject_code,
            { "Code", "dof.tep1.reject.code", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL } },

        { &hf_tep_reject_data,
            { "Data", "dof.tep1.reject.data", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        /* TEP.2.1 */
        { &hf_tep_2_1_domain,
            { "Domain", "dof.2008.4.tep1.2.1.domain", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_tep_2_1_initiator_block,
            { "Initiator Block", "dof.2008.4.tep1.2.1.initiator_block", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        { &hf_tep_2_1_ticket_confirmation,
            { "Ticket Confirmation", "dof.2008.4.tep1.2.1.ticket_confirmation", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        /* TEP.2.2 */
        { &hf_tep_2_2_initiator_ticket,
            { "Initiator Ticket", "dof.2008.4.tep1.2.2.initiator_ticket", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        { &hf_tep_2_2_ticket_confirmation,
            { "Ticket Confirmation", "dof.2008.4.tep1.2.2.ticket_confirmation", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        { &hf_tep_2_2_responder_initialization,
            { "Responder Initialization", "dof.2008.4.tep1.2.2.responder_initialization", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        { &hf_tep_2_2_responder_block,
            { "Responder Block", "dof.2008.4.tep1.2.2.responder_block", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        { &hf_tep_2_2_authenticator_initialization,
            { "Authenticator Initialization", "dof.2008.4.tep1.2.2.authenticator_initialization", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        /* TEP.2.2.1 */
        { &hf_tep_2_2_1_state_identifier,
            { "State Identifier", "dof.2008.4.tep1.2.2.1.state_identifier", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },

        { &hf_tep_2_2_1_initial_state,
            { "Initial State", "dof.2008.4.tep1.2.2.1.initial_state", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        { &hf_tep_session_key,
            { "Session Key", "dof.session_key", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    };

    static gint *ett[] =
    {
        &ett_tep_dsp,
        &ett_tep_dsp_options,
        &ett_tep,
        &ett_tep_operation,

        &ett_tep_2_1_domain,
        &ett_tep_2_1_initiator_block,

        &ett_tep_2_2_initiator_ticket,
        &ett_tep_2_2_responder_initialization,
        &ett_tep_2_2_responder_block,
        &ett_tep_2_2_authenticator_initialization,

        &ett_tep_2_2_1_initial_state,
    };

    /* module_t *tep_module;*/

    /* No Configuration options to register? */

    proto_tep = proto_register_protocol("DOF Ticket Exchange Protocol Version 1", "DOF.TEP1", "dof.tep1");

    proto_tep_dsp = proto_register_protocol("DOF Ticket Exchange Protocol DSP Options", "DOF.TEP1.DSP", "dof.tep1.dsp");

    proto_register_field_array(proto_tep, hf, array_length(hf));
    proto_register_field_array(proto_tep_dsp, hfdsp, array_length(hfdsp));
    proto_register_subtree_array(ett, array_length(ett));

    /* tep_module = prefs_register_protocol( proto_tep, NULL );*/
}

/**
 * The registration hand-off routine
 */
static void dof_reg_handoff_tep_128(void)
{
    dissector_handle_t tep_handle = create_dissector_handle(dissect_tep, proto_tep);
    dissector_handle_t dsp_handle = create_dissector_handle(dissect_tep_dsp, proto_tep_dsp);

    dissector_add_uint("dof.app", DOF_PROTOCOL_TEP, tep_handle);
    dissector_add_uint("dof.dsp.options", DSP_TEP_FAMILY | DOF_PROTOCOL_TEP, dsp_handle);
}

static void dof_tep_register(void)
{
    dof_register_tep_128();
}

static void dof_tep_handoff(void)
{
    dof_reg_handoff_tep_128();
}

/* TRP Registration Support */

static void dof_trp_reset(void)
{
}

static void dof_trp_cleanup(void)
{
}

static void dof_register_trp_129(void)
{
    expert_module_t *expert_trp;

    static hf_register_info hfdsp[] =
    {
        { &hf_trp_dsp_option,
            { "Ticket Request Protocol", "dof.trp.dsp_opt", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    static hf_register_info hf[] =
    {
        { &hf_trp_opcode,
            { "Opcode", "dof.trp.opcode", FT_UINT8, BASE_DEC, VALS(trp_opcode_strings), 0x0, NULL, HFILL } },

        { &hf_domain,
            { "Domain", "dof.trp.domain", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_identity_resolution,
            { "Identity Resolution", "dof.trp.identity_resolution", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_initiator_request,
            { "Initiator Request", "dof.trp.initiator_request", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_responder_request,
            { "Responder Request", "dof.trp.responder_request", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_initiator_ticket,
            { "Initiator Ticket", "dof.trp.initiator_ticket", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_responder_ticket,
            { "Responder Ticket", "dof.trp.responder_ticket", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_authentication_block,
            { "Authentication Block", "dof.trp.authentication_block", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_group_identifier,
            { "Group Identifier", "dof.trp.group_identifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_node_identifier,
            { "Node Identifier", "dof.trp.node_identifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_thb,
            { "Thb", "dof.trp.thb", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL } },

        { &hf_tmin,
            { "Tmin", "dof.trp.tmin", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL } },

        { &hf_tmax,
            { "Tmax", "dof.trp.tmax", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL } },

        { &hf_trp_epoch,
            { "Epoch", "dof.trp.epoch", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL } },

        { &hf_sidg,
            { "SIDg", "dof.trp.sid_g", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_security_scope,
            { "Security Scope", "dof.trp.security_scope", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_security_mode,
            { "Security Mode", "dof.trp.security_mode", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_ssid,
            { "SSID", "dof.trp.ssid", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

#if 0 /* not used yet */
        { &hf_initiator_pg,
            { "Initiator Permissions", "dof.trp.initiator_pg", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
#endif

        { &hf_initiator_validation,
            { "Initiator Validation", "dof.trp.initiator_validation", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_responder_pg,
            { "Responder Permissions", "dof.trp.responder_pg", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_responder_validation,
            { "Responder Validation", "dof.trp.responder_validation", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_errorcode,
            { "Error Code", "dof.trp.errorcode", FT_UINT8, BASE_DEC, VALS(trp_error_strings), 0x0, NULL, HFILL } },

        { &hf_trp_duration,
            { "Duration", "dof.trp.duration", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

#if 0 /* not used yet */
        { &hf_trp_rnonce,
            { "Requestor Nonce", "dof.trp.rnonce", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_pnonce,
            { "Provider Nonce", "dof.trp.pnonce", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_reqid,
            { "Requestor ID", "dof.trp.reqid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_provid,
            { "Provider ID", "dof.trp.provid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_perm_count,
            { "Permission Count", "dof.trp.perm.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_perm_type,
            { "Permission Type", "dof.trp.perm.type", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_perm_rflags,
            { "Requestor SRP Flags", "dof.trp.rflags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_perm_rcache,
            { "Requestor SRP Cache", "dof.trp.rcache", FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL } },

        { &hf_trp_perm_rsrp,
            { "Requestor SRP", "dof.trp.rsrp", FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL } },

        { &hf_trp_perm_rsrp_a,
            { "Requestor SRP A", "dof.trp.rsrp.a", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_perm_rsrp_u,
            { "Requestor SRP u", "dof.trp.rsrp.u", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_perm_pflags,
            { "Provider SRP Flags", "dof.trp.pflags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_perm_pcache,
            { "Provider SRP Cache", "dof.trp.pcache", FT_BOOLEAN, 8, NULL, 0x2, NULL, HFILL } },

        { &hf_trp_perm_psrp,
            { "Provider SRP", "dof.trp.psrp", FT_BOOLEAN, 8, NULL, 0x1, NULL, HFILL } },

        { &hf_trp_perm_psrp_a,
            { "Provider SRP A", "dof.trp.psrp.a", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_perm_psrp_u,
            { "Provider SRP u", "dof.trp.psrp.u", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_perm_psrp_b,
            { "Provider SRP B", "dof.trp.psrp.b", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_perm_psrp_s,
            { "Provider SRP S", "dof.trp.psrp.s", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_confirmation,
            { "Confirmation", "dof.trp.confirmation", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_perm_pke,
            { "Provider Key Expression", "dof.trp.pke", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_trp_perm_pka,
            { "Provider Key Authenticator", "dof.trp.pka", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
#endif
    };

    static gint *ett[] =
    {
        &ett_trp_dsp,
        &ett_trp,
        &ett_domain,
        &ett_identity_resolution,
        &ett_initiator_request,
        &ett_initiator_ticket,
        &ett_responder_request,
        &ett_responder_ticket,
        &ett_authentication_block,
        &ett_group_identifier,
        &ett_node_identifier,
        &ett_sidg,
        &ett_security_scope,
        &ett_security_mode,
        &ett_initiator_pg,
        &ett_initiator_validation,
        &ett_responder_pg,
        &ett_responder_validation,
        &ett_trp_permset,
        &ett_srp_flags,
        &ett_trp_ticket,
    };

    static ei_register_info ei[] =
    {
        { &ei_trp_initiator_id_known, { "dof.trp.initiator_id_known", PI_PROTOCOL, PI_COMMENT, "Initiator identity known", EXPFILL } },
        { &ei_trp_kek_discovered, { "dof.trp.kek_discovered", PI_PROTOCOL, PI_COMMENT, "KEK discovered", EXPFILL } },
    };

    /* No Configuration options to register? */

    proto_trp = proto_register_protocol("DOF Ticket Request Protocol", "DOF.TRP", "dof.trp");

    proto_trp_dsp = proto_register_protocol("DOF Ticket Request Protocol DSP Options", "DOF.TRP.DSP", "dof.trp.dsp");

    proto_register_field_array(proto_trp, hf, array_length(hf));
    proto_register_field_array(proto_trp_dsp, hfdsp, array_length(hfdsp));
    proto_register_subtree_array(ett, array_length(ett));
    expert_trp = expert_register_protocol(proto_trp);
    expert_register_field_array(expert_trp, ei, array_length(ei));
}

/**
 * The registration hand-off routine
 */
static void dof_reg_handoff_trp_129(void)
{
    dissector_handle_t trp_handle = create_dissector_handle(dissect_trp, proto_trp);
    dissector_handle_t dsp_handle = create_dissector_handle(dissect_trp_dsp, proto_trp_dsp);

    dissector_add_uint("dof.app", DOF_PROTOCOL_TRP, trp_handle);
    dissector_add_uint("dof.dsp.options", DSP_TRP_FAMILY | DOF_PROTOCOL_TRP, dsp_handle);
}

static void dof_trp_register(void)
{
    dof_register_trp_129();
}

static void dof_trp_handoff(void)
{
    dof_reg_handoff_trp_129();
}

/* Wireshark Dissector Registration Proper */

/**
 * This is called only during reset (file load, reload, etc.).
 */
static void dof_reset_routine(void)
{
    dof_tun_reset();
    dof_reset();
    oid_reset();
    dof_dnp_reset();
    dof_dpp_reset();
    app_reset();
    dof_dsp_reset();
    dof_ccm_reset();
    dof_oap_reset();
    dof_sgmp_reset();
    dof_tep_reset();
    dof_trp_reset();
}

static void dof_cleanup_routine(void)
{
    dof_tun_cleanup();
    dof_cleanup();
    oid_cleanup();
    dof_dnp_cleanup();
    dof_dpp_cleanup();
    app_cleanup();
    dof_dsp_cleanup();
    dof_ccm_cleanup();
    dof_oap_cleanup();
    dof_sgmp_cleanup();
    dof_tep_cleanup();
    dof_trp_cleanup();
}

/**
 * This is the first entry point into the dissector, called on program launch.
 */
void proto_register_dof(void)
{
    dof_tun_register();
    dof_register();
    oid_register();
    dof_dnp_register();
    dof_dpp_register();
    app_register();
    dof_dsp_register();
    dof_ccm_register();
    dof_oap_register();
    dof_sgmp_register();
    dof_tep_register();
    dof_trp_register();

    register_init_routine(&dof_reset_routine);
    register_cleanup_routine(&dof_cleanup_routine);
}

/**
 * This routine is called after initialization and whenever the preferences are changed.
 */
void proto_reg_handoff_dof(void)
{
    dof_tun_handoff();
    dof_handoff();
    oid_handoff();
    dof_dnp_handoff();
    dof_dpp_handoff();
    app_handoff();
    dof_dsp_handoff();
    dof_ccm_handoff();
    dof_oap_handoff();
    dof_sgmp_handoff();
    dof_tep_handoff();
    dof_trp_handoff();
}

/**
 * Protocol-specific data attached to a conversation_t structure - protocol
 * index and opaque pointer.
 */
typedef struct _dof_proto_data {
    int     proto;
    void    *proto_data;
} dof_proto_data;

static gint p_compare(gconstpointer a, gconstpointer b)
{
    const dof_proto_data *ap = (const dof_proto_data *)a;
    const dof_proto_data *bp = (const dof_proto_data *)b;

    if (ap->proto > bp->proto)
        return 1;
    else if (ap->proto == bp->proto)
        return 0;
    else
        return -1;
}

#if 0 /* TODO not used yet */
static void dof_session_add_proto_data(dof_session_data *session, int proto, void *proto_data)
{
    dof_proto_data *p1 = wmem_new0(wmem_packet_scope(), dof_proto_data);

    p1->proto = proto;
    p1->proto_data = proto_data;

    /* Add it to the list of items for this conversation. */

    session->data_list = g_slist_insert_sorted(session->data_list, (gpointer *)p1, p_compare);
}

static void *dof_session_get_proto_data(dof_session_data *session, int proto)
{
    dof_proto_data temp, *p1;
    GSList *item;

    temp.proto = proto;
    temp.proto_data = NULL;

    item = g_slist_find_custom(session->data_list, (gpointer *)&temp,
                               p_compare);

    if (item != NULL)
    {
        p1 = (dof_proto_data *)item->data;
        return p1->proto_data;
    }

    return NULL;
}

static void dof_session_delete_proto_data(dof_session_data *session, int proto)
{
    dof_proto_data temp;
    GSList *item;

    temp.proto = proto;
    temp.proto_data = NULL;

    item = g_slist_find_custom(session->data_list, (gpointer *)&temp,
                               p_compare);

    while (item)
    {
        session->data_list = g_slist_remove(session->data_list, item->data);
        item = item->next;
    }
}
#endif

static void dof_packet_add_proto_data(dof_packet_data *packet, int proto, void *proto_data)
{
    dof_proto_data *p1 = wmem_new0(wmem_file_scope(), dof_proto_data);

    p1->proto = proto;
    p1->proto_data = proto_data;

    /* Add it to the list of items for this conversation. */

    packet->data_list = g_slist_insert_sorted(packet->data_list, (gpointer *)p1, p_compare);
}

static void *dof_packet_get_proto_data(dof_packet_data *packet, int proto)
{
    dof_proto_data temp, *p1;
    GSList *item;

    temp.proto = proto;
    temp.proto_data = NULL;

    item = g_slist_find_custom(packet->data_list, (gpointer *)&temp,
                               p_compare);

    if (item != NULL)
    {
        p1 = (dof_proto_data *)item->data;
        return p1->proto_data;
    }

    return NULL;
}

#if 0 /* TODO not used yet */
static void dof_packet_delete_proto_data(dof_packet_data *packet, int proto)
{
    dof_proto_data temp;
    GSList *item;

    temp.proto = proto;
    temp.proto_data = NULL;

    item = g_slist_find_custom(packet->data_list, (gpointer *)&temp,
                               p_compare);

    while (item)
    {
        packet->data_list = g_slist_remove(packet->data_list, item->data);
        item = item->next;
    }
}
#endif

static gint dof_dissect_pdu_as_field(dissector_t dissector, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int item, int ett, void *result)
{
    int block_length;
    tvbuff_t *start = tvb_new_subset(tvb, offset, -1, -1);
    proto_tree *my_tree;
    proto_item *ti = proto_tree_add_item(tree, item, tvb, offset, -1, ENC_NA);
    my_tree = proto_item_add_subtree(ti, ett);
    block_length = dof_dissect_pdu(dissector, start, pinfo, my_tree, result);
    return offset + block_length;
}

static gint dof_dissect_pdu(dissector_t dissector, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *result)
{
    gint len = dissector(tvb, pinfo, tree, result);
    proto_item_set_len(proto_tree_get_parent(tree), len);

    return len;
}

static int dof_dissect_dnp_length(tvbuff_t *tvb, packet_info *pinfo, guint8 version, gint *offset)
{
    dissector_handle_t dp;

    dp = dissector_get_uint_handle(dnp_framing_dissectors, version);
    if (!dp)
        return -1;

    return call_dissector_only(dp, tvb, pinfo, NULL, offset);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
