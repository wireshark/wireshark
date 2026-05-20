/** @file
 *
 * VoIP calls summary addition for Wireshark
 *
 * Copyright 2004, Ericsson , Spain
 * By Francisco Alcoba <francisco.alcoba@ericsson.com>
 *
 * based on h323_calls.h
 * Copyright 2004, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
 *
 * H323, RTP and Graph Support
 * By Alejandro Vaquero, alejandro.vaquero@verso.com
 * Copyright 2005, Verso Technologies Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __VOIP_CALLS_H__
#define __VOIP_CALLS_H__

#include <glib.h>

#include <stdio.h>

#include "epan/address.h"
#include "epan/packet.h"
#include "epan/guid-utils.h"
#include "epan/tap.h"
#include "epan/tap-voip.h"
#include "epan/sequence_analysis.h"

/** @file
 *  "VoIP Calls" dialog box common routines.
 *  @ingroup main_ui_group
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/****************************************************************************/
/** @brief Array of human-readable names for each VoIP call state, indexed by state value. */
extern const char *voip_call_state_name[8];


/**
 * @brief Identifies the signalling protocol of a captured VoIP call.
 */
typedef enum _voip_protocol {
    VOIP_SIP,      /**< Session Initiation Protocol. */
    VOIP_ISUP,     /**< ISDN User Part (SS7). */
    VOIP_H323,     /**< H.323 multimedia signalling. */
    VOIP_MGCP,     /**< Media Gateway Control Protocol. */
    VOIP_AC_ISDN,  /**< ACTrace ISDN signalling. */
    VOIP_AC_CAS,   /**< ACTrace Channel Associated Signalling. */
    MEDIA_T38,     /**< T.38 fax-over-IP. */
    TEL_H248,      /**< H.248 / Megaco gateway control. */
    TEL_SCCP,      /**< Signalling Connection Control Part (SS7). */
    TEL_BSSMAP,    /**< Base Station System Management Application Part (GSM). */
    TEL_RANAP,     /**< Radio Access Network Application Part (UMTS). */
    VOIP_UNISTIM,  /**< Nortel UNISTIM IP phone protocol. */
    VOIP_SKINNY,   /**< Cisco Skinny Client Control Protocol (SCCP). */
    VOIP_IAX2,     /**< Inter-Asterisk eXchange protocol v2. */
    VOIP_COMMON    /**< Generic / unclassified VoIP protocol. */
} voip_protocol;


/**
 * @brief Indices into the per-protocol hash table array in #_voip_calls_tapinfo.
 */
typedef enum _hash_indexes {
    SIP_HASH = 0 /**< Hash table index for SIP calls. */
} hash_indexes;


/** @brief Array of human-readable names for each #voip_protocol value. */
extern const char *voip_protocol_name[];


/**
 * @brief Controls which calls are shown in the VoIP flow graph.
 */
typedef enum _flow_show_options
{
    FLOW_ALL,          /**< Show all captured VoIP calls. */
    FLOW_ONLY_INVITES  /**< Show only calls that contain a SIP INVITE. */
} flow_show_options;

/** defines specific SIP data */

/**
 * @brief Tracks the signalling state of an in-progress SIP call.
 */
typedef enum _sip_call_state {
    SIP_INVITE_SENT, /**< INVITE request has been sent; awaiting response. */
    SIP_200_REC,     /**< 200 OK response received; call is established. */
    SIP_CANCEL_SENT  /**< CANCEL request has been sent; call is being torn down. */
} sip_call_state;


/**
 * @brief Protocol-specific call metadata for SIP calls.
 */
typedef struct _sip_calls_info {
    char         *call_identifier; /**< SIP Call-ID header value uniquely identifying this dialog. */
    uint32_t      invite_cseq;     /**< CSeq number of the initial INVITE request. */
    sip_call_state sip_state;      /**< Current signalling state of this SIP call. */
} sip_calls_info_t;


/**
 * @brief Protocol-specific call metadata for ISUP calls.
 */
typedef struct _isup_calls_info {
    uint16_t cic; /**< Circuit Identification Code assigned to this call. */
    uint32_t opc; /**< Originating Point Code (SS7 network address of the source). */
    uint32_t dpc; /**< Destination Point Code (SS7 network address of the destination). */
    uint8_t  ni;  /**< Network Indicator identifying the SS7 network (national/international). */
} isup_calls_info_t;


/**
 * @brief H.245 control channel address and port tuple.
 */
typedef struct _h245_address {
    address  h245_address; /**< IP address of the H.245 control channel endpoint. */
    uint16_t h245_port;    /**< UDP/TCP port of the H.245 control channel endpoint. */
} h245_address_t;


/**
 * @brief Protocol-specific call metadata for H.323 calls.
 */
typedef struct _h323_calls_info {
    e_guid_t *guid;                /**< H.225 Call ID GUID uniquely identifying this H.323 call. */
    GList    *h245_list;           /**< List of #h245_address_t entries for tunnelled H.245 channels. */
    address   h225SetupAddr;       /**< Source IP from the H.225 SETUP message, used to determine packet direction. */
    bool      is_h245;             /**< True if a separate H.245 control channel has been detected. */
    bool      is_faststart_Setup;  /**< True if a fastStart element was present in the H.225 SETUP message. */
    bool      is_faststart_Proc;   /**< True if a fastStart element was present in Proceeding, Alerting, Progress, or Connect. */
    bool      is_h245Tunneling;    /**< True if H.245 messages are tunnelled inside H.225 messages. */
    int32_t   q931_crv;            /**< Q.931 Call Reference Value for the forward direction. */
    int32_t   q931_crv2;           /**< Q.931 Call Reference Value for the reverse direction. */
    unsigned  requestSeqNum;       /**< H.225 RAS request sequence number for matching responses. */
} h323_calls_info_t;


/**
 * @brief Protocol-specific call metadata for MGCP calls.
 */
typedef struct _mgcp_calls_info {
    char *endpointId;    /**< MGCP endpoint identifier string (e.g. "aaln/1@gateway.example.com"). */
    bool  fromEndpoint;  /**< True if the call was originated by the endpoint; false if by the MGC. */
} mgcp_calls_info_t;


/**
 * @brief Protocol-specific call metadata for ACTrace ISDN calls.
 */
typedef struct _actrace_isdn_calls_info {
    int32_t crv;   /**< Q.931 Call Reference Value identifying this ISDN call. */
    int     trunk; /**< Trunk number on which this call is active. */
} actrace_isdn_calls_info_t;


/**
 * @brief Protocol-specific call metadata for ACTrace CAS calls.
 */
typedef struct _actrace_cas_calls_info {
    int32_t bchannel; /**< B-channel number carrying this CAS call. */
    int     trunk;    /**< Trunk number on which this call is active. */
} actrace_cas_calls_info_t;


/**
 * @brief Protocol-specific call metadata for Cisco Skinny (SCCP) calls.
 */
typedef struct _skinny_calls_info {
    uint32_t callId; /**< Skinny protocol call identifier. */
} skinny_calls_info_t;


/**
 * @brief Unified record describing a single detected VoIP call across all supported protocols.
 */
typedef struct _voip_calls_info {
    voip_call_state        call_state;        /**< High-level signalling state of the call (e.g. CALL_SETUP, IN_CALL, COMPLETED). */
    voip_call_active_state call_active_state;  /**< Active/inactive classification of the call. */
    char                  *call_id;           /**< Protocol-level call identifier string. */
    char                  *from_identity;     /**< Calling party identity (e.g. SIP From URI, ISUP CgPN). */
    char                  *to_identity;       /**< Called party identity (e.g. SIP To URI, ISUP CdPN). */
    void                  *prot_info;         /**< Pointer to the protocol-specific info struct (e.g. #sip_calls_info_t). */
    void (*free_prot_info)(void *);           /**< Destructor callback for @c prot_info; called when the record is freed. */
    address                initial_speaker;   /**< Network address of the party that initiated the call. */
    uint32_t               npackets;          /**< Total number of packets attributed to this call. */
    voip_protocol          protocol;          /**< Signalling protocol of this call; selects the active @c prot_info type. */
    char                  *protocol_name;     /**< Human-readable protocol name string. */
    char                  *call_comment;      /**< Optional free-text comment annotating this call. */
    uint16_t               call_num;          /**< Sequential call index assigned by the tap for display purposes. */
    frame_data            *start_fd;          /**< Frame data of the first packet of this call. */
    nstime_t               start_rel_ts;      /**< Relative timestamp of the first packet of this call. */
    frame_data            *stop_fd;           /**< Frame data of the last packet of this call. */
    nstime_t               stop_rel_ts;       /**< Relative timestamp of the last packet of this call. */
} voip_calls_info_t;


/**
 * @brief Aggregated tap state for the VoIP calls analysis, covering all detected calls and streams.
 *
 * Holds all cross-protocol state accumulated by the VoIP tap during a capture
 * session. Most fields are private to @c voip_calls.c.
 */
typedef struct _voip_calls_tapinfo {
    tap_reset_cb         tap_reset;          /**< Callback invoked to reset all tap state between captures. */
    tap_packet_cb        tap_packet;         /**< Callback invoked once per packet to update tap state. */
    tap_draw_cb          tap_draw;           /**< Callback invoked to redraw the UI after processing. */
    void                *tap_data;           /**< Opaque user data pointer passed to all tap callbacks. */
    int                  ncalls;             /**< Total number of calls detected so far. */
    GQueue              *callsinfos;         /**< Queue of all detected calls (#voip_calls_info_t). */
    GHashTable          *callsinfo_hashtable[1]; /**< Per-protocol hash tables for fast call lookup; index by #hash_indexes (currently only SIP). */
    int                  npackets;           /**< Total number of packets attributed to all calls. */
    voip_calls_info_t   *filter_calls_fwd;   /**< Call record used as a directional filter in certain tap modes. */
    int                  start_packets;      /**< Number of calls currently in the setup/ringing phase. */
    int                  completed_calls;    /**< Number of calls that completed normally. */
    int                  rejected_calls;     /**< Number of calls that were rejected or failed. */
    seq_analysis_info_t *graph_analysis;     /**< Sequence-diagram analysis state for the flow graph. */
    epan_t              *session;            /**< Wireshark dissection session owning this tap instance. */
    int                  nrtpstreams;        /**< Number of RTP streams detected across all calls. */
    GList               *rtpstream_list;     /**< List of #rtpstream_info_t entries for all RTP streams. */
    uint32_t             rtp_evt_frame_num;  /**< Frame number of the most recently seen RTP event packet. */
    uint8_t              rtp_evt;            /**< RTP event code from the most recently seen RFC 4733 packet. */
    bool                 rtp_evt_end;        /**< True if the most recently seen RTP event packet has the End bit set. */
    char                *sdp_summary;        /**< Summary string extracted from the most recently parsed SDP body. */
    uint32_t             sdp_frame_num;      /**< Frame number in which the most recent SDP body was observed. */
    uint32_t             mtp3_opc;           /**< MTP3 Originating Point Code from the most recent MTP3 packet. */
    uint32_t             mtp3_dpc;           /**< MTP3 Destination Point Code from the most recent MTP3 packet. */
    uint8_t              mtp3_ni;            /**< MTP3 Network Indicator from the most recent MTP3 packet. */
    uint32_t             mtp3_frame_num;     /**< Frame number of the most recently seen MTP3 packet. */
    struct _h245_labels *h245_labels;        /**< H.245 flow-graph label state for this session. */
    uint8_t              q931_cause_value;   /**< Q.931 cause value from the most recently seen release message. */
    int32_t              q931_crv;           /**< Q.931 Call Reference Value from the most recently seen Q.931 message. */
    uint32_t             q931_frame_num;     /**< Frame number of the most recently seen Q.931 packet. */
    uint32_t             h225_frame_num;     /**< Frame number of the most recently seen H.225 packet. */
    uint16_t             h225_call_num;      /**< Call index of the call associated with the most recent H.225 packet. */
    int                  h225_cstype;        /**< H.225 call signal type of the most recent H.225 message (enum value). */
    bool                 h225_is_faststart;  /**< True if the most recently seen H.225 message contained a fastStart element. */
    uint32_t             sip_frame_num;      /**< Frame number of the most recently seen SIP packet. */
    uint32_t             actrace_frame_num;  /**< Frame number of the most recently seen ACTrace packet. */
    int32_t              actrace_trunk;      /**< Trunk number from the most recently seen ACTrace packet. */
    int32_t              actrace_direction;  /**< Direction flag from the most recently seen ACTrace packet. */
    flow_show_options    fs_option;          /**< Current flow-graph display filter (all calls or INVITE-only). */
    uint32_t             redraw;             /**< Non-zero if the UI needs to be redrawn. */
    bool                 apply_display_filter; /**< True if the current Wireshark display filter should restrict shown calls. */
} voip_calls_tapinfo_t;

#if 0
#define VOIP_CALLS_DEBUG(...) { \
    char *VOIP_CALLS_DEBUG_MSG = ws_strdup_printf(__VA_ARGS__); \
    ws_warning("voip_calls: %s:%d %s", G_STRFUNC, __LINE__, VOIP_CALLS_DEBUG_MSG); \
    g_free(VOIP_CALLS_DEBUG_MSG); \
}
#else
#define VOIP_CALLS_DEBUG(...)
#endif

/****************************************************************************/
/* INTERFACE */

/**
 * @brief Registers the voip_calls tap listeners (if not already done).
 *
 * From that point on, the calls list will be updated with every redissection.
 * This function is also the entry point for the initialization routine of the tap system.
 * So whenever voip_calls.c is added to the list of WIRESHARK_TAP_SRCs, the tap will be registered on startup.
 * If not, it will be registered on demand by the voip_calls functions that need it.
 *
 * @param tap_id_base Pointer to the base tap information structure for VoIP calls.
 */
void voip_calls_init_all_taps(voip_calls_tapinfo_t *tap_id_base);

/**
 * @brief Removes the voip_calls tap listener (if not already done).
 *
 * From that point on, the voip calls list won't be updated any more.
 *
 * @param tap_id_base Pointer to the base tap information structure for VoIP calls.
 */
void voip_calls_remove_all_tap_listeners(voip_calls_tapinfo_t *tap_id_base);

/**
 * @brief Cleans up memory of voip calls tap.
 *
 * @param tapinfo Pointer to the VoIP calls tap information structure.
 */
void voip_calls_reset_all_taps(voip_calls_tapinfo_t *tapinfo);

/**
 * @brief Sets whether to apply display filter for VoIP calls.
 *
 * @param tapinfo Pointer to the VoIP calls tap information structure.
 * @param apply Boolean indicating whether to apply the display filter.
 */
void
voip_calls_set_apply_display_filter(voip_calls_tapinfo_t *tapinfo, bool apply);

/**
 * @brief Frees one callsinfo
 * @param callsinfo Pointer to the callsinfo structure to free.
 */
void
voip_calls_free_callsinfo(voip_calls_info_t *callsinfo);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __VOIP_CALLS_H__ */
