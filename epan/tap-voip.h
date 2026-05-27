/** @file
 *
 * VoIP packet tap interface   2007 Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

/**
 * @brief Signaling state of a VoIP call session.
 */
typedef enum _voip_call_state {
    VOIP_NO_STATE,    /**< No state assigned; uninitialized */
    VOIP_CALL_SETUP,  /**< Call setup in progress (e.g., INVITE sent, not yet ringing) */
    VOIP_RINGING,     /**< Remote party is being alerted (ringing) */
    VOIP_IN_CALL,     /**< Call has been established and is active */
    VOIP_CANCELLED,   /**< Call was cancelled by the originating party before being answered */
    VOIP_COMPLETED,   /**< Call completed normally (answered and subsequently ended) */
    VOIP_REJECTED,    /**< Call was rejected by the remote party */
    VOIP_UNKNOWN      /**< Call state could not be determined from the captured traffic */
} voip_call_state;


/**
 * @brief Indicates whether a VoIP call is currently considered active or inactive.
 */
typedef enum _voip_call_active_state {
    VOIP_ACTIVE,   /**< Call is currently active (ongoing or recently seen) */
    VOIP_INACTIVE  /**< Call is no longer active (ended, timed out, or complete) */
} voip_call_active_state;


/**
 * @brief Per-packet metadata delivered to the VoIP calls tap for both common and proprietary protocols.
 */
typedef struct _voip_packet_info_t {
    char                   *protocol_name;      /**< Name of the VoIP protocol that generated this record (e.g., "SIP", "H.323") */
    char                   *call_id;            /**< Unique call identifier string extracted from the protocol (e.g., SIP Call-ID) */
    voip_call_state         call_state;         /**< Current signaling state of the call as of this packet */
    voip_call_active_state  call_active_state;  /**< Whether the call is considered active or inactive as of this packet */
    char                   *from_identity;      /**< Display string identifying the calling party (e.g., SIP From URI) */
    char                   *to_identity;        /**< Display string identifying the called party (e.g., SIP To URI) */
    char                   *call_comment;       /**< Optional free-text annotation describing the call */
    char                   *frame_label;        /**< Short label for this packet shown in the flow graph (e.g., "INVITE") */
    char                   *frame_comment;      /**< Extended comment for this packet shown in the flow graph */
} voip_packet_info_t;
