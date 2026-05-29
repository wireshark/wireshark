/* packet-unistim.h
 * header field declarations, value_string definitions, true_false_string
 * definitions and function prototypes for main dissectors
 * Copyright 2007 Don Newton <dnewton@cypresscom.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_UNISTIM_H
#define PACKET_UNISTIM_H

/**
 * @brief Holds per-packet metadata captured by the UNISTIM dissector tap.
 */
typedef struct _unistim_info_t
{
    uint8_t        rudp_type;      /**< RUDP packet type: NAK, ACK, or Payload. */
    uint8_t        payload_type;   /**< UNISTIM payload type: aggregate, non-aggregate, or encapsulated. */
    uint32_t       sequence;       /**< RUDP sequence number. */
    uint32_t       termid;         /**< Terminal ID, if available. */
    address        it_ip;          /**< IP address of the IT (phone), determined by which side is sending terminal IDs. */
    uint32_t       it_port;        /**< UDP port of the IT (phone). */
    address        ni_ip;          /**< IP address of the NI (server), determined by which side is sending terminal IDs. */
    int            key_val;        /**< Key pressed; -1 if no key event in this packet. */
    int            key_state;      /**< Key state: 1 = down, 0 = up. */
    int            hook_state;     /**< Hook state: 1 = off-hook, 0 = on-hook. */
    int            stream_connect; /**< Audio stream state: 1 = connected, 0 = disconnected. */
    int            trans_connect;  /**< Transducer connection state: 1 = connected, 0 = disconnected. */
    int            set_termid;     /**< Whether to assign the terminal ID: 1 = set terminal ID. */
    const uint8_t *string_data;    /**< Pointer to display string data whenever a string is written to the phone display; NULL if unused. */
    int            call_state;     /**< Call state (currently unused). */
    unsigned char *key_buffer;     /**< Buffer of call keys pressed; used by the VoIP calls tap in voip-calls.c. */
} unistim_info_t;

#endif

