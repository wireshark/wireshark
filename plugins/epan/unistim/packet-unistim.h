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

typedef struct _unistim_info_t
{
	uint8_t       rudp_type;      /* NAK, ACK, Payload */
	uint8_t       payload_type;   /* unistim payload type (aggregate, non-aggregate, encapsulated) */
	uint32_t      sequence;       /* rudp sequence number */
	uint32_t      termid;         /* termid if available */
	address       it_ip;          /* IP addr of it, determined by who is sending termids */
	uint32_t      it_port;        /* port of it (phone) */
	address       ni_ip;          /* IP addr of ni (server) as determined by who's sending termids */
	int           key_val;        /* actual key pressed (-1 if not used) */
	int           key_state;      /* Key state 1=down 0=up */
	int           hook_state;     /* Hook state 1=offhook 0=onhook */
	int           stream_connect; /* Audio stream connect 1=connect 0=disconnect */
	int           trans_connect;  /* Transducer connect? 1=connect 0=disconnect */
	int	      set_termid;     /* Set the termid 1=set termid */
	const uint8_t *string_data;   /* Any time a string is written to the display, this has the string */
	int           call_state;     /* Not used? */
	unsigned char *key_buffer;    /* Used in voip-calls.c tap, holds call keys pressed */
} unistim_info_t;

#endif

