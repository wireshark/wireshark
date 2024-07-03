/* packet-alcap.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_ALCAP_H
#define PACKET_ALCAP_H

#include "packet-e164.h"

extern void alcap_tree_from_bearer_key(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, const char* key);

typedef struct _alcap_msg_data_t {
    unsigned msg_type;
    unsigned framenum;
    struct _alcap_msg_data_t* next;
    struct _alcap_msg_data_t* last;
} alcap_msg_data_t;

typedef struct _alcap_leg_info_t  {
	uint32_t dsaid;
	uint32_t osaid;
	uint32_t pathid;
	uint32_t cid;
	uint32_t sugr;
	char* orig_nsap;
	char* dest_nsap;
    alcap_msg_data_t* msgs;
    unsigned release_cause;
} alcap_leg_info_t;


typedef struct _alcap_message_info_t {
	unsigned msg_type;
	uint32_t dsaid;
	uint32_t osaid;
	uint32_t pathid;
	uint32_t cid;
	uint32_t sugr;
	char* orig_nsap;
	char* dest_nsap;
    unsigned release_cause;
} alcap_message_info_t;

#endif
