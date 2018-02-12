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

#include <epan/dissectors/packet-e164.h>

extern void alcap_tree_from_bearer_key(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo, const gchar* key);

typedef struct _alcap_msg_data_t {
    guint msg_type;
    guint framenum;
    struct _alcap_msg_data_t* next;
    struct _alcap_msg_data_t* last;
} alcap_msg_data_t;

typedef struct _alcap_leg_info_t  {
	guint32 dsaid;
	guint32 osaid;
	guint32 pathid;
	guint32 cid;
	guint32 sugr;
	gchar* orig_nsap;
	gchar* dest_nsap;
    alcap_msg_data_t* msgs;
    guint release_cause;
} alcap_leg_info_t;


typedef struct _alcap_message_info_t {
	guint msg_type;
	guint32 dsaid;
	guint32 osaid;
	guint32 pathid;
	guint32 cid;
	guint32 sugr;
	gchar* orig_nsap;
	gchar* dest_nsap;
    guint release_cause;
} alcap_message_info_t;

#endif
