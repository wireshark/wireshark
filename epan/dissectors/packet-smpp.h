/* packet-smpp.h
 * Routines for Short Message Peer to Peer dissection
 * Copyright 2001, Tom Uijldert.
 *
 * Data Coding Scheme decoding for GSM (SMS and CBS),
 * provided by Olivier Biot.
 *
 * Dissection of multiple SMPP PDUs within one packet
 * provided by Chris Wilson.
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * ----------
 *
 * Dissector of an SMPP (Short Message Peer to Peer) PDU, as defined by the
 * SMS forum (www.smsforum.net) in "SMPP protocol specification v3.4"
 * (document version: 12-Oct-1999 Issue 1.2)
 */

#ifndef __PACKET_SMPP_H_
#define __PACKET_SMPP_H_

#include "packet-gsm_sms.h"

typedef struct _smpp_data_t {
        gboolean udhi;
        guint encoding;
        gsm_sms_udh_fields_t *udh_fields;
} smpp_data_t;

/*
 * Export dissection of some parameters
 */
void smpp_handle_dcs(proto_tree *tree, tvbuff_t *tvb, int *offset, guint *encoding);


/* Tap Record */
typedef struct _smpp_tap_rec_t {
	guint command_id;
	guint command_status;
} smpp_tap_rec_t;

#endif
