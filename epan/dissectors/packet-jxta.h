/* packet-jxta.c
 *
 * Routines for JXTA packet dissection
 * JXTA specification from https://jxta-spec.dev.java.net
 *
 * Copyright 2004-08, Mike Duigou <bondolo@dev.java.net>
 *
 * Heavily based on packet-jabber.c, which in turn is heavily based on
 * on packet-acap.c, which in turn is heavily based on
 * packet-imap.c, Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 * Copied from packet-pop.c, packet-jabber.c, packet-udp.c, packet-http.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __PACKET_JXTA_H__
#define __PACKET_JXTA_H__

#include <glib.h>
#include <epan/address.h>

/**
*   Stream Conversation data
**/
typedef struct jxta_tap_header {
    address src_address;
    address dest_address;
    uint32_t size;
} jxta_tap_header;

#endif
