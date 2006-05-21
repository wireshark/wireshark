/* packet-jxta.h
 * Routines for JXTA packet dissection
 * Copyright 2004-05, Mike Duigou <bondolo@jxta.org>
 * Heavily based on packet-jabber.c, which in turn is heavily based on 
 * on packet-acap.c, which in turn is heavily based on 
 * packet-imap.c, Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c, packet-jabber.c, packet-udp.c
 *
 * JXTA specification from http://spec.jxta.org
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#ifndef __PACKET_JXTA_H__
#define __PACKET_JXTA_H__
#include <glib.h>

#include <epan/packet.h>

/**
*   Stream Conversation data
**/
typedef struct jxta_tap_header {
    address src_address;
    address dest_address;
    guint32 size;
} jxta_tap_header;
#endif
