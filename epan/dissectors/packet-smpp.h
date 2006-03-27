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
 * $Id$
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * ----------
 *
 * Dissector of an SMPP (Short Message Peer to Peer) PDU, as defined by the
 * SMS forum (www.smsforum.net) in "SMPP protocol specification v3.4"
 * (document version: 12-Oct-1999 Issue 1.2)
 */
 
/*
 * Export dissection of some parameters
 */
void smpp_handle_dcs(proto_tree *tree, tvbuff_t *tvb, int *offset);
