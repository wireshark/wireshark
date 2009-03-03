/* packet-miop.h
 * Declaration of routines for CORBA MIOP dissection
 * Significantly based on packet-giop.h
 * Copyright 2009 Alvaro Vega Garcia <avega at tid dot es>
 *
 * Based on Unreliable Multicast Draft Adopted Specification
 * 2001 October (OMG)
 * Chapter 29: Unreliable Multicast Inter-ORB Protocol (MIOP)
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef PACKET_MIOP_H
#define PACKET_MIOP_H

/*
 * Useful visible data/structs
 */

#define MIOP_HEADER_SIZE    16

typedef struct UniqueId {
  guint32 id_len;	/* length < 252 */
  guint8 *id;		/* ptr to id */
} UniqueId;

typedef struct PacketHeader_1_0 {
  guint8 magic[4];
  guint8 hdr_version;
  guint8 flags;
  guint16 packet_length;
  guint32 packet_number;
  guint32 number_of_packets;
  /* UniqueId id; */
} PacketHeader;


static dissector_handle_t miop_handle;

static void dissect_miop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void proto_register_miop();

void proto_reg_handoff_miop();

#endif /* PACKET_MIOP_H */
