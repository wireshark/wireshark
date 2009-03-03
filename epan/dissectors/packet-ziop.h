/* packet-ziop.h
 * Declaration of routines for ZIOP dissection
 * Significantly based on packet-giop.h
 * Copyright 2009 Alvaro Vega Garcia <avega at tid dot es>
 *
 * Based on GIOP Compression FTF Beta 1
 * OMG mars/2008-12-20
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

#ifndef PACKET_ZIOP_H
#define PACKET_ZIOP_H

/*
 * Useful visible data/structs
 */

#define ZIOP_HEADER_SIZE    12 

#define ZIOP_MAGIC 	 "ZIOP"

typedef struct ZIOPHeader_1_0 {
  guint8 magic[4];
  guint8 giop_version_major;
  guint8 giop_version_minor;
  guint8 flags;
  guint8 message_type;
  guint32 message_size;
} ZIOPHeader;


typedef struct ZIOP_CompressionData {
  guint16 compressor_id;
  guint16 padding; /* to be skipped due to CDR rules */
  guint32 original_length;
  /* Compression::Buffer data; */
} CompressionData;





extern void dissect_ziop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

gboolean
dissect_ziop_heur (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree);

void proto_register_ziop();

void proto_reg_handoff_ziop();

#endif /* PACKET_ZIOP_H */
