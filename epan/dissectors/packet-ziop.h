/* packet-ziop.h
 * Declaration of routines for ZIOP dissection
 * Significantly based on packet-giop.h
 * Copyright 2009 Alvaro Vega Garcia <avega at tid dot es>
 *
 * Based on GIOP Compression FTF Beta 1
 * OMG mars/2008-12-20
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_ZIOP_H
#define PACKET_ZIOP_H

/*
 * Useful visible data/structs
 */

#define ZIOP_HEADER_SIZE    12

#define ZIOP_MAGIC 	 "ZIOP"

typedef struct ZIOPHeader_1_0 {
  uint8_t magic[4];
  uint8_t giop_version_major;
  uint8_t giop_version_minor;
  uint8_t flags;
  uint8_t message_type;
  uint32_t message_size;
} ZIOPHeader;


typedef struct ZIOP_CompressionData {
  uint16_t compressor_id;
  uint16_t padding; /* to be skipped due to CDR rules */
  uint32_t original_length;
  /* Compression::Buffer data; */
} CompressionData;

bool
dissect_ziop_heur (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data);

#endif /* PACKET_ZIOP_H */
