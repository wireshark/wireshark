/* packet-sctp.h
 *
 * Defintion of SCTP specific structures used by tap listeners.
 *
 * Copyright 2004 Michael Tuexen <tuexen [AT] fh-muenster.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_SCTP_H__
#define __PACKET_SCTP_H__

#define MAXIMUM_NUMBER_OF_TVBS 2048

struct _sctp_info {
  gboolean incomplete;
  gboolean adler32_calculated;
  gboolean adler32_correct;
  gboolean crc32c_calculated;
  gboolean crc32c_correct;
  gboolean checksum_zero;
  gboolean vtag_reflected;
  guint16 sport;
  guint16 dport;
  address ip_src;
  address ip_dst;
  guint32 verification_tag;
  guint16 assoc_index;
  guint16 direction;
  guint32 number_of_tvbs;
  tvbuff_t *tvb[MAXIMUM_NUMBER_OF_TVBS];
};

typedef struct _sctp_fragment {
  guint32 frame_num;
  guint32 tsn;
  guint32 len;
  unsigned char *data;
  struct _sctp_fragment *next;
} sctp_fragment;

typedef struct _sctp_frag_be {
  sctp_fragment* fragment;
  struct _sctp_frag_be *next;
} sctp_frag_be;

typedef struct _sctp_complete_msg {
  guint32 begin;
  guint32 end;
  sctp_fragment* reassembled_in;
  guint32 len;
  unsigned char *data;
  struct _sctp_complete_msg *next;
} sctp_complete_msg;

typedef struct _sctp_frag_msg {
  sctp_frag_be* begins;
  sctp_frag_be* ends;
  sctp_fragment* fragments;
  sctp_complete_msg* messages;
  struct _sctp_frag_msg* next;
} sctp_frag_msg;


#endif
