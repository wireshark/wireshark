/* packet-rohc.h
 * Routines for RObust Header Compression (ROHC) dissection.
 *
 * Copyright 2011, Anders Broman <anders.broman[at]ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref:
 * http://www.ietf.org/rfc/rfc3095.txt         RObust Header Compression (ROHC): Framework and four profiles: RTP, UDP, ESP, and uncompressed
 * http://datatracker.ietf.org/doc/rfc4815/    RObust Header Compression (ROHC): Corrections and Clarifications to RFC 3095
 * http://datatracker.ietf.org/doc/rfc5225/    RObust Header Compression Version 2 (ROHCv2): Profiles for RTP, UDP, IP, ESP and UDP-Lite
 */

#ifndef PACKET_ROHC_H
#define PACKET_ROHC_H

#define MAX_CID      15

 /* ROHC Profiles */
#define ROHC_PROFILE_UNCOMPRESSED   0
#define ROHC_PROFILE_RTP            1
#define ROHC_PROFILE_UDP            2
#define ROHC_PROFILE_IP             4
#define ROHC_PROFILE_UNKNOWN        0xFFFF

enum rohc_mode
{
  MODE_NOT_SET = 0,
  UNIDIRECTIONAL = 1,
  OPTIMISTIC_BIDIRECTIONAL = 2,
  RELIABLE_BIDIRECTIONAL = 3
};

enum rohc_d_mode
{
  NO_CONTEXT = 1,
  STATIC_CONTEXT = 2,
  FULL_CONTEXT = 3
};
typedef struct rohc_info
{
    gboolean           rohc_compression;
    guint8             rohc_ip_version;
    gboolean           cid_inclusion_info;
    gboolean           large_cid_present;
    enum rohc_mode     mode;
    gboolean           rnd;
    gboolean           udp_checksum_present;
    guint16            profile;
    proto_item         *last_created_item;
} rohc_info;


typedef struct rohc_context
{
    guint8             rohc_ip_version[MAX_CID+1];
    gboolean           large_cid_present[MAX_CID+1];
    enum rohc_mode     mode[MAX_CID+1];
    enum rohc_d_mode   d_mode[MAX_CID+1];
    gboolean           rnd[MAX_CID+1];
    gboolean           udp_checkum_present[MAX_CID+1];
    guint16            profile[MAX_CID+1];
	gboolean           rohc_context_init[MAX_CID+1];
	gint               ir_frame_number[MAX_CID+1];        /* The frame number of the last IR packet seen */

} rohc_context;

#endif /* PACKET_ROHC_H */
