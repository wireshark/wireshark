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


typedef struct rohc_info
{
    bool               rohc_compression;
    uint8_t            rohc_ip_version;
    bool               cid_inclusion_info;
    bool               large_cid_present;
    enum rohc_mode     mode;
    bool               rnd;
    bool               udp_checksum_present;
    uint16_t           profile;
    proto_item         *last_created_item;
} rohc_info;

#endif /* PACKET_ROHC_H */
